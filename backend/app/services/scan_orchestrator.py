from __future__ import annotations

from collections.abc import Sequence
from datetime import UTC, datetime

from sqlalchemy.ext.asyncio import AsyncSession

from app.models.finding import Evidence, Finding
from app.models.scan import Scan, ScanStatus
from app.models.target import Target
from app.scanners.base import BaseDetector, ScanContext
from app.scanners.zap_validation import corroborate_with_zap


async def run_scan(
    db: AsyncSession,
    scan: Scan,
    target: Target,
    detectors: Sequence[BaseDetector],
    use_zap: bool = False,
) -> Scan:
    """Run the selected detectors against one approved target."""

    scan.status = ScanStatus.RUNNING
    scan.started_at = datetime.now(UTC)

    try:
        scan_config = dict(target.scan_config or {})
        scan_config["use_zap"] = use_zap
        if "vulnvista_dvwa" in (target.base_url or ""):
            headers = dict(scan_config.get("headers", {}))
            headers.setdefault("Host", "localhost")
            scan_config["headers"] = headers

        context = ScanContext(
            target_id=str(target.id),
            base_url=target.base_url or "",
            extra=scan_config,
        )

        failed_detectors = 0
        pages_scanned = 0

        for detector in detectors:
            try:
                # A detector may return one result or one result per crawled page.
                for result in await detector.check_all(context):
                    pages_scanned = max(
                        pages_scanned,
                        int(result.evidence.get("pages_crawled", 0)),
                    )
                    result = await corroborate_with_zap(detector.detector_id, context, result)
                    # Optional detector-specific secondary validation.
                    result = await detector.validate(result)

                    # Only create a finding when something was detected.
                    if result.detected:
                        finding_data = detector.build_finding(
                            scan_id=str(scan.id),
                            target_id=str(target.id),
                            result=result,
                        )

                        finding = Finding(**finding_data)
                        db.add(finding)

                        # Store the detector evidence separately.
                        if result.evidence:
                            evidence = Evidence(
                                finding=finding,
                                evidence_type="detector",
                                content=result.evidence,
                            )
                            db.add(evidence)

            except Exception as exc:
                failed_detectors += 1

                # Keep the scan running even if one detector fails.
                print(f"Detector '{detector.detector_id}' failed: {exc}")

        if failed_detectors == 0:
            scan.status = ScanStatus.COMPLETED
        elif failed_detectors < len(detectors):
            scan.status = ScanStatus.PARTIAL
        else:
            scan.status = ScanStatus.FAILED

        scan.completed_at = datetime.now(UTC)
        scan.pages_scanned = pages_scanned

        if scan.started_at:
            scan.duration_seconds = (scan.completed_at - scan.started_at).total_seconds()

        await db.commit()
        await db.refresh(scan)

        return scan

    except Exception as exc:
        scan.status = ScanStatus.FAILED
        scan.error_summary = str(exc)
        scan.completed_at = datetime.now(UTC)

        await db.commit()
        await db.refresh(scan)

        raise
