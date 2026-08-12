"""Executes a scan's detectors against its target and persists results.

Designed to run detached from the request that created the scan (FastAPI
BackgroundTask), so it opens its own database session rather than borrowing the
request-scoped one, which is already closed by the time this runs.
"""

from __future__ import annotations

import logging
import uuid
from datetime import UTC, datetime

from sqlalchemy.ext.asyncio import AsyncSession

from app.database.session import AsyncSessionLocal
from app.models.finding import Evidence, Finding
from app.models.scan import Scan, ScanStatus
from app.models.target import Target
from app.scanners import BaseDetector, get_detectors_for_profile
from app.scanners.base import DetectorResult, ScanContext

logger = logging.getLogger(__name__)

# Detector verdicts that are worth recording as a Finding. A clean
# "NOT_DETECTED" run leaves no finding behind, and an "ERROR" run is surfaced via
# the scan's error_summary rather than as a phantom finding.
_REPORTABLE = {"CONFIRMED", "SUSPECTED", "INCONCLUSIVE"}


async def run_scan(scan_id: uuid.UUID) -> None:
    """Run every detector in the scan's profile and persist findings/evidence.

    Guarantees the scan always ends in a terminal status — a crash anywhere here
    marks it FAILED rather than leaving it stuck in RUNNING (which would make the
    UI poll forever).
    """
    async with AsyncSessionLocal() as db:
        scan = await db.get(Scan, scan_id)
        if scan is None:
            logger.warning("run_scan: scan %s no longer exists", scan_id)
            return
        target = await db.get(Target, scan.target_id)
        if target is None or not target.base_url:
            scan.status = ScanStatus.FAILED
            scan.error_summary = "Target missing or has no base_url"
            await db.commit()
            return

        scan.status = ScanStatus.RUNNING
        scan.started_at = datetime.now(UTC)
        await db.commit()

        context = ScanContext(
            target_id=str(target.id), base_url=target.base_url, extra=target.scan_config or {}
        )
        detectors = get_detectors_for_profile(scan.scan_profile)

        errors = 0
        try:
            for detector in detectors:
                try:
                    result = await detector.check(context)
                    result = await detector.validate(result)
                except Exception as exc:  # a detector bug must not sink the whole scan
                    logger.exception("detector %s crashed", detector.detector_id)
                    errors += 1
                    scan.error_summary = f"{detector.detector_id}: {exc}"
                    continue

                if result.validation_status == "ERROR":
                    errors += 1
                    scan.error_summary = result.evidence_summary
                elif result.validation_status in _REPORTABLE:
                    _persist_finding(db, detector, scan, target, result)

            if errors == 0:
                scan.status = ScanStatus.COMPLETED
            elif errors < len(detectors):
                scan.status = ScanStatus.PARTIAL
            else:
                scan.status = ScanStatus.FAILED
        except Exception as exc:  # never leave the scan stuck in RUNNING
            logger.exception("run_scan failed for %s", scan_id)
            scan.status = ScanStatus.FAILED
            scan.error_summary = f"Scan runner error: {exc}"

        completed = datetime.now(UTC)
        scan.completed_at = completed
        if scan.started_at is not None:
            scan.duration_seconds = (completed - scan.started_at).total_seconds()
        await db.commit()


def _persist_finding(
    db: AsyncSession,
    detector: BaseDetector,
    scan: Scan,
    target: Target,
    result: DetectorResult,
) -> None:
    """Create a Finding (+ its Evidence row) from a detector result."""
    payload = detector.build_finding(str(scan.id), str(target.id), result)
    # build_finding emits str ids for the shared contract; the ORM columns are
    # UUID, so hand it the real UUIDs.
    payload["scan_id"] = scan.id
    payload["target_id"] = target.id
    finding = Finding(**payload)
    if result.evidence:
        finding.evidence.append(
            Evidence(evidence_type="detector_probe", content=result.evidence)
        )
    db.add(finding)
