"""Executes a scan's detectors against its target and persists results.

Designed to run detached from the request that created the scan (FastAPI
BackgroundTask), so it opens its own database session rather than borrowing the
request-scoped one, which is already closed by the time this runs.
"""

from __future__ import annotations

import logging
import uuid
from datetime import UTC, datetime
from urllib.parse import urlparse

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

# Upper bound on in-scope paths a single scan will attack, so a large discovery
# tree can't turn one scan into thousands of detector runs.
MAX_SCOPED_PATHS = 25


def _build_runs(
    detectors: list[BaseDetector], target: Target, scan: Scan
) -> list[tuple[BaseDetector, ScanContext]]:
    """Expand the scan into concrete (detector, context) runs.

    Unscoped scan (no in_scope_paths): each detector runs once with the target's
    own base_url, exactly as before.

    Scoped scan: host-level detectors (TLS, open services, …) still run once for
    the whole target, while path-level detectors run once per in-scope path —
    the path is fed both as the context's base_url and as ``discovery_path`` so
    every detector, whether it keys off the URL path or the override, probes that
    exact path. Out-of-scope paths are simply never turned into a run.
    """
    base_extra = target.scan_config or {}
    base_context = ScanContext(
        target_id=str(target.id), base_url=target.base_url, extra=base_extra
    )

    in_scope = scan.in_scope_paths or []
    if not in_scope:
        return [(detector, base_context) for detector in detectors]

    parsed = urlparse(target.base_url)
    origin = f"{parsed.scheme}://{parsed.netloc}"
    # The crawler keys discovered entries by URL, so one path arrives once per
    # URL that reached it (DVWA links /instructions.php from six pages).
    # Normalize, then dedupe preserving order — otherwise a scoped run attacks
    # the same path once per duplicate, and the MAX_SCOPED_PATHS cap spends its
    # budget on repeats and silently drops paths the operator did select.
    normalized = [p if p.startswith("/") else f"/{p}" for p in in_scope]
    paths = list(dict.fromkeys(normalized))[:MAX_SCOPED_PATHS]

    runs: list[tuple[BaseDetector, ScanContext]] = []
    for detector in detectors:
        if detector.scan_scope == "host":
            runs.append((detector, base_context))
            continue
        for path in paths:
            runs.append(
                (
                    detector,
                    ScanContext(
                        target_id=str(target.id),
                        base_url=f"{origin}{path}",
                        extra={**base_extra, "discovery_path": path},
                    ),
                )
            )
    return runs


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

        detectors = get_detectors_for_profile(scan.scan_profile)
        runs = _build_runs(detectors, target, scan)

        errors = 0
        mixed_outcomes = False
        try:
            for detector, context in runs:
                detector_had_error = False
                detector_had_non_error = False
                try:
                    results = await detector.check_many(context)
                except Exception as exc:  # a detector bug must not sink the whole scan
                    logger.exception("detector %s crashed", detector.detector_id)
                    errors += 1
                    scan.error_summary = f"{detector.detector_id}: {exc}"
                    continue

                for raw_result in results:
                    result = await detector.validate(context, raw_result)
                    if result.validation_status == "ERROR":
                        detector_had_error = True
                        scan.error_summary = result.evidence_summary
                    else:
                        detector_had_non_error = True
                        if result.validation_status in _REPORTABLE:
                            _persist_finding(db, detector, scan, target, result)

                if detector_had_error:
                    errors += 1
                if detector_had_error and detector_had_non_error:
                    mixed_outcomes = True

            if errors == 0:
                scan.status = ScanStatus.COMPLETED
            elif errors < len(runs) or mixed_outcomes:
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
