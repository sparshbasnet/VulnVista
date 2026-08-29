"""Runs a crawl for a Discovery and persists the resulting path map.

Detached from the request that created the discovery (FastAPI BackgroundTask),
so it opens its own DB session — mirrors scan_runner.run_scan.
"""

from __future__ import annotations

import logging
import uuid
from datetime import UTC, datetime

from app.database.session import AsyncSessionLocal
from app.models.discovery import Discovery, DiscoveryStatus
from app.models.target import Target
from app.services.crawler import crawl

logger = logging.getLogger(__name__)


async def run_discovery(discovery_id: uuid.UUID) -> None:
    """Crawl the discovery's target and store the discovered paths.

    Always ends in a terminal status — a crash marks it FAILED rather than
    leaving it RUNNING (which would make the UI poll forever)."""
    async with AsyncSessionLocal() as db:
        discovery = await db.get(Discovery, discovery_id)
        if discovery is None:
            logger.warning("run_discovery: discovery %s no longer exists", discovery_id)
            return
        target = await db.get(Target, discovery.target_id)
        if target is None or not target.base_url:
            discovery.status = DiscoveryStatus.FAILED
            discovery.error_summary = "Target missing or has no base_url"
            await db.commit()
            return

        discovery.status = DiscoveryStatus.RUNNING
        discovery.started_at = datetime.now(UTC)
        await db.commit()

        try:
            paths = await crawl(target.base_url, target.scan_config or {})
            discovery.paths = paths
            discovery.page_count = len(paths)
            discovery.status = DiscoveryStatus.COMPLETED
        except Exception as exc:  # never leave the discovery stuck in RUNNING
            logger.exception("run_discovery failed for %s", discovery_id)
            discovery.status = DiscoveryStatus.FAILED
            discovery.error_summary = f"Crawl error: {exc}"

        discovery.completed_at = datetime.now(UTC)
        await db.commit()
