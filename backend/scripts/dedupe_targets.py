"""Collapse duplicate target records created before reuse-or-create existed.

Targets registered from the Scans page used to insert a fresh row per scan, so a
single lab host can hold dozens of records with the scan history and findings
split across them. This merges rows that share a normalised endpoint AND
identical scan_config — the same rule `POST /targets` now applies — keeping the
oldest record and repointing scans and findings at it.

Rows whose scan_config differs are left alone: those are genuinely distinct
assessment contexts, not duplicates.

    docker compose exec backend uv run python scripts/dedupe_targets.py
    docker compose exec backend uv run python scripts/dedupe_targets.py --apply

Reports what it would do and changes nothing unless --apply is passed.
"""

from __future__ import annotations

import argparse
import asyncio
import sys
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from sqlalchemy import func, select, update  # noqa: E402

from app.api.v1.targets import _endpoint_identity, _same_scan_config  # noqa: E402
from app.database.session import AsyncSessionLocal  # noqa: E402
from app.models.finding import Finding  # noqa: E402
from app.models.scan import Scan  # noqa: E402
from app.models.target import Target  # noqa: E402


def _group_duplicates(targets: list[Target]) -> list[list[Target]]:
    """Duplicate sets, oldest first within each set, singletons dropped."""
    by_endpoint: dict[tuple[str, str], list[Target]] = defaultdict(list)
    for target in targets:
        identity = _endpoint_identity(target.base_url, target.ip_address)
        if not identity:
            # No endpoint means nothing to match on; never merge these.
            continue
        by_endpoint[(identity, target.environment)].append(target)

    groups: list[list[Target]] = []
    for candidates in by_endpoint.values():
        remaining = sorted(candidates, key=lambda t: t.created_at)
        while remaining:
            keeper, rest = remaining[0], remaining[1:]
            same = [t for t in rest if _same_scan_config(t.scan_config, keeper.scan_config)]
            remaining = [t for t in rest if t not in same]
            if same:
                groups.append([keeper, *same])
    return groups


async def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--apply", action="store_true", help="perform the merge (default: dry run)")
    args = parser.parse_args()

    async with AsyncSessionLocal() as db:
        targets = list((await db.execute(select(Target))).scalars().all())
        groups = _group_duplicates(targets)

        if not groups:
            print(f"{len(targets)} targets, no duplicates found.")
            return

        merged_away = sum(len(group) - 1 for group in groups)
        print(f"{len(targets)} targets -> {len(targets) - merged_away} after merge\n")

        for keeper, *duplicates in groups:
            duplicate_ids = [t.id for t in duplicates]
            scans = await db.scalar(
                select(func.count()).select_from(Scan).where(Scan.target_id.in_(duplicate_ids))
            )
            findings = await db.scalar(
                select(func.count()).select_from(Finding).where(Finding.target_id.in_(duplicate_ids))
            )
            print(
                f"  {keeper.base_url or keeper.ip_address}"
                f" [{keeper.environment}, config={keeper.scan_config or 'none'}]"
            )
            print(
                f"    keep {keeper.id} ({keeper.name}); "
                f"merge {len(duplicates)} row(s), moving {scans} scan(s) and {findings} finding(s)"
            )

            if args.apply:
                await db.execute(
                    update(Scan).where(Scan.target_id.in_(duplicate_ids)).values(target_id=keeper.id)
                )
                await db.execute(
                    update(Finding)
                    .where(Finding.target_id.in_(duplicate_ids))
                    .values(target_id=keeper.id)
                )
                for duplicate in duplicates:
                    await db.delete(duplicate)

        if args.apply:
            await db.commit()
            print("\nApplied.")
        else:
            print("\nDry run — nothing changed. Re-run with --apply to perform the merge.")


if __name__ == "__main__":
    asyncio.run(main())
