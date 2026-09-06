"""Run the passive misconfiguration detector against an authorized lab target.

Usage (from backend/):
    uv run python scripts/manual_check_misconfiguration.py
    uv run python scripts/manual_check_misconfiguration.py --base-url http://juice-shop:3000
"""

from __future__ import annotations

import argparse
import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.scanners.base import ScanContext  # noqa: E402
from app.scanners.misconfiguration import MisconfigurationDetector  # noqa: E402


async def main(base_url: str) -> None:
    result = await MisconfigurationDetector().check(
        ScanContext(target_id="manual-check", base_url=base_url)
    )
    print("detected:", result.detected)
    print("severity:", result.severity, "confidence:", result.confidence)
    print("validation_status:", result.validation_status)
    print("cwe:", result.cwe, "cvss:", result.cvss_score)
    print("endpoint:", result.endpoint)
    print("summary:", result.evidence_summary)
    print("evidence:", result.evidence)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--base-url",
        default="http://localhost:3000",
        help="Authorized lab base URL (default: http://localhost:3000)",
    )
    args = parser.parse_args()
    asyncio.run(main(args.base_url))
