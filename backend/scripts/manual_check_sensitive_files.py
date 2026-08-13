"""Manual live-run of the sensitive-files detector against a real target.

Not part of the automated test suite (backend/tests/test_sensitive_files.py
covers the pure classify()/is_exposed() logic without any network calls).
This script exists to sanity-check the detector's full check() flow against
a live target and eyeball the actual findings. Requires the target lab to be
reachable, e.g. `docker compose -f lab/docker-compose.yml up -d juice-shop`.

Usage (from backend/):
    uv run python scripts/manual_check_sensitive_files.py
    uv run python scripts/manual_check_sensitive_files.py --base-url http://localhost:3000
"""

from __future__ import annotations

import argparse
import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.scanners.base import ScanContext  # noqa: E402
from app.scanners.sensitive_files import SensitiveFilesDetector  # noqa: E402


async def main(base_url: str) -> None:
    detector = SensitiveFilesDetector()
    context = ScanContext(target_id="manual-check", base_url=base_url)
    result = await detector.check(context)

    print("detected:", result.detected)
    print("severity:", result.severity, "confidence:", result.confidence)
    print("validation_status:", result.validation_status)
    print("cwe:", result.cwe, "cvss:", result.cvss_score)
    print("endpoint:", result.endpoint)
    print("summary:", result.evidence_summary)
    print("exposed_files:")
    for exposed in result.evidence["exposed_files"]:
        print(" ", exposed)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--base-url",
        default="http://localhost:3000",
        help="Target base URL (default: http://localhost:3000, the local Juice Shop lab)",
    )
    args = parser.parse_args()
    asyncio.run(main(args.base_url))
