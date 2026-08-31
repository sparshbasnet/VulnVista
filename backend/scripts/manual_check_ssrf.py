"""Run the controlled SSRF detector against the bundled Juice Shop lab.

Run from inside the backend container so the callback hostname is reachable:
    docker compose exec -T backend uv run python scripts/manual_check_ssrf.py
"""

from __future__ import annotations

import argparse
import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.scanners.base import ScanContext  # noqa: E402
from app.scanners.ssrf import SSRFDetector  # noqa: E402


async def main(base_url: str, callback_host: str) -> None:
    result = await SSRFDetector().check(
        ScanContext(
            target_id="manual-check",
            base_url=base_url,
            extra={"callback_host": callback_host},
        )
    )
    print("detected:", result.detected)
    print("severity:", result.severity, "confidence:", result.confidence)
    print("validation_status:", result.validation_status)
    print("cwe:", result.cwe, "cvss:", result.cvss_score)
    print("endpoint:", result.endpoint, "parameter:", result.parameter)
    print("summary:", result.evidence_summary)
    print("evidence:", result.evidence)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-url", default="http://juice-shop:3000")
    parser.add_argument("--callback-host", default="backend")
    args = parser.parse_args()
    asyncio.run(main(args.base_url, args.callback_host))
