"""Run the XSS detector end-to-end against the local DVWA lab.

Usage (from backend/):
    uv run python scripts/manual_check_xss.py
    uv run python scripts/manual_check_xss.py --base-url http://dvwa
"""

from __future__ import annotations

import argparse
import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.scanners.base import ScanContext  # noqa: E402
from app.scanners.xss import XSSDetector  # noqa: E402


async def main(base_url: str) -> None:
    # Explicit configuration keeps the script useful through localhost, whose
    # hostname cannot match the detector's in-network `dvwa` convenience preset.
    context = ScanContext(
        target_id="manual-check",
        base_url=base_url,
        extra={
            "login_path": "/login.php",
            "login_submit_field": "Login",
            "login_submit_value": "Login",
            "username": "admin",
            "password": "password",
            "post_login_cookies": {"security": "low"},
            "exec_path": "/vulnerabilities/xss_r/",
            "parameter": "name",
            "method": "GET",
        },
    )
    result = await XSSDetector().check(context)

    print("detected:", result.detected)
    print("severity:", result.severity, "confidence:", result.confidence)
    print("validation_status:", result.validation_status)
    print("cwe:", result.cwe, "cvss:", result.cvss_score)
    print("endpoint:", result.endpoint, "parameter:", result.parameter)
    print("summary:", result.evidence_summary)
    print("evidence:", result.evidence)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--base-url",
        default="http://localhost:8081",
        help="DVWA base URL (default: http://localhost:8081)",
    )
    args = parser.parse_args()
    asyncio.run(main(args.base_url))
