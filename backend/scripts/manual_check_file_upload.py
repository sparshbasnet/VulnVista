"""Run the harmless file-upload detector against the local DVWA lab.

Usage (from backend/):
    uv run python scripts/manual_check_file_upload.py
    uv run python scripts/manual_check_file_upload.py --base-url http://dvwa
"""

from __future__ import annotations

import argparse
import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.scanners.base import ScanContext  # noqa: E402
from app.scanners.file_upload import FileUploadDetector  # noqa: E402


async def main(base_url: str) -> None:
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
            "upload_path": "/vulnerabilities/upload/",
            "file_field": "uploaded",
            "submit_field": "Upload",
            "submit_value": "Upload",
            "public_base_path": "/hackable/uploads/",
        },
    )
    result = await FileUploadDetector().check(context)

    print("detected:", result.detected)
    print("severity:", result.severity, "confidence:", result.confidence)
    print("validation_status:", result.validation_status)
    print("cwe:", result.cwe, "cvss:", result.cvss_score)
    print("endpoint:", result.endpoint, "file_field:", result.parameter)
    print("summary:", result.evidence_summary)
    print("evidence:", result.evidence)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--base-url",
        default="http://localhost:8080",
        help="DVWA base URL (default: http://localhost:8080)",
    )
    args = parser.parse_args()
    asyncio.run(main(args.base_url))
