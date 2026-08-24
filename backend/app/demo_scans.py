"""Run and display the three supported DVWA demonstration scans.

Usage inside the backend container:
    uv run python -m app.demo_scans
    uv run python -m app.demo_scans --show
"""

from __future__ import annotations

import argparse
import asyncio
import json
from dataclasses import asdict
from pathlib import Path

from app.scanners.base import ScanContext
from app.scanners.csrf import CSRFDetector
from app.scanners.file_upload import FileUploadDetector
from app.scanners.path_traversal import PathTraversalDetector

RESULT_PATH = Path("/data/uploads/professor-demo-results.json")
DEMO_TARGET = "http://dvwa"


async def run_demo() -> None:
    """Run safe CSRF, path-traversal, and file-upload checks in the DVWA lab."""
    context = ScanContext(target_id="professor-demo", base_url=DEMO_TARGET)
    results = []

    for detector in (CSRFDetector(), PathTraversalDetector(), FileUploadDetector()):
        result = await detector.check(context)
        results.append(asdict(result))
        print(f"{result.detector}: {result.validation_status} | detected={result.detected}")

    RESULT_PATH.write_text(json.dumps({"target": DEMO_TARGET, "results": results}, indent=2))
    print(f"\nFull report saved to {RESULT_PATH}")


def show_results() -> None:
    """Display the most recently saved demonstration report."""
    if not RESULT_PATH.exists():
        raise SystemExit("No report found. Run the demonstration first.")
    print(RESULT_PATH.read_text())


def main() -> None:
    parser = argparse.ArgumentParser(description="Run the isolated DVWA scan demonstration.")
    parser.add_argument("--show", action="store_true", help="display the last saved report")
    args = parser.parse_args()

    if args.show:
        show_results()
    else:
        asyncio.run(run_demo())


if __name__ == "__main__":
    main()
