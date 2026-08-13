"""Manual live-run of the vulnerable-services detector against a real target.

Not part of the automated test suite (backend/tests/test_vulnerable_services.py
covers XML parsing, signature matching, and classify() with fixture data, no
network/no nmap invocation). This script exercises the full check() flow —
actually invoking nmap and scanning a live target — so requires nmap to be
installed (already baked into the backend Docker image) and the target to be
reachable. Runs slower than the other manual_check_*.py scripts since it's a
real port scan, not a handful of HTTP requests.

Usage (from backend/, or inside the backend container):
    uv run python scripts/manual_check_vulnerable_services.py <host>
    uv run python scripts/manual_check_vulnerable_services.py metasploitable2
    uv run python scripts/manual_check_vulnerable_services.py --ports 1-1000 metasploitable2
"""

from __future__ import annotations

import argparse
import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.scanners.base import ScanContext  # noqa: E402
from app.scanners.vulnerable_services import VulnerableServicesDetector  # noqa: E402


async def main(host: str, ports: str | None) -> None:
    detector = VulnerableServicesDetector()
    extra = {"ports": ports} if ports else {}
    context = ScanContext(target_id="manual-check", base_url=f"http://{host}", extra=extra)
    result = await detector.check(context)

    print("detected:", result.detected)
    print("severity:", result.severity, "confidence:", result.confidence)
    print("validation_status:", result.validation_status)
    print("cwe:", result.cwe, "cve:", result.cve, "cvss:", result.cvss_score)
    print("endpoint:", result.endpoint)
    print("summary:", result.evidence_summary)
    if "open_ports" in result.evidence:
        print("open_ports:")
        for svc in result.evidence["open_ports"]:
            print(" ", svc)
        print("vulnerabilities:")
        for vuln in result.evidence["vulnerabilities"]:
            print(" ", vuln)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("host", help="Target hostname or IP, as the backend reaches it")
    parser.add_argument(
        "--ports",
        default=None,
        help="Explicit nmap port spec (e.g. '1-1000' or '21,22,80'). Default: top 1000 ports.",
    )
    args = parser.parse_args()
    asyncio.run(main(args.host, args.ports))
