"""Manual live-run of the weak-TLS detector against a real target.

Not part of the automated test suite (backend/tests/test_weak_tls.py covers
classify_ciphers()/classify_certificate()/classify_vulnerabilities()/
classify() with hand-built TLSObservation fixtures, no real TLS connection).
This script exercises the full check() flow — actually connecting to a live
TLS service via SSLyze — so requires the target to be reachable.

Usage (from backend/, or inside the backend container):
    uv run python scripts/manual_check_weak_tls.py <host>
    uv run python scripts/manual_check_weak_tls.py tls-test
    uv run python scripts/manual_check_weak_tls.py --port 8443 localhost
"""

from __future__ import annotations

import argparse
import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.scanners.base import ScanContext  # noqa: E402
from app.scanners.weak_tls import WeakTLSDetector  # noqa: E402


async def main(host: str, port: int) -> None:
    detector = WeakTLSDetector()
    context = ScanContext(target_id="manual-check", base_url=f"https://{host}:{port}")
    result = await detector.check(context)

    print("detected:", result.detected)
    print("severity:", result.severity, "confidence:", result.confidence)
    print("validation_status:", result.validation_status)
    print("cwe:", result.cwe, "cve:", result.cve, "cvss:", result.cvss_score)
    print("endpoint:", result.endpoint)
    print("summary:", result.evidence_summary)
    if "accepted_protocols" in result.evidence:
        print("accepted_protocols:")
        for protocol, ciphers in result.evidence["accepted_protocols"].items():
            print(f"  {protocol}: {ciphers}")
        print("certificate:", result.evidence["certificate"])
        print("vulnerabilities:", result.evidence["vulnerabilities"])


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("host", help="Target hostname or IP, as the backend reaches it")
    parser.add_argument("--port", type=int, default=443, help="TLS port (default: 443)")
    args = parser.parse_args()
    asyncio.run(main(args.host, args.port))
