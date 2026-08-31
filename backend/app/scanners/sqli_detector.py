"""SQL Injection detector backed by ZAP's SQL Injection active-scan rules."""

import asyncio
import json
import os
from typing import Any

from app.scanners.base import BaseDetector, DetectorResult, ScanContext
from app.services.zap_client import ZAPClient, zap_client


class SQLiDetector(BaseDetector):
    """Detect SQL injection on Juice Shop's JSON login endpoint.

    ``login_path`` and ``login_payload`` in :attr:`ScanContext.extra` allow a
    caller to use the same detector against another approved JSON login route.
    """

    detector_id = "sqli_detector"
    name = "SQL Injection Detector"
    vulnerability_type = "SQL Injection"
    supported_targets = ["http", "https"]

    def __init__(self, client: ZAPClient = zap_client) -> None:
        self.client = client

    async def check(self, context: ScanContext) -> DetectorResult:
        """Run the blocking ZAP scan off the event loop."""
        return await asyncio.to_thread(self._check_sync, context)

    def _check_sync(self, context: ScanContext) -> DetectorResult:
        base_url = context.base_url.rstrip("/")
        login_path = str(context.extra.get("login_path", "/rest/user/login"))
        if not login_path.startswith("/"):
            login_path = f"/{login_path}"
        login_url = f"{base_url}{login_path}"
        payload = context.extra.get(
            "login_payload", {"email": "test@test.com", "password": "test123"}
        )
        post_data = (
            payload
            if isinstance(payload, str)
            else json.dumps(payload, separators=(",", ":"))
        )

        self.client.access_url(base_url)
        self.client.seed_json_post_request(login_url, post_data)
        rule_ids = self.client.get_sqli_rule_ids()
        if not rule_ids:
            raise RuntimeError("The connected ZAP instance has no SQL Injection active-scan rules")

        scan_id = self.client.active_scan_with_rules(
            login_url,
            rule_ids,
            method="POST",
            post_data=post_data,
            timeout=max(1, int(context.timeout_seconds)),
        )
        alerts = self.client.get_alerts(base_url)
        sqli_alerts = [
            alert
            for alert in alerts
            if "sql injection" in alert.get("name", "").lower()
        ]
        return self._result(sqli_alerts, login_url, scan_id, rule_ids)

    def _result(
        self, alerts: list[dict[str, Any]], login_url: str, scan_id: str, rule_ids: list[str]
    ) -> DetectorResult:
        if not alerts:
            return DetectorResult(
                detector=self.detector_id,
                vulnerability=self.vulnerability_type,
                detected=False,
                validation_status="NOT_DETECTED",
                severity="INFO",
                confidence="NONE",
                endpoint=login_url,
                evidence={"scan_id": scan_id, "rule_ids": rule_ids, "alerts": []},
                remediation="Use parameterized queries and server-side input validation.",
                cwe="CWE-89",
                owasp_category="A03:2021 - Injection",
            )

        primary = max(alerts, key=lambda alert: self._risk_rank(alert.get("risk", "")))
        return DetectorResult(
            detector=self.detector_id,
            vulnerability=self.vulnerability_type,
            detected=True,
            validation_status="CONFIRMED",
            severity=self._severity(primary.get("risk", "")),
            confidence=primary.get("confidence", "HIGH").upper(),
            endpoint=primary.get("url", login_url),
            parameter=primary.get("param") or None,
            evidence={"scan_id": scan_id, "rule_ids": rule_ids, "alerts": alerts},
            remediation=(
                "Use parameterized queries or a safe ORM API; never concatenate untrusted "
                "input into SQL statements. Validate input server-side and use least-privilege "
                "database credentials."
            ),
            cwe="CWE-89",
            cvss_score=8.8,
            owasp_category="A03:2021 - Injection",
        )

    @staticmethod
    def _risk_rank(risk: str) -> int:
        return {"informational": 0, "low": 1, "medium": 2, "high": 3}.get(risk.lower(), 0)

    @classmethod
    def _severity(cls, risk: str) -> str:
        return {0: "INFO", 1: "LOW", 2: "MEDIUM", 3: "HIGH"}[cls._risk_rank(risk)]


async def _main() -> None:
    """Run a manual SQLi detector check against Juice Shop.

    Use ``SQLI_TARGET_URL`` to point this at another approved target.
    """
    target_url = os.getenv("SQLI_TARGET_URL", "http://juice-shop:3000")
    result = await SQLiDetector().check(
        ScanContext(
            target_id="manual-juice-shop",
            base_url=target_url,
            timeout_seconds=300,
        )
    )
    print(json.dumps(result.__dict__, indent=2, default=str))


if __name__ == "__main__":
    asyncio.run(_main())

# import asyncio
# import json
# import os
# async def _main() -> None:
#     """Run a manual XSS scan against Juice Shop."""
#     target_url = os.getenv("XSS_TARGET_URL", "http://juice-shop:3000")

#     result = await XSSDetector().check(
#         ScanContext(
#             target_id="manual-xss",
#             base_url=target_url,
#             timeout_seconds=300,
#         )
#     )

#     print(json.dumps(result.__dict__, indent=2, default=str))


# if __name__ == "__main__":
#     asyncio.run(_main())