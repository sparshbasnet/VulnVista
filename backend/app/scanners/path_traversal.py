from __future__ import annotations

import re
from urllib.parse import urlparse

import httpx

from app.scanners.base import BaseDetector, DetectorResult, ScanContext


class PathTraversalDetector(BaseDetector):
    """Check supported lab applications with their safe, target-specific probes."""

    detector_id = "path_traversal"
    name = "Path Traversal Detector"
    vulnerability_type = "Path Traversal"
    supported_targets = ["web"]

    async def check(self, context: ScanContext) -> DetectorResult:
        hostname = urlparse(context.base_url).hostname or ""

        if "juice" in hostname.lower():
            return await self._check_juice_shop(context)

        return await self._check_dvwa(context)

    async def _check_juice_shop(self, context: ScanContext) -> DetectorResult:
        """Check Juice Shop's file endpoint without requesting operating-system files."""
        probe_path = "/ftp/%2e%2e%2fpackage.json"

        try:
            async with httpx.AsyncClient(
                timeout=context.timeout_seconds,
                follow_redirects=True,
                headers=context.extra.get("headers", {}),
            ) as client:
                response = await client.get(f"{context.base_url}{probe_path}")
        except httpx.HTTPError as exc:
            return self._error_result(str(exc))

        package_metadata_exposed = (
            response.status_code == 200
            and '"name"' in response.text
            and "juice-shop" in response.text
        )
        if package_metadata_exposed:
            return DetectorResult(
                detector=self.detector_id,
                vulnerability="Path Traversal",
                detected=True,
                validation_status="CONFIRMED",
                severity="HIGH",
                confidence="HIGH",
                endpoint=str(response.url),
                evidence={"indicator": "Juice Shop package metadata was accessible via traversal."},
                remediation=(
                    "Reject traversal sequences and restrict file-serving routes to an allowlist."
                ),
                cwe="CWE-22",
                owasp_category="A01:2021 - Broken Access Control",
                cvss_score=8.5,
            )

        return DetectorResult(
            detector=self.detector_id,
            vulnerability="Path Traversal",
            detected=False,
            validation_status="NOT_DETECTED",
            severity="HIGH",
            confidence="LOW",
            evidence={
                "reason": "Juice Shop did not expose package metadata through the traversal probe.",
                "status_code": response.status_code,
            },
            remediation=(
                "Reject traversal sequences and restrict file-serving routes to an allowlist."
            ),
            cwe="CWE-22",
            owasp_category="A01:2021 - Broken Access Control",
        )

    async def _check_dvwa(self, context: ScanContext) -> DetectorResult:
        try:
            async with httpx.AsyncClient(
                timeout=context.timeout_seconds,
                follow_redirects=True,
                headers=context.extra.get("headers", {}),
            ) as client:
                login_page = await client.get(f"{context.base_url}/login.php")
                token_match = re.search(r"name='user_token' value='([^']+)'", login_page.text)

                if not token_match:
                    return DetectorResult(
                        detector=self.detector_id,
                        vulnerability="Path Traversal",
                        detected=False,
                        validation_status="ERROR",
                        severity="HIGH",
                        confidence="LOW",
                        evidence={"reason": "Unable to extract DVWA login token."},
                        remediation="Validate file paths.",
                        cwe="CWE-22",
                        owasp_category="A01:2021 - Broken Access Control",
                    )

                await client.post(
                    f"{context.base_url}/login.php",
                    data={
                        "username": "admin",
                        "password": "password",
                        "Login": "Login",
                        "user_token": token_match.group(1),
                    },
                )
                response = await client.get(
                    f"{context.base_url}/vulnerabilities/fi/?page=../../../../../../etc/passwd"
                )
        except httpx.HTTPError as exc:
            return self._error_result(str(exc))

        if "root:x:" in response.text:
            return DetectorResult(
                detector=self.detector_id,
                vulnerability="Path Traversal",
                detected=True,
                validation_status="CONFIRMED",
                severity="HIGH",
                confidence="HIGH",
                endpoint=str(response.url),
                evidence={"indicator": "root:x:"},
                remediation="Validate and sanitize file paths.",
                cwe="CWE-22",
                owasp_category="A01:2021 - Broken Access Control",
                cvss_score=8.5,
            )

        return DetectorResult(
            detector=self.detector_id,
            vulnerability="Path Traversal",
            detected=False,
            validation_status="NOT_DETECTED",
            severity="HIGH",
            confidence="LOW",
            evidence={"reason": "Path traversal was not detected."},
            remediation="Validate file paths.",
            cwe="CWE-22",
            owasp_category="A01:2021 - Broken Access Control",
        )

    def _error_result(self, error: str) -> DetectorResult:
        return DetectorResult(
            detector=self.detector_id,
            vulnerability="Path Traversal",
            detected=False,
            validation_status="ERROR",
            severity="HIGH",
            confidence="LOW",
            evidence={"error": error},
            remediation="Validate file paths.",
            cwe="CWE-22",
            owasp_category="A01:2021 - Broken Access Control",
        )
