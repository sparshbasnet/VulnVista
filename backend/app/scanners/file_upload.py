from __future__ import annotations

import re
from urllib.parse import urljoin, urlparse

import httpx

from app.scanners.base import BaseDetector, DetectorResult, ScanContext


class FileUploadDetector(BaseDetector):
    """Safely inspect authenticated upload forms for missing type restrictions."""

    detector_id = "file_upload"
    name = "File Upload Detector"
    vulnerability_type = "File Upload"
    supported_targets = ["web"]

    async def check(self, context: ScanContext) -> DetectorResult:
        upload_url = urljoin(context.base_url, "/vulnerabilities/upload/")
        hostname = (urlparse(context.base_url).hostname or "").lower()

        try:
            async with httpx.AsyncClient(
                timeout=context.timeout_seconds,
                follow_redirects=True,
                headers=context.extra.get("headers", {}),
            ) as client:
                client.cookies.update(context.extra.get("cookies", {}))

                # DVWA's upload exercise is authenticated. Use the seeded lab
                # credentials by default, while allowing Target.scan_config to
                # override them for an authorized test account.
                if "dvwa" in hostname:
                    login_page = await client.get(urljoin(context.base_url, "/login.php"))
                    token_match = re.search(
                        r"name=[\"']user_token[\"']\s+value=[\"']([^\"']+)[\"']",
                        login_page.text,
                        flags=re.IGNORECASE,
                    )
                    if not token_match:
                        return self._error_result("Unable to extract DVWA login token.")

                    await client.post(
                        urljoin(context.base_url, "/login.php"),
                        data={
                            "username": str(context.extra.get("username", "admin")),
                            "password": str(context.extra.get("password", "password")),
                            "Login": "Login",
                            "user_token": token_match.group(1),
                        },
                    )
                    client.cookies.set("security", str(context.extra.get("security", "low")))

                response = await client.get(upload_url)
        except httpx.HTTPError as exc:
            return self._error_result(str(exc))

        file_input = re.search(
            r"<input\b(?=[^>]*\btype=[\"']file[\"'])[^>]*>",
            response.text,
            flags=re.IGNORECASE,
        )
        has_accept_allowlist = bool(
            file_input
            and re.search(r"\baccept=[\"'][^\"']+", file_input.group(0), re.IGNORECASE)
        )

        if file_input and not has_accept_allowlist:
            return DetectorResult(
                detector=self.detector_id,
                vulnerability="Unrestricted File Upload",
                detected=True,
                validation_status="SUSPECTED",
                severity="HIGH",
                confidence="MEDIUM",
                endpoint=str(response.url),
                description=(
                    "An authenticated upload form accepts a file input without a declared "
                    "client-side type allowlist."
                ),
                evidence={
                    "status_code": response.status_code,
                    "file_input": file_input.group(0),
                    "accept_attribute_present": False,
                    "probe": "authenticated form inspection only; no file was uploaded",
                },
                remediation=(
                    "Enforce an allowlist of file types and MIME signatures server-side, "
                    "rename uploads, and store them outside the web root."
                ),
                cwe="CWE-434",
                owasp_category="A05:2021 - Security Misconfiguration",
                cvss_score=8.0,
            )

        return DetectorResult(
            detector=self.detector_id,
            vulnerability="Unrestricted File Upload",
            detected=False,
            validation_status="NOT_DETECTED",
            severity="HIGH",
            confidence="LOW",
            endpoint=str(response.url),
            evidence={
                "reason": "No unrestricted file-upload form detected.",
                "status_code": response.status_code,
                "file_input_present": bool(file_input),
                "accept_attribute_present": has_accept_allowlist,
            },
            remediation="Restrict uploads to an allowlist of safe file types.",
            cwe="CWE-434",
            owasp_category="A05:2021 - Security Misconfiguration",
        )

    def _error_result(self, error: str) -> DetectorResult:
        return DetectorResult(
            detector=self.detector_id,
            vulnerability="Unrestricted File Upload",
            detected=False,
            validation_status="ERROR",
            severity="HIGH",
            confidence="LOW",
            evidence={"error": error},
            evidence_summary=error,
            remediation="Restrict uploads to an allowlist of safe file types.",
            cwe="CWE-434",
            owasp_category="A05:2021 - Security Misconfiguration",
        )
