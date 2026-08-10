from __future__ import annotations

from html.parser import HTMLParser
from urllib.parse import urljoin

import httpx

from app.scanners.base import BaseDetector, DetectorResult, ScanContext


class _FormParser(HTMLParser):
    """Extract basic information about HTML forms."""

    def __init__(self) -> None:
        super().__init__()
        self.forms: list[dict[str, object]] = []
        self._current_form: dict[str, object] | None = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attributes = dict(attrs)

        if tag.lower() == "form":
            self._current_form = {
                "method": (attributes.get("method") or "GET").upper(),
                "action": attributes.get("action") or "",
                "inputs": [],
            }

        elif tag.lower() == "input" and self._current_form is not None:
            inputs = self._current_form["inputs"]
            assert isinstance(inputs, list)

            inputs.append(
                {
                    "name": attributes.get("name") or "",
                    "type": (attributes.get("type") or "text").lower(),
                }
            )

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() == "form" and self._current_form is not None:
            self.forms.append(self._current_form)
            self._current_form = None


class CSRFDetector(BaseDetector):
    """Passive detector for potentially missing CSRF protection."""

    detector_id = "csrf"
    name = "Cross-Site Request Forgery Detector"
    vulnerability_type = "CSRF"
    supported_targets = ["web"]

    async def check(self, context: ScanContext) -> DetectorResult:
        try:
            async with httpx.AsyncClient(
                timeout=context.timeout_seconds,
                follow_redirects=True,
            ) as client:
                response = await client.get(context.base_url)

        except httpx.HTTPError as exc:
            return DetectorResult(
                detector=self.detector_id,
                vulnerability="Cross-Site Request Forgery",
                detected=False,
                validation_status="ERROR",
                severity="MEDIUM",
                confidence="LOW",
                evidence={
                    "error": str(exc),
                },
                remediation=(
                    "Ensure state-changing requests use an appropriate CSRF "
                    "protection mechanism."
                ),
                cwe="CWE-352",
                owasp_category="A01:2021 - Broken Access Control",
            )

        content_type = response.headers.get("content-type", "").lower()

        if "html" not in content_type:
            return DetectorResult(
                detector=self.detector_id,
                vulnerability="Cross-Site Request Forgery",
                detected=False,
                validation_status="NOT_DETECTED",
                severity="MEDIUM",
                confidence="LOW",
                evidence={
                    "reason": "Target response was not HTML.",
                    "status_code": response.status_code,
                    "content_type": content_type,
                },
                remediation=(
                    "Ensure state-changing requests use an appropriate CSRF "
                    "protection mechanism."
                ),
                cwe="CWE-352",
                owasp_category="A01:2021 - Broken Access Control",
            )

        parser = _FormParser()
        parser.feed(response.text)

        post_forms = [
            form for form in parser.forms
            if form["method"] == "POST"
        ]

        if not post_forms:
            return DetectorResult(
                detector=self.detector_id,
                vulnerability="Cross-Site Request Forgery",
                detected=False,
                validation_status="NOT_DETECTED",
                severity="MEDIUM",
                confidence="LOW",
                evidence={
                    "reason": "No POST forms were found on the inspected page.",
                    "forms_checked": len(parser.forms),
                },
                remediation=(
                    "Ensure state-changing requests use an appropriate CSRF "
                    "protection mechanism."
                ),
                cwe="CWE-352",
                owasp_category="A01:2021 - Broken Access Control",
            )

        token_names = {
            "csrf",
            "csrf_token",
            "csrftoken",
            "_csrf",
            "_csrf_token",
            "xsrf",
            "xsrf_token",
            "authenticity_token",
        }

        vulnerable_form: dict[str, object] | None = None

        for form in post_forms:
            inputs = form["inputs"]
            assert isinstance(inputs, list)

            input_names = {
                str(item["name"]).lower()
                for item in inputs
                if item.get("name")
            }

            if not input_names.intersection(token_names):
                vulnerable_form = form
                break

        if vulnerable_form is None:
            return DetectorResult(
                detector=self.detector_id,
                vulnerability="Cross-Site Request Forgery",
                detected=False,
                validation_status="NOT_DETECTED",
                severity="MEDIUM",
                confidence="MEDIUM",
                evidence={
                    "forms_checked": len(post_forms),
                    "reason": (
                        "POST forms contained fields commonly associated "
                        "with CSRF protection."
                    ),
                },
                remediation=(
                    "Continue enforcing CSRF protection on all state-changing "
                    "requests."
                ),
                cwe="CWE-352",
                owasp_category="A01:2021 - Broken Access Control",
            )

        action = str(vulnerable_form["action"])
        endpoint = urljoin(context.base_url, action)

        return DetectorResult(
            detector=self.detector_id,
            vulnerability="Cross-Site Request Forgery",
            detected=True,
            validation_status="SUSPECTED",
            severity="MEDIUM",
            confidence="MEDIUM",
            endpoint=endpoint,
            evidence={
                "reason": (
                    "A POST form was found without a field matching common "
                    "CSRF-token naming conventions."
                ),
                "forms_checked": len(post_forms),
                "form_action": action,
            },
            remediation=(
                "Add a strong, unpredictable CSRF token to state-changing "
                "requests and validate the token server-side. Also consider "
                "SameSite cookie protections."
            ),
            cwe="CWE-352",
            owasp_category="A01:2021 - Broken Access Control",
            cvss_score=6.5,
        )