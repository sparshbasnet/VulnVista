from __future__ import annotations

import asyncio
from collections import deque
from html.parser import HTMLParser
from urllib.parse import ParseResult, urldefrag, urljoin, urlparse

import httpx

from app.scanners.base import BaseDetector, DetectorResult, ScanContext


class _PageParser(HTMLParser):
    """Extract HTML forms and navigable links without executing page scripts."""

    def __init__(self) -> None:
        super().__init__()
        self.forms: list[dict[str, object]] = []
        self.links: list[str] = []
        self._current_form: dict[str, object] | None = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attributes = dict(attrs)
        tag = tag.lower()

        if tag == "form":
            self._current_form = {
                "method": (attributes.get("method") or "GET").upper(),
                "action": attributes.get("action") or "",
                "inputs": [],
            }
        elif tag == "input" and self._current_form is not None:
            inputs = self._current_form["inputs"]
            assert isinstance(inputs, list)
            inputs.append(
                {
                    "name": attributes.get("name") or "",
                    "type": (attributes.get("type") or "text").lower(),
                }
            )
        elif tag == "a" and attributes.get("href"):
            self.links.append(attributes["href"])

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() == "form" and self._current_form is not None:
            self.forms.append(self._current_form)
            self._current_form = None


class CSRFDetector(BaseDetector):
    """Passively detect potentially missing CSRF protection on crawled HTML pages."""

    detector_id = "csrf"
    name = "Cross-Site Request Forgery Detector"
    vulnerability_type = "CSRF"
    supported_targets = ["web"]

    async def check(self, context: ScanContext) -> DetectorResult:
        """Inspect only the base page, retained for direct detector use and tests."""
        try:
            async with self._client(context) as client:
                response = await client.get(context.base_url)
        except httpx.HTTPError as exc:
            return self._error_result(str(exc))

        return self._inspect_response(response, context.base_url)

    async def check_all(self, context: ScanContext) -> list[DetectorResult]:
        """Crawl a bounded same-origin scope and inspect every HTML response."""
        max_pages = int(context.extra.get("crawl_max_pages", 50))
        max_depth = int(context.extra.get("crawl_max_depth", 3))
        delay_seconds = float(context.extra.get("crawl_delay_seconds", 0.1))
        allowed_prefix = str(context.extra.get("crawl_path_prefix", "/"))
        base = urlparse(context.base_url)
        queue: deque[tuple[str, int]] = deque([(context.base_url, 0)])
        visited: set[str] = set()
        results: list[DetectorResult] = []
        request_errors = 0

        async with self._client(context) as client:
            while queue and len(visited) < max_pages:
                page_url, depth = queue.popleft()
                if page_url in visited:
                    continue
                visited.add(page_url)

                try:
                    response = await client.get(page_url)
                except httpx.HTTPError:
                    request_errors += 1
                    continue

                content_type = response.headers.get("content-type", "").lower()
                if "html" not in content_type:
                    continue

                inspection = self._inspect_response(response, page_url)
                if inspection.detected:
                    inspection.evidence["pages_crawled"] = len(visited)
                    results.append(inspection)

                if depth < max_depth:
                    parser = _PageParser()
                    parser.feed(response.text)
                    for link in parser.links:
                        candidate = self._safe_crawl_url(link, page_url, base, allowed_prefix)
                        if candidate and candidate not in visited:
                            queue.append((candidate, depth + 1))

                if delay_seconds > 0 and queue:
                    await asyncio.sleep(delay_seconds)

        if results:
            for result in results:
                result.evidence["pages_crawled"] = len(visited)
            return results

        return [
            DetectorResult(
                detector=self.detector_id,
                vulnerability="Cross-Site Request Forgery",
                detected=False,
                validation_status="NOT_DETECTED",
                severity="MEDIUM",
                confidence="LOW",
                evidence={
                    "reason": "No POST forms without a common CSRF-token field were found.",
                    "pages_crawled": len(visited),
                    "request_errors": request_errors,
                },
                remediation="Ensure state-changing requests use appropriate CSRF protection.",
                cwe="CWE-352",
                owasp_category="A01:2021 - Broken Access Control",
            )
        ]

    def _client(self, context: ScanContext) -> httpx.AsyncClient:
        return httpx.AsyncClient(
            timeout=context.timeout_seconds,
            follow_redirects=True,
            headers=context.extra.get("headers", {}),
        )

    def _inspect_response(self, response: httpx.Response, page_url: str) -> DetectorResult:
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
                remediation="Ensure state-changing requests use appropriate CSRF protection.",
                cwe="CWE-352",
                owasp_category="A01:2021 - Broken Access Control",
            )

        parser = _PageParser()
        parser.feed(response.text)
        post_forms = [form for form in parser.forms if form["method"] == "POST"]

        if not post_forms:
            return DetectorResult(
                detector=self.detector_id,
                vulnerability="Cross-Site Request Forgery",
                detected=False,
                validation_status="NOT_DETECTED",
                severity="MEDIUM",
                confidence="LOW",
                evidence={"reason": "No POST forms were found on the inspected page."},
                remediation="Ensure state-changing requests use appropriate CSRF protection.",
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
            input_names = {str(item["name"]).lower() for item in inputs if item.get("name")}
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
                    "reason": "POST forms included CSRF-token fields.",
                },
                remediation="Continue enforcing CSRF protection on all state-changing requests.",
                cwe="CWE-352",
                owasp_category="A01:2021 - Broken Access Control",
            )

        action = str(vulnerable_form["action"])
        return DetectorResult(
            detector=self.detector_id,
            vulnerability="Cross-Site Request Forgery",
            detected=True,
            validation_status="SUSPECTED",
            severity="MEDIUM",
            confidence="MEDIUM",
            endpoint=urljoin(page_url, action),
            evidence={
                "reason": "A POST form was found without a common CSRF-token field.",
                "forms_checked": len(post_forms),
                "form_action": action,
                "page": page_url,
            },
            remediation=(
                "Add a strong, unpredictable CSRF token to state-changing requests and "
                "validate the token server-side. Also consider SameSite cookie protections."
            ),
            cwe="CWE-352",
            owasp_category="A01:2021 - Broken Access Control",
            cvss_score=6.5,
        )

    def _safe_crawl_url(
        self,
        link: str,
        page_url: str,
        base: ParseResult,
        allowed_prefix: str,
    ) -> str | None:
        candidate, _ = urldefrag(urljoin(page_url, link))
        parsed = urlparse(candidate)
        if parsed.scheme not in {"http", "https"} or parsed.netloc != base.netloc:
            return None
        if not parsed.path.startswith(allowed_prefix):
            return None
        blocked_segments = ("logout", "signout", "delete", "remove", "payment", "checkout")
        if any(segment in parsed.path.lower() for segment in blocked_segments):
            return None
        return candidate

    def _error_result(self, error: str) -> DetectorResult:
        return DetectorResult(
            detector=self.detector_id,
            vulnerability="Cross-Site Request Forgery",
            detected=False,
            validation_status="ERROR",
            severity="MEDIUM",
            confidence="LOW",
            evidence={"error": error},
            remediation="Ensure state-changing requests use appropriate CSRF protection.",
            cwe="CWE-352",
            owasp_category="A01:2021 - Broken Access Control",
        )
