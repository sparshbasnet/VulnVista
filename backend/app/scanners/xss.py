"""Cross-site scripting detector with browser-side execution validation.

The detector submits a unique, harmless JavaScript canary to discovered form
and query-string inputs.  A finding is confirmed only when Chromium observes
that canary changing a DOM attribute.  Seeing the marker in an HTTP response
is retained as useful evidence, but reflection alone is never classified as
XSS.
"""

from __future__ import annotations

import secrets
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlencode, urljoin, urlparse

import httpx

from app.scanners.base import BaseDetector, DetectorResult, ScanContext
from app.scanners.command_injection import (
    Candidate,
    _candidates_from_form,
    _candidates_from_query,
    _explicit_candidate,
    parse_forms,
)
from app.scanners.presets.xss import GENERIC_DEFAULTS, LAB_PRESETS


class DetectorError(Exception):
    """The detector could not produce a trustworthy verdict."""


@dataclass
class Decision:
    detected: bool
    validation_status: str
    confidence: str
    reason: str


def classify(marker_reflected: bool, marker_executed: bool) -> Decision:
    """Apply the central safety rule: reflection is not proof of XSS."""
    if marker_executed:
        return Decision(
            True,
            "CONFIRMED",
            "HIGH",
            "the controlled JavaScript canary executed and changed the page DOM",
        )
    if marker_reflected:
        return Decision(
            False,
            "NOT_DETECTED",
            "HIGH",
            "the canary was reflected but browser-side execution was not observed",
        )
    return Decision(
        False,
        "NOT_DETECTED",
        "HIGH",
        "the canary was neither reflected nor executed in the browser",
    )


def build_payload(marker: str) -> str:
    """Return an inert canary whose only effect is setting one DOM attribute."""
    return (
        '\'"><img src=x onerror="document.documentElement.setAttribute('
        f"'data-vulnvista-xss','{marker}')\">"
    )


class XSSDetector(BaseDetector):
    detector_id = "xss"
    name = "Cross-Site Scripting (XSS)"
    vulnerability_type = "xss"
    supported_targets = ["webapp"]

    async def check(self, context: ScanContext) -> DetectorResult:
        parsed = urlparse(context.base_url)
        host = parsed.hostname or ""
        base = f"{parsed.scheme}://{parsed.netloc}"
        cfg = {**GENERIC_DEFAULTS, **LAB_PRESETS.get(host, {}), **context.extra}
        discovery_path = cfg.get("discovery_path") or parsed.path or "/"

        try:
            async with httpx.AsyncClient(
                follow_redirects=True,
                timeout=cfg["request_timeout"],
                cookies=cfg.get("cookies", {}),
                headers=cfg.get("headers", {}),
            ) as client:
                if cfg.get("login_path") and cfg.get("username") and cfg.get("password"):
                    await self._authenticate(client, base, host, cfg)

                explicit = _explicit_candidate(base, cfg)
                if explicit is not None:
                    candidates = [explicit]
                    source = (
                        "explicit configuration" if "parameter" in context.extra else "lab preset"
                    )
                else:
                    candidates = await self._discover_candidates(
                        client, context, base, discovery_path
                    )
                    source = "auto-discovered"
                if not candidates:
                    raise DetectorError(
                        f"No form fields or query parameters were found at "
                        f"{urljoin(base + '/', discovery_path.lstrip('/'))} to test for XSS. "
                        "Provide 'parameter' and 'exec_path'/'injection_url' in the "
                        "target's scan configuration when the input is not discoverable."
                    )

                last: tuple[Candidate, Decision, dict[str, Any]] | None = None
                for raw_candidate in candidates[: cfg["max_candidates"]]:
                    candidate = await self._prime_candidate(client, raw_candidate)
                    marker = f"XSS-{secrets.token_hex(8)}"
                    payload = build_payload(marker)
                    executed, reflected = await self._browser_probe(
                        candidate, payload, marker, client, cfg
                    )
                    decision = classify(reflected, executed)
                    evidence = {
                        "marker": marker,
                        "payload": payload,
                        "marker_reflected": reflected,
                        "browser_execution_confirmed": executed,
                        "browser_engine": "chromium",
                        "candidate_source": source,
                        "candidates_probed": min(len(candidates), cfg["max_candidates"]),
                    }
                    last = candidate, decision, evidence
                    if decision.detected:
                        break

                assert last is not None
                return self._result(*last)
        except DetectorError as exc:
            return self._error_result(context, str(exc))
        except httpx.HTTPError as exc:
            return self._error_result(
                context, f"Could not reach the target ({type(exc).__name__}: {exc})."
            )

    async def _authenticate(
        self, client: httpx.AsyncClient, base: str, host: str, cfg: dict[str, Any]
    ) -> None:
        login_url = urljoin(base + "/", cfg["login_path"].lstrip("/"))
        page = await client.get(login_url)
        page.raise_for_status()
        forms = parse_forms(page.text, str(page.url))
        form = forms[0] if forms else None
        data = {f.name: f.value for f in form.fields if f.type == "hidden"} if form else {}
        data[cfg.get("username_field", "username")] = cfg["username"]
        data[cfg.get("password_field", "password")] = cfg["password"]
        if cfg.get("login_submit_field"):
            data[cfg["login_submit_field"]] = cfg.get("login_submit_value", "")
        response = await client.post(form.action if form else login_url, data=data)
        if "setup.php" in str(response.url):
            raise DetectorError("DVWA is not initialized; create/reset its database first.")
        if cfg["login_path"] in str(response.url) or "login failed" in response.text.lower():
            raise DetectorError(f"Login failed for user '{cfg['username']}' at {login_url}.")
        for name, value in cfg.get("post_login_cookies", {}).items():
            client.cookies.set(name, value, domain=host, path="/")

    async def _discover_candidates(
        self,
        client: httpx.AsyncClient,
        context: ScanContext,
        base: str,
        discovery_path: str,
    ) -> list[Candidate]:
        candidates = _candidates_from_query(context.base_url)
        page = await client.get(urljoin(base + "/", discovery_path.lstrip("/")))
        page.raise_for_status()
        for form in parse_forms(page.text, str(page.url)):
            candidates.extend(_candidates_from_form(form))
        return candidates

    async def _prime_candidate(self, client: httpx.AsyncClient, candidate: Candidate) -> Candidate:
        if candidate.method.upper() != "POST":
            return candidate
        page = await client.get(candidate.url)
        page.raise_for_status()
        forms = parse_forms(page.text, str(page.url))
        form = next((item for item in forms if item.action == candidate.url), None)
        form = form or (forms[0] if forms else None)
        hidden = {f.name: f.value for f in form.fields if f.type == "hidden"} if form else {}
        return Candidate(
            candidate.method,
            candidate.url,
            candidate.param,
            {**hidden, **candidate.fixed_fields},
        )

    async def _browser_probe(
        self,
        candidate: Candidate,
        payload: str,
        marker: str,
        client: httpx.AsyncClient,
        cfg: dict[str, Any],
    ) -> tuple[bool, bool]:
        """Return (executed, reflected) from one authoritative browser submission."""
        try:
            from playwright.async_api import TimeoutError as PlaywrightTimeoutError
            from playwright.async_api import async_playwright
        except ImportError as exc:  # pragma: no cover - deployment configuration failure
            raise DetectorError(
                "Playwright is not installed; browser execution is required to validate XSS."
            ) from exc

        try:
            async with async_playwright() as playwright:
                browser = await playwright.chromium.launch(headless=cfg["headless"])
                try:
                    browser_context = await browser.new_context(
                        ignore_https_errors=True,
                        extra_http_headers=cfg.get("headers", {}),
                    )
                    cookies = []
                    for cookie in client.cookies.jar:
                        domain = cookie.domain or (urlparse(candidate.url).hostname or "")
                        cookies.append(
                            {
                                "name": cookie.name,
                                "value": cookie.value,
                                "domain": domain,
                                "path": cookie.path or "/",
                            }
                        )
                    if cookies:
                        await browser_context.add_cookies(cookies)
                    page = await browser_context.new_page()
                    fields = {**candidate.fixed_fields, candidate.param: payload}
                    if candidate.method.upper() == "GET":
                        separator = "&" if "?" in candidate.url else "?"
                        await page.goto(
                            f"{candidate.url}{separator}{urlencode(fields)}",
                            wait_until="domcontentloaded",
                        )
                    else:
                        await page.goto(candidate.url, wait_until="domcontentloaded")
                        await page.evaluate(
                            """({url, fields}) => {
                                const form = document.createElement('form');
                                form.method = 'POST'; form.action = url;
                                for (const [name, value] of Object.entries(fields)) {
                                    const input = document.createElement('input');
                                    input.name = name; input.value = value;
                                    form.appendChild(input);
                                }
                                document.body.appendChild(form); form.submit();
                            }""",
                            {"url": candidate.url, "fields": fields},
                        )
                        await page.wait_for_load_state("domcontentloaded")

                    verification = cfg.get("verification_url") or cfg.get("verification_path")
                    if verification:
                        await page.goto(
                            urljoin(candidate.url, verification),
                            wait_until="domcontentloaded",
                        )

                    try:
                        await page.wait_for_function(
                            "marker => document.documentElement.getAttribute("
                            "'data-vulnvista-xss') === marker",
                            arg=marker,
                            timeout=cfg["browser_timeout_ms"],
                        )
                        executed = True
                    except PlaywrightTimeoutError:
                        executed = False
                    reflected = marker in await page.content()
                    return executed, reflected
                finally:
                    await browser.close()
        except DetectorError:
            raise
        except Exception as exc:
            message = f"Chromium validation failed ({type(exc).__name__}: {exc})."
            raise DetectorError(message) from exc

    def _result(
        self, candidate: Candidate, decision: Decision, evidence: dict[str, Any]
    ) -> DetectorResult:
        return DetectorResult(
            detector=self.detector_id,
            vulnerability=self.name,
            detected=decision.detected,
            validation_status=decision.validation_status,
            severity="HIGH" if decision.detected else "INFO",
            confidence=decision.confidence,
            endpoint=candidate.url,
            parameter=candidate.param,
            description=(
                "Attacker-controlled input executes as JavaScript in a user's browser. "
                "The detector uses a harmless DOM-only canary and requires observed execution."
            ),
            evidence_summary=(
                f"{decision.reason}; parameter={candidate.param}, "
                f"reflected={evidence['marker_reflected']}, "
                f"browser_executed={evidence['browser_execution_confirmed']}."
            ),
            evidence=evidence,
            remediation=(
                "Apply context-aware output encoding, sanitize untrusted HTML with a maintained "
                "allowlist sanitizer, avoid unsafe DOM sinks, and enforce a restrictive Content "
                "Security Policy as defence in depth."
            ),
            cwe="CWE-79",
            cvss_score=8.2 if decision.detected else 0.0,
            owasp_category="A03:2021 - Injection",
        )

    def _error_result(self, context: ScanContext, message: str) -> DetectorResult:
        return DetectorResult(
            detector=self.detector_id,
            vulnerability=self.name,
            detected=False,
            validation_status="ERROR",
            severity="INFO",
            confidence="LOW",
            endpoint=context.base_url,
            evidence_summary=f"Scan error: {message}",
            evidence={"error": message},
            description="Detector could not complete browser-side XSS validation.",
            cwe="CWE-79",
            owasp_category="A03:2021 - Injection",
        )
