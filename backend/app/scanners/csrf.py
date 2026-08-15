"""Cross-Site Request Forgery (CSRF) detector.

Generic and evidence-based, same approach as ``weak_auth.py`` and
``command_injection.py``. CSRF is fundamentally different from those two in
one respect: proving it usually means actually performing the state-changing
operation, which is only safe to do automatically when the caller knows the
operation is idempotent/resettable. So this detector runs in two tiers:

  1. Passive signals (always run, read-only, safe against any target):
     - Discover a state-changing form (the target's own page, or an explicit
       ``action_path`` override) and inspect its hidden fields for anything
       that looks like an anti-CSRF token (name matching common conventions).
     - If a token is found, refetch the same form with a second, independent
       (cookie-less) client and compare token values. An identical value
       across two unrelated sessions means the token isn't actually bound to
       a session and can't stop forgery, even though one is present.
     - A state-changing form reachable via plain GET is flagged on its own —
       no CSRF token can help if the action doesn't even require a request
       body, since a bare `<img src>` on an attacker page can trigger it.

  2. Active proof (opt-in — only runs when the caller supplies an explicit
     ``action_path`` + ``password_field``, e.g. a lab preset or explicit scan
     config): replay the state-changing request using the victim's ambient
     session but with the anti-CSRF token dropped and the Origin/Referer
     spoofed to an unrelated host, exactly as a real cross-site attacker page
     would send it. Success is judged by a configurable ``success_indicator``
     string, or by response status otherwise. When it succeeds and the caller
     supplied a ``reset_value``, the state is immediately restored using the
     authentic (non-forged) session so later scans/detectors relying on it
     (e.g. the DVWA lab login) keep working.

Everything is overridable via ``ScanContext.extra`` (populated from
``Target.scan_config``) — ``action_path``, ``method``, ``password_field``,
``confirm_field``, ``submit_field``/``submit_value``, ``success_indicator``,
``reset_value``, ``login_path``/``username``/``password``, etc. The bundled
DVWA lab container gets a preset with all of this pre-filled (its low-security
password-change form has no token and accepts plain GET, by design).
"""

from __future__ import annotations

import re
import secrets
from dataclasses import dataclass
from typing import Any
from urllib.parse import urljoin, urlparse

import httpx

from app.scanners.base import BaseDetector, DetectorResult, ScanContext
from app.scanners.command_injection import FormSpec, parse_forms

GENERIC_DEFAULTS: dict[str, Any] = {
    "request_timeout": 15.0,
    "forged_origin": "https://csrf-poc.vulnvista.invalid",
}

_TOKEN_NAME_RE = re.compile(
    r"csrf|xsrf|authenticity_token|_token|nonce|anti[-_]?forgery|requestverificationtoken",
    re.IGNORECASE,
)

# Convenience preset for the bundled DVWA lab container. Its CSRF exercise is
# a password-change form that, at low security, carries no anti-CSRF token
# and accepts a plain GET — deliberately vulnerable so the active proof below
# always has something real to demonstrate against.
LAB_PRESETS: dict[str, dict[str, Any]] = {
    "dvwa": {
        "login_path": "/login.php",
        "login_submit_field": "Login",
        "login_submit_value": "Login",
        "username": "admin",
        "password": "password",
        "post_login_cookies": {"security": "low"},
        "action_path": "/vulnerabilities/csrf/",
        "method": "GET",
        "password_field": "password_new",
        "confirm_field": "password_conf",
        "submit_field": "Change",
        "submit_value": "Change",
        "new_value": "vulnvista-csrf-{token}",
        "success_indicator": "Password Changed.",
        "reset_value": "password",
    },
}
LAB_PRESETS["vulnvista_dvwa"] = LAB_PRESETS["dvwa"]


class DetectorError(Exception):
    """A detector could not run to completion — carries a human-readable reason
    that is surfaced to the user (distinct from a raw transport error)."""


@dataclass
class CandidateForm:
    """The resolved state-changing target: submit ``fields`` (defaults for
    every non-hidden input) to ``url`` via ``method``. ``token_field`` names
    the hidden field that looks like an anti-CSRF token, if any."""

    url: str
    method: str
    fields: dict[str, str]
    hidden_fields: dict[str, str]
    token_field: str | None
    source: str  # "explicit configuration" | "lab preset" | "auto-discovered"


@dataclass
class Decision:
    detected: bool
    validation_status: str
    confidence: str
    reason: str
    cwe: str
    cvss_score: float


def classify(
    has_token: bool,
    token_session_bound: bool | None,
    form_uses_get: bool,
    active_checked: bool,
    active_bypassed: bool,
) -> Decision:
    """Turn the raw signals into a validation verdict.

    Kept pure (no I/O) so the decision policy can be unit-tested directly.
    """
    if active_checked and active_bypassed:
        return Decision(
            True, "CONFIRMED", "HIGH",
            "a forged cross-site request (token dropped, Origin/Referer spoofed) "
            "reproduced the state change using only the victim's ambient session",
            cwe="CWE-352", cvss_score=8.8,
        )
    if active_checked:
        return Decision(
            False, "NOT_DETECTED", "HIGH",
            "the forged cross-site request was rejected — the target validates "
            "the anti-CSRF token and/or the request's origin",
            cwe="CWE-352", cvss_score=0.0,
        )
    if not has_token and form_uses_get:
        return Decision(
            True, "CONFIRMED", "MEDIUM",
            "the state-changing operation is reachable via a plain GET request "
            "with no anti-CSRF token",
            cwe="CWE-352", cvss_score=6.5,
        )
    if not has_token:
        return Decision(
            True, "CONFIRMED", "MEDIUM",
            "the state-changing form carries no anti-CSRF token",
            cwe="CWE-352", cvss_score=6.5,
        )
    if token_session_bound is False:
        return Decision(
            True, "CONFIRMED", "MEDIUM",
            "the anti-CSRF token is identical across independent sessions, so "
            "it is not actually bound to the victim's session and cannot "
            "prevent forgery",
            cwe="CWE-352", cvss_score=6.5,
        )
    if token_session_bound is True:
        return Decision(
            False, "NOT_DETECTED", "HIGH",
            "an anti-CSRF token is present and verified session-bound",
            cwe="CWE-352", cvss_score=0.0,
        )
    return Decision(
        False, "NOT_DETECTED", "LOW",
        "an anti-CSRF token is present (session-binding not verified)",
        cwe="CWE-352", cvss_score=0.0,
    )


class CSRFDetector(BaseDetector):
    detector_id = "csrf"
    name = "Cross-Site Request Forgery"
    vulnerability_type = "csrf"
    supported_targets = ["webapp"]

    async def check(self, context: ScanContext) -> DetectorResult:
        parsed = urlparse(context.base_url)
        host = parsed.hostname or ""
        base = f"{parsed.scheme}://{parsed.netloc}"
        cfg = {**GENERIC_DEFAULTS, **LAB_PRESETS.get(host, {}), **context.extra}
        discovery_path = cfg.get("discovery_path") or parsed.path or "/"
        source = (
            "explicit configuration" if "action_path" in context.extra
            else "lab preset" if host in LAB_PRESETS
            else "auto-discovered"
        )

        try:
            async with httpx.AsyncClient(
                timeout=cfg["request_timeout"],
                follow_redirects=True,
                cookies=cfg.get("cookies", {}),
                headers=cfg.get("headers", {}),
            ) as client:
                if cfg.get("login_path") and cfg.get("username") and cfg.get("password"):
                    await self._authenticate(client, base, host, cfg)

                form = await self._resolve_form(client, base, discovery_path, cfg, source)
                token_bound = await self._check_token_session_binding(client, form, cfg)

                active_checked = active_bypassed = False
                extra_evidence: dict[str, Any] = {}
                if cfg.get("action_path") and cfg.get("password_field"):
                    active_checked, active_bypassed, extra_evidence = await self._attempt_forgery(
                        client, form, cfg
                    )

                decision = classify(
                    has_token=form.token_field is not None,
                    token_session_bound=token_bound,
                    form_uses_get=form.method == "GET",
                    active_checked=active_checked,
                    active_bypassed=active_bypassed,
                )
                evidence = {
                    "form_endpoint": form.url,
                    "form_method": form.method,
                    "form_discovery": form.source,
                    "token_field": form.token_field,
                    "token_session_bound": token_bound,
                    "active_check_performed": active_checked,
                    "active_check_bypassed": active_bypassed,
                    **extra_evidence,
                }
                return self._result(form, decision, evidence)
        except DetectorError as exc:
            return self._error_result(context, cfg, str(exc))
        except httpx.HTTPError as exc:
            return self._error_result(
                context, cfg, f"Could not reach the target ({type(exc).__name__}: {exc})."
            )

    async def _authenticate(
        self, client: httpx.AsyncClient, base: str, host: str, cfg: dict[str, Any]
    ) -> None:
        """Best-effort form login: GET the login page, resubmit its hidden
        fields unchanged plus the given username/password. Only ever runs
        when the caller (a lab preset or an explicit override) supplied
        login_path/username/password."""
        login_url = urljoin(base + "/", cfg["login_path"])
        page = await client.get(login_url)
        page.raise_for_status()

        forms = parse_forms(page.text, str(page.url))
        login_form = forms[0] if forms else None

        data: dict[str, str] = {}
        if login_form:
            data.update({f.name: f.value for f in login_form.fields if f.type == "hidden"})
        data[cfg.get("username_field", "username")] = cfg["username"]
        data[cfg.get("password_field_login", "password")] = cfg["password"]
        if cfg.get("login_submit_field"):
            data[cfg["login_submit_field"]] = cfg.get("login_submit_value", "")

        post_url = login_form.action if login_form else login_url
        resp = await client.post(post_url, data=data)
        final_url = str(resp.url)

        if "setup.php" in final_url:
            raise DetectorError(
                "DVWA's database is not initialized. In your browser open DVWA's setup page "
                "(e.g. http://localhost:8081/setup.php) and click 'Create / Reset Database', "
                "then run the scan again."
            )
        if cfg["login_path"] in final_url or "login failed" in resp.text.lower():
            raise DetectorError(
                f"Login failed for user '{cfg['username']}' at {login_url}. Check the credentials."
            )

        for name, value in cfg.get("post_login_cookies", {}).items():
            client.cookies.set(name, value, domain=host, path="/")

    async def _resolve_form(
        self,
        client: httpx.AsyncClient,
        base: str,
        discovery_path: str,
        cfg: dict[str, Any],
        source: str,
    ) -> CandidateForm:
        if cfg.get("action_path"):
            url = urljoin(f"{base}/", cfg["action_path"].lstrip("/"))
            page = await client.get(url)
            page.raise_for_status()
            forms = parse_forms(page.text, str(page.url))
            method = cfg.get("method")
            matched = next(
                (f for f in forms if not method or f.method == method), forms[0] if forms else None
            )
            if matched is None:
                raise DetectorError(f"No form was found at {url}.")
            return self._build_candidate(matched, cfg, source)

        url = urljoin(f"{base}/", discovery_path.lstrip("/"))
        page = await client.get(url)
        page.raise_for_status()
        forms = parse_forms(page.text, str(page.url))
        matched = next(
            (f for f in forms if any(fld.type not in ("hidden", "submit") for fld in f.fields)),
            None,
        )
        if matched is None:
            raise DetectorError(
                f"No state-changing form was found at {url}. Provide an explicit "
                "'action_path' (and optionally 'method') in the target's scan configuration."
            )
        return self._build_candidate(matched, cfg, source)

    def _build_candidate(self, form: FormSpec, cfg: dict[str, Any], source: str) -> CandidateForm:
        hidden = {f.name: f.value for f in form.fields if f.type == "hidden"}
        visible = {f.name: f.value for f in form.fields if f.type not in ("hidden", "submit")}
        token_field = next((name for name in hidden if _TOKEN_NAME_RE.search(name)), None)
        return CandidateForm(
            url=form.action,
            method=cfg.get("method", form.method),
            fields=visible,
            hidden_fields=hidden,
            token_field=token_field,
            source=source,
        )

    async def _check_token_session_binding(
        self, client: httpx.AsyncClient, form: CandidateForm, cfg: dict[str, Any]
    ) -> bool | None:
        """Refetch the same form with a fresh, independent (cookie-less)
        client and compare the token value. A mismatch proves the token is
        session-bound; a match means it isn't real protection. Returns None
        (not verified) when the comparison can't be made safely — e.g. the
        page requires the authenticated session to even show the form."""
        if form.token_field is None:
            return None
        original_value = form.hidden_fields.get(form.token_field)
        if not original_value:
            return None
        try:
            async with httpx.AsyncClient(
                timeout=cfg["request_timeout"], follow_redirects=True
            ) as fresh:
                page = await fresh.get(form.url)
                if page.status_code >= 400:
                    return None
                forms = parse_forms(page.text, str(page.url))
        except httpx.HTTPError:
            return None
        matched = next((f for f in forms if f.action == form.url), forms[0] if forms else None)
        if matched is None:
            return None
        fresh_value = next(
            (f.value for f in matched.fields if f.name == form.token_field), None
        )
        if not fresh_value:
            return None
        return fresh_value != original_value

    async def _attempt_forgery(
        self, client: httpx.AsyncClient, form: CandidateForm, cfg: dict[str, Any]
    ) -> tuple[bool, bool, dict[str, Any]]:
        """Replay the state-changing request as a cross-site attacker page
        would send it: the victim's session cookies are still attached
        (that's the whole premise of CSRF), but the anti-CSRF token is
        dropped and Origin/Referer point at an unrelated host."""
        marker = secrets.token_hex(4)
        forged_value = cfg.get("new_value", "vulnvista-csrf-{token}").format(token=marker)
        pw_field = cfg["password_field"]
        confirm_field = cfg.get("confirm_field")

        data = {**form.fields, pw_field: forged_value}
        if confirm_field:
            data[confirm_field] = forged_value
        if cfg.get("submit_field"):
            data[cfg["submit_field"]] = cfg.get("submit_value", "")

        headers = {"Origin": cfg["forged_origin"], "Referer": f"{cfg['forged_origin']}/"}
        resp = await self._submit(client, form, data, headers)

        success_indicator = cfg.get("success_indicator")
        bypassed = (
            success_indicator in resp.text if success_indicator else resp.status_code < 400
        )

        evidence = {
            "forged_field": pw_field,
            "forged_value": forged_value,
            "forged_origin": cfg["forged_origin"],
            "forged_response_status": resp.status_code,
            "success_indicator_checked": success_indicator is not None,
        }

        if bypassed and cfg.get("reset_value") is not None:
            await self._reset_state(client, form, cfg)

        return True, bypassed, evidence

    async def _reset_state(
        self, client: httpx.AsyncClient, form: CandidateForm, cfg: dict[str, Any]
    ) -> None:
        """Restore the field to its known-good value using the authentic
        (non-forged) session, so later scans/detectors depending on it (e.g.
        the DVWA lab credential) keep working."""
        pw_field = cfg["password_field"]
        confirm_field = cfg.get("confirm_field")
        reset_value = cfg["reset_value"]
        data = {**form.fields, pw_field: reset_value}
        if confirm_field:
            data[confirm_field] = reset_value
        if cfg.get("submit_field"):
            data[cfg["submit_field"]] = cfg.get("submit_value", "")
        try:
            await self._submit(client, form, data, headers={})
        except httpx.HTTPError:
            pass

    async def _submit(
        self,
        client: httpx.AsyncClient,
        form: CandidateForm,
        data: dict[str, str],
        headers: dict[str, str],
    ) -> httpx.Response:
        if form.method == "GET":
            return await client.get(form.url, params=data, headers=headers)
        return await client.post(form.url, data=data, headers=headers)

    def _result(
        self, form: CandidateForm, decision: Decision, evidence: dict[str, Any]
    ) -> DetectorResult:
        summary = (
            f"{decision.reason} (form {evidence['form_discovery']}, method={form.method}). "
            f"token_field={evidence['token_field']}, active_check_performed="
            f"{evidence['active_check_performed']}."
        )
        severity = (
            "CRITICAL" if evidence["active_check_bypassed"]
            else "HIGH" if decision.detected
            else "INFO"
        )
        return DetectorResult(
            detector=self.detector_id,
            vulnerability=self.name,
            detected=decision.detected,
            validation_status=decision.validation_status,
            severity=severity,
            confidence=decision.confidence,
            endpoint=form.url,
            parameter=form.token_field,
            description=(
                "A state-changing operation can be triggered by a forged "
                "cross-site request: the target either carries no anti-CSRF "
                "token, accepts a token that is not bound to the victim's "
                "session, or is reachable via a plain GET request — letting "
                "an attacker-controlled page perform the action using the "
                "victim's ambient session."
            ),
            evidence_summary=summary,
            evidence=evidence,
            remediation=(
                "Require a per-session, unpredictable anti-CSRF token on "
                "every state-changing request and reject requests where it "
                "is missing or invalid. Restrict state-changing operations "
                "to POST/PUT/DELETE (never GET), set the session cookie's "
                "SameSite attribute to Lax or Strict, and validate the "
                "Origin/Referer header as defense in depth."
            ),
            cwe=decision.cwe,
            cvss_score=decision.cvss_score,
            owasp_category="A01:2021 - Broken Access Control",
        )

    def _error_result(
        self, context: ScanContext, cfg: dict[str, Any], message: str
    ) -> DetectorResult:
        parsed = urlparse(context.base_url)
        base = f"{parsed.scheme}://{parsed.netloc}"
        endpoint = (
            urljoin(f"{base}/", cfg["action_path"].lstrip("/"))
            if cfg.get("action_path")
            else context.base_url
        )
        return DetectorResult(
            detector=self.detector_id,
            vulnerability=self.name,
            detected=False,
            validation_status="ERROR",
            severity="INFO",
            confidence="LOW",
            endpoint=endpoint,
            parameter=None,
            description="Detector could not complete against the target.",
            evidence_summary=f"Scan error: {message}",
            evidence={"error": message},
            cwe="CWE-352",
            owasp_category="A01:2021 - Broken Access Control",
        )
