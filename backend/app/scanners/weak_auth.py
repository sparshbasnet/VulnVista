"""Weak-authentication-controls detector.

Generic and evidence-based, same as ``command_injection.py`` — the technique
works against any site with a discoverable (or explicitly configured) login
form, not just OWASP Juice Shop. Two independent signals:

  1. Missing rate limiting / lockout: repeatedly submit a wrong password to
     the login form for a small, fixed attempt budget (default 12 — well
     below anything that could be called brute-forcing). If none of those
     attempts are throttled (HTTP 429 or a lockout/CAPTCHA hint in the body)
     the target has no brute-force protection.
  2. Username enumeration: compare the target's own response for a
     known-valid username vs a freshly-generated, essentially-guaranteed-
     not-to-exist username (each paired with the same wrong password). A
     status-code or response-shape differential is a direct oracle for which
     usernames are registered accounts. This check requires a known-valid
     username — supplied via ``ScanContext.extra['known_username']`` — since
     an arbitrary target's valid accounts can't be discovered safely; it is
     skipped (not run, not scored either way) when none is supplied. When
     the target additionally exposes a separate GET oracle endpoint whose
     JSON response shape differs by account existence (``enumeration_path``,
     e.g. Juice Shop's password-reset security-question lookup), that oracle
     is used instead of a login-response diff, since it is a cleaner signal.

The login form itself is discovered generically: fetch the target's own
page (or an explicit ``login_path`` override), parse its ``<form>``
elements, and use the first one containing a password-type field, carrying
its hidden fields (CSRF tokens etc.) through verbatim. A short list of
common login paths is tried as a fallback when the target's own page has no
such form. Everything is overridable via ``ScanContext.extra`` (populated
from ``Target.scan_config``) — ``login_path``, ``username_field``,
``password_field``, ``known_username``, ``request_style`` ("json" for a
JSON API with no HTML form, e.g. Juice Shop), ``rate_limit_attempts``, etc.
A known lab host (Juice Shop) gets a preset with all of this pre-filled.

Both checks only ever touch the target-supplied known account and synthetic
addresses — no real user is targeted and no password is guessed or cracked.
"""

from __future__ import annotations

import secrets
from dataclasses import dataclass
from typing import Any
from urllib.parse import urljoin, urlparse

import httpx

from app.scanners.base import BaseDetector, DetectorResult, ScanContext
from app.scanners.command_injection import FormSpec, parse_forms

# Target-agnostic tuning only. Everything target-specific lives in
# LAB_PRESETS or is supplied by the caller via ScanContext.extra.
GENERIC_DEFAULTS: dict[str, Any] = {
    "rate_limit_attempts": 12,
    "request_timeout": 15.0,
}

# Tried in order (after the target's own path) when no login_path override
# is given and the target's own page has no login form.
COMMON_LOGIN_PATHS = [
    "/login",
    "/signin",
    "/sign-in",
    "/account/login",
    "/users/sign_in",
    "/auth/login",
    "/wp-login.php",
]

_LOCKOUT_KEYWORDS = ("lock", "too many attempts", "rate limit", "captcha")

# Convenience preset for the bundled Juice Shop lab container, so its
# quick-start keeps working with zero configuration — it's a pure JSON REST
# API with no server-rendered login form to discover, and its enumeration
# oracle lives on a separate endpoint from the login one.
LAB_PRESETS: dict[str, dict[str, Any]] = {
    "juice-shop": {
        "login_path": "/rest/user/login",
        "request_style": "json",
        "username_field": "email",
        "password_field": "password",
        "known_username": "admin@juice-sh.op",
        "enumeration_path": "/rest/user/security-question",
        "enumeration_param": "email",
        "enumeration_response_key": "question",
    },
}
LAB_PRESETS["vulnvista_juice_shop"] = LAB_PRESETS["juice-shop"]


class DetectorError(Exception):
    """A detector could not run to completion — carries a human-readable reason
    that is surfaced to the user (distinct from a raw transport error)."""


@dataclass
class LoginForm:
    """The resolved login target: submit ``username_field``/``password_field``
    inside ``fixed_fields`` (any hidden/CSRF fields, held at their captured
    value) to ``url`` via ``method``, as JSON or form-encoded per ``style``."""

    url: str
    method: str
    username_field: str
    password_field: str
    fixed_fields: dict[str, str]
    style: str  # "json" | "form"
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
    enumeration_leaked: bool,
    lockout_triggered: bool,
    attempts_made: int,
    enumeration_checked: bool = True,
) -> Decision:
    """Turn the raw signals into a validation verdict.

    Kept pure (no I/O) so the decision policy can be unit-tested directly.
    """
    if enumeration_leaked and not lockout_triggered:
        return Decision(
            True, "CONFIRMED", "HIGH",
            f"username enumeration oracle confirmed and no lockout/rate-limit "
            f"after {attempts_made} failed login attempts",
            cwe="CWE-307", cvss_score=7.5,
        )
    if enumeration_leaked:
        return Decision(
            True, "CONFIRMED", "HIGH",
            "username enumeration oracle confirmed via differential login/oracle response",
            cwe="CWE-203", cvss_score=5.3,
        )
    if not lockout_triggered:
        return Decision(
            True, "CONFIRMED", "MEDIUM",
            f"no lockout/rate-limiting observed after {attempts_made} failed "
            "login attempts",
            cwe="CWE-307", cvss_score=6.5,
        )
    note = "" if enumeration_checked else " (enumeration check skipped — no known_username supplied)"
    return Decision(
        False, "NOT_DETECTED", "LOW",
        f"no enumeration oracle observed and rate-limiting/lockout is enforced{note}",
        cwe="CWE-307", cvss_score=0.0,
    )


class WeakAuthDetector(BaseDetector):
    detector_id = "weak_auth"
    name = "Weak Authentication Controls"
    vulnerability_type = "weak_auth"
    supported_targets = ["webapp"]

    async def check(self, context: ScanContext) -> DetectorResult:
        parsed = urlparse(context.base_url)
        host = parsed.hostname or ""
        base = f"{parsed.scheme}://{parsed.netloc}"
        cfg = {**GENERIC_DEFAULTS, **LAB_PRESETS.get(host, {}), **context.extra}
        discovery_path = cfg.get("discovery_path") or parsed.path or "/"
        source = (
            "explicit configuration" if "login_path" in context.extra
            else "lab preset" if host in LAB_PRESETS
            else "auto-discovered"
        )

        try:
            async with httpx.AsyncClient(timeout=cfg["request_timeout"], follow_redirects=True) as client:
                login = await self._resolve_login(client, base, discovery_path, cfg, source)
                lockout_triggered, statuses = await self._check_rate_limit(client, login, cfg)
                enum_checked, enum_leaked, enum_evidence = await self._check_enumeration(
                    client, base, login, cfg
                )

            decision = classify(enum_leaked, lockout_triggered, len(statuses), enum_checked)
            evidence = {
                "login_endpoint": login.url,
                "login_discovery": login.source,
                "username_field": login.username_field,
                "password_field": login.password_field,
                "login_attempt_statuses": statuses,
                "lockout_triggered": lockout_triggered,
                "rate_limit_attempts": cfg["rate_limit_attempts"],
                **enum_evidence,
            }
            return self._result(login, decision, evidence)
        except DetectorError as exc:
            return self._error_result(context, cfg, str(exc))
        except httpx.HTTPError as exc:
            return self._error_result(
                context, cfg, f"Could not reach the target ({type(exc).__name__}: {exc})."
            )

    async def _resolve_login(
        self,
        client: httpx.AsyncClient,
        base: str,
        discovery_path: str,
        cfg: dict[str, Any],
        source: str,
    ) -> LoginForm:
        if cfg.get("request_style") == "json":
            if not cfg.get("login_path"):
                raise DetectorError("request_style is 'json' but no login_path was supplied.")
            return LoginForm(
                url=urljoin(f"{base}/", cfg["login_path"].lstrip("/")),
                method=cfg.get("method", "POST"),
                username_field=cfg.get("username_field", "username"),
                password_field=cfg.get("password_field", "password"),
                fixed_fields={},
                style="json",
                source=source,
            )

        if cfg.get("login_path") and cfg.get("username_field") and cfg.get("password_field"):
            form = await self._fetch_login_form(client, urljoin(f"{base}/", cfg["login_path"].lstrip("/")))
            return LoginForm(
                url=form.action if form else urljoin(f"{base}/", cfg["login_path"].lstrip("/")),
                method=(form.method if form else cfg.get("method", "POST")),
                username_field=cfg["username_field"],
                password_field=cfg["password_field"],
                fixed_fields=_hidden_fields(form) if form else {},
                style="form",
                source=source,
            )

        paths = [cfg["login_path"]] if cfg.get("login_path") else [discovery_path, *COMMON_LOGIN_PATHS]
        tried: set[str] = set()
        for path in paths:
            if path in tried:
                continue
            tried.add(path)
            form = await self._fetch_login_form(client, urljoin(f"{base}/", path.lstrip("/")))
            if form is None:
                continue
            password_field = next((f for f in form.fields if f.type == "password"), None)
            if password_field is None:
                continue
            username_field = next(
                (f for f in form.fields if f is not password_field and f.type in {"text", "email"}),
                None,
            )
            if username_field is None:
                continue
            return LoginForm(
                url=form.action,
                method=form.method,
                username_field=username_field.name,
                password_field=password_field.name,
                fixed_fields=_hidden_fields(form),
                style="form",
                source=source,
            )

        hint = f" at {cfg['login_path']}" if cfg.get("login_path") else f" at {base}{discovery_path} or common login paths"
        raise DetectorError(
            f"No login form with a password field was found{hint}. Provide an explicit "
            "'login_path' (plus 'username_field'/'password_field' if auto-detection still "
            "fails, or 'request_style': 'json' for a JSON API with no HTML form) in the "
            "target's scan configuration."
        )

    async def _fetch_login_form(self, client: httpx.AsyncClient, url: str) -> FormSpec | None:
        try:
            page = await client.get(url)
        except httpx.HTTPError:
            return None
        if page.status_code >= 400:
            return None
        forms = parse_forms(page.text, str(page.url))
        return next((f for f in forms if any(fld.type == "password" for fld in f.fields)), None)

    async def _submit_login(
        self, client: httpx.AsyncClient, login: LoginForm, username: str, password: str
    ) -> httpx.Response:
        data = {**login.fixed_fields, login.username_field: username, login.password_field: password}
        if login.style == "json":
            return await client.post(login.url, json=data)
        return await client.post(login.url, data=data)

    async def _check_rate_limit(
        self, client: httpx.AsyncClient, login: LoginForm, cfg: dict[str, Any]
    ) -> tuple[bool, list[int]]:
        """Fire a small, fixed budget of failed logins against one account
        (the configured known_username, or a synthetic one) and see whether
        any attempt is ever throttled or locked out."""
        username = cfg.get("known_username") or f"vulnvista-test-{secrets.token_hex(4)}@example.invalid"
        statuses: list[int] = []
        lockout_triggered = False
        for _ in range(cfg["rate_limit_attempts"]):
            bogus_password = f"vulnvista-wrong-{secrets.token_hex(4)}"
            resp = await self._submit_login(client, login, username, bogus_password)
            statuses.append(resp.status_code)
            if resp.status_code == 429 or _looks_locked_out(resp.text):
                lockout_triggered = True
                break
        return lockout_triggered, statuses

    async def _check_enumeration(
        self, client: httpx.AsyncClient, base: str, login: LoginForm, cfg: dict[str, Any]
    ) -> tuple[bool, bool, dict[str, Any]]:
        known_username = cfg.get("known_username")
        if not known_username:
            return False, False, {
                "enumeration_checked": False,
                "enumeration_method": None,
                "enumeration_endpoint": None,
                "known_username": None,
                "known_username_signal": None,
                "unknown_username_signal": None,
            }

        unknown_username = f"vulnvista-nonexistent-{secrets.token_hex(4)}@example.invalid"

        if cfg.get("enumeration_path"):
            leaked, evidence = await self._check_enumeration_oracle(
                client, base, cfg, known_username, unknown_username
            )
        else:
            leaked, evidence = await self._check_enumeration_login_diff(
                client, login, known_username, unknown_username
            )
        return True, leaked, evidence

    async def _check_enumeration_oracle(
        self,
        client: httpx.AsyncClient,
        base: str,
        cfg: dict[str, Any],
        known_username: str,
        unknown_username: str,
    ) -> tuple[bool, dict[str, Any]]:
        """Compare a GET oracle endpoint's JSON response for a known vs. a
        synthetic random account. A known-only hit means the endpoint leaks
        which accounts are registered (e.g. Juice Shop's password-reset
        security-question lookup)."""
        url = urljoin(f"{base}/", cfg["enumeration_path"].lstrip("/"))
        param = cfg.get("enumeration_param", "email")
        key = cfg.get("enumeration_response_key", "question")

        known_resp = await client.get(url, params={param: known_username})
        unknown_resp = await client.get(url, params={param: unknown_username})

        if known_resp.status_code == 404 or unknown_resp.status_code == 404:
            raise DetectorError(f"Enumeration oracle endpoint not found at {url}.")

        known_signal = bool(_safe_json(known_resp).get(key))
        unknown_signal = bool(_safe_json(unknown_resp).get(key))

        return known_signal and not unknown_signal, {
            "enumeration_checked": True,
            "enumeration_method": "oracle_endpoint",
            "enumeration_endpoint": url,
            "known_username": known_username,
            "known_username_signal": known_signal,
            "unknown_username_signal": unknown_signal,
        }

    async def _check_enumeration_login_diff(
        self,
        client: httpx.AsyncClient,
        login: LoginForm,
        known_username: str,
        unknown_username: str,
    ) -> tuple[bool, dict[str, Any]]:
        """Generic fallback when no dedicated oracle endpoint is configured:
        compare the login endpoint's own response for a known vs. synthetic
        account, each with the same wrong password. A status-code or
        response-length differential (beyond trivial noise) is the oracle.
        This is a blackbox heuristic — response bodies are recorded as
        evidence for human review rather than trusted blindly."""
        bogus_password = f"vulnvista-wrong-{secrets.token_hex(4)}"
        known_resp = await self._submit_login(client, login, known_username, bogus_password)
        unknown_resp = await self._submit_login(client, login, unknown_username, bogus_password)

        known_signal = f"status:{known_resp.status_code},len:{len(known_resp.text)}"
        unknown_signal = f"status:{unknown_resp.status_code},len:{len(unknown_resp.text)}"
        leaked = (
            known_resp.status_code != unknown_resp.status_code
            or abs(len(known_resp.text) - len(unknown_resp.text)) > 5
        )

        return leaked, {
            "enumeration_checked": True,
            "enumeration_method": "login_differential",
            "enumeration_endpoint": login.url,
            "known_username": known_username,
            "known_username_signal": known_signal,
            "unknown_username_signal": unknown_signal,
        }

    def _result(self, login: LoginForm, decision: Decision, evidence: dict[str, Any]) -> DetectorResult:
        summary = (
            f"{decision.reason} (login {evidence['login_discovery']}). "
            f"login_attempts={len(evidence['login_attempt_statuses'])}, "
            f"enumeration_checked={evidence['enumeration_checked']}."
        )
        return DetectorResult(
            detector=self.detector_id,
            vulnerability=self.name,
            detected=decision.detected,
            validation_status=decision.validation_status,
            severity="HIGH" if decision.detected else "INFO",
            confidence=decision.confidence,
            endpoint=login.url,
            parameter=login.username_field,
            description=(
                "The target's authentication controls allow an attacker to "
                "determine which usernames/emails are registered accounts "
                "and/or place no limit on repeated failed login attempts, "
                "enabling credential stuffing and brute-force attacks."
            ),
            evidence_summary=summary,
            evidence=evidence,
            remediation=(
                "Return identical responses for existing and non-existing "
                "accounts on every auth-adjacent endpoint (login, password "
                "reset, registration). Add rate limiting and progressive "
                "lockout/backoff on login attempts, keyed by account and by "
                "source IP."
            ),
            cwe=decision.cwe,
            cvss_score=decision.cvss_score,
            owasp_category="A07:2021 - Identification and Authentication Failures",
        )

    def _error_result(
        self, context: ScanContext, cfg: dict[str, Any], message: str
    ) -> DetectorResult:
        parsed = urlparse(context.base_url)
        base = f"{parsed.scheme}://{parsed.netloc}"
        endpoint = urljoin(f"{base}/", cfg["login_path"].lstrip("/")) if cfg.get("login_path") else context.base_url
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
            cwe="CWE-307",
            owasp_category="A07:2021 - Identification and Authentication Failures",
        )


def _hidden_fields(form: FormSpec) -> dict[str, str]:
    return {f.name: f.value for f in form.fields if f.type == "hidden"}


def _looks_locked_out(body: str) -> bool:
    lowered = body.lower()
    return any(keyword in lowered for keyword in _LOCKOUT_KEYWORDS)


def _safe_json(resp: httpx.Response) -> dict[str, Any]:
    try:
        data = resp.json()
    except ValueError:
        return {}
    return data if isinstance(data, dict) else {}
