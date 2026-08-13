"""Weak-authentication-controls detector.

Evidence-based, same as ``command_injection.py``: it never assumes a weakness,
it proves one against the live target. Two independent, non-destructive
signals are used against OWASP Juice Shop:

  1. Username enumeration: Juice Shop's password-reset flow exposes
     ``GET /rest/user/security-question?email=<addr>``. For a registered
     address it returns that user's real security question; for an address
     that does not exist it returns ``{}``. That differential is a direct
     oracle for which email addresses are registered accounts — proven by
     comparing a known lab account against a freshly-generated random
     address, never by touching a real user.
  2. Missing rate limiting / lockout: repeatedly POST a wrong password to
     ``/rest/user/login`` for a known lab account, using a small, fixed
     attempt budget (default 12 — well below anything that could be called
     brute-forcing). If none of those attempts are throttled (HTTP 429) or
     rejected with a lockout message, the target has no brute-force
     protection on login.

Both checks only ever touch the pre-seeded default lab admin account
(``admin@juice-sh.op``) and synthetic addresses — no real user is targeted
and no password is guessed or cracked. Juice Shop-specific paths live in
overridable defaults, not in the detection logic, so the same detector can
be pointed at another target via ``ScanContext.extra``.
"""

from __future__ import annotations

import secrets
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlparse

import httpx

from app.scanners.base import BaseDetector, DetectorResult, ScanContext

# Lab defaults target OWASP Juice Shop's seeded admin account and its
# password-reset / login REST endpoints. Everything here is overridable via
# ScanContext.extra.
DEFAULTS: dict[str, Any] = {
    "login_path": "/rest/user/login",
    "security_question_path": "/rest/user/security-question",
    "known_user_email": "admin@juice-sh.op",
    "rate_limit_attempts": 12,
    "request_timeout": 15.0,
}


class DetectorError(Exception):
    """A detector could not run to completion — carries a human-readable reason
    that is surfaced to the user (distinct from a raw transport error)."""


@dataclass
class Decision:
    detected: bool
    validation_status: str
    confidence: str
    reason: str
    cwe: str
    cvss_score: float


def classify(enumeration_leaked: bool, lockout_triggered: bool, attempts_made: int) -> Decision:
    """Turn the two raw signals into a validation verdict.

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
            "username enumeration oracle confirmed via differential "
            "security-question response",
            cwe="CWE-203", cvss_score=5.3,
        )
    if not lockout_triggered:
        return Decision(
            True, "CONFIRMED", "MEDIUM",
            f"no lockout/rate-limiting observed after {attempts_made} failed "
            "login attempts",
            cwe="CWE-307", cvss_score=6.5,
        )
    return Decision(
        False, "NOT_DETECTED", "LOW",
        "no enumeration oracle observed and rate-limiting/lockout is enforced",
        cwe="CWE-307", cvss_score=0.0,
    )


class WeakAuthDetector(BaseDetector):
    detector_id = "weak_auth"
    name = "Weak Authentication Controls"
    vulnerability_type = "weak_auth"
    supported_targets = ["juice-shop", "webapp"]

    async def check(self, context: ScanContext) -> DetectorResult:
        cfg = {**DEFAULTS, **context.extra}
        parsed = urlparse(context.base_url)
        base = f"{parsed.scheme}://{parsed.netloc}"

        try:
            async with httpx.AsyncClient(timeout=cfg["request_timeout"]) as client:
                enumeration_leaked, enum_evidence = await self._check_enumeration(client, base, cfg)
                lockout_triggered, attempts_made, rate_evidence = await self._check_rate_limit(
                    client, base, cfg
                )

            decision = classify(enumeration_leaked, lockout_triggered, attempts_made)
            return self._result(context, cfg, decision, {**enum_evidence, **rate_evidence})
        except DetectorError as exc:
            return self._error_result(context, cfg, str(exc))
        except httpx.HTTPError as exc:
            return self._error_result(
                context, cfg, f"Could not reach the target ({type(exc).__name__}: {exc})."
            )

    async def _check_enumeration(
        self, client: httpx.AsyncClient, base: str, cfg: dict[str, Any]
    ) -> tuple[bool, dict[str, Any]]:
        """Compare the security-question oracle for a known vs. a synthetic
        random address. A known-only hit means the endpoint leaks which
        emails are registered accounts."""
        url = f"{base}{cfg['security_question_path']}"
        known_email = cfg["known_user_email"]
        unknown_email = f"vulnvista-nonexistent-{secrets.token_hex(4)}@example.invalid"

        known_resp = await client.get(url, params={"email": known_email})
        unknown_resp = await client.get(url, params={"email": unknown_email})

        if known_resp.status_code == 404 or unknown_resp.status_code == 404:
            raise DetectorError(
                f"Security-question endpoint not found at {url} — target does "
                "not look like OWASP Juice Shop."
            )

        known_has_question = bool(_safe_json(known_resp).get("question"))
        unknown_has_question = bool(_safe_json(unknown_resp).get("question"))
        leaked = known_has_question and not unknown_has_question

        return leaked, {
            "known_email": known_email,
            "known_email_has_question": known_has_question,
            "unknown_email_has_question": unknown_has_question,
            "enumeration_endpoint": url,
        }

    async def _check_rate_limit(
        self, client: httpx.AsyncClient, base: str, cfg: dict[str, Any]
    ) -> tuple[bool, int, dict[str, Any]]:
        """Fire a small, fixed budget of failed logins against a known lab
        account and see whether any attempt is ever throttled or locked out."""
        url = f"{base}{cfg['login_path']}"
        email = cfg["known_user_email"]
        bogus_password = f"vulnvista-wrong-{secrets.token_hex(4)}"

        statuses: list[int] = []
        lockout_triggered = False
        for _ in range(cfg["rate_limit_attempts"]):
            resp = await client.post(url, json={"email": email, "password": bogus_password})
            statuses.append(resp.status_code)
            if resp.status_code == 429 or "lock" in resp.text.lower():
                lockout_triggered = True
                break

        return lockout_triggered, len(statuses), {
            "login_endpoint": url,
            "login_attempt_statuses": statuses,
        }

    def _result(
        self,
        context: ScanContext,
        cfg: dict[str, Any],
        decision: Decision,
        evidence: dict[str, Any],
    ) -> DetectorResult:
        endpoint = f"{context.base_url.rstrip('/')}{cfg['login_path']}"
        summary = (
            f"{decision.reason}. "
            f"known_email_has_question={evidence['known_email_has_question']}, "
            f"unknown_email_has_question={evidence['unknown_email_has_question']}, "
            f"login_attempts={len(evidence['login_attempt_statuses'])}."
        )
        return DetectorResult(
            detector=self.detector_id,
            vulnerability=self.name,
            detected=decision.detected,
            validation_status=decision.validation_status,
            severity="HIGH" if decision.detected else "INFO",
            confidence=decision.confidence,
            endpoint=endpoint,
            parameter="email",
            description=(
                "The target's authentication controls allow an attacker to "
                "determine which email addresses are registered accounts "
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
        return DetectorResult(
            detector=self.detector_id,
            vulnerability=self.name,
            detected=False,
            validation_status="ERROR",
            severity="INFO",
            confidence="LOW",
            endpoint=f"{context.base_url.rstrip('/')}{cfg['login_path']}",
            parameter="email",
            description="Detector could not complete against the target.",
            evidence_summary=f"Scan error: {message}",
            evidence={"error": message},
            cwe="CWE-307",
            owasp_category="A07:2021 - Identification and Authentication Failures",
        )


def _safe_json(resp: httpx.Response) -> dict[str, Any]:
    try:
        data = resp.json()
    except ValueError:
        return {}
    return data if isinstance(data, dict) else {}
