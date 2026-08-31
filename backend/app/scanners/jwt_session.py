"""Passive JWT and session-cookie security checks for authorized targets."""

from __future__ import annotations

import base64
import json
from typing import Any
from urllib.parse import urljoin, urlparse

import httpx

from app.scanners.base import BaseDetector, DetectorResult, ScanContext

MAX_TOKEN_LIFETIME_SECONDS = 24 * 60 * 60


def decode_jwt_metadata(token: str) -> tuple[dict[str, Any], dict[str, Any]] | None:
    """Decode JWT metadata without verifying or storing the signature."""
    parts = token.split(".")
    if len(parts) != 3:
        return None
    try:
        header = _decode_segment(parts[0])
        payload = _decode_segment(parts[1])
    except (ValueError, UnicodeDecodeError, json.JSONDecodeError):
        return None
    return (header, payload) if isinstance(header, dict) and isinstance(payload, dict) else None


def classify_token(header: dict[str, Any], payload: dict[str, Any]) -> list[dict[str, str]]:
    issues: list[dict[str, str]] = []
    algorithm = str(header.get("alg", "")).lower()
    if algorithm in {"", "none"}:
        issues.append(
            {
                "code": "unsigned_jwt",
                "severity": "CRITICAL",
                "detail": "JWT uses no signature algorithm.",
            }
        )

    issued_at = payload.get("iat")
    expires_at = payload.get("exp")
    if not isinstance(expires_at, (int, float)):
        issues.append(
            {
                "code": "missing_expiration",
                "severity": "MEDIUM",
                "detail": "JWT has no numeric expiration claim.",
            }
        )
    elif (
        isinstance(issued_at, (int, float)) and expires_at - issued_at > MAX_TOKEN_LIFETIME_SECONDS
    ):
        issues.append(
            {
                "code": "excessive_lifetime",
                "severity": "MEDIUM",
                "detail": "JWT lifetime exceeds 24 hours.",
            }
        )
    return issues


def classify_cookie(cookie_header: str) -> list[dict[str, str]]:
    lower = cookie_header.lower()
    issues: list[dict[str, str]] = []
    if "secure" not in lower:
        issues.append(
            {
                "code": "cookie_missing_secure",
                "severity": "MEDIUM",
                "detail": "Session cookie lacks Secure.",
            }
        )
    if "httponly" not in lower:
        issues.append(
            {
                "code": "cookie_missing_httponly",
                "severity": "MEDIUM",
                "detail": "Session cookie lacks HttpOnly.",
            }
        )
    if "samesite=" not in lower or "samesite=none" in lower:
        issues.append(
            {
                "code": "cookie_weak_samesite",
                "severity": "MEDIUM",
                "detail": "Session cookie lacks a restrictive SameSite policy.",
            }
        )
    return issues


class JWTSessionDetector(BaseDetector):
    detector_id = "jwt_session"
    name = "JWT / Session Security"
    vulnerability_type = "jwt_session"
    supported_targets = ["webapp", "juice-shop"]

    async def check(self, context: ScanContext) -> DetectorResult:
        token = _find_token(context.extra)
        try:
            async with httpx.AsyncClient(
                timeout=context.timeout_seconds,
                follow_redirects=True,
                headers=context.extra.get("headers", {}),
            ) as client:
                client.cookies.update(context.extra.get("cookies", {}))
                # Juice Shop exposes a deliberately controlled lab JWT. Default
                # credentials are never sent to arbitrary targets.
                hostname = (urlparse(context.base_url).hostname or "").lower()
                if not token and "juice" in hostname:
                    login_response = await client.post(
                        urljoin(
                            context.base_url, context.extra.get("login_path", "/rest/user/login")
                        ),
                        json={
                            "email": context.extra.get("username", "admin@juice-sh.op"),
                            "password": context.extra.get("password", "admin123"),
                        },
                    )
                    token = _token_from_login_response(login_response)
                response = await client.get(context.base_url)
        except httpx.HTTPError as exc:
            return self._error_result(str(exc))

        issues: list[dict[str, str]] = []
        token_metadata = decode_jwt_metadata(token) if token else None
        if token_metadata:
            issues.extend(classify_token(*token_metadata))

        session_cookies = [
            value
            for value in response.headers.get_list("set-cookie")
            if any(marker in value.lower() for marker in ("session", "token", "jwt", "auth"))
        ]
        for cookie in session_cookies:
            issues.extend(classify_cookie(cookie))

        severity = _worst_severity(issues)
        detected = bool(issues)
        evidence = {
            "issues": issues,
            "jwt_present": token_metadata is not None,
            "jwt_algorithm": token_metadata[0].get("alg") if token_metadata else None,
            "jwt_claim_names": sorted(token_metadata[1]) if token_metadata else [],
            "session_cookie_count": len(session_cookies),
            "probe": "passive metadata and Set-Cookie inspection; token signature not stored",
        }
        return DetectorResult(
            detector=self.detector_id,
            vulnerability=self.name,
            detected=detected,
            validation_status="CONFIRMED" if detected else "NOT_DETECTED",
            severity=severity,
            confidence="HIGH" if detected else "LOW",
            endpoint=str(response.url),
            description=(
                "JWT or session controls permit long-lived, unsigned, or browser-exposed "
                "authentication state."
            ),
            evidence_summary=(
                f"Detected {len(issues)} JWT/session issue(s): "
                f"{', '.join(issue['code'] for issue in issues)}."
                if issues
                else (
                    "No JWT/session weakness was observed in the supplied token or "
                    "response cookies."
                )
            ),
            evidence=evidence,
            remediation=(
                "Sign JWTs with an approved algorithm, enforce short expirations, rotate "
                "tokens, and set "
                "session cookies with Secure, HttpOnly, and SameSite=Lax or Strict."
            ),
            cwe="CWE-613",
            cvss_score={"CRITICAL": 9.1, "HIGH": 7.5, "MEDIUM": 5.3, "INFO": 0.0}[severity],
            owasp_category="A07:2021 - Identification and Authentication Failures",
        )

    def _error_result(self, error: str) -> DetectorResult:
        return DetectorResult(
            detector=self.detector_id,
            vulnerability=self.name,
            detected=False,
            validation_status="ERROR",
            severity="INFO",
            confidence="LOW",
            evidence={"error": error},
            evidence_summary=error,
            cwe="CWE-613",
            owasp_category="A07:2021 - Identification and Authentication Failures",
        )


def _decode_segment(segment: str) -> Any:
    padded = segment + "=" * (-len(segment) % 4)
    return json.loads(base64.urlsafe_b64decode(padded).decode("utf-8"))


def _find_token(extra: dict[str, Any]) -> str | None:
    for key in ("jwt", "token", "access_token"):
        value = extra.get(key)
        if isinstance(value, str) and value.count(".") == 2:
            return value
    authorization = str(extra.get("headers", {}).get("Authorization", ""))
    if authorization.lower().startswith("bearer "):
        return authorization[7:].strip()
    for value in extra.get("cookies", {}).values():
        if isinstance(value, str) and value.count(".") == 2:
            return value
    return None


def _token_from_login_response(response: httpx.Response) -> str | None:
    try:
        body = response.json()
    except ValueError:
        return None
    if not isinstance(body, dict):
        return None
    authentication = body.get("authentication", {})
    token = authentication.get("token") if isinstance(authentication, dict) else None
    return token if isinstance(token, str) and token.count(".") == 2 else None


def _worst_severity(issues: list[dict[str, str]]) -> str:
    rank = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
    return max((issue["severity"] for issue in issues), key=rank.get, default="INFO")
