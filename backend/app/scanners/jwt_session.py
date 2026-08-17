"""Controlled detector for JWT / session authentication weaknesses.

A synthetic laboratory account logs in to obtain a genuine session token, which
is parsed but never verified locally — the detector only reads its header and
claims. Two baselines are then established against a session-check endpoint: the
value it returns for the genuine token, and the value it returns for no token at
all. A negative control (a structurally invalid token) confirms the endpoint
actually distinguishes an authenticated session from an anonymous one before any
verdict is trusted.

The detector then submits tokens that a correct server must reject — an
`alg: none` unsigned token and a token whose signature has been invalidated —
each carrying a unique, tampered identity claim. A finding is confirmed only when
one of these forged tokens is accepted as an authenticated session, which proves
the target does not verify token integrity. When the tampered claim is reflected
back in the session-check response, impersonation is demonstrated directly.

The genuine token is never replayed as an attack and its sensitive claims
(passwords, secrets, the raw signature) are masked before anything is stored. The
bundled Juice Shop preset provisions one `@lab.invalid` account and checks its
`/rest/user/whoami` session. Other authorized targets supply their own login
flow, token submission style, session-check endpoint, and claim mapping through
ScanContext.extra.
"""

from __future__ import annotations

import base64
import binascii
import json
import secrets
from contextlib import AsyncExitStack
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urljoin, urlparse

import httpx

from app.scanners.base import BaseDetector, DetectorResult, ScanContext

GENERIC_DEFAULTS: dict[str, Any] = {
    "request_timeout": 15.0,
    "login_username_field": "username",
    "login_password_field": "password",
    "login_request_style": "form",
    "register_request_style": "json",
    "token_submission": "header",
    "token_header": "Authorization",
    "token_header_prefix": "Bearer ",
    "session_check_method": "GET",
}

LAB_PRESETS: dict[str, dict[str, Any]] = {
    "juice-shop": {
        "login_path": "/rest/user/login",
        "login_username_field": "email",
        "login_password_field": "password",
        "login_request_style": "json",
        "token_json_path": "authentication.token",
        "token_submission": "cookie",
        "token_cookie": "token",
        "session_check_path": "/rest/user/whoami",
        "session_marker_json_path": "user.email",
        "tamper_claim_path": "data.email",
        "register_path": "/api/Users/",
        "register_request_style": "json",
        "register_password_repeat_field": "passwordRepeat",
        "register_extra_fields": {
            "securityQuestion": {"id": 1},
            "securityAnswer": "vulnvista lab",
        },
        "username": "vulnvista.jwt@lab.invalid",
        "password": "VulnVistaJwt1!",
    }
}
LAB_PRESETS["vulnvista_juice_shop"] = LAB_PRESETS["juice-shop"]

# Claim keys whose values must never be persisted or logged in the clear.
SENSITIVE_CLAIM_KEYS = {"password", "totpsecret", "token", "secret", "hash", "otp"}


class DetectorError(Exception):
    """Expected, actionable detector failure shown directly to the operator."""


@dataclass
class ForgeryProbe:
    """One token a correct server must reject, and how the target responded."""

    name: str
    description: str
    accepted: bool
    echoed: bool
    status_code: int
    marker: str | None


@dataclass
class Decision:
    detected: bool
    validation_status: str
    confidence: str
    severity: str
    cwe: str
    cvss_score: float
    reason: str


@dataclass
class Structural:
    """What parsing the genuine token (without verifying it) revealed."""

    algorithm: str | None = None
    token_type: str | None = None
    has_expiration: bool = False
    issued_unsigned: bool = False
    claim_keys: list[str] = field(default_factory=list)


def b64url_decode(segment: str) -> bytes:
    return base64.urlsafe_b64decode(segment + "=" * (-len(segment) % 4))


def b64url_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def encode_segment(payload: dict[str, Any]) -> str:
    return b64url_encode(json.dumps(payload, separators=(",", ":")).encode("utf-8"))


def get_nested(mapping: Any, dotted_path: str) -> Any:
    """Safely retrieve a dotted field from JSON-like dictionaries."""
    current = mapping
    for key in dotted_path.split("."):
        if not isinstance(current, dict) or key not in current:
            return None
        current = current[key]
    return current


def set_nested(mapping: dict[str, Any], dotted_path: str, value: Any) -> bool:
    """Set a dotted field in place; returns False if the path does not exist."""
    keys = dotted_path.split(".")
    current: Any = mapping
    for key in keys[:-1]:
        if not isinstance(current, dict) or key not in current:
            return False
        current = current[key]
    if not isinstance(current, dict) or keys[-1] not in current:
        return False
    current[keys[-1]] = value
    return True


def parse_jwt(token: str) -> tuple[dict[str, Any], dict[str, Any], str]:
    """Read a JWT's header and claims without verifying its signature."""
    parts = token.split(".")
    if len(parts) != 3:
        raise DetectorError("The session token is not a three-part JWT.")
    try:
        header = json.loads(b64url_decode(parts[0]))
        payload = json.loads(b64url_decode(parts[1]))
    except (binascii.Error, ValueError, UnicodeDecodeError) as exc:
        raise DetectorError(f"The session token could not be decoded as a JWT: {exc}") from exc
    if not isinstance(header, dict) or not isinstance(payload, dict):
        raise DetectorError("The session token's header and claims are not JSON objects.")
    return header, payload, parts[2]


def redact_claims(value: Any) -> Any:
    """Recursively mask sensitive values so evidence never leaks secrets."""
    if isinstance(value, dict):
        return {
            key: ("***redacted***" if key.lower() in SENSITIVE_CLAIM_KEYS else redact_claims(inner))
            for key, inner in value.items()
        }
    if isinstance(value, list):
        return [redact_claims(item) for item in value]
    return value


def classify(
    oracle_valid: bool,
    forgeries: list[ForgeryProbe],
    structural: Structural,
) -> Decision:
    """Turn the forgery outcomes and structural weaknesses into the shared verdict."""
    if not oracle_valid:
        return Decision(
            detected=False,
            validation_status="INCONCLUSIVE",
            confidence="LOW",
            severity="INFO",
            cwe="CWE-345",
            cvss_score=0.0,
            reason=(
                "the session-check endpoint did not reliably distinguish an authenticated "
                "session from an anonymous one, so token acceptance could not be judged"
            ),
        )

    accepted = [probe for probe in forgeries if probe.accepted]
    if accepted:
        echoed = any(probe.echoed for probe in accepted)
        names = ", ".join(probe.name for probe in accepted)
        return Decision(
            detected=True,
            validation_status="CONFIRMED",
            confidence="HIGH" if echoed else "MEDIUM",
            severity="CRITICAL" if echoed else "HIGH",
            cwe="CWE-347",
            cvss_score=9.1 if echoed else 8.1,
            reason=(
                f"the target accepted a forged token ({names}) as a valid session"
                + (
                    ", returning the tampered identity claim in the session response, which "
                    "demonstrates impersonation"
                    if echoed
                    else ", proving token signatures are not verified"
                )
            ),
        )

    if structural.issued_unsigned:
        return Decision(
            detected=True,
            validation_status="CONFIRMED",
            confidence="HIGH",
            severity="HIGH",
            cwe="CWE-347",
            cvss_score=7.5,
            reason="the target issues unsigned session tokens (header alg is 'none')",
        )

    if not structural.has_expiration:
        return Decision(
            detected=True,
            validation_status="SUSPECTED",
            confidence="MEDIUM",
            severity="MEDIUM",
            cwe="CWE-613",
            cvss_score=5.3,
            reason=(
                "the session token carries no expiration ('exp') claim, so a captured token "
                "remains valid indefinitely"
            ),
        )

    return Decision(
        detected=False,
        validation_status="NOT_DETECTED",
        confidence="LOW",
        severity="INFO",
        cwe="CWE-347",
        cvss_score=0.0,
        reason=(
            "the target rejected every forged token and the issued token is signed and "
            "carries an expiration claim"
        ),
    )


class JWTSessionDetector(BaseDetector):
    detector_id = "jwt_session"
    name = "JWT / Session Weaknesses"
    vulnerability_type = "jwt_session"
    supported_targets = ["webapp"]

    async def check(self, context: ScanContext) -> DetectorResult:
        parsed = urlparse(context.base_url)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            return self._error_result(context, "Target must be an absolute HTTP(S) URL.")

        host = parsed.hostname or ""
        origin = f"{parsed.scheme}://{parsed.netloc}"
        cfg = {**GENERIC_DEFAULTS, **LAB_PRESETS.get(host, {}), **context.extra}
        source = (
            "explicit configuration"
            if "session_check_path" in context.extra
            else "lab preset"
            if host in LAB_PRESETS
            else None
        )

        for required in ("login_path", "session_check_path", "session_marker_json_path"):
            if not cfg.get(required):
                return self._error_result(
                    context,
                    "No JWT/session configuration is known for this target. Provide "
                    "'login_path', account credentials, 'session_check_path', "
                    "'session_marker_json_path', and the token submission style in the "
                    "target's scan configuration.",
                )

        submission = str(cfg["token_submission"]).lower()
        if submission == "cookie" and not cfg.get("token_cookie"):
            return self._error_result(
                context, "token_submission 'cookie' requires 'token_cookie' (the cookie name)."
            )
        if submission not in {"cookie", "header"}:
            return self._error_result(
                context, "token_submission must be 'cookie' or 'header'."
            )

        session_url = urljoin(f"{origin}/", str(cfg["session_check_path"]).lstrip("/"))
        if not self._same_origin(session_url, parsed):
            return self._error_result(
                context, "The session-check endpoint must share the authorized target's origin."
            )
        method = str(cfg["session_check_method"]).upper()
        marker_path = str(cfg["session_marker_json_path"])

        try:
            async with AsyncExitStack() as stack:
                client = await stack.enter_async_context(self._new_client(cfg))
                anonymous = await stack.enter_async_context(self._new_client(cfg, bare=True))

                token = await self._obtain_token(client, origin, cfg)
                header, payload, signature = parse_jwt(token)
                structural = self._describe(header, payload)

                genuine_status, genuine_marker = await self._session_marker(
                    anonymous, session_url, method, cfg, token, marker_path
                )
                unauth_status, unauth_marker = await self._session_marker(
                    anonymous, session_url, method, cfg, None, marker_path
                )
                garbage = f"{b64url_encode(b'{}')}.{b64url_encode(b'{}')}.{secrets.token_hex(8)}"
                _, garbage_marker = await self._session_marker(
                    anonymous, session_url, method, cfg, garbage, marker_path
                )

                oracle_valid = (
                    genuine_marker is not None
                    and genuine_marker != unauth_marker
                    and garbage_marker == unauth_marker
                )

                forgeries: list[ForgeryProbe] = []
                if oracle_valid:
                    forgeries = await self._run_forgeries(
                        anonymous,
                        session_url,
                        method,
                        cfg,
                        header,
                        payload,
                        signature,
                        marker_path,
                        unauth_marker,
                    )

            decision = classify(oracle_valid, forgeries, structural)
            return self._result(
                decision=decision,
                structural=structural,
                header=header,
                payload=payload,
                forgeries=forgeries,
                genuine_marker=genuine_marker,
                unauth_marker=unauth_marker,
                oracle_valid=oracle_valid,
                endpoint=session_url,
                source=source,
            )
        except (httpx.HTTPError, DetectorError, ValueError) as exc:
            return self._error_result(context, f"{type(exc).__name__}: {exc}", session_url)

    def _new_client(self, cfg: dict[str, Any], bare: bool = False) -> httpx.AsyncClient:
        return httpx.AsyncClient(
            timeout=cfg["request_timeout"],
            follow_redirects=True,
            cookies={} if bare else dict(cfg.get("cookies", {})),
            headers={} if bare else dict(cfg.get("headers", {})),
        )

    @staticmethod
    def _same_origin(url: str, target: Any) -> bool:
        parsed = urlparse(url)
        return parsed.scheme == target.scheme and parsed.netloc.lower() == target.netloc.lower()

    async def _obtain_token(
        self, client: httpx.AsyncClient, origin: str, cfg: dict[str, Any]
    ) -> str:
        username, password = cfg.get("username"), cfg.get("password")
        if not username or not password:
            raise DetectorError(
                "A laboratory account is required; provide 'username' and 'password'."
            )
        response = await self._login(client, origin, cfg, str(username), str(password))
        if response.status_code >= 400:
            if not cfg.get("register_path"):
                raise DetectorError(
                    f"Login failed with HTTP {response.status_code}. Provide working "
                    "credentials, or a 'register_path' so a synthetic account can be created."
                )
            await self._register(client, origin, cfg, str(username), str(password))
            response = await self._login(client, origin, cfg, str(username), str(password))
            if response.status_code >= 400:
                raise DetectorError(
                    f"Login failed with HTTP {response.status_code} even after registration."
                )

        token_path = cfg.get("token_json_path")
        if token_path:
            try:
                token = get_nested(response.json(), str(token_path))
            except ValueError as exc:
                raise DetectorError("The login response was not valid JSON.") from exc
            if not isinstance(token, str) or not token:
                raise DetectorError(
                    f"The login response did not contain token field '{token_path}'."
                )
            return token

        cookie_name = cfg.get("token_cookie")
        if cookie_name and client.cookies.get(str(cookie_name)):
            return str(client.cookies.get(str(cookie_name)))
        raise DetectorError(
            "No session token was found. Provide 'token_json_path' or 'token_cookie'."
        )

    async def _login(
        self,
        client: httpx.AsyncClient,
        origin: str,
        cfg: dict[str, Any],
        username: str,
        password: str,
    ) -> httpx.Response:
        login_url = urljoin(f"{origin}/", str(cfg["login_path"]).lstrip("/"))
        credentials = {
            str(cfg["login_username_field"]): username,
            str(cfg["login_password_field"]): password,
        }
        if str(cfg["login_request_style"]).lower() == "json":
            return await client.post(login_url, json=credentials)
        return await client.post(login_url, data=credentials)

    async def _register(
        self,
        client: httpx.AsyncClient,
        origin: str,
        cfg: dict[str, Any],
        username: str,
        password: str,
    ) -> None:
        register_url = urljoin(f"{origin}/", str(cfg["register_path"]).lstrip("/"))
        payload: dict[str, Any] = {
            str(cfg.get("register_username_field", cfg["login_username_field"])): username,
            str(cfg.get("register_password_field", cfg["login_password_field"])): password,
        }
        repeat_field = cfg.get("register_password_repeat_field")
        if repeat_field:
            payload[str(repeat_field)] = password
        extra_fields = cfg.get("register_extra_fields")
        if isinstance(extra_fields, dict):
            payload.update(extra_fields)
        if str(cfg["register_request_style"]).lower() == "json":
            response = await client.post(register_url, json=payload)
        else:
            response = await client.post(register_url, data=payload)
        # A 4xx here is tolerated only when the account already exists; the retried
        # login is the real gate on whether provisioning succeeded.
        if response.status_code >= 500:
            raise DetectorError(
                f"Could not provision the synthetic account at {register_url} "
                f"(HTTP {response.status_code})."
            )

    def _describe(self, header: dict[str, Any], payload: dict[str, Any]) -> Structural:
        algorithm = header.get("alg")
        return Structural(
            algorithm=str(algorithm) if algorithm is not None else None,
            token_type=str(header.get("typ")) if header.get("typ") is not None else None,
            has_expiration="exp" in payload,
            issued_unsigned=isinstance(algorithm, str) and algorithm.lower() == "none",
            claim_keys=sorted(payload.keys()),
        )

    async def _session_marker(
        self,
        client: httpx.AsyncClient,
        url: str,
        method: str,
        cfg: dict[str, Any],
        token: str | None,
        marker_path: str,
    ) -> tuple[int, str | None]:
        """Submit one token (or none) and read the identity marker the target returns."""
        headers: dict[str, str] = {}
        if token is not None:
            if str(cfg["token_submission"]).lower() == "cookie":
                headers["Cookie"] = f"{cfg['token_cookie']}={token}"
            else:
                prefix = str(cfg["token_header_prefix"])
                headers[str(cfg["token_header"])] = f"{prefix}{token}"
        response = await client.request(method, url, headers=headers)
        marker: Any = None
        try:
            marker = get_nested(response.json(), marker_path)
        except ValueError:
            marker = None
        return response.status_code, None if marker in (None, "") else str(marker)

    async def _run_forgeries(
        self,
        client: httpx.AsyncClient,
        url: str,
        method: str,
        cfg: dict[str, Any],
        header: dict[str, Any],
        payload: dict[str, Any],
        signature: str,
        marker_path: str,
        unauth_marker: str | None,
    ) -> list[ForgeryProbe]:
        """Submit tokens a correct server must reject, each with a tampered identity."""
        forged_value = f"vulnvista-jwt-{secrets.token_hex(8)}@lab.invalid"
        tamper_path = cfg.get("tamper_claim_path")

        def tampered_payload() -> tuple[dict[str, Any], bool]:
            body = json.loads(json.dumps(payload))
            applied = bool(tamper_path) and set_nested(body, str(tamper_path), forged_value)
            return body, applied

        probes: list[ForgeryProbe] = []

        # 1) Unsigned token: alg 'none' with an empty signature.
        none_header = {**header, "alg": "none"}
        none_payload, none_applied = tampered_payload()
        none_token = f"{encode_segment(none_header)}.{encode_segment(none_payload)}."
        probes.append(
            await self._probe_forgery(
                client, url, method, cfg, marker_path, unauth_marker,
                name="alg_none",
                description="unsigned token with header alg set to 'none'",
                token=none_token,
                forged_value=forged_value if none_applied else None,
            )
        )

        # 2) Invalidated signature: original header/alg, tampered claims, broken signature.
        tampered_body, tampered_applied = tampered_payload()
        broken_signature = self._invalidate_signature(signature)
        invalid_token = (
            f"{encode_segment(header)}.{encode_segment(tampered_body)}.{broken_signature}"
        )
        probes.append(
            await self._probe_forgery(
                client, url, method, cfg, marker_path, unauth_marker,
                name="invalid_signature",
                description="token with tampered claims and an invalidated signature",
                token=invalid_token,
                forged_value=forged_value if tampered_applied else None,
            )
        )
        return probes

    async def _probe_forgery(
        self,
        client: httpx.AsyncClient,
        url: str,
        method: str,
        cfg: dict[str, Any],
        marker_path: str,
        unauth_marker: str | None,
        name: str,
        description: str,
        token: str,
        forged_value: str | None,
    ) -> ForgeryProbe:
        status, marker = await self._session_marker(client, url, method, cfg, token, marker_path)
        echoed = forged_value is not None and marker == forged_value
        # Accepted = the target treated the forged token as an authenticated session:
        # it echoed our tampered identity, or returned an authenticated marker that a
        # correct (rejecting) server would not have produced for an anonymous caller.
        accepted = echoed or (marker is not None and marker != unauth_marker)
        return ForgeryProbe(
            name=name,
            description=description,
            accepted=accepted,
            echoed=echoed,
            status_code=status,
            marker=marker,
        )

    @staticmethod
    def _invalidate_signature(signature: str) -> str:
        """Return a signature guaranteed not to match the tampered payload."""
        try:
            raw = bytearray(b64url_decode(signature))
        except binascii.Error:
            raw = bytearray()
        if raw:
            raw[0] ^= 0xFF
            return b64url_encode(bytes(raw))
        return b64url_encode(secrets.token_bytes(32))

    def _result(
        self,
        decision: Decision,
        structural: Structural,
        header: dict[str, Any],
        payload: dict[str, Any],
        forgeries: list[ForgeryProbe],
        genuine_marker: str | None,
        unauth_marker: str | None,
        oracle_valid: bool,
        endpoint: str,
        source: str | None,
    ) -> DetectorResult:
        return DetectorResult(
            detector=self.detector_id,
            vulnerability=self.name,
            detected=decision.detected,
            validation_status=decision.validation_status,
            severity=decision.severity,
            confidence=decision.confidence,
            endpoint=endpoint,
            parameter="session_token",
            description=(
                "The application does not verify the integrity or lifetime of its session "
                "tokens: a token that a correct server would reject is accepted as a valid "
                "session, allowing an attacker to forge tokens and impersonate other users."
            ),
            evidence_summary=(
                f"{decision.reason}. Issued algorithm: {structural.algorithm}; "
                f"expiration claim present: {structural.has_expiration}."
            ),
            evidence={
                "issued_token": {
                    "header": redact_claims(header),
                    "algorithm": structural.algorithm,
                    "type": structural.token_type,
                    "has_expiration_claim": structural.has_expiration,
                    "issued_unsigned": structural.issued_unsigned,
                    "claim_keys": structural.claim_keys,
                    "claims": redact_claims(payload),
                    "signature": "***redacted***",
                },
                "oracle": {
                    "valid": oracle_valid,
                    "authenticated_marker_present": genuine_marker is not None,
                    "distinguishes_authenticated_from_anonymous": (
                        genuine_marker != unauth_marker
                    ),
                },
                "forgery_probes": [
                    {
                        "name": probe.name,
                        "description": probe.description,
                        "accepted_as_session": probe.accepted,
                        "tampered_claim_echoed": probe.echoed,
                        "status_code": probe.status_code,
                    }
                    for probe in forgeries
                ],
                "genuine_token_replayed_as_attack": False,
                "sensitive_claims_masked": True,
                "configuration_source": source,
            },
            remediation=(
                "Verify every token server-side before trusting it: enforce a fixed expected "
                "algorithm and reject 'none' and algorithm-confusion attempts; validate the "
                "signature against the correct key on every request; and require and check "
                "'exp' (and 'iat'/'nbf') so tokens expire. Prefer short-lived tokens with "
                "server-side revocation, and never accept identity or role claims from an "
                "unverified token."
            ),
            cwe=decision.cwe,
            cvss_score=decision.cvss_score,
            owasp_category="A07:2021 - Identification and Authentication Failures",
        )

    def _error_result(
        self, context: ScanContext, message: str, endpoint: str | None = None
    ) -> DetectorResult:
        return DetectorResult(
            detector=self.detector_id,
            vulnerability=self.name,
            detected=False,
            validation_status="ERROR",
            severity="INFO",
            confidence="LOW",
            endpoint=endpoint or context.base_url,
            description="Detector could not complete against the target.",
            evidence_summary=f"Scan error: {message}",
            evidence={"error": message},
            cwe="CWE-347",
            owasp_category="A07:2021 - Identification and Authentication Failures",
        )
