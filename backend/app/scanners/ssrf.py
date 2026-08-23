"""Controlled out-of-band detector for Server-Side Request Forgery (SSRF).

The only positive signal is a request received by a local callback listener at
a unique, unguessable path supplied exclusively to the target. This proves the
application server fetched attacker-controlled input without requesting cloud
metadata, loopback services, or any third-party system. The callback returns a
404 with an empty body so URL-import features do not persist callback content.

The bundled Juice Shop preset authenticates with its documented lab account,
uses the profile-image URL importer, and restores the user's original image
setting afterward. Other authorized applications can provide an explicit
endpoint, request style, parameter, authentication cookie/header, and optional
login configuration through ScanContext.extra.
"""

from __future__ import annotations

import asyncio
import secrets
from dataclasses import dataclass
from typing import Any
from urllib.parse import urljoin, urlparse

import httpx

from app.scanners.base import BaseDetector, DetectorResult, ScanContext

GENERIC_DEFAULTS: dict[str, Any] = {
    "request_timeout": 15.0,
    "callback_wait_seconds": 5.0,
    "callback_host": "backend",
    "request_method": "POST",
    "request_style": "form",
    "parameter": "url",
}

LAB_PRESETS: dict[str, dict[str, Any]] = {
    "juice-shop": {
        "ssrf_endpoint": "/profile/image/url",
        "parameter": "imageUrl",
        "request_method": "POST",
        "request_style": "form",
        "login_path": "/rest/user/login",
        "login_username_field": "email",
        "login_password_field": "password",
        "username": "admin@juice-sh.op",
        "password": "admin123",
        "login_request_style": "json",
        "token_json_path": "authentication.token",
        "token_cookie": "token",
        "profile_path": "/rest/user/whoami",
        "profile_json_path": "user.profileImage",
        "restore_parameter": "imageUrl",
    }
}
LAB_PRESETS["vulnvista_juice_shop"] = LAB_PRESETS["juice-shop"]

ALLOWED_CALLBACK_HOSTS = {"backend", "vulnvista_backend"}


class DetectorError(Exception):
    """Expected, actionable detector failure shown directly to the operator."""


@dataclass
class CallbackObservation:
    hit: bool = False
    method: str | None = None
    path: str | None = None
    source_ip: str | None = None
    user_agent: str | None = None


@dataclass
class Decision:
    detected: bool
    validation_status: str
    confidence: str
    severity: str
    reason: str


def classify(callback_hit: bool) -> Decision:
    """Convert the attributable callback signal to the shared verdict."""
    if callback_hit:
        return Decision(
            detected=True,
            validation_status="CONFIRMED",
            confidence="HIGH",
            severity="HIGH",
            reason=(
                "the controlled callback received a request at the unique path "
                "that was supplied only to the target"
            ),
        )
    return Decision(
        detected=False,
        validation_status="NOT_DETECTED",
        confidence="LOW",
        severity="INFO",
        reason="the controlled callback did not receive the unique request",
    )


def get_nested(mapping: Any, dotted_path: str) -> Any:
    """Safely retrieve a dotted field from JSON-like dictionaries."""
    current = mapping
    for key in dotted_path.split("."):
        if not isinstance(current, dict) or key not in current:
            return None
        current = current[key]
    return current


class _CallbackServer:
    """Minimal HTTP listener that records only the detector's unique path."""

    def __init__(self, expected_path: str) -> None:
        self.expected_path = expected_path
        self.observation = CallbackObservation()
        self.hit_event = asyncio.Event()
        self._server: asyncio.Server | None = None

    async def __aenter__(self) -> _CallbackServer:
        try:
            self._server = await asyncio.start_server(self._handle, host="0.0.0.0", port=0)
        except OSError as exc:
            raise DetectorError(f"Could not start the local SSRF callback listener: {exc}") from exc
        return self

    async def __aexit__(self, *exc_info: object) -> None:
        if self._server is not None:
            self._server.close()
            await self._server.wait_closed()

    @property
    def port(self) -> int:
        assert self._server is not None and self._server.sockets
        return self._server.sockets[0].getsockname()[1]

    async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            request_line = (await asyncio.wait_for(reader.readline(), timeout=5.0)).decode(
                "latin-1", errors="replace"
            )
            parts = request_line.strip().split()
            method = parts[0] if len(parts) >= 1 else ""
            path = parts[1].split("?", 1)[0] if len(parts) >= 2 else ""
            headers: dict[str, str] = {}
            while True:
                line = await asyncio.wait_for(reader.readline(), timeout=2.0)
                if not line or line in (b"\r\n", b"\n"):
                    break
                name, separator, value = line.decode("latin-1", errors="replace").partition(":")
                if separator:
                    headers[name.strip().lower()] = value.strip()

            if path == self.expected_path:
                peer = writer.get_extra_info("peername")
                self.observation = CallbackObservation(
                    hit=True,
                    method=method,
                    path=path,
                    source_ip=str(peer[0]) if peer else None,
                    user_agent=headers.get("user-agent"),
                )
                self.hit_event.set()

            writer.write(
                b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
            )
            await writer.drain()
        except (TimeoutError, ConnectionError):
            pass
        finally:
            writer.close()


class SSRFDetector(BaseDetector):
    detector_id = "ssrf"
    name = "Server-Side Request Forgery (SSRF)"
    vulnerability_type = "ssrf"
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
            if "ssrf_endpoint" in context.extra
            else "lab preset"
            if host in LAB_PRESETS
            else None
        )
        if not cfg.get("ssrf_endpoint"):
            return self._error_result(
                context,
                "No server-side URL-fetching endpoint is known for this target. Provide "
                "'ssrf_endpoint', 'parameter', and 'request_style' ('form', 'json', or "
                "'query') in the target's scan configuration.",
            )

        raw_endpoint = str(cfg["ssrf_endpoint"])
        endpoint = (
            raw_endpoint
            if urlparse(raw_endpoint).scheme in {"http", "https"}
            else urljoin(f"{origin}/", raw_endpoint.lstrip("/"))
        )
        endpoint_parsed = urlparse(endpoint)
        if (
            endpoint_parsed.scheme != parsed.scheme
            or endpoint_parsed.netloc.lower() != parsed.netloc.lower()
        ):
            return self._error_result(
                context,
                "The SSRF endpoint must use the same origin as the authorized target.",
                endpoint,
            )
        callback_host = str(cfg["callback_host"]).lower().strip()
        if callback_host not in ALLOWED_CALLBACK_HOSTS:
            return self._error_result(
                context,
                "callback_host must be a VulnVista backend service alias "
                f"({', '.join(sorted(ALLOWED_CALLBACK_HOSTS))}).",
                endpoint,
            )
        callback_path = f"/vulnvista-ssrf-{secrets.token_hex(12)}.jpg"
        submission_status: int | None = None
        original_value: str | None = None
        restoration_attempted = False
        restoration_succeeded = False

        try:
            async with httpx.AsyncClient(
                timeout=cfg["request_timeout"],
                follow_redirects=True,
                cookies=cfg.get("cookies", {}),
                headers=cfg.get("headers", {}),
            ) as client:
                if cfg.get("login_path"):
                    await self._authenticate(client, origin, cfg)
                if cfg.get("profile_path") and cfg.get("profile_json_path"):
                    original_value = await self._read_profile_value(client, origin, cfg)

                async with _CallbackServer(callback_path) as callback:
                    callback_url = f"http://{callback_host}:{callback.port}{callback_path}"
                    response = await self._submit(client, endpoint, callback_url, cfg)
                    submission_status = response.status_code
                    if response.status_code == 404:
                        raise DetectorError(
                            f"{endpoint} returned 404 Not Found; verify 'ssrf_endpoint'."
                        )
                    if response.status_code in {401, 403}:
                        raise DetectorError(
                            f"{endpoint} rejected the request with HTTP {response.status_code}; "
                            "provide valid cookies, headers, or login configuration."
                        )
                    try:
                        await asyncio.wait_for(
                            callback.hit_event.wait(), timeout=cfg["callback_wait_seconds"]
                        )
                    except TimeoutError:
                        pass
                    observation = callback.observation

                if original_value is not None and self._safe_restore_value(original_value):
                    restoration_attempted = True
                    restore_cfg = {
                        **cfg,
                        "parameter": cfg.get("restore_parameter", cfg["parameter"]),
                    }
                    restore_response = await self._submit(
                        client, endpoint, original_value, restore_cfg
                    )
                    restoration_succeeded = restore_response.status_code < 400

            decision = classify(observation.hit)
            return self._result(
                decision=decision,
                observation=observation,
                endpoint=endpoint,
                callback_path=callback_path,
                submission_status=submission_status,
                source=source,
                restoration_attempted=restoration_attempted,
                restoration_succeeded=restoration_succeeded,
                parameter=str(cfg["parameter"]),
            )
        except (httpx.HTTPError, DetectorError, ValueError) as exc:
            return self._error_result(context, f"{type(exc).__name__}: {exc}", endpoint)

    async def _authenticate(
        self, client: httpx.AsyncClient, origin: str, cfg: dict[str, Any]
    ) -> None:
        if not cfg.get("username") or not cfg.get("password"):
            raise DetectorError("The configured SSRF endpoint requires login credentials.")
        login_url = urljoin(f"{origin}/", str(cfg["login_path"]).lstrip("/"))
        credentials = {
            cfg.get("login_username_field", "username"): cfg["username"],
            cfg.get("login_password_field", "password"): cfg["password"],
        }
        if cfg.get("login_request_style", "form") == "json":
            response = await client.post(login_url, json=credentials)
        else:
            response = await client.post(login_url, data=credentials)
        if response.status_code >= 400:
            raise DetectorError(f"Login failed with HTTP {response.status_code} at {login_url}.")

        token_path = cfg.get("token_json_path")
        if token_path:
            token = get_nested(response.json(), token_path)
            if not isinstance(token, str) or not token:
                raise DetectorError(f"Login response did not contain token field '{token_path}'.")
            if cfg.get("token_cookie"):
                client.cookies.set(str(cfg["token_cookie"]), token)
            elif cfg.get("token_header"):
                client.headers[str(cfg["token_header"])] = f"Bearer {token}"

    async def _read_profile_value(
        self, client: httpx.AsyncClient, origin: str, cfg: dict[str, Any]
    ) -> str | None:
        profile_url = urljoin(f"{origin}/", str(cfg["profile_path"]).lstrip("/"))
        response = await client.get(profile_url)
        if response.status_code >= 400:
            return None
        value = get_nested(response.json(), str(cfg["profile_json_path"]))
        return value if isinstance(value, str) and value else None

    async def _submit(
        self,
        client: httpx.AsyncClient,
        endpoint: str,
        callback_url: str,
        cfg: dict[str, Any],
    ) -> httpx.Response:
        method = str(cfg.get("request_method", "POST")).upper()
        style = str(cfg.get("request_style", "form")).lower()
        parameter = str(cfg.get("parameter", "url"))
        if method not in {"GET", "POST"}:
            raise DetectorError("SSRF request_method must be GET or POST.")
        if style == "query":
            return await client.request(method, endpoint, params={parameter: callback_url})
        if method != "POST":
            raise DetectorError("The 'form' and 'json' request styles require POST.")
        if style == "form":
            return await client.post(endpoint, data={parameter: callback_url})
        if style == "json":
            return await client.post(endpoint, json={parameter: callback_url})
        raise DetectorError("SSRF request_style must be 'form', 'json', or 'query'.")

    @staticmethod
    def _safe_restore_value(value: str) -> bool:
        parsed = urlparse(value)
        return not parsed.scheme and not parsed.netloc

    def _result(
        self,
        decision: Decision,
        observation: CallbackObservation,
        endpoint: str,
        callback_path: str,
        submission_status: int | None,
        source: str | None,
        restoration_attempted: bool,
        restoration_succeeded: bool,
        parameter: str,
    ) -> DetectorResult:
        return DetectorResult(
            detector=self.detector_id,
            vulnerability=self.name,
            detected=decision.detected,
            validation_status=decision.validation_status,
            severity=decision.severity,
            confidence=decision.confidence,
            endpoint=endpoint,
            parameter=parameter,
            description=(
                "The application fetched a URL controlled by the requester from its own "
                "server-side network context, which could allow access to otherwise "
                "unreachable internal services if destination controls are absent."
            ),
            evidence_summary=f"{decision.reason}. Target response: HTTP {submission_status}.",
            evidence={
                "callback_received": observation.hit,
                "callback": {
                    "method": observation.method,
                    "path": observation.path,
                    "source_ip": observation.source_ip,
                    "user_agent": observation.user_agent,
                },
                "expected_callback_path": callback_path,
                "submission_status_code": submission_status,
                "configuration_source": source,
                "callback_owned_by_scanner": True,
                "private_or_metadata_endpoint_requested": False,
                "restoration_attempted": restoration_attempted,
                "restoration_request_succeeded": restoration_succeeded,
            },
            remediation=(
                "Avoid server-side fetching of user-supplied URLs. Where it is required, "
                "allowlist exact schemes, hosts, ports, and paths; resolve and validate DNS "
                "results before every connection and redirect; block loopback, link-local, "
                "private, multicast, and cloud-metadata ranges for IPv4 and IPv6; disable "
                "unnecessary redirects; and enforce outbound network egress controls."
            ),
            cwe="CWE-918",
            cvss_score=8.1 if decision.detected else 0.0,
            owasp_category="A10:2021 - Server-Side Request Forgery (SSRF)",
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
            cwe="CWE-918",
            owasp_category="A10:2021 - Server-Side Request Forgery (SSRF)",
        )
