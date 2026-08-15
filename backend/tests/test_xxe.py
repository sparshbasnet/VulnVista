import asyncio
import re
from urllib.parse import urlparse

import httpx
import pytest

from app.scanners import get_detectors_for_profile
from app.scanners.base import ScanContext
from app.scanners.xxe import XXEDetector, build_payload, classify


def test_build_payload_embeds_callback_url_as_system_entity() -> None:
    payload = build_payload("http://backend:12345/abc123")
    assert '<!ENTITY xxe SYSTEM "http://backend:12345/abc123">' in payload
    assert "&xxe;" in payload


def test_classify_oob_hit_is_confirmed_high() -> None:
    decision = classify(oob_hit=True, in_band_reflected=False)
    assert decision.detected is True
    assert decision.validation_status == "CONFIRMED"
    assert decision.confidence == "HIGH"


def test_classify_in_band_reflected_is_confirmed_high() -> None:
    decision = classify(oob_hit=False, in_band_reflected=True)
    assert decision.detected is True
    assert decision.validation_status == "CONFIRMED"
    assert decision.confidence == "HIGH"


def test_classify_both_signals_is_confirmed_high() -> None:
    decision = classify(oob_hit=True, in_band_reflected=True)
    assert decision.detected is True
    assert decision.validation_status == "CONFIRMED"
    assert decision.confidence == "HIGH"


def test_classify_no_signal_is_not_detected() -> None:
    decision = classify(oob_hit=False, in_band_reflected=False)
    assert decision.detected is False
    assert decision.validation_status == "NOT_DETECTED"
    assert decision.confidence == "LOW"


def test_profile_resolves_to_xxe_detector() -> None:
    detectors = get_detectors_for_profile("xxe")
    assert [d.detector_id for d in detectors] == ["xxe"]


def _mock_client(monkeypatch: pytest.MonkeyPatch, handler) -> None:
    real_init = httpx.AsyncClient.__init__

    def patched_init(self: httpx.AsyncClient, *args, **kwargs):
        kwargs["transport"] = httpx.MockTransport(handler)
        real_init(self, *args, **kwargs)

    monkeypatch.setattr(httpx.AsyncClient, "__init__", patched_init)


_SYSTEM_URL_RE = re.compile(r'SYSTEM "([^"]+)"')
# Keeps fire-and-forget "simulated vulnerable parser" tasks alive until they
# complete — nothing else in the test holds a reference to them.
_background_tasks: set[asyncio.Task] = set()


async def _fetch_via_raw_socket(url: str) -> bytes:
    """Simulate a vulnerable XML parser resolving the external entity: a
    plain asyncio TCP client, deliberately not httpx, so it isn't affected by
    the httpx.AsyncClient monkeypatch used to mock the "target" side."""
    parsed = urlparse(url)
    reader, writer = await asyncio.open_connection(parsed.hostname, parsed.port)
    request = (
        f"GET {parsed.path or '/'} HTTP/1.1\r\n"
        f"Host: {parsed.hostname}\r\nConnection: close\r\n\r\n"
    )
    writer.write(request.encode())
    await writer.drain()
    body = await reader.read()
    writer.close()
    await writer.wait_closed()
    return body


async def test_check_confirms_oob_hit_on_generic_raw_endpoint(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        body = request.read().decode()
        match = _SYSTEM_URL_RE.search(body)
        assert match is not None
        if match.group(1).startswith("http://"):
            _background_tasks.add(asyncio.ensure_future(_fetch_via_raw_socket(match.group(1))))
        return httpx.Response(200, text="<result>accepted</result>")

    _mock_client(monkeypatch, handler)
    result = await XXEDetector().check(
        ScanContext(
            target_id="t1",
            base_url="https://example.test",
            extra={
                "xml_endpoint": "/api/import",
                "request_style": "raw",
                "oob_wait_seconds": 2.0,
                "callback_host": "127.0.0.1",
                "local_file_path": None,
            },
        )
    )

    assert result.validation_status == "CONFIRMED"
    assert result.confidence == "HIGH"
    assert result.evidence["oob_hit"] is True
    assert result.evidence["request_style"] == "raw"
    assert result.evidence["endpoint_discovery"] == "explicit configuration"


async def test_check_confirms_local_file_fingerprint_reflected(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Mirrors what Juice Shop's real libxmljs2-based parser actually does:
    it never makes a network call for an http:// SYSTEM identifier, but it
    does resolve file:// ones and echo the parsed document (with the entity
    substituted) back in an error message."""

    def handler(request: httpx.Request) -> httpx.Response:
        body = request.read().decode()
        match = _SYSTEM_URL_RE.search(body)
        assert match is not None
        if match.group(1).startswith("file://"):
            return httpx.Response(
                410, text='Error: deprecated: <foo>PRETTY_NAME="Debian GNU/Linux"</foo>'
            )
        return httpx.Response(410, text="Error: deprecated: failed to load: No such file")

    _mock_client(monkeypatch, handler)
    result = await XXEDetector().check(
        ScanContext(
            target_id="t1",
            base_url="https://example.test",
            extra={
                "xml_endpoint": "/api/import",
                "request_style": "raw",
                "oob_wait_seconds": 0.1,
                "callback_host": "127.0.0.1",
            },
        )
    )

    assert result.validation_status == "CONFIRMED"
    assert result.evidence["oob_hit"] is False
    assert result.evidence["local_file_reflected"] is True
    assert result.evidence["in_band_reflected"] is True


async def test_check_not_detected_when_entity_is_never_resolved(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(400, text="<error>malformed document</error>")

    _mock_client(monkeypatch, handler)
    result = await XXEDetector().check(
        ScanContext(
            target_id="t1",
            base_url="https://example.test",
            extra={
                "xml_endpoint": "/api/import",
                "request_style": "raw",
                "oob_wait_seconds": 0.1,
            },
        )
    )

    assert result.validation_status == "NOT_DETECTED"
    assert result.evidence["oob_hit"] is False
    assert result.evidence["local_file_reflected"] is False
    assert result.evidence["in_band_reflected"] is False


async def test_check_uses_juice_shop_lab_preset_multipart_upload(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/file-upload"
        body = request.read().decode(errors="ignore")
        match = _SYSTEM_URL_RE.search(body)
        assert match is not None
        if match.group(1).startswith("file://"):
            return httpx.Response(
                410, text='deprecated: <foo>PRETTY_NAME="Distroless"</foo> (probe.xml)'
            )
        return httpx.Response(410, text="deprecated: failed to load: No such file (probe.xml)")

    _mock_client(monkeypatch, handler)
    result = await XXEDetector().check(
        ScanContext(
            target_id="t1",
            base_url="http://juice-shop:3000",
            extra={"oob_wait_seconds": 0.1},
        )
    )

    assert result.validation_status == "CONFIRMED"
    assert result.evidence["endpoint_discovery"] == "lab preset"
    assert result.evidence["request_style"] == "multipart"
    assert result.evidence["local_file_reflected"] is True


async def test_check_errors_without_xml_endpoint_or_preset(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(404)

    _mock_client(monkeypatch, handler)
    result = await XXEDetector().check(
        ScanContext(target_id="t1", base_url="https://unknown-target.test", extra={})
    )

    assert result.validation_status == "ERROR"
    assert "No XML-accepting endpoint" in result.evidence_summary


async def test_check_errors_on_404_endpoint(monkeypatch: pytest.MonkeyPatch) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(404)

    _mock_client(monkeypatch, handler)
    result = await XXEDetector().check(
        ScanContext(
            target_id="t1",
            base_url="https://example.test",
            extra={"xml_endpoint": "/no/such/path", "request_style": "raw"},
        )
    )

    assert result.validation_status == "ERROR"
    assert "404" in result.evidence_summary
