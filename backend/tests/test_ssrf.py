import asyncio
from urllib.parse import parse_qs

import httpx
import pytest

import app.scanners.ssrf as ssrf_module
from app.scanners import get_detectors_for_profile
from app.scanners.base import ScanContext
from app.scanners.ssrf import CallbackObservation, SSRFDetector, classify, get_nested


def test_classify_requires_callback_for_confirmation() -> None:
    confirmed = classify(True)
    absent = classify(False)
    assert confirmed.detected is True
    assert confirmed.validation_status == "CONFIRMED"
    assert confirmed.confidence == "HIGH"
    assert confirmed.severity == "HIGH"
    assert absent.detected is False
    assert absent.validation_status == "NOT_DETECTED"


def test_get_nested_reads_token_and_handles_missing_fields() -> None:
    payload = {"authentication": {"token": "token-1"}}
    assert get_nested(payload, "authentication.token") == "token-1"
    assert get_nested(payload, "authentication.missing") is None
    assert get_nested([], "authentication.token") is None


def test_profile_resolves_to_ssrf_detector() -> None:
    detectors = get_detectors_for_profile("ssrf")
    assert [detector.detector_id for detector in detectors] == ["ssrf"]


def _mock_client(monkeypatch: pytest.MonkeyPatch, handler) -> None:
    real_init = httpx.AsyncClient.__init__

    def patched_init(self: httpx.AsyncClient, *args, **kwargs):
        kwargs["transport"] = httpx.MockTransport(handler)
        real_init(self, *args, **kwargs)

    monkeypatch.setattr(httpx.AsyncClient, "__init__", patched_init)


class FakeCallbackServer:
    instances: list["FakeCallbackServer"] = []

    def __init__(self, expected_path: str) -> None:
        self.expected_path = expected_path
        self.observation = CallbackObservation()
        self.hit_event = asyncio.Event()
        self.port = 43210
        self.instances.append(self)

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc_info: object) -> None:
        return None

    def record_hit(self) -> None:
        self.observation = CallbackObservation(
            hit=True,
            method="GET",
            path=self.expected_path,
            source_ip="172.20.0.8",
            user_agent="node",
        )
        self.hit_event.set()


async def test_juice_shop_preset_confirms_callback_and_restores_profile(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    FakeCallbackServer.instances.clear()
    monkeypatch.setattr(ssrf_module, "_CallbackServer", FakeCallbackServer)
    submitted_values: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/rest/user/login":
            assert request.method == "POST"
            assert request.read() == b'{"email":"admin@juice-sh.op","password":"admin123"}'
            return httpx.Response(200, json={"authentication": {"token": "lab-token"}})
        if request.url.path == "/rest/user/whoami":
            assert request.headers["cookie"] == "token=lab-token"
            return httpx.Response(
                200,
                json={"user": {"profileImage": "assets/public/images/defaultAdmin.png"}},
            )
        if request.url.path == "/profile/image/url":
            assert request.headers["cookie"] == "token=lab-token"
            value = parse_qs(request.read().decode())["imageUrl"][0]
            submitted_values.append(value)
            if value.startswith("http://backend:43210/"):
                FakeCallbackServer.instances[-1].record_hit()
            return httpx.Response(200)
        return httpx.Response(404)

    _mock_client(monkeypatch, handler)
    result = await SSRFDetector().check(
        ScanContext(target_id="t1", base_url="http://juice-shop:3000")
    )

    assert result.detected is True
    assert result.validation_status == "CONFIRMED"
    assert result.severity == "HIGH"
    assert result.parameter == "imageUrl"
    assert result.cwe == "CWE-918"
    assert result.evidence["callback_received"] is True
    assert result.evidence["callback"]["source_ip"] == "172.20.0.8"
    assert result.evidence["callback"]["path"] == result.evidence["expected_callback_path"]
    assert result.evidence["private_or_metadata_endpoint_requested"] is False
    assert result.evidence["restoration_attempted"] is True
    assert result.evidence["restoration_request_succeeded"] is True
    assert submitted_values[-1] == "assets/public/images/defaultAdmin.png"


async def test_no_callback_is_not_detected(monkeypatch: pytest.MonkeyPatch) -> None:
    FakeCallbackServer.instances.clear()
    monkeypatch.setattr(ssrf_module, "_CallbackServer", FakeCallbackServer)

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/fetch"
        assert request.method == "POST"
        assert request.read().startswith(b'{"target":"http://backend:43210/')
        return httpx.Response(202)

    _mock_client(monkeypatch, handler)
    result = await SSRFDetector().check(
        ScanContext(
            target_id="t1",
            base_url="https://example.test",
            extra={
                "ssrf_endpoint": "/fetch",
                "parameter": "target",
                "request_style": "json",
                "callback_wait_seconds": 0.01,
            },
        )
    )

    assert result.detected is False
    assert result.validation_status == "NOT_DETECTED"
    assert result.evidence["callback_received"] is False


async def test_query_style_supports_full_endpoint_url(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    FakeCallbackServer.instances.clear()
    monkeypatch.setattr(ssrf_module, "_CallbackServer", FakeCallbackServer)

    def handler(request: httpx.Request) -> httpx.Response:
        assert str(request.url).startswith("https://example.test/proxy?")
        assert request.url.params["url"].startswith("http://backend:43210/")
        FakeCallbackServer.instances[-1].record_hit()
        return httpx.Response(200)

    _mock_client(monkeypatch, handler)
    result = await SSRFDetector().check(
        ScanContext(
            target_id="t1",
            base_url="https://example.test",
            extra={
                "ssrf_endpoint": "https://example.test/proxy",
                "request_method": "GET",
                "request_style": "query",
            },
        )
    )

    assert result.validation_status == "CONFIRMED"
    assert result.endpoint == "https://example.test/proxy"


async def test_cross_origin_endpoint_is_rejected() -> None:
    result = await SSRFDetector().check(
        ScanContext(
            target_id="t1",
            base_url="https://example.test",
            extra={"ssrf_endpoint": "https://other.test/fetch"},
        )
    )
    assert result.validation_status == "ERROR"
    assert "same origin" in result.evidence_summary


async def test_arbitrary_callback_host_is_rejected() -> None:
    result = await SSRFDetector().check(
        ScanContext(
            target_id="t1",
            base_url="https://example.test",
            extra={"ssrf_endpoint": "/fetch", "callback_host": "169.254.169.254"},
        )
    )
    assert result.validation_status == "ERROR"
    assert "VulnVista backend service alias" in result.evidence_summary


async def test_missing_endpoint_returns_actionable_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    result = await SSRFDetector().check(
        ScanContext(target_id="t1", base_url="https://example.test")
    )
    assert result.validation_status == "ERROR"
    assert "ssrf_endpoint" in result.evidence_summary


async def test_authentication_failure_is_error(monkeypatch: pytest.MonkeyPatch) -> None:
    FakeCallbackServer.instances.clear()
    monkeypatch.setattr(ssrf_module, "_CallbackServer", FakeCallbackServer)

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(401)

    _mock_client(monkeypatch, handler)
    result = await SSRFDetector().check(
        ScanContext(target_id="t1", base_url="http://juice-shop:3000")
    )
    assert result.validation_status == "ERROR"
    assert "Login failed with HTTP 401" in result.evidence_summary


async def test_unsupported_mutating_method_is_rejected(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    FakeCallbackServer.instances.clear()
    monkeypatch.setattr(ssrf_module, "_CallbackServer", FakeCallbackServer)

    def handler(request: httpx.Request) -> httpx.Response:
        pytest.fail("unsupported method must be rejected before an HTTP request")

    _mock_client(monkeypatch, handler)
    result = await SSRFDetector().check(
        ScanContext(
            target_id="t1",
            base_url="https://example.test",
            extra={"ssrf_endpoint": "/fetch", "request_method": "DELETE"},
        )
    )
    assert result.validation_status == "ERROR"
    assert "must be GET or POST" in result.evidence_summary


async def test_invalid_target_returns_actionable_error() -> None:
    result = await SSRFDetector().check(ScanContext(target_id="t1", base_url="example.test"))
    assert result.validation_status == "ERROR"
    assert "absolute HTTP(S) URL" in result.evidence_summary
