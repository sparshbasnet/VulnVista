import httpx

from app.scanners import get_detectors_for_profile
from app.scanners.base import ScanContext
from app.scanners.misconfiguration import (
    PROBE_ORIGIN,
    MisconfigurationDetector,
    classify_cors,
    classify_headers,
)


class FakeAsyncClient:
    def __init__(self, responses: list[httpx.Response | Exception], **kwargs):
        self.responses = iter(responses)

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return None

    async def _next(self):
        response = next(self.responses)
        if isinstance(response, Exception):
            raise response
        return response

    async def get(self, url: str):
        return await self._next()

    async def options(self, url: str, headers: dict[str, str]):
        return await self._next()


def test_hardened_https_headers_have_no_issue() -> None:
    headers = httpx.Headers(
        {
            "Content-Security-Policy": "default-src 'self'",
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
            "Referrer-Policy": "no-referrer",
            "Strict-Transport-Security": "max-age=31536000",
            "Server": "application",
        }
    )

    assert classify_headers(headers, is_https=True) == []


def test_missing_headers_and_version_disclosure_are_detected() -> None:
    issues = classify_headers(httpx.Headers({"Server": "nginx/1.25.4"}), is_https=True)
    codes = {issue["code"] for issue in issues}

    assert "missing_security_header" in codes
    assert "missing_hsts" in codes
    assert "version_disclosure" in codes


def test_reflected_credentialed_cors_is_high_severity() -> None:
    issues = classify_cors(
        httpx.Headers(
            {
                "Access-Control-Allow-Origin": PROBE_ORIGIN,
                "Access-Control-Allow-Credentials": "true",
            }
        )
    )

    assert issues == [
        {
            "code": "credentialed_origin_reflection",
            "severity": "HIGH",
            "detail": PROBE_ORIGIN,
        }
    ]


def test_profile_resolves_to_misconfiguration_detector() -> None:
    detectors = get_detectors_for_profile("misconfiguration")
    assert [detector.detector_id for detector in detectors] == ["misconfiguration"]


async def test_detector_combines_header_and_cors_evidence(monkeypatch) -> None:
    get_response = httpx.Response(
        200,
        headers={"Server": "Express/4.0"},
        request=httpx.Request("GET", "https://test.local"),
    )
    options_response = httpx.Response(
        204,
        headers={
            "Access-Control-Allow-Origin": PROBE_ORIGIN,
            "Access-Control-Allow-Credentials": "true",
        },
        request=httpx.Request("OPTIONS", "https://test.local"),
    )
    monkeypatch.setattr(
        "app.scanners.misconfiguration.httpx.AsyncClient",
        lambda **kwargs: FakeAsyncClient([get_response, options_response], **kwargs),
    )

    result = await MisconfigurationDetector().check(
        ScanContext(target_id="test-target", base_url="https://test.local")
    )

    assert result.detected is True
    assert result.validation_status == "CONFIRMED"
    assert result.severity == "HIGH"
    assert result.evidence["probe_origin"] == PROBE_ORIGIN


async def test_detector_returns_controlled_error(monkeypatch) -> None:
    request = httpx.Request("GET", "https://test.local")
    monkeypatch.setattr(
        "app.scanners.misconfiguration.httpx.AsyncClient",
        lambda **kwargs: FakeAsyncClient(
            [httpx.ConnectError("connection failed", request=request)], **kwargs
        ),
    )

    result = await MisconfigurationDetector().check(
        ScanContext(target_id="test-target", base_url="https://test.local")
    )

    assert result.detected is False
    assert result.validation_status == "ERROR"
