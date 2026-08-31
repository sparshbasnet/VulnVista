import httpx
import pytest

from app.scanners import get_detectors_for_profile
from app.scanners.base import ScanContext
from app.scanners.misconfiguration import (
    MisconfigurationDetector,
    Weakness,
    check_cookie_attributes,
    check_security_headers,
    classify,
)


def _weakness(severity: str) -> Weakness:
    return Weakness(
        check="test",
        detail="test weakness",
        severity=severity,
        cwe="CWE-16",
        endpoint="https://example.test",
        evidence={},
    )


def test_classify_uses_strongest_observed_weakness() -> None:
    decision = classify([_weakness("LOW"), _weakness("HIGH"), _weakness("MEDIUM")])
    assert decision.detected is True
    assert decision.validation_status == "CONFIRMED"
    assert decision.confidence == "HIGH"
    assert decision.severity == "HIGH"


def test_classify_empty_observation_is_not_detected() -> None:
    decision = classify([])
    assert decision.detected is False
    assert decision.validation_status == "NOT_DETECTED"
    assert decision.severity == "INFO"


def test_security_headers_reports_missing_controls_at_medium() -> None:
    weaknesses = check_security_headers(httpx.Headers({}), "https", "https://example.test")
    header_finding = next(item for item in weaknesses if item.check == "security_headers")
    assert header_finding.severity == "MEDIUM"
    assert "Strict-Transport-Security" in header_finding.evidence["missing_headers"]


def test_security_headers_accepts_csp_frame_ancestors() -> None:
    headers = httpx.Headers(
        {
            "Content-Security-Policy": "default-src 'self'; frame-ancestors 'none'",
            "X-Content-Type-Options": "nosniff",
            "Referrer-Policy": "strict-origin-when-cross-origin",
            "Strict-Transport-Security": "max-age=31536000",
        }
    )
    assert check_security_headers(headers, "https", "https://example.test") == []


def test_cookie_check_retains_name_but_not_value() -> None:
    weaknesses = check_cookie_attributes(
        ["session_id=super-secret; Path=/; SameSite=Lax"], "https://example.test"
    )
    assert len(weaknesses) == 1
    assert weaknesses[0].severity == "MEDIUM"
    assert weaknesses[0].evidence["cookie_name"] == "session_id"
    assert "super-secret" not in str(weaknesses[0].evidence)
    assert weaknesses[0].evidence["missing_attributes"] == ["Secure", "HttpOnly"]


def test_profile_resolves_to_misconfiguration_detector() -> None:
    detectors = get_detectors_for_profile("misconfiguration")
    assert [detector.detector_id for detector in detectors] == ["misconfiguration"]


def _mock_client(monkeypatch: pytest.MonkeyPatch, handler) -> None:
    real_init = httpx.AsyncClient.__init__

    def patched_init(self: httpx.AsyncClient, *args, **kwargs):
        kwargs["transport"] = httpx.MockTransport(handler)
        real_init(self, *args, **kwargs)

    monkeypatch.setattr(httpx.AsyncClient, "__init__", patched_init)


async def test_detector_records_each_directly_observed_weakness(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/":
            return httpx.Response(
                200,
                headers={
                    "Server": "Apache/2.4.49",
                    "Set-Cookie": "session_id=abc; Path=/; SameSite=Lax",
                },
                text="application home",
            )
        if request.url.path == "/uploads/":
            return httpx.Response(200, text="<title>Index of /uploads/</title>")
        if request.url.path == "/internal/diagnostics":
            return httpx.Response(200, text='{"propertySources": []}')
        return httpx.Response(404, text="not found")

    _mock_client(monkeypatch, handler)
    result = await MisconfigurationDetector().check(
        ScanContext(
            target_id="t1",
            base_url="http://example.test",
            extra={
                "directory_paths": ["/uploads/"],
                "diagnostic_paths": ["/internal/diagnostics"],
            },
        )
    )

    assert result.validation_status == "CONFIRMED"
    assert result.severity == "HIGH"
    checks = {item["check"] for item in result.evidence["weaknesses"]}
    assert checks == {
        "security_headers",
        "version_disclosure",
        "cookie_attributes",
        "directory_listing",
        "exposed_service",
    }
    assert result.evidence["request_methods"] == ["GET"]
    assert "abc" not in str(result.evidence)


async def test_hardened_target_is_not_detected(monkeypatch: pytest.MonkeyPatch) -> None:
    secure_headers = {
        "Content-Security-Policy": "default-src 'self'; frame-ancestors 'none'",
        "X-Content-Type-Options": "nosniff",
        "Referrer-Policy": "strict-origin-when-cross-origin",
        "Strict-Transport-Security": "max-age=31536000",
        "Set-Cookie": "session_id=abc; Secure; HttpOnly; SameSite=Lax",
    }

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/":
            return httpx.Response(200, headers=secure_headers, text="application home")
        return httpx.Response(404, text="not found")

    _mock_client(monkeypatch, handler)
    result = await MisconfigurationDetector().check(
        ScanContext(
            target_id="t1",
            base_url="https://example.test",
            extra={"directory_paths": [], "diagnostic_paths": []},
        )
    )

    assert result.detected is False
    assert result.validation_status == "NOT_DETECTED"
    assert result.evidence["weakness_count"] == 0


async def test_verbose_error_baseline_is_reported_without_full_body(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/":
            return httpx.Response(
                200,
                headers={
                    "Content-Security-Policy": "frame-ancestors 'none'",
                    "X-Content-Type-Options": "nosniff",
                    "Referrer-Policy": "no-referrer",
                },
                text="home",
            )
        return httpx.Response(
            500,
            text="private-prefix " + "Traceback (most recent call last)" + " private-suffix",
        )

    _mock_client(monkeypatch, handler)
    result = await MisconfigurationDetector().check(
        ScanContext(
            target_id="t1",
            base_url="http://example.test",
            extra={"directory_paths": [], "diagnostic_paths": []},
        )
    )

    error = next(
        item
        for item in result.evidence["weaknesses"]
        if item["check"] == "error_information_leakage"
    )
    assert error["evidence"]["matched_signature"] == "traceback (most recent call last)"
    assert "response_snippet" in error["evidence"]


async def test_invalid_target_returns_actionable_error() -> None:
    result = await MisconfigurationDetector().check(
        ScanContext(target_id="t1", base_url="example.test")
    )
    assert result.validation_status == "ERROR"
    assert "absolute HTTP(S) URL" in result.evidence_summary
