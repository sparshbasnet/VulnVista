import httpx
import pytest

from app.scanners import get_detectors_for_profile
from app.scanners.base import ScanContext
from app.scanners.sql_injection import (
    TIME_THRESHOLD_MS,
    SQLInjectionDetector,
    _boolean_diff,
    _find_sql_error,
    classify,
)


def test_find_sql_error_detects_signature_absent_from_baseline() -> None:
    signature = _find_sql_error(
        "You have an error in your SQL syntax near ''1''", "Row: Alice"
    )
    assert signature == "you have an error in your sql syntax"


def test_find_sql_error_ignores_signature_already_in_baseline() -> None:
    # the app's own page legitimately mentions "syntax" elsewhere — a real
    # error signature must be new, not merely present.
    assert _find_sql_error("mysql_fetch already appears here", "mysql_fetch already appears here") is None


def test_find_sql_error_no_match() -> None:
    assert _find_sql_error("Row: Alice", "Row: Alice") is None


def test_boolean_diff_true_when_true_matches_baseline_and_false_differs() -> None:
    assert _boolean_diff("Product: Widget", "Product: Widget", "No product found") is True


def test_boolean_diff_false_when_all_identical() -> None:
    assert _boolean_diff("Row: Alice", "Row: Alice", "Row: Alice") is False


def test_boolean_diff_false_when_true_does_not_match_baseline() -> None:
    # true condition should reproduce baseline; if it doesn't, the false/true
    # split isn't trustworthy evidence of query control.
    assert _boolean_diff("Row: Alice", "Something else entirely", "Row: Alice") is False


def test_classify_error_signature_alone_is_confirmed_high() -> None:
    decision = classify(error_signature="sqlstate[", boolean_diff=False, time_delta_ms=0)
    assert decision.detected is True
    assert decision.validation_status == "CONFIRMED"
    assert decision.confidence == "HIGH"


def test_classify_boolean_and_time_is_confirmed_high() -> None:
    decision = classify(
        error_signature=None,
        boolean_diff=True,
        time_delta_ms=TIME_THRESHOLD_MS + 100,
    )
    assert decision.detected is True
    assert decision.confidence == "HIGH"


def test_classify_boolean_only_is_confirmed_medium() -> None:
    decision = classify(error_signature=None, boolean_diff=True, time_delta_ms=0)
    assert decision.detected is True
    assert decision.confidence == "MEDIUM"


def test_classify_time_only_is_confirmed_medium() -> None:
    decision = classify(
        error_signature=None, boolean_diff=False, time_delta_ms=TIME_THRESHOLD_MS + 100
    )
    assert decision.detected is True
    assert decision.confidence == "MEDIUM"


def test_classify_no_signal_is_not_detected() -> None:
    decision = classify(error_signature=None, boolean_diff=False, time_delta_ms=0)
    assert decision.detected is False
    assert decision.validation_status == "NOT_DETECTED"


def test_profile_resolves_to_sql_injection_detector() -> None:
    detectors = get_detectors_for_profile("sql_injection")
    assert [d.detector_id for d in detectors] == ["sql_injection"]


def _mock_client(monkeypatch: pytest.MonkeyPatch, handler) -> None:
    real_init = httpx.AsyncClient.__init__

    def patched_init(self: httpx.AsyncClient, *args, **kwargs):
        kwargs["transport"] = httpx.MockTransport(handler)
        real_init(self, *args, **kwargs)

    monkeypatch.setattr(httpx.AsyncClient, "__init__", patched_init)


async def test_check_detects_error_based_injection_on_arbitrary_host(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        idv = request.url.params.get("id", "")
        if "'" in idv and "AND" not in idv.upper():
            return httpx.Response(500, text="You have an error in your SQL syntax")
        if "'1'='2" in idv:
            return httpx.Response(200, text="<html>No results</html>")
        return httpx.Response(200, text="<html>Row: Alice</html>")

    _mock_client(monkeypatch, handler)
    result = await SQLInjectionDetector().check(
        ScanContext(target_id="t1", base_url="https://example.test/products?id=1", extra={})
    )

    assert result.validation_status == "CONFIRMED"
    assert result.confidence == "HIGH"
    assert result.evidence["error_signature"] is not None
    assert result.evidence["candidate_source"] == "auto-discovered"
    assert result.parameter == "id"


async def test_check_never_treats_error_status_as_transport_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A 500 response carrying the SQL error is the signal, not a crash —
    the detector must not blow up on a non-2xx probe response."""

    def handler(request: httpx.Request) -> httpx.Response:
        idv = request.url.params.get("id", "")
        if "'" in idv:
            return httpx.Response(500, text="internal server error, no SQL details leaked")
        return httpx.Response(200, text="<html>Row: Alice</html>")

    _mock_client(monkeypatch, handler)
    result = await SQLInjectionDetector().check(
        ScanContext(target_id="t1", base_url="https://example.test/products?id=1", extra={})
    )

    assert result.validation_status == "NOT_DETECTED"
    assert result.evidence["status_codes"]["error"] == 500


async def test_check_detects_boolean_blind_injection(monkeypatch: pytest.MonkeyPatch) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        idv = request.url.params.get("id", "")
        if "'1'='2" in idv:
            return httpx.Response(200, text="<html>No product found</html>")
        return httpx.Response(200, text="<html>Product: Widget</html>")

    _mock_client(monkeypatch, handler)
    result = await SQLInjectionDetector().check(
        ScanContext(target_id="t1", base_url="https://example.test/product?id=1", extra={})
    )

    assert result.validation_status == "CONFIRMED"
    assert result.evidence["boolean_diff"] is True
    assert result.evidence["error_signature"] is None


async def test_check_no_signal_is_not_detected(monkeypatch: pytest.MonkeyPatch) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text="<html>Row: Alice</html>")

    _mock_client(monkeypatch, handler)
    result = await SQLInjectionDetector().check(
        ScanContext(target_id="t1", base_url="https://example.test/product?id=1", extra={})
    )

    assert result.validation_status == "NOT_DETECTED"


async def test_check_uses_dvwa_lab_preset(monkeypatch: pytest.MonkeyPatch) -> None:
    login_page = (
        '<form action="/login.php" method="post">'
        '<input type="hidden" name="user_token" value="tok1">'
        '<input name="username"><input type="password" name="password">'
        '<input type="submit" name="Login" value="Login"></form>'
    )

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/login.php" and request.method == "GET":
            return httpx.Response(200, text=login_page)
        if request.url.path == "/login.php" and request.method == "POST":
            return httpx.Response(302, headers={"location": "/index.php"})
        if request.url.path == "/vulnerabilities/sqli/":
            idv = request.url.params.get("id", "")
            if "'" in idv and "AND" not in idv.upper():
                return httpx.Response(200, text="You have an error in your SQL syntax")
            return httpx.Response(200, text="<html>ID: 1, First name: admin</html>")
        return httpx.Response(404)

    _mock_client(monkeypatch, handler)
    result = await SQLInjectionDetector().check(
        ScanContext(target_id="t1", base_url="http://dvwa", extra={})
    )

    assert result.validation_status == "CONFIRMED"
    assert result.evidence["candidate_source"] == "explicit configuration"
    assert result.endpoint == "http://dvwa/vulnerabilities/sqli/"
    assert result.parameter == "id"


async def test_check_errors_when_no_candidates_found(monkeypatch: pytest.MonkeyPatch) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text="<html>marketing homepage, nothing to probe</html>")

    _mock_client(monkeypatch, handler)
    result = await SQLInjectionDetector().check(
        ScanContext(target_id="t1", base_url="https://no-forms.test", extra={})
    )

    assert result.validation_status == "ERROR"
    assert "No form fields or query parameters" in result.evidence_summary
