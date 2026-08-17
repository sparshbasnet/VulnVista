import httpx
import pytest

from app.scanners import get_detectors_for_profile
from app.scanners.base import ScanContext
from app.scanners.weak_auth import WeakAuthDetector, classify


def test_classify_enumeration_and_no_lockout_is_confirmed_high() -> None:
    decision = classify(enumeration_leaked=True, lockout_triggered=False, attempts_made=12)
    assert decision.detected is True
    assert decision.validation_status == "CONFIRMED"
    assert decision.confidence == "HIGH"
    assert decision.cwe == "CWE-307"


def test_classify_enumeration_only_is_confirmed_high() -> None:
    decision = classify(enumeration_leaked=True, lockout_triggered=True, attempts_made=3)
    assert decision.detected is True
    assert decision.validation_status == "CONFIRMED"
    assert decision.confidence == "HIGH"
    assert decision.cwe == "CWE-203"


def test_classify_no_lockout_only_is_confirmed_medium() -> None:
    decision = classify(enumeration_leaked=False, lockout_triggered=False, attempts_made=12)
    assert decision.detected is True
    assert decision.validation_status == "CONFIRMED"
    assert decision.confidence == "MEDIUM"
    assert decision.cwe == "CWE-307"


def test_classify_no_signal_is_not_detected() -> None:
    decision = classify(enumeration_leaked=False, lockout_triggered=True, attempts_made=3)
    assert decision.detected is False
    assert decision.validation_status == "NOT_DETECTED"


def test_classify_notes_skipped_enumeration_when_not_checked() -> None:
    decision = classify(
        enumeration_leaked=False, lockout_triggered=True, attempts_made=3, enumeration_checked=False
    )
    assert decision.detected is False
    assert "skipped" in decision.reason


def test_profile_resolves_to_weak_auth_detector() -> None:
    detectors = get_detectors_for_profile("weak_auth")
    assert [d.detector_id for d in detectors] == ["weak_auth"]


def _mock_client(monkeypatch: pytest.MonkeyPatch, handler) -> None:
    real_init = httpx.AsyncClient.__init__

    def patched_init(self: httpx.AsyncClient, *args, **kwargs):
        kwargs["transport"] = httpx.MockTransport(handler)
        real_init(self, *args, **kwargs)

    monkeypatch.setattr(httpx.AsyncClient, "__init__", patched_init)


LOGIN_PAGE_HTML = """
<html><body>
<form action="/do-login" method="post">
  <input type="hidden" name="csrf" value="tok-abc123">
  <input type="text" name="user_email">
  <input type="password" name="user_pw">
</form>
</body></html>
"""


async def test_check_auto_discovers_login_form_and_flags_missing_lockout(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/" and request.method == "GET":
            return httpx.Response(200, text="<html>no form on the homepage</html>")
        if request.url.path == "/login" and request.method == "GET":
            return httpx.Response(200, text=LOGIN_PAGE_HTML)
        if request.url.path == "/do-login" and request.method == "POST":
            return httpx.Response(401, text="invalid credentials")
        return httpx.Response(404)

    _mock_client(monkeypatch, handler)
    result = await WeakAuthDetector().check(
        ScanContext(target_id="t1", base_url="https://example.test", extra={})
    )

    assert result.validation_status == "CONFIRMED"
    assert result.evidence["login_discovery"] == "auto-discovered"
    assert result.evidence["username_field"] == "user_email"
    assert result.evidence["password_field"] == "user_pw"
    assert len(result.evidence["login_attempt_statuses"]) == 12
    assert result.evidence["lockout_triggered"] is False
    assert result.evidence["enumeration_checked"] is False


async def test_check_flags_enumeration_via_login_differential(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/login" and request.method == "GET":
            return httpx.Response(200, text=LOGIN_PAGE_HTML)
        if request.url.path == "/do-login" and request.method == "POST":
            body = request.read().decode()
            if "user_email=real" in body:
                return httpx.Response(200, text="Wrong password for this account.")
            return httpx.Response(401, text="No such user.")
        return httpx.Response(404)

    _mock_client(monkeypatch, handler)
    result = await WeakAuthDetector().check(
        ScanContext(
            target_id="t1",
            base_url="https://example.test/login",
            extra={"known_username": "real"},
        )
    )

    assert result.validation_status == "CONFIRMED"
    assert result.evidence["enumeration_checked"] is True
    assert result.evidence["enumeration_method"] == "login_differential"


async def test_check_uses_juice_shop_lab_preset(monkeypatch: pytest.MonkeyPatch) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/rest/user/login":
            return httpx.Response(401, json={"message": "bad"})
        if request.url.path == "/rest/user/security-question":
            email = request.url.params.get("email")
            if email == "admin@juice-sh.op":
                return httpx.Response(200, json={"question": "Pet name?"})
            return httpx.Response(200, json={})
        return httpx.Response(404)

    _mock_client(monkeypatch, handler)
    result = await WeakAuthDetector().check(
        ScanContext(target_id="t1", base_url="http://juice-shop:3000", extra={})
    )

    assert result.validation_status == "CONFIRMED"
    assert result.confidence == "HIGH"
    assert result.evidence["login_discovery"] == "lab preset"
    assert result.evidence["enumeration_method"] == "oracle_endpoint"
    assert result.evidence["known_username_signal"] is True
    assert result.evidence["unknown_username_signal"] is False


async def test_check_errors_when_no_login_form_found(monkeypatch: pytest.MonkeyPatch) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text="<html>marketing homepage, no login here</html>")

    _mock_client(monkeypatch, handler)
    result = await WeakAuthDetector().check(
        ScanContext(target_id="t1", base_url="https://no-login.test", extra={})
    )

    assert result.validation_status == "ERROR"
    assert "No login form" in result.evidence_summary
