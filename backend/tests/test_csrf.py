import httpx
import pytest

from app.scanners import get_detectors_for_profile
from app.scanners.base import ScanContext
from app.scanners.csrf import GENERIC_DEFAULTS, CSRFDetector, classify


def test_classify_active_bypass_is_confirmed_high() -> None:
    decision = classify(
        has_token=False, token_session_bound=None, form_uses_get=True,
        active_checked=True, active_bypassed=True,
    )
    assert decision.detected is True
    assert decision.validation_status == "CONFIRMED"
    assert decision.confidence == "HIGH"
    assert decision.cwe == "CWE-352"


def test_classify_active_rejected_is_not_detected() -> None:
    decision = classify(
        has_token=True, token_session_bound=True, form_uses_get=False,
        active_checked=True, active_bypassed=False,
    )
    assert decision.detected is False
    assert decision.validation_status == "NOT_DETECTED"
    assert decision.confidence == "HIGH"


def test_classify_no_token_and_get_is_confirmed_medium() -> None:
    decision = classify(
        has_token=False, token_session_bound=None, form_uses_get=True,
        active_checked=False, active_bypassed=False,
    )
    assert decision.detected is True
    assert decision.validation_status == "CONFIRMED"
    assert decision.confidence == "MEDIUM"


def test_classify_no_token_post_is_confirmed_medium() -> None:
    decision = classify(
        has_token=False, token_session_bound=None, form_uses_get=False,
        active_checked=False, active_bypassed=False,
    )
    assert decision.detected is True
    assert decision.validation_status == "CONFIRMED"


def test_classify_token_not_session_bound_is_confirmed() -> None:
    decision = classify(
        has_token=True, token_session_bound=False, form_uses_get=False,
        active_checked=False, active_bypassed=False,
    )
    assert decision.detected is True
    assert decision.validation_status == "CONFIRMED"
    assert decision.confidence == "MEDIUM"


def test_classify_token_session_bound_is_not_detected_high() -> None:
    decision = classify(
        has_token=True, token_session_bound=True, form_uses_get=False,
        active_checked=False, active_bypassed=False,
    )
    assert decision.detected is False
    assert decision.validation_status == "NOT_DETECTED"
    assert decision.confidence == "HIGH"


def test_classify_token_unverified_is_not_detected_low() -> None:
    decision = classify(
        has_token=True, token_session_bound=None, form_uses_get=False,
        active_checked=False, active_bypassed=False,
    )
    assert decision.detected is False
    assert decision.validation_status == "NOT_DETECTED"
    assert decision.confidence == "LOW"


def test_profile_resolves_to_csrf_detector() -> None:
    detectors = get_detectors_for_profile("csrf")
    assert [d.detector_id for d in detectors] == ["csrf"]


def _mock_client(monkeypatch: pytest.MonkeyPatch, handler) -> None:
    real_init = httpx.AsyncClient.__init__

    def patched_init(self: httpx.AsyncClient, *args, **kwargs):
        kwargs["transport"] = httpx.MockTransport(handler)
        real_init(self, *args, **kwargs)

    monkeypatch.setattr(httpx.AsyncClient, "__init__", patched_init)


@pytest.mark.parametrize("base_url", ["example.test/profile", "ftp://example.test/profile"])
async def test_check_rejects_non_http_absolute_targets(base_url: str) -> None:
    result = await CSRFDetector().check(
        ScanContext(target_id="t1", base_url=base_url, extra={})
    )

    assert result.validation_status == "ERROR"
    assert result.detected is False
    assert "absolute HTTP(S) URL" in result.evidence_summary


NO_TOKEN_GET_FORM_HTML = """
<html><body>
<form action="/profile" method="GET">
  <input type="text" name="bio" value="hello">
  <input type="submit" name="Save" value="Save">
</form>
</body></html>
"""


async def test_check_flags_missing_token_on_get_form(monkeypatch: pytest.MonkeyPatch) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/" and request.method == "GET":
            return httpx.Response(200, text=NO_TOKEN_GET_FORM_HTML)
        return httpx.Response(404)

    _mock_client(monkeypatch, handler)
    result = await CSRFDetector().check(
        ScanContext(target_id="t1", base_url="https://example.test", extra={})
    )

    assert result.validation_status == "CONFIRMED"
    assert result.confidence == "MEDIUM"
    assert result.evidence["form_discovery"] == "auto-discovered"
    assert result.evidence["token_field"] is None
    assert result.evidence["form_method"] == "GET"
    assert result.cwe == "CWE-352"


STATIC_TOKEN_FORM_HTML = """
<html><body>
<form action="/" method="POST">
  <input type="hidden" name="csrf_token" value="static-abc-123">
  <input type="text" name="bio" value="hello">
  <input type="submit" name="Save" value="Save">
</form>
</body></html>
"""


async def test_check_flags_token_not_session_bound(monkeypatch: pytest.MonkeyPatch) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/" and request.method == "GET":
            return httpx.Response(200, text=STATIC_TOKEN_FORM_HTML)
        return httpx.Response(404)

    _mock_client(monkeypatch, handler)
    result = await CSRFDetector().check(
        ScanContext(target_id="t1", base_url="https://example.test", extra={})
    )

    assert result.validation_status == "CONFIRMED"
    assert result.evidence["token_field"] == "csrf_token"
    assert result.evidence["token_session_bound"] is False


async def test_check_not_detected_when_token_is_session_bound(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    call_count = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/" and request.method == "GET":
            call_count["n"] += 1
            token = f"session-token-{call_count['n']}"
            html = (
                '<form action="/" method="POST">'
                f'<input type="hidden" name="csrf_token" value="{token}">'
                '<input type="text" name="bio" value="hello">'
                '<input type="submit" name="Save" value="Save">'
                "</form>"
            )
            return httpx.Response(200, text=html)
        return httpx.Response(404)

    _mock_client(monkeypatch, handler)
    result = await CSRFDetector().check(
        ScanContext(target_id="t1", base_url="https://example.test", extra={})
    )

    assert result.validation_status == "NOT_DETECTED"
    assert result.confidence == "HIGH"
    assert result.evidence["token_session_bound"] is True


async def test_check_errors_when_no_state_changing_form_found(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text="<html>marketing homepage, no forms here</html>")

    _mock_client(monkeypatch, handler)
    result = await CSRFDetector().check(
        ScanContext(target_id="t1", base_url="https://no-forms.test", extra={})
    )

    assert result.validation_status == "ERROR"
    assert "No state-changing form" in result.evidence_summary


DVWA_LOGIN_HTML = """
<html><body>
<form action="login.php" method="post">
  <input type="text" name="username">
  <input type="password" name="password">
  <input type="submit" name="Login" value="Login">
</form>
</body></html>
"""

DVWA_CSRF_HTML = """
<html><body>
<form action="#" method="GET">
  <input type="password" name="password_new">
  <input type="password" name="password_conf">
  <input type="submit" name="Change" value="Change">
</form>
</body></html>
"""


def _dvwa_handler(requests_log, csrf_response):
    def handler(request: httpx.Request) -> httpx.Response:
        requests_log.append(request)
        path = request.url.path
        if path == "/login.php" and request.method == "GET":
            return httpx.Response(200, text=DVWA_LOGIN_HTML)
        if path == "/login.php" and request.method == "POST":
            body = request.read().decode()
            if "username=admin" in body and "password=password" in body:
                return httpx.Response(302, headers={"Location": "/index.php"})
            return httpx.Response(200, text="login failed")
        if path == "/index.php":
            return httpx.Response(200, text="<html>Welcome admin</html>")
        if path == "/vulnerabilities/csrf/" and request.method == "GET":
            if "password_new" in request.url.params:
                return csrf_response(request)
            return httpx.Response(200, text=DVWA_CSRF_HTML)
        return httpx.Response(404)

    return handler


async def test_check_dvwa_preset_confirms_bypass_and_resets_password(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    requests_log: list[httpx.Request] = []
    handler = _dvwa_handler(
        requests_log, lambda request: httpx.Response(200, text="<html>Password Changed.</html>")
    )

    _mock_client(monkeypatch, handler)
    result = await CSRFDetector().check(
        ScanContext(target_id="t1", base_url="http://dvwa", extra={})
    )

    assert result.validation_status == "CONFIRMED"
    assert result.severity == "CRITICAL"
    assert result.evidence["active_check_performed"] is True
    assert result.evidence["active_check_bypassed"] is True

    submissions = [r for r in requests_log if "password_new" in r.url.params]
    assert len(submissions) == 2, "expected a forged submission and a reset submission"
    forged, reset = submissions
    assert forged.headers.get("origin") == GENERIC_DEFAULTS["forged_origin"]
    assert reset.url.params["password_new"] == "password"
    assert "origin" not in reset.headers


async def test_check_dvwa_preset_not_detected_when_origin_is_validated(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    requests_log: list[httpx.Request] = []

    def csrf_response(request: httpx.Request) -> httpx.Response:
        if request.headers.get("origin") == GENERIC_DEFAULTS["forged_origin"]:
            return httpx.Response(200, text="<html>CSRF token is incorrect.</html>")
        return httpx.Response(200, text="<html>Password Changed.</html>")

    handler = _dvwa_handler(requests_log, csrf_response)

    _mock_client(monkeypatch, handler)
    result = await CSRFDetector().check(
        ScanContext(target_id="t1", base_url="http://dvwa", extra={})
    )

    assert result.validation_status == "NOT_DETECTED"
    assert result.evidence["active_check_performed"] is True
    assert result.evidence["active_check_bypassed"] is False

    submissions = [r for r in requests_log if "password_new" in r.url.params]
    assert len(submissions) == 1, "no reset should be attempted when the forgery was rejected"
