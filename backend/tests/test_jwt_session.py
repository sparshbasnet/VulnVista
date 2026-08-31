import base64
import json

import httpx

from app.scanners import get_detectors_for_profile
from app.scanners.base import ScanContext
from app.scanners.jwt_session import (
    JWTSessionDetector,
    classify_cookie,
    classify_token,
    decode_jwt_metadata,
)


class FakeAsyncClient:
    def __init__(self, responses: list[httpx.Response | Exception], **kwargs):
        self.responses = iter(responses)
        self.cookies = httpx.Cookies()

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return None

    async def get(self, url: str):
        return self._next()

    async def post(self, url: str, json: dict[str, str]):
        return self._next()

    def _next(self):
        response = next(self.responses)
        if isinstance(response, Exception):
            raise response
        return response


def make_token(header: dict, payload: dict) -> str:
    def encode(value: dict) -> str:
        raw = json.dumps(value).encode()
        return base64.urlsafe_b64encode(raw).decode().rstrip("=")

    return f"{encode(header)}.{encode(payload)}.signature"


def test_unsigned_token_and_missing_expiration_are_detected() -> None:
    issues = classify_token({"alg": "none"}, {"sub": "user-1"})

    assert {issue["code"] for issue in issues} == {"unsigned_jwt", "missing_expiration"}


def test_short_lived_signed_token_has_no_issue() -> None:
    assert classify_token({"alg": "RS256"}, {"iat": 100, "exp": 3700}) == []


def test_cookie_requires_secure_httponly_and_restrictive_samesite() -> None:
    assert classify_cookie("session=abc; Path=/; SameSite=None")
    assert classify_cookie("session=abc; Secure; HttpOnly; SameSite=Lax") == []


def test_malformed_token_is_not_decoded() -> None:
    assert decode_jwt_metadata("not.a.jwt") is None


def test_profile_resolves_to_jwt_session_detector() -> None:
    detectors = get_detectors_for_profile("jwt_session")
    assert [detector.detector_id for detector in detectors] == ["jwt_session"]


async def test_detector_reports_issues_without_storing_raw_token(monkeypatch) -> None:
    token = make_token({"alg": "none"}, {"sub": "user-1"})
    response = httpx.Response(
        200,
        headers={"set-cookie": "session=abc; Path=/"},
        request=httpx.Request("GET", "http://test.local"),
    )
    monkeypatch.setattr(
        "app.scanners.jwt_session.httpx.AsyncClient",
        lambda **kwargs: FakeAsyncClient([response], **kwargs),
    )

    result = await JWTSessionDetector().check(
        ScanContext(
            target_id="test-target",
            base_url="http://test.local",
            extra={"cookies": {"token": token}},
        )
    )

    assert result.detected is True
    assert result.validation_status == "CONFIRMED"
    assert result.severity == "CRITICAL"
    assert result.evidence["jwt_algorithm"] == "none"
    assert token not in json.dumps(result.evidence)


async def test_detector_returns_controlled_error(monkeypatch) -> None:
    request = httpx.Request("GET", "http://test.local")
    monkeypatch.setattr(
        "app.scanners.jwt_session.httpx.AsyncClient",
        lambda **kwargs: FakeAsyncClient(
            [httpx.ConnectError("connection failed", request=request)], **kwargs
        ),
    )

    result = await JWTSessionDetector().check(
        ScanContext(target_id="test-target", base_url="http://test.local")
    )

    assert result.detected is False
    assert result.validation_status == "ERROR"


async def test_juice_shop_uses_controlled_lab_token(monkeypatch) -> None:
    token = make_token({"alg": "HS256"}, {"sub": "admin"})
    login_response = httpx.Response(
        200,
        json={"authentication": {"token": token}},
        request=httpx.Request("POST", "http://juice-shop:3000/rest/user/login"),
    )
    page_response = httpx.Response(
        200,
        request=httpx.Request("GET", "http://juice-shop:3000"),
    )
    monkeypatch.setattr(
        "app.scanners.jwt_session.httpx.AsyncClient",
        lambda **kwargs: FakeAsyncClient([login_response, page_response], **kwargs),
    )

    result = await JWTSessionDetector().check(
        ScanContext(target_id="test-target", base_url="http://juice-shop:3000")
    )

    assert result.detected is True
    assert result.evidence["jwt_present"] is True
    assert result.evidence["jwt_algorithm"] == "HS256"
    assert token not in json.dumps(result.evidence)
