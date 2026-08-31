import base64
import json

import httpx
import pytest

from app.scanners import get_detectors_for_profile
from app.scanners.base import ScanContext
from app.scanners.jwt_session import (
    DetectorError,
    ForgeryProbe,
    JWTSessionDetector,
    Structural,
    b64url_decode,
    b64url_encode,
    classify,
    parse_jwt,
    redact_claims,
    set_nested,
)


def _b64(payload: dict) -> str:
    return b64url_encode(json.dumps(payload, separators=(",", ":")).encode())


def _token(header: dict, payload: dict, signature: str = "sig") -> str:
    return f"{_b64(header)}.{_b64(payload)}.{signature}"


def _probe(name: str, accepted: bool, echoed: bool = False) -> ForgeryProbe:
    return ForgeryProbe(
        name=name, description="", accepted=accepted, echoed=echoed, status_code=200, marker=None
    )


def test_profile_resolves_to_jwt_session_detector() -> None:
    detectors = get_detectors_for_profile("jwt_session")
    assert [detector.detector_id for detector in detectors] == ["jwt_session"]


def test_parse_jwt_reads_header_and_claims_without_verifying() -> None:
    header, payload, signature = parse_jwt(_token({"alg": "RS256"}, {"data": {"email": "a"}}))
    assert header == {"alg": "RS256"}
    assert payload == {"data": {"email": "a"}}
    assert signature == "sig"


def test_parse_jwt_rejects_non_three_part_token() -> None:
    with pytest.raises(DetectorError, match="three-part JWT"):
        parse_jwt("not-a-jwt")


def test_set_nested_only_touches_existing_paths() -> None:
    body = {"data": {"email": "old"}}
    assert set_nested(body, "data.email", "new") is True
    assert body["data"]["email"] == "new"
    assert set_nested(body, "data.missing", "x") is False
    assert set_nested(body, "absent.email", "x") is False


def test_redact_claims_masks_sensitive_values_recursively() -> None:
    claims = {"data": {"email": "a@b.c", "password": "hash", "totpSecret": "s"}, "token": "t"}
    redacted = redact_claims(claims)
    assert redacted["data"]["email"] == "a@b.c"
    assert redacted["data"]["password"] == "***redacted***"
    assert redacted["data"]["totpSecret"] == "***redacted***"
    assert redacted["token"] == "***redacted***"


def test_classify_confirms_forged_token_acceptance_with_impersonation() -> None:
    decision = classify(True, [_probe("alg_none", accepted=True, echoed=True)], Structural())
    assert decision.detected is True
    assert decision.validation_status == "CONFIRMED"
    assert decision.severity == "CRITICAL"
    assert decision.confidence == "HIGH"
    assert decision.cwe == "CWE-347"


def test_classify_accepted_but_not_echoed_is_confirmed_at_lower_confidence() -> None:
    decision = classify(True, [_probe("alg_none", accepted=True, echoed=False)], Structural())
    assert decision.validation_status == "CONFIRMED"
    assert decision.severity == "HIGH"
    assert decision.confidence == "MEDIUM"


def test_classify_missing_expiration_is_suspected_when_no_forgery() -> None:
    decision = classify(
        True,
        [_probe("alg_none", accepted=False)],
        Structural(algorithm="RS256", has_expiration=False),
    )
    assert decision.detected is True
    assert decision.validation_status == "SUSPECTED"
    assert decision.cwe == "CWE-613"


def test_classify_all_rejected_and_signed_with_exp_is_not_detected() -> None:
    decision = classify(
        True,
        [_probe("alg_none", accepted=False), _probe("invalid_signature", accepted=False)],
        Structural(algorithm="RS256", has_expiration=True),
    )
    assert decision.detected is False
    assert decision.validation_status == "NOT_DETECTED"


def test_classify_broken_oracle_is_inconclusive() -> None:
    decision = classify(False, [], Structural())
    assert decision.detected is False
    assert decision.validation_status == "INCONCLUSIVE"
    assert decision.cwe == "CWE-345"


def _mock_client(monkeypatch: pytest.MonkeyPatch, handler) -> None:
    real_init = httpx.AsyncClient.__init__

    def patched_init(self: httpx.AsyncClient, *args, **kwargs):
        kwargs["transport"] = httpx.MockTransport(handler)
        real_init(self, *args, **kwargs)

    monkeypatch.setattr(httpx.AsyncClient, "__init__", patched_init)


LAB_EMAIL = "vulnvista.jwt@lab.invalid"


def _genuine_token(email: str = LAB_EMAIL, with_exp: bool = False) -> str:
    payload: dict = {"data": {"id": 24, "email": email, "password": "9f9d..."}, "bid": 6}
    if with_exp:
        payload["exp"] = 9999999999
    return _token({"typ": "JWT", "alg": "RS256"}, payload)


def _read_cookie_token(request: httpx.Request) -> str | None:
    cookie = request.headers.get("cookie", "")
    for part in cookie.split(";"):
        name, _, value = part.strip().partition("=")
        if name == "token":
            return value
    return None


def _juice_shop_handler(
    *,
    accept_alg_none: bool = True,
    accept_any_signature: bool = False,
    with_exp: bool = False,
    record: list[str] | None = None,
):
    """Model Juice Shop: whoami echoes the token's data.email, but only for a token
    whose signature it accepts. By default it (insecurely) accepts alg:none."""

    def whoami_email(token: str | None) -> str | None:
        if not token:
            return None
        parts = token.split(".")
        if len(parts) != 3:
            return None
        try:
            header = json.loads(b64url_decode(parts[0]))
            payload = json.loads(b64url_decode(parts[1]))
        except Exception:
            return None
        alg = str(header.get("alg", "")).lower()
        signature_ok = (
            accept_any_signature
            or (alg == "none" and accept_alg_none and parts[2] == "")
            or (alg == "rs256" and parts[2] == "genuine")  # only the real signature verifies
        )
        if not signature_ok:
            return None
        email = payload.get("data", {}).get("email")
        return email or None

    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if record is not None:
            record.append(f"{request.method} {path}")

        if path == "/api/Users/":
            return httpx.Response(201, json={"status": "success"})

        if path == "/rest/user/login":
            payload = _genuine_token(with_exp=with_exp)
            # The genuine token carries the reserved "genuine" signature the mock verifies.
            header_b64, claims_b64, _ = payload.split(".")
            token = f"{header_b64}.{claims_b64}.genuine"
            return httpx.Response(
                200, json={"authentication": {"token": token, "bid": 6, "umail": LAB_EMAIL}}
            )

        if path == "/rest/user/whoami":
            email = whoami_email(_read_cookie_token(request))
            if email is None:
                return httpx.Response(200, json={"user": {}})
            return httpx.Response(200, json={"user": {"id": 24, "email": email}})

        return httpx.Response(404)

    return handler


async def test_juice_shop_preset_confirms_alg_none_forgery(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _mock_client(monkeypatch, _juice_shop_handler())
    result = await JWTSessionDetector().check(
        ScanContext(target_id="t1", base_url="http://juice-shop:3000")
    )

    assert result.detected is True
    assert result.validation_status == "CONFIRMED"
    assert result.severity == "CRITICAL"
    assert result.confidence == "HIGH"
    assert result.cwe == "CWE-347"
    assert result.cvss_score == 9.1
    assert result.owasp_category == "A07:2021 - Identification and Authentication Failures"
    assert result.endpoint == "http://juice-shop:3000/rest/user/whoami"

    probes = {p["name"]: p for p in result.evidence["forgery_probes"]}
    assert probes["alg_none"]["accepted_as_session"] is True
    assert probes["alg_none"]["tampered_claim_echoed"] is True
    # Juice Shop DOES verify RS256, so tampering the payload under the real alg is refused.
    assert probes["invalid_signature"]["accepted_as_session"] is False
    assert result.evidence["oracle"]["valid"] is True
    assert result.evidence["genuine_token_replayed_as_attack"] is False


async def test_evidence_masks_sensitive_claims_and_signature(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _mock_client(monkeypatch, _juice_shop_handler())
    result = await JWTSessionDetector().check(
        ScanContext(target_id="t1", base_url="http://juice-shop:3000")
    )
    issued = result.evidence["issued_token"]
    assert issued["claims"]["data"]["password"] == "***redacted***"
    assert issued["claims"]["data"]["email"] == LAB_EMAIL
    assert issued["signature"] == "***redacted***"
    assert result.evidence["sensitive_claims_masked"] is True


async def test_secure_target_verifying_signatures_is_not_detected(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _mock_client(
        monkeypatch, _juice_shop_handler(accept_alg_none=False, with_exp=True)
    )
    result = await JWTSessionDetector().check(
        ScanContext(target_id="t1", base_url="http://juice-shop:3000")
    )
    assert result.detected is False
    assert result.validation_status == "NOT_DETECTED"
    assert result.cvss_score == 0.0


async def test_missing_expiration_alone_is_suspected(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Signatures are verified (alg:none refused) but the issued token has no exp claim.
    _mock_client(
        monkeypatch, _juice_shop_handler(accept_alg_none=False, with_exp=False)
    )
    result = await JWTSessionDetector().check(
        ScanContext(target_id="t1", base_url="http://juice-shop:3000")
    )
    assert result.validation_status == "SUSPECTED"
    assert result.severity == "MEDIUM"
    assert result.cwe == "CWE-613"


async def test_broken_oracle_returning_a_constant_marker_is_inconclusive(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # whoami returns the same identity for everyone — genuine, anonymous, and garbage
    # alike — so authenticated and anonymous sessions can't be told apart.
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/Users/":
            return httpx.Response(201, json={"status": "success"})
        if request.url.path == "/rest/user/login":
            header_b64, claims_b64, _ = _genuine_token().split(".")
            token = f"{header_b64}.{claims_b64}.genuine"
            return httpx.Response(200, json={"authentication": {"token": token}})
        if request.url.path == "/rest/user/whoami":
            return httpx.Response(200, json={"user": {"email": "everyone@lab.invalid"}})
        return httpx.Response(404)

    _mock_client(monkeypatch, handler)
    result = await JWTSessionDetector().check(
        ScanContext(target_id="t1", base_url="http://juice-shop:3000")
    )
    assert result.validation_status == "INCONCLUSIVE"
    assert result.evidence["oracle"]["valid"] is False


async def test_genuine_token_is_never_submitted_to_the_session_check(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    submitted_tokens: list[str | None] = []

    def handler(request: httpx.Request) -> httpx.Response:
        base = _juice_shop_handler()
        if request.url.path == "/rest/user/whoami":
            submitted_tokens.append(_read_cookie_token(request))
        return base(request)

    _mock_client(monkeypatch, handler)
    await JWTSessionDetector().check(
        ScanContext(target_id="t1", base_url="http://juice-shop:3000")
    )
    # The genuine token ends in the reserved ".genuine" signature; it is read once to
    # establish the authenticated baseline but never used to build a forged probe.
    genuine_used = [t for t in submitted_tokens if t and t.endswith(".genuine")]
    assert len(genuine_used) == 1  # baseline only
    forged = [t for t in submitted_tokens if t and not t.endswith(".genuine")]
    assert forged, "at least one forged token must be submitted"


async def test_explicit_configuration_against_header_bearer_target(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/login":
            token = _token({"alg": "HS256"}, {"sub": "user-1"}, signature="valid")
            return httpx.Response(200, json={"jwt": token})
        if request.url.path == "/me":
            auth = request.headers.get("authorization", "")
            token = auth[len("Bearer ") :] if auth.startswith("Bearer ") else ""
            parts = token.split(".")
            if len(parts) != 3:
                return httpx.Response(401, json={"id": None})
            # Insecure: accepts any token shape without checking the signature.
            try:
                payload = json.loads(b64url_decode(parts[1]))
            except Exception:
                return httpx.Response(401, json={"id": None})
            return httpx.Response(200, json={"id": payload.get("sub")})
        return httpx.Response(404)

    _mock_client(monkeypatch, handler)
    result = await JWTSessionDetector().check(
        ScanContext(
            target_id="t1",
            base_url="https://api.example.test",
            extra={
                "login_path": "/login",
                "login_request_style": "json",
                "token_json_path": "jwt",
                "token_submission": "header",
                "session_check_path": "/me",
                "session_marker_json_path": "id",
                "tamper_claim_path": "sub",
                "username": "user-1",
                "password": "pw",
            },
        )
    )
    assert result.validation_status == "CONFIRMED"
    assert result.evidence["configuration_source"] == "explicit configuration"
    probes = {p["name"]: p for p in result.evidence["forgery_probes"]}
    assert probes["invalid_signature"]["accepted_as_session"] is True


async def test_missing_configuration_returns_actionable_error() -> None:
    result = await JWTSessionDetector().check(
        ScanContext(target_id="t1", base_url="https://example.test")
    )
    assert result.validation_status == "ERROR"
    assert "session_check_path" in result.evidence_summary


async def test_cookie_submission_requires_cookie_name() -> None:
    result = await JWTSessionDetector().check(
        ScanContext(
            target_id="t1",
            base_url="https://example.test",
            extra={
                "login_path": "/login",
                "session_check_path": "/me",
                "session_marker_json_path": "id",
                "token_submission": "cookie",
            },
        )
    )
    assert result.validation_status == "ERROR"
    assert "token_cookie" in result.evidence_summary


async def test_cross_origin_session_check_is_rejected() -> None:
    result = await JWTSessionDetector().check(
        ScanContext(
            target_id="t1",
            base_url="https://example.test",
            extra={
                "login_path": "/login",
                "session_check_path": "https://other.test/me",
                "session_marker_json_path": "id",
            },
        )
    )
    assert result.validation_status == "ERROR"
    assert "origin" in result.evidence_summary.lower()


async def test_invalid_target_returns_actionable_error() -> None:
    result = await JWTSessionDetector().check(
        ScanContext(target_id="t1", base_url="example.test")
    )
    assert result.validation_status == "ERROR"
    assert "absolute HTTP(S) URL" in result.evidence_summary


def test_b64url_roundtrip_handles_padding() -> None:
    for raw in (b"a", b"ab", b"abc", b"abcd"):
        assert b64url_decode(b64url_encode(raw)) == raw
        assert "=" not in b64url_encode(raw)
        # Standard base64 of these would include padding we must strip.
        assert base64.urlsafe_b64encode(raw).rstrip(b"=").decode() == b64url_encode(raw)
