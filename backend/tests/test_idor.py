import httpx
import pytest

from app.scanners import get_detectors_for_profile
from app.scanners.base import ScanContext
from app.scanners.idor import (
    IDORDetector,
    ObjectProbe,
    attribute_owner,
    classify,
    get_nested,
)


def _probe(status: int = 200, marker: str | None = None, body_hash: str = "h") -> ObjectProbe:
    return ObjectProbe(status_code=status, owner_marker=marker, body_hash=body_hash)


def test_profile_resolves_to_idor_detector() -> None:
    detectors = get_detectors_for_profile("idor")
    assert [detector.detector_id for detector in detectors] == ["idor"]


def test_get_nested_reads_object_id_and_handles_missing_fields() -> None:
    payload = {"authentication": {"bid": 6}}
    assert get_nested(payload, "authentication.bid") == 6
    assert get_nested(payload, "authentication.missing") is None
    assert get_nested([], "authentication.bid") is None


def test_owner_marker_attribution_beats_body_comparison() -> None:
    # Bodies are identical, but the explicit owner field still resolves ownership.
    cross = _probe(marker="25", body_hash="same")
    a_own = _probe(marker="24", body_hash="same")
    b_own = _probe(marker="25", body_hash="same")
    assert attribute_owner(cross, a_own, b_own) == "other_user"


def test_owner_marker_matching_requester_is_same_user() -> None:
    cross = _probe(marker="24", body_hash="x")
    a_own = _probe(marker="24", body_hash="x")
    b_own = _probe(marker="25", body_hash="y")
    assert attribute_owner(cross, a_own, b_own) == "same_user"


def test_body_comparison_attributes_ownership_without_a_marker() -> None:
    cross = _probe(body_hash="b-view")
    a_own = _probe(body_hash="a-view")
    b_own = _probe(body_hash="b-view")
    assert attribute_owner(cross, a_own, b_own) == "other_user"
    assert attribute_owner(_probe(body_hash="a-view"), a_own, b_own) == "same_user"


def test_identical_owned_objects_are_indistinguishable() -> None:
    cross = _probe(body_hash="same")
    assert attribute_owner(cross, _probe(body_hash="same"), _probe(body_hash="same")) == (
        "indistinguishable"
    )


def test_classify_requires_attributable_cross_read_for_confirmation() -> None:
    confirmed = classify(_probe(200), "other_user", unauthenticated_ok=False)
    assert confirmed.detected is True
    assert confirmed.validation_status == "CONFIRMED"
    assert confirmed.confidence == "HIGH"
    assert confirmed.severity == "HIGH"
    assert "unauthenticated request for it is refused" in confirmed.reason


def test_classify_denied_and_session_scoped_responses_are_not_findings() -> None:
    denied = classify(_probe(403), "unknown", unauthenticated_ok=False)
    assert denied.detected is False
    assert denied.validation_status == "NOT_DETECTED"

    scoped = classify(_probe(200), "same_user", unauthenticated_ok=False)
    assert scoped.detected is False
    assert scoped.validation_status == "NOT_DETECTED"
    assert "ignored the supplied identifier" in scoped.reason


def test_classify_unattributable_difference_is_only_suspected() -> None:
    decision = classify(_probe(200), "unknown", unauthenticated_ok=False)
    assert decision.detected is True
    assert decision.validation_status == "SUSPECTED"
    assert decision.confidence == "MEDIUM"


def test_classify_indistinguishable_objects_are_inconclusive() -> None:
    decision = classify(_probe(200), "indistinguishable", unauthenticated_ok=False)
    assert decision.detected is False
    assert decision.validation_status == "INCONCLUSIVE"


def _mock_client(monkeypatch: pytest.MonkeyPatch, handler) -> None:
    real_init = httpx.AsyncClient.__init__

    def patched_init(self: httpx.AsyncClient, *args, **kwargs):
        kwargs["transport"] = httpx.MockTransport(handler)
        real_init(self, *args, **kwargs)

    monkeypatch.setattr(httpx.AsyncClient, "__init__", patched_init)


# Mirrors the real Juice Shop lab: two accounts, baskets 6 and 7, whose owner is
# reported as data.UserId, reachable only with the bearer token.
JUICE_SHOP_ACCOUNTS = {
    "vulnvista.idor.a@lab.invalid": {"token": "token-a", "bid": 6, "uid": 24},
    "vulnvista.idor.b@lab.invalid": {"token": "token-b", "bid": 7, "uid": 25},
}
BASKET_OWNER = {6: 24, 7: 25}


def _juice_shop_handler(
    *,
    enforce_ownership: bool = False,
    registered: set[str] | None = None,
    record: list[tuple[str, str | None]] | None = None,
) -> object:
    known = JUICE_SHOP_ACCOUNTS if registered is None else {}

    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        authorization = request.headers.get("authorization")
        if record is not None:
            record.append((f"{request.method} {path}", authorization))

        if path == "/api/Users/":
            email = request.read().decode()
            for candidate in JUICE_SHOP_ACCOUNTS:
                if candidate in email:
                    assert registered is not None
                    registered.add(candidate)
                    return httpx.Response(201, json={"status": "success"})
            return httpx.Response(400)

        if path == "/rest/user/login":
            import json as _json

            body = _json.loads(request.read())
            email = body["email"]
            available = known or {
                name: JUICE_SHOP_ACCOUNTS[name] for name in (registered or set())
            }
            if email not in available:
                return httpx.Response(401, json={"error": "Invalid email or password."})
            account = JUICE_SHOP_ACCOUNTS[email]
            return httpx.Response(
                200,
                json={
                    "authentication": {
                        "token": account["token"],
                        "bid": account["bid"],
                        "umail": email,
                    }
                },
            )

        if path.startswith("/rest/basket/"):
            basket_id = int(path.rsplit("/", 1)[1])
            caller = next(
                (
                    account
                    for account in JUICE_SHOP_ACCOUNTS.values()
                    if authorization == f"Bearer {account['token']}"
                ),
                None,
            )
            if caller is None:
                return httpx.Response(401, json={"error": "Unauthorized"})
            if enforce_ownership and BASKET_OWNER[basket_id] != caller["uid"]:
                return httpx.Response(403, json={"error": "Forbidden"})
            return httpx.Response(
                200,
                json={
                    "status": "success",
                    "data": {
                        "id": basket_id,
                        "coupon": None,
                        "UserId": BASKET_OWNER[basket_id],
                        "Products": [],
                    },
                },
            )

        return httpx.Response(404)

    return handler


async def test_juice_shop_preset_confirms_cross_account_read(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _mock_client(monkeypatch, _juice_shop_handler())
    result = await IDORDetector().check(
        ScanContext(target_id="t1", base_url="http://juice-shop:3000")
    )

    assert result.detected is True
    assert result.validation_status == "CONFIRMED"
    assert result.severity == "HIGH"
    assert result.confidence == "HIGH"
    assert result.cwe == "CWE-639"
    assert result.owasp_category == "A01:2021 - Broken Access Control"
    assert result.cvss_score == 6.5
    assert result.endpoint == "http://juice-shop:3000/rest/basket/7"
    assert result.evidence["ownership_attribution"] == "other_user"
    assert result.evidence["read_only"] is True
    assert result.evidence["request_method"] == "GET"
    assert result.evidence["own_object"]["object_id"] == "6"
    assert result.evidence["own_object"]["owner_marker"] == "24"
    assert result.evidence["other_account_object_as_first_account"]["owner_marker"] == "25"
    assert result.evidence["cross_response_matches_owner_view"] is True
    assert result.evidence["unauthenticated_control"]["status_code"] == 401
    assert result.evidence["unauthenticated_control"]["served_owner_data"] is False
    assert result.evidence["synthetic_accounts_provisioned"] == []
    assert result.evidence["configuration_source"] == "lab preset"


async def test_secure_target_enforcing_ownership_is_not_detected(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _mock_client(monkeypatch, _juice_shop_handler(enforce_ownership=True))
    result = await IDORDetector().check(
        ScanContext(target_id="t1", base_url="http://juice-shop:3000")
    )

    assert result.detected is False
    assert result.validation_status == "NOT_DETECTED"
    assert result.cvss_score == 0.0
    assert "HTTP 403" in result.evidence_summary


async def test_missing_accounts_are_provisioned_before_login(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    registered: set[str] = set()
    _mock_client(monkeypatch, _juice_shop_handler(registered=registered))
    result = await IDORDetector().check(
        ScanContext(target_id="t1", base_url="http://juice-shop:3000")
    )

    assert registered == set(JUICE_SHOP_ACCOUNTS)
    assert result.validation_status == "CONFIRMED"
    assert result.evidence["synthetic_accounts_provisioned"] == ["a", "b"]


async def test_each_account_uses_its_own_isolated_session(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    record: list[tuple[str, str | None]] = []
    _mock_client(monkeypatch, _juice_shop_handler(record=record))
    await IDORDetector().check(ScanContext(target_id="t1", base_url="http://juice-shop:3000"))

    basket_reads = [entry for entry in record if entry[0].startswith("GET /rest/basket/")]
    assert basket_reads == [
        ("GET /rest/basket/6", "Bearer token-a"),
        ("GET /rest/basket/7", "Bearer token-b"),
        ("GET /rest/basket/7", None),  # unauthenticated control
        ("GET /rest/basket/7", "Bearer token-a"),  # the cross-account probe
    ]


async def test_detector_never_sends_a_mutating_request(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    record: list[tuple[str, str | None]] = []
    _mock_client(monkeypatch, _juice_shop_handler(record=record))
    await IDORDetector().check(ScanContext(target_id="t1", base_url="http://juice-shop:3000"))

    mutating = [
        entry
        for entry in record
        if entry[0].startswith(("PUT ", "PATCH ", "DELETE "))
        or (entry[0].startswith("POST ") and "/rest/basket/" in entry[0])
    ]
    assert mutating == []


async def test_public_object_is_reported_as_unauthenticated_exposure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/login":
            user = request.url.params.get("u") or request.read().decode()
            token = "token-a" if "alice" in user else "token-b"
            oid = 1 if "alice" in user else 2
            return httpx.Response(200, json={"token": token, "oid": oid})
        if request.url.path.startswith("/api/orders/"):
            oid = int(request.url.path.rsplit("/", 1)[1])
            return httpx.Response(200, json={"id": oid, "owner": 10 + oid})
        return httpx.Response(404)

    _mock_client(monkeypatch, handler)
    result = await IDORDetector().check(
        ScanContext(
            target_id="t1",
            base_url="https://example.test",
            extra={
                "login_path": "/login",
                "login_request_style": "form",
                "token_json_path": "token",
                "token_header": "Authorization",
                "object_id_json_path": "oid",
                "object_path_template": "/api/orders/{object_id}",
                "owner_marker_json_path": "owner",
                "user_a_username": "alice",
                "user_a_password": "pw-a",
                "user_b_username": "bob",
                "user_b_password": "pw-b",
            },
        )
    )

    assert result.validation_status == "CONFIRMED"
    assert result.cvss_score == 7.5
    assert result.evidence["unauthenticated_control"]["served_owner_data"] is True
    assert "without any authentication at all" in result.evidence_summary
    assert result.evidence["configuration_source"] == "explicit configuration"


async def test_missing_object_template_returns_actionable_error() -> None:
    result = await IDORDetector().check(
        ScanContext(target_id="t1", base_url="https://example.test")
    )
    assert result.validation_status == "ERROR"
    assert "object_path_template" in result.evidence_summary


async def test_template_without_placeholder_is_rejected() -> None:
    result = await IDORDetector().check(
        ScanContext(
            target_id="t1",
            base_url="https://example.test",
            extra={"object_path_template": "/api/orders/1", "login_path": "/login"},
        )
    )
    assert result.validation_status == "ERROR"
    assert "{object_id}" in result.evidence_summary


async def test_mutating_request_method_is_rejected_before_any_request(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        pytest.fail("a write method must be rejected before any request is sent")

    _mock_client(monkeypatch, handler)
    result = await IDORDetector().check(
        ScanContext(
            target_id="t1",
            base_url="https://example.test",
            extra={
                "object_path_template": "/api/orders/{object_id}",
                "login_path": "/login",
                "object_request_method": "DELETE",
            },
        )
    )
    assert result.validation_status == "ERROR"
    assert "read-only by design" in result.evidence_summary


async def test_cross_origin_object_path_is_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/login":
            oid = 1 if "user-1" in request.read().decode() else 2
            return httpx.Response(200, json={"token": f"t{oid}", "oid": oid})
        pytest.fail("no request may leave the authorized origin")

    _mock_client(monkeypatch, handler)
    result = await IDORDetector().check(
        ScanContext(
            target_id="t1",
            base_url="https://example.test",
            extra={
                "login_path": "/login",
                "token_json_path": "token",
                "object_id_json_path": "oid",
                "object_path_template": "https://other.test/api/orders/{object_id}",
                "user_a_username": "user-1",
                "user_a_password": "pw",
                "user_b_username": "user-2",
                "user_b_password": "pw",
            },
        )
    )
    assert result.validation_status == "ERROR"
    assert "same origin" in result.evidence_summary


async def test_shared_object_id_between_accounts_is_an_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/login":
            return httpx.Response(200, json={"token": "t", "oid": 1})
        return httpx.Response(200, json={"id": 1})

    _mock_client(monkeypatch, handler)
    result = await IDORDetector().check(
        ScanContext(
            target_id="t1",
            base_url="https://example.test",
            extra={
                "login_path": "/login",
                "token_json_path": "token",
                "object_id_json_path": "oid",
                "object_path_template": "/api/orders/{object_id}",
                "user_a_username": "user-1",
                "user_a_password": "pw",
                "user_b_username": "user-2",
                "user_b_password": "pw",
            },
        )
    )
    assert result.validation_status == "ERROR"
    assert "same object id" in result.evidence_summary


async def test_failed_login_without_registration_is_actionable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _mock_client(monkeypatch, lambda request: httpx.Response(401))
    result = await IDORDetector().check(
        ScanContext(
            target_id="t1",
            base_url="https://example.test",
            extra={
                "login_path": "/login",
                "object_path_template": "/api/orders/{object_id}",
                "object_id_json_path": "oid",
                "user_a_username": "user-1",
                "user_a_password": "pw",
                "user_b_username": "user-2",
                "user_b_password": "pw",
            },
        )
    )
    assert result.validation_status == "ERROR"
    assert "register_path" in result.evidence_summary


async def test_missing_baseline_for_own_object_is_an_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/login":
            oid = 1 if "alice" in request.read().decode() else 2
            return httpx.Response(200, json={"token": f"t{oid}", "oid": oid})
        return httpx.Response(500)

    _mock_client(monkeypatch, handler)
    result = await IDORDetector().check(
        ScanContext(
            target_id="t1",
            base_url="https://example.test",
            extra={
                "login_path": "/login",
                "token_json_path": "token",
                "object_id_json_path": "oid",
                "object_path_template": "/api/orders/{object_id}",
                "user_a_username": "alice",
                "user_a_password": "pw",
                "user_b_username": "bob",
                "user_b_password": "pw",
            },
        )
    )
    assert result.validation_status == "ERROR"
    assert "no legitimate baseline" in result.evidence_summary


async def test_invalid_target_returns_actionable_error() -> None:
    result = await IDORDetector().check(ScanContext(target_id="t1", base_url="example.test"))
    assert result.validation_status == "ERROR"
    assert "absolute HTTP(S) URL" in result.evidence_summary
