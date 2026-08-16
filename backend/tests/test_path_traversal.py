import httpx
import pytest

from app.scanners import get_detectors_for_profile
from app.scanners.base import ScanContext
from app.scanners.path_traversal import (
    CANARY_MARKER,
    CANARY_PATH,
    PathTraversalDetector,
    build_traversal_variants,
    classify,
    extract_marker_snippet,
)


def test_build_variants_target_only_controlled_canary() -> None:
    variants = build_traversal_variants("/srv/canaries/path-test.txt", 3)
    assert variants == [
        "../srv/canaries/path-test.txt",
        "../../srv/canaries/path-test.txt",
        "../../../srv/canaries/path-test.txt",
        "/srv/canaries/path-test.txt",
    ]
    assert not any("passwd" in payload or ".env" in payload for payload in variants)


def test_classify_requires_returned_canary() -> None:
    clean = classify([])
    assert clean.detected is False
    assert clean.validation_status == "NOT_DETECTED"

    confirmed = classify(["../../srv/canary.txt"])
    assert confirmed.detected is True
    assert confirmed.validation_status == "CONFIRMED"
    assert confirmed.confidence == "HIGH"


def test_extract_marker_snippet_excludes_unrelated_body_data() -> None:
    body = "A" * 200 + CANARY_MARKER + "B" * 200
    snippet = extract_marker_snippet(body, CANARY_MARKER, radius=10)
    assert snippet == "A" * 10 + CANARY_MARKER + "B" * 10


def test_profile_resolves_to_path_traversal_detector() -> None:
    detectors = get_detectors_for_profile("path_traversal")
    assert [detector.detector_id for detector in detectors] == ["path_traversal"]


def _mock_client(monkeypatch: pytest.MonkeyPatch, handler) -> None:
    real_init = httpx.AsyncClient.__init__

    def patched_init(self: httpx.AsyncClient, *args, **kwargs):
        kwargs["transport"] = httpx.MockTransport(handler)
        real_init(self, *args, **kwargs)

    monkeypatch.setattr(httpx.AsyncClient, "__init__", patched_init)


LOGIN_HTML = """
<form action="/login.php" method="POST">
  <input type="hidden" name="user_token" value="token-1">
  <input name="username">
  <input type="password" name="password">
  <input type="submit" name="Login" value="Login">
</form>
"""


async def test_dvwa_preset_confirms_only_controlled_canary(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    payloads: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/login.php" and request.method == "GET":
            return httpx.Response(200, text=LOGIN_HTML)
        if request.url.path == "/login.php" and request.method == "POST":
            return httpx.Response(302, headers={"Location": "/index.php"})
        if request.url.path == "/index.php":
            return httpx.Response(200, text="Welcome")
        if request.url.path == "/vulnerabilities/fi/":
            value = request.url.params.get("page", "")
            payloads.append(value)
            if value.startswith("../../../") and value.endswith(CANARY_PATH.lstrip("/")):
                return httpx.Response(200, text=f"before {CANARY_MARKER} after")
            return httpx.Response(200, text="ordinary permitted page")
        return httpx.Response(404)

    _mock_client(monkeypatch, handler)
    result = await PathTraversalDetector().check(
        ScanContext(target_id="t1", base_url="http://dvwa")
    )

    assert result.validation_status == "CONFIRMED"
    assert result.parameter == "page"
    assert result.cwe == "CWE-22"
    assert result.evidence["candidate_source"] == "lab preset"
    assert result.evidence["sensitive_system_files_probed"] is False
    assert result.evidence["successful_probes"][0]["payload"].startswith("../../../")
    assert all("/etc/passwd" not in payload for payload in payloads)


async def test_generic_target_requires_controlled_canary(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        pytest.fail("No request should run without controlled canary configuration")

    _mock_client(monkeypatch, handler)
    result = await PathTraversalDetector().check(
        ScanContext(target_id="t1", base_url="https://example.test/files?page=welcome")
    )

    assert result.validation_status == "ERROR"
    assert "canary_path" in result.evidence_summary
    assert "canary_marker" in result.evidence_summary


async def test_no_marker_is_not_detected(monkeypatch: pytest.MonkeyPatch) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text="safe response without controlled marker")

    _mock_client(monkeypatch, handler)
    result = await PathTraversalDetector().check(
        ScanContext(
            target_id="t1",
            base_url="https://example.test/download?page=welcome.txt",
            extra={"canary_path": "/srv/canary.txt", "canary_marker": "SAFE-CANARY"},
        )
    )

    assert result.validation_status == "NOT_DETECTED"
    assert result.detected is False
    assert result.evidence["successful_probes"] == []


async def test_baseline_contamination_returns_error(monkeypatch: pytest.MonkeyPatch) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text=f"unexpected {CANARY_MARKER}")

    _mock_client(monkeypatch, handler)
    result = await PathTraversalDetector().check(
        ScanContext(
            target_id="t1",
            base_url="https://example.test/download?page=welcome.txt",
            extra={"canary_path": CANARY_PATH, "canary_marker": CANARY_MARKER},
        )
    )

    assert result.validation_status == "ERROR"
    assert "already appears" in result.evidence_summary
