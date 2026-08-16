import httpx
import pytest

from app.scanners import get_detectors_for_profile
from app.scanners.base import ScanContext
from app.scanners.xss import XSSDetector, build_payload, classify


def test_classify_requires_browser_execution() -> None:
    reflected_only = classify(marker_reflected=True, marker_executed=False)
    assert reflected_only.detected is False
    assert reflected_only.validation_status == "NOT_DETECTED"

    executed = classify(marker_reflected=False, marker_executed=True)
    assert executed.detected is True
    assert executed.validation_status == "CONFIRMED"
    assert executed.confidence == "HIGH"


def test_payload_is_unique_dom_only_canary() -> None:
    payload = build_payload("XSS-deadbeef")
    assert "data-vulnvista-xss" in payload
    assert "XSS-deadbeef" in payload
    assert "alert(" not in payload


def test_profile_resolves_to_xss_detector() -> None:
    assert [detector.detector_id for detector in get_detectors_for_profile("xss")] == ["xss"]


def _mock_client(monkeypatch: pytest.MonkeyPatch, handler) -> None:
    real_init = httpx.AsyncClient.__init__

    def patched_init(self: httpx.AsyncClient, *args, **kwargs):
        kwargs["transport"] = httpx.MockTransport(handler)
        real_init(self, *args, **kwargs)

    monkeypatch.setattr(httpx.AsyncClient, "__init__", patched_init)


FORM_HTML = """
<html><body>
  <form action="/search" method="GET">
    <input type="search" name="q">
    <input type="submit" value="Search">
  </form>
</body></html>
"""


async def test_reflection_without_execution_is_not_a_finding(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/":
            return httpx.Response(200, text=FORM_HTML)
        if request.url.path == "/search":
            return httpx.Response(200, text=f"<p>{request.url.params['q']}</p>")
        return httpx.Response(404)

    async def did_not_execute(self, candidate, payload, marker, client, cfg):
        return False, True

    _mock_client(monkeypatch, handler)
    monkeypatch.setattr(XSSDetector, "_browser_probe", did_not_execute)

    result = await XSSDetector().check(ScanContext(target_id="t1", base_url="https://example.test"))

    assert result.validation_status == "NOT_DETECTED"
    assert result.detected is False
    assert result.evidence["marker_reflected"] is True
    assert result.evidence["browser_execution_confirmed"] is False


async def test_browser_execution_confirms_xss(monkeypatch: pytest.MonkeyPatch) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/":
            return httpx.Response(200, text=FORM_HTML)
        if request.url.path == "/search":
            return httpx.Response(200, text=f"<p>{request.url.params['q']}</p>")
        return httpx.Response(404)

    async def executed(self, candidate, payload, marker, client, cfg):
        assert marker in payload
        assert candidate.param == "q"
        return True, True

    _mock_client(monkeypatch, handler)
    monkeypatch.setattr(XSSDetector, "_browser_probe", executed)

    result = await XSSDetector().check(ScanContext(target_id="t1", base_url="https://example.test"))

    assert result.validation_status == "CONFIRMED"
    assert result.detected is True
    assert result.severity == "HIGH"
    assert result.confidence == "HIGH"
    assert result.parameter == "q"
    assert result.cwe == "CWE-79"
    assert result.cvss_score == 8.2


async def test_no_inputs_returns_actionable_error(monkeypatch: pytest.MonkeyPatch) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text="<html><body>No inputs</body></html>")

    _mock_client(monkeypatch, handler)
    result = await XSSDetector().check(ScanContext(target_id="t1", base_url="https://example.test"))

    assert result.validation_status == "ERROR"
    assert "No form fields or query parameters" in result.evidence_summary
