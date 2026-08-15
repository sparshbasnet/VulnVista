import httpx
import pytest

from app.scanners import get_detectors_for_profile
from app.scanners.base import ScanContext
from app.scanners.command_injection import (
    TIME_THRESHOLD_MS,
    CommandInjectionDetector,
    classify,
    extract_evidence_snippet,
    parse_forms,
)


def test_parse_forms_collects_action_method_and_fields() -> None:
    html = """
    <form action="/vulnerabilities/exec/" method="POST">
      <input type="hidden" name="user_token" value="abc123def456" />
      <input type="text" name="ip" value="127.0.0.1" />
      <input type="password" name="unused_password" />
      <input type="submit" name="Submit" value="Submit" />
    </form>
    """
    forms = parse_forms(html, "http://dvwa/vulnerabilities/exec/")
    assert len(forms) == 1
    form = forms[0]
    assert form.action == "http://dvwa/vulnerabilities/exec/"
    assert form.method == "POST"
    fields_by_name = {f.name: f for f in form.fields}
    assert fields_by_name["user_token"].type == "hidden"
    assert fields_by_name["user_token"].value == "abc123def456"
    assert fields_by_name["ip"].type == "text"
    assert fields_by_name["unused_password"].type == "password"


def test_parse_forms_resolves_relative_action() -> None:
    html = '<form action="login.php" method="GET"><input name="q" /></form>'
    forms = parse_forms(html, "http://example.com/app/index.php")
    assert forms[0].action == "http://example.com/app/login.php"


def test_parse_forms_no_forms() -> None:
    assert parse_forms("<div>no forms here</div>", "http://example.com") == []


def test_extract_evidence_snippet_prefers_pre_block() -> None:
    html = "<pre>PING 127.0.0.1\nCMDINJ-deadbeef</pre>"
    assert extract_evidence_snippet(html, "CMDINJ-deadbeef") == "PING 127.0.0.1\nCMDINJ-deadbeef"


def test_extract_evidence_snippet_falls_back_to_marker_window() -> None:
    html = "<div class='result'>Output: CMDINJ-deadbeef ok</div>"
    snippet = extract_evidence_snippet(html, "CMDINJ-deadbeef")
    assert snippet is not None
    assert "CMDINJ-deadbeef" in snippet


def test_extract_evidence_snippet_marker_absent() -> None:
    assert extract_evidence_snippet("<div>nothing to see</div>", "CMDINJ-deadbeef") is None


def test_classify_marker_reflected_is_confirmed() -> None:
    decision = classify(marker_reflected=True, time_delta_ms=0, threshold_ms=TIME_THRESHOLD_MS)
    assert decision.detected is True
    assert decision.validation_status == "CONFIRMED"
    assert decision.confidence == "HIGH"


def test_classify_blind_timing_only_is_confirmed_medium() -> None:
    decision = classify(
        marker_reflected=False,
        time_delta_ms=TIME_THRESHOLD_MS + 500,
        threshold_ms=TIME_THRESHOLD_MS,
    )
    assert decision.detected is True
    assert decision.validation_status == "CONFIRMED"
    assert decision.confidence == "MEDIUM"


def test_classify_no_signal_is_not_detected() -> None:
    decision = classify(marker_reflected=False, time_delta_ms=100, threshold_ms=TIME_THRESHOLD_MS)
    assert decision.detected is False
    assert decision.validation_status == "NOT_DETECTED"


def test_profile_resolves_to_command_injection_detector() -> None:
    detectors = get_detectors_for_profile("command_injection")
    assert [d.detector_id for d in detectors] == ["command_injection"]


def test_unknown_profile_falls_back_to_default() -> None:
    detectors = get_detectors_for_profile("does-not-exist")
    assert [d.detector_id for d in detectors] == ["command_injection"]


# --- check_many() multi-result support ----------------------------------


def _mock_client(monkeypatch: pytest.MonkeyPatch, handler) -> None:
    real_init = httpx.AsyncClient.__init__

    def patched_init(self: httpx.AsyncClient, *args, **kwargs):
        kwargs["transport"] = httpx.MockTransport(handler)
        real_init(self, *args, **kwargs)

    monkeypatch.setattr(httpx.AsyncClient, "__init__", patched_init)


def _extract_marker(payload: str) -> str | None:
    if "echo" not in payload:
        return None
    return payload.split("echo", 1)[1].strip()


def _injected_param_value(request: httpx.Request) -> str:
    """Whichever of `host`/`target` actually carries a payload (contains a
    separator character), as opposed to sitting at its untouched fixed value."""
    for name in ("host", "target"):
        value = request.url.params.get(name, "")
        if ";" in value:
            return value
    return ""


def _both_candidates_vulnerable_handler(request: httpx.Request) -> httpx.Response:
    """Whichever of the two query params carries the injected payload
    reflects it — both `host` and `target` are independently vulnerable."""
    marker = _extract_marker(_injected_param_value(request))
    if marker:
        return httpx.Response(200, text=f"<pre>{marker}</pre>")
    return httpx.Response(200, text="<pre>ok</pre>")


def _only_host_vulnerable_handler(request: httpx.Request) -> httpx.Response:
    """Only `host` reflects an injected marker; `target` is sanitized and
    never reflects anything, regardless of what's injected into it."""
    marker = _extract_marker(request.url.params.get("host", ""))
    if marker:
        return httpx.Response(200, text=f"<pre>{marker}</pre>")
    return httpx.Response(200, text="<pre>ok</pre>")


async def test_check_many_returns_confirmed_result_per_vulnerable_candidate(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _mock_client(monkeypatch, _both_candidates_vulnerable_handler)

    results = await CommandInjectionDetector().check_many(
        ScanContext(
            target_id="t1",
            base_url="https://example.test/ping?host=127.0.0.1&target=127.0.0.1",
            extra={},
        )
    )

    assert len(results) == 2
    assert all(result.detected for result in results)
    assert all(result.validation_status == "CONFIRMED" for result in results)
    assert {result.parameter for result in results} == {"host", "target"}
    # each result records how many candidates were probed overall, plus its
    # own position among them
    assert all(result.evidence["candidates_probed"] == 2 for result in results)
    assert {result.evidence["candidate_index"] for result in results} == {1, 2}


async def test_check_many_partial_confirmation_mixes_confirmed_and_not_detected(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _mock_client(monkeypatch, _only_host_vulnerable_handler)

    results = await CommandInjectionDetector().check_many(
        ScanContext(
            target_id="t1",
            base_url="https://example.test/ping?host=127.0.0.1&target=127.0.0.1",
            extra={},
        )
    )

    assert len(results) == 2
    by_param = {result.parameter: result for result in results}
    assert by_param["host"].detected is True
    assert by_param["host"].validation_status == "CONFIRMED"
    assert by_param["target"].detected is False
    assert by_param["target"].validation_status == "NOT_DETECTED"
    # check_many() doesn't stop probing after the first confirmation
    assert by_param["target"].evidence["candidates_probed"] == 2


async def test_check_wrapper_returns_first_detected_result_for_compatibility(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _mock_client(monkeypatch, _only_host_vulnerable_handler)

    result = await CommandInjectionDetector().check(
        ScanContext(
            target_id="t1",
            base_url="https://example.test/ping?host=127.0.0.1&target=127.0.0.1",
            extra={},
        )
    )

    assert result.detected is True
    assert result.parameter == "host"


async def test_check_many_explicit_multi_path_config_probes_every_path(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        marker = _extract_marker(request.url.params.get("cmd", ""))
        if marker and request.url.path == "/exec-a":
            return httpx.Response(200, text=f"<pre>{marker}</pre>")
        return httpx.Response(200, text="<pre>ok</pre>")

    _mock_client(monkeypatch, handler)

    results = await CommandInjectionDetector().check_many(
        ScanContext(
            target_id="t1",
            base_url="https://example.test",
            extra={
                "parameter": "cmd",
                "exec_paths": ["/exec-a", "/exec-b"],
                "method": "GET",
            },
        )
    )

    assert len(results) == 2
    assert {result.evidence["candidate_source"] for result in results} == {"explicit configuration"}
    by_endpoint = {result.endpoint: result for result in results}
    assert by_endpoint["https://example.test/exec-a"].detected is True
    assert by_endpoint["https://example.test/exec-b"].detected is False


async def test_check_many_returns_single_error_result_when_no_candidates_found(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text="<html>marketing homepage, nothing to probe</html>")

    _mock_client(monkeypatch, handler)

    results = await CommandInjectionDetector().check_many(
        ScanContext(target_id="t1", base_url="https://no-forms.test", extra={})
    )

    assert len(results) == 1
    assert results[0].validation_status == "ERROR"
    assert "No form fields or query parameters" in results[0].evidence_summary
