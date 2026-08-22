from app.scanners import get_detectors_for_profile
from app.scanners.command_injection import (
    TIME_THRESHOLD_MS,
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


# --- Optional OWASP ZAP cross-check (opt-in via ScanContext.extra['use_zap']) ---

from app.scanners.command_injection import (  # noqa: E402
    _is_cmdi_alert,
    combine_with_zap,
)


def test_is_cmdi_alert_matches_by_cwe() -> None:
    assert _is_cmdi_alert({"alert": "Something", "cweid": "78"}) is True


def test_is_cmdi_alert_matches_by_plugin_id() -> None:
    assert _is_cmdi_alert({"alert": "Something", "pluginId": "90020"}) is True


def test_is_cmdi_alert_matches_by_name() -> None:
    assert _is_cmdi_alert({"alert": "Remote OS Command Injection"}) is True


def test_is_cmdi_alert_ignores_unrelated() -> None:
    assert _is_cmdi_alert({"alert": "SQL Injection", "cweid": "89"}) is False


def test_combine_with_zap_unused_passes_manual_through() -> None:
    assert combine_with_zap(
        manual_detected=True, manual_confidence="MEDIUM",
        zap_used=False, zap_reachable=False, zap_detected=False,
    ) == (True, "CONFIRMED", "MEDIUM")


def test_combine_with_zap_unreachable_passes_manual_through() -> None:
    assert combine_with_zap(
        manual_detected=False, manual_confidence="LOW",
        zap_used=True, zap_reachable=False, zap_detected=False,
    ) == (False, "NOT_DETECTED", "LOW")


def test_combine_with_zap_both_agree_is_high_confidence() -> None:
    assert combine_with_zap(
        manual_detected=True, manual_confidence="MEDIUM",
        zap_used=True, zap_reachable=True, zap_detected=True,
    ) == (True, "CONFIRMED", "HIGH")


def test_combine_with_zap_manual_only_keeps_manual_confidence() -> None:
    assert combine_with_zap(
        manual_detected=True, manual_confidence="HIGH",
        zap_used=True, zap_reachable=True, zap_detected=False,
    ) == (True, "CONFIRMED", "HIGH")


def test_combine_with_zap_zap_only_is_medium_confidence() -> None:
    assert combine_with_zap(
        manual_detected=False, manual_confidence="LOW",
        zap_used=True, zap_reachable=True, zap_detected=True,
    ) == (True, "CONFIRMED", "MEDIUM")


def test_combine_with_zap_neither_found_anything() -> None:
    assert combine_with_zap(
        manual_detected=False, manual_confidence="LOW",
        zap_used=True, zap_reachable=True, zap_detected=False,
    ) == (False, "NOT_DETECTED", "LOW")
