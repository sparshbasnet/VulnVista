from app.scanners import get_detectors_for_profile
from app.scanners.command_injection import (
    TIME_THRESHOLD_MS,
    classify,
    extract_command_output,
    extract_user_token,
)


def test_extract_user_token_present() -> None:
    html = "<input type='hidden' name='user_token' value='abc123def456' />"
    assert extract_user_token(html) == "abc123def456"


def test_extract_user_token_absent() -> None:
    assert extract_user_token("<form></form>") is None


def test_extract_command_output_strips_markup() -> None:
    html = "<pre>PING 127.0.0.1\nCMDINJ-deadbeef</pre>"
    assert extract_command_output(html) == "PING 127.0.0.1\nCMDINJ-deadbeef"


def test_extract_command_output_none() -> None:
    assert extract_command_output("<div>no pre here</div>") is None


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
