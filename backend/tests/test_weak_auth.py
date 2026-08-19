from app.scanners import get_detectors_for_profile
from app.scanners.weak_auth import classify


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


def test_profile_resolves_to_weak_auth_detector() -> None:
    detectors = get_detectors_for_profile("weak_auth")
    assert [d.detector_id for d in detectors] == ["weak_auth"]
