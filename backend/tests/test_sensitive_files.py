from app.scanners import get_detectors_for_profile
from app.scanners.sensitive_files import classify, is_exposed


def test_is_exposed_true_when_status_differs_from_baseline() -> None:
    exposed = is_exposed(
        status_code=200, content_length=512, baseline_status=404, baseline_length=0
    )
    assert exposed is True


def test_is_exposed_true_when_same_200_but_different_length() -> None:
    exposed = is_exposed(
        status_code=200, content_length=512, baseline_status=200, baseline_length=1900
    )
    assert exposed is True


def test_is_exposed_false_when_matches_spa_fallback() -> None:
    exposed = is_exposed(
        status_code=200, content_length=1900, baseline_status=200, baseline_length=1900
    )
    assert exposed is False


def test_is_exposed_false_on_404() -> None:
    exposed = is_exposed(
        status_code=404, content_length=0, baseline_status=200, baseline_length=1900
    )
    assert exposed is False


def test_is_exposed_false_on_4xx_5xx() -> None:
    exposed = is_exposed(
        status_code=403, content_length=20, baseline_status=200, baseline_length=1900
    )
    assert exposed is False


def test_classify_no_exposures_is_not_detected() -> None:
    decision = classify([])
    assert decision.detected is False
    assert decision.validation_status == "NOT_DETECTED"
    assert decision.severity == "INFO"
    assert decision.worst_category is None


def test_classify_credential_store_is_critical() -> None:
    decision = classify(["backup_file", "credential_store", "source_map"])
    assert decision.detected is True
    assert decision.validation_status == "CONFIRMED"
    assert decision.confidence == "HIGH"
    assert decision.severity == "CRITICAL"
    assert decision.worst_category == "credential_store"


def test_classify_backup_file_only_is_medium() -> None:
    decision = classify(["backup_file"])
    assert decision.detected is True
    assert decision.severity == "MEDIUM"
    assert decision.worst_category == "backup_file"


def test_classify_source_map_only_is_low() -> None:
    decision = classify(["source_map"])
    assert decision.detected is True
    assert decision.severity == "LOW"
    assert decision.worst_category == "source_map"


def test_profile_resolves_to_sensitive_files_detector() -> None:
    detectors = get_detectors_for_profile("sensitive_files")
    assert [d.detector_id for d in detectors] == ["sensitive_files"]
