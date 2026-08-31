import httpx
import pytest

from app.scanners import get_detectors_for_profile
from app.scanners.base import ScanContext
from app.scanners.sensitive_files import (
    GENERIC_CANDIDATE_FILES,
    LAB_PRESETS,
    SensitiveFilesDetector,
    classify,
    is_exposed,
)


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


def _mock_client(monkeypatch: pytest.MonkeyPatch, handler) -> None:
    real_init = httpx.AsyncClient.__init__

    def patched_init(self: httpx.AsyncClient, *args, **kwargs):
        kwargs["transport"] = httpx.MockTransport(handler)
        real_init(self, *args, **kwargs)

    monkeypatch.setattr(httpx.AsyncClient, "__init__", patched_init)


async def test_check_uses_generic_candidates_against_an_arbitrary_host(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    checked_paths: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        checked_paths.append(request.url.path)
        if request.url.path == "/.env":
            return httpx.Response(200, text="DB_PASSWORD=secret123")
        return httpx.Response(404, text="not found")

    _mock_client(monkeypatch, handler)
    result = await SensitiveFilesDetector().check(
        ScanContext(target_id="t1", base_url="https://example.test", extra={})
    )

    assert result.validation_status == "CONFIRMED"
    assert result.evidence["exposed_files"][0]["path"] == "/.env"
    # generic candidates only — no /ftp/* lab-preset paths for a non-lab host
    assert result.evidence["checked_count"] == len(GENERIC_CANDIDATE_FILES)
    assert not any(path.startswith("/ftp/") for path in checked_paths)


async def test_check_layers_juice_shop_lab_preset_on_generic_candidates(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    checked_paths: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        checked_paths.append(request.url.path)
        return httpx.Response(404, text="not found")

    _mock_client(monkeypatch, handler)
    result = await SensitiveFilesDetector().check(
        ScanContext(target_id="t1", base_url="http://juice-shop:3000", extra={})
    )

    assert result.evidence["checked_count"] == (
        len(GENERIC_CANDIDATE_FILES) + len(LAB_PRESETS["juice-shop"])
    )
    assert any(path.startswith("/ftp/") for path in checked_paths)
