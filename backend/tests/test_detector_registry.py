import pytest

from app.scanners import get_detectors_for_profile
from app.scanners.csrf import CSRFDetector
from app.scanners.detector_registry import get_detectors
from app.scanners.path_traversal import PathTraversalDetector


def test_generic_authorized_website_uses_passive_detector_only():
    detectors = get_detectors("https://example.com")

    assert [type(detector) for detector in detectors] == [CSRFDetector]


def test_dvwa_and_juice_shop_include_target_specific_path_traversal_detector():
    for base_url in ("http://vulnvista_dvwa", "http://vulnvista_juice_shop:3000"):
        detectors = get_detectors(base_url)

        assert [type(detector) for detector in detectors] == [CSRFDetector, PathTraversalDetector]


@pytest.mark.parametrize(
    ("profile", "detector_id"),
    [
        ("sqli_detector", "sqli_detector"),
        ("command_injection", "command_injection"),
        ("xss", "xss"),
        ("file_upload", "file_upload"),
        ("path_traversal", "path_traversal"),
        ("csrf", "csrf"),
        ("idor", "idor"),
        ("jwt_session", "jwt_session"),
        ("weak_auth", "weak_auth"),
        ("ssrf", "ssrf"),
        ("xxe", "xxe"),
        ("sensitive_files", "sensitive_files"),
        ("vulnerable_services", "vulnerable_services"),
        ("misconfiguration", "misconfiguration"),
        ("weak_tls", "weak_tls"),
    ],
)
def test_dashboard_profile_resolves_to_matching_detector(profile: str, detector_id: str) -> None:
    detectors = get_detectors_for_profile(profile)

    assert [detector.detector_id for detector in detectors] == [detector_id]
