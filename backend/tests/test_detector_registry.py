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
