"""Detector registry.

Detectors register themselves here by instance. Scan *profiles* name which
detectors run for a given scan, so the API/runner never hardcode a detector
list — adding a detector (e.g. a future ZAP-backed one) is a one-line change
here.
"""

from app.scanners.base import BaseDetector, DetectorResult, ScanContext
from app.scanners.command_injection import CommandInjectionDetector

# detector_id -> singleton instance
DETECTOR_REGISTRY: dict[str, BaseDetector] = {
    detector.detector_id: detector
    for detector in (CommandInjectionDetector(),)
}

# scan_profile -> ordered detector_ids to run
SCAN_PROFILES: dict[str, list[str]] = {
    "default": ["command_injection"],
    "command_injection": ["command_injection"],
}


def get_detectors_for_profile(profile: str) -> list[BaseDetector]:
    """Resolve a scan profile to its detector instances, falling back to default."""
    detector_ids = SCAN_PROFILES.get(profile, SCAN_PROFILES["default"])
    return [DETECTOR_REGISTRY[d] for d in detector_ids if d in DETECTOR_REGISTRY]


__all__ = [
    "BaseDetector",
    "DetectorResult",
    "ScanContext",
    "DETECTOR_REGISTRY",
    "SCAN_PROFILES",
    "get_detectors_for_profile",
]
