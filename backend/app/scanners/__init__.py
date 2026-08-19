"""Detector registry.

Detectors register themselves here by instance. Scan *profiles* name which
detectors run for a given scan, so the API/runner never hardcode a detector
list — adding a detector (e.g. a future ZAP-backed one) is a one-line change
here.
"""

from app.scanners.base import BaseDetector, DetectorResult, ScanContext
from app.scanners.command_injection import CommandInjectionDetector
from app.scanners.sensitive_files import SensitiveFilesDetector
from app.scanners.sqli_detector import SQLiDetector
from app.scanners.vulnerable_services import VulnerableServicesDetector
from app.scanners.weak_auth import WeakAuthDetector
from app.scanners.weak_tls import WeakTLSDetector
from app.scanners.xss import XSSDetector
from app.scanners.xxe import XXEDetector
from app.scanners.idor import IDORDetector

# detector_id -> singleton instance
DETECTOR_REGISTRY: dict[str, BaseDetector] = {
    detector.detector_id: detector
    for detector in (
        CommandInjectionDetector(),
        SQLiDetector(),
        WeakAuthDetector(),
        SensitiveFilesDetector(),
        VulnerableServicesDetector(),
        WeakTLSDetector(),
        XSSDetector(),
        XXEDetector(),
        IDORDetector(),
    )
}

# scan_profile -> ordered detector_ids to run
SCAN_PROFILES: dict[str, list[str]] = {
    "default": ["command_injection"],
    "command_injection": ["command_injection"],
    "sqli_detector": ["sqli_detector"],
    "weak_auth": ["weak_auth"],
    "sensitive_files": ["sensitive_files"],
    "vulnerable_services": ["vulnerable_services"],
    "weak_tls": ["weak_tls"],
    "xss": ["xss"],
    "xxe": ["xxe"],
    "idor": ["idor"],
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
