"""Detector registry.

Detectors register themselves here by instance. Scan *profiles* name which
detectors run for a given scan, so the API/runner never hardcode a detector
list — adding a detector (e.g. a future ZAP-backed one) is a one-line change
here.
"""

from app.scanners.base import BaseDetector, DetectorResult, ScanContext
from app.scanners.command_injection import CommandInjectionDetector
from app.scanners.csrf import CSRFDetector
from app.scanners.file_upload import FileUploadDetector
from app.scanners.path_traversal import PathTraversalDetector
from app.scanners.sensitive_files import SensitiveFilesDetector
from app.scanners.vulnerable_services import VulnerableServicesDetector
from app.scanners.weak_auth import WeakAuthDetector
from app.scanners.weak_tls import WeakTLSDetector

# detector_id -> singleton instance
DETECTOR_REGISTRY: dict[str, BaseDetector] = {
    detector.detector_id: detector
    for detector in (
        CommandInjectionDetector(),
        CSRFDetector(),
        PathTraversalDetector(),
        WeakAuthDetector(),
        SensitiveFilesDetector(),
        VulnerableServicesDetector(),
        FileUploadDetector(),
        WeakTLSDetector(),
    )
}

# scan_profile -> ordered detector_ids to run
SCAN_PROFILES: dict[str, list[str]] = {
    "default": ["command_injection"],
    "command_injection": ["command_injection"],
    "csrf": ["csrf"],
    "path_traversal": ["path_traversal"],
    "weak_auth": ["weak_auth"],
    "sensitive_files": ["sensitive_files"],
    "vulnerable_services": ["vulnerable_services"],
    "file_upload": ["file_upload"],
    "weak_tls": ["weak_tls"],
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
