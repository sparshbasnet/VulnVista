"""Detector registry — resolves a scan's profile name to detector instances."""

from __future__ import annotations

from app.scanners.base import BaseDetector
from app.scanners.command_injection import CommandInjectionDetector

DEFAULT_PROFILE = "command_injection"

_PROFILES: dict[str, list[type[BaseDetector]]] = {
    "default": [CommandInjectionDetector],
    "command_injection": [CommandInjectionDetector],
}


def get_detectors_for_profile(profile: str) -> list[BaseDetector]:
    """Resolve a scan profile name to its detector instances.

    Falls back to the default profile for unknown names so a stale/typo'd
    profile can't block a scan from running at all.
    """
    detector_classes = _PROFILES.get(profile, _PROFILES[DEFAULT_PROFILE])
    return [detector_cls() for detector_cls in detector_classes]


__all__ = ["BaseDetector", "get_detectors_for_profile"]
