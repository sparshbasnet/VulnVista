from __future__ import annotations

from urllib.parse import urlparse

from app.scanners.base import BaseDetector
from app.scanners.csrf import CSRFDetector
from app.scanners.path_traversal import PathTraversalDetector


def get_detectors(base_url: str) -> list[BaseDetector]:
    """Return safe detectors compatible with the target application profile."""
    hostname = (urlparse(base_url).hostname or "").lower()
    detectors: list[BaseDetector] = [CSRFDetector()]

    # Path-traversal probes use application-specific routes and must never be
    # sent to an arbitrary approved website.
    if "dvwa" in hostname or "juice" in hostname:
        detectors.append(PathTraversalDetector())

    return detectors
