from __future__ import annotations

from app.scanners.base import BaseDetector
from app.scanners.csrf import CSRFDetector
from app.scanners.path_traversal import (
    PathTraversalDetector,
)


def get_detectors() -> list[BaseDetector]:

    return [
        CSRFDetector(),
        PathTraversalDetector(),
    ]