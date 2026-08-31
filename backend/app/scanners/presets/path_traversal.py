"""Lab presets for the path-traversal detector.

The canary lives at a controlled path outside any web content directory and
holds only a unique marker — retrieving that exact marker is the sole proof of
traversal, so the detector never requests real system files.
"""

from __future__ import annotations

from typing import Any

from app.scanners.presets.common import dvwa_login, register_aliases

CANARY_MARKER = "VULNVISTA_PATH_TRAVERSAL_CANARY_7F3A9C2E"
CANARY_PATH = "/var/lib/vulnvista-canary/vulnvista-path-traversal-canary.txt"

GENERIC_DEFAULTS: dict[str, Any] = {
    "request_timeout": 15.0,
    "max_candidates": 5,
    "max_depth": 8,
    "benign_value": "index.html",
}

LAB_PRESETS: dict[str, dict[str, Any]] = register_aliases(
    {
        "dvwa": {
            **dvwa_login(),
            "exec_path": "/vulnerabilities/fi/",
            "parameter": "page",
            "method": "GET",
            "benign_value": "file1.php",
            "canary_path": CANARY_PATH,
            "canary_marker": CANARY_MARKER,
        },
    }
)
