"""Lab presets for the command-injection detector."""

from __future__ import annotations

from typing import Any

from app.scanners.presets.common import dvwa_login, register_aliases

# Generic knobs applied to any target unless a lab preset or ScanContext.extra
# overrides them.
GENERIC_DEFAULTS: dict[str, Any] = {
    "benign_value": "127.0.0.1",
    "separator": ";",
    "request_timeout": 20.0,
    "max_candidates": 5,
}

# Convenience presets for the bundled lab containers, keyed by hostname, so the
# DVWA quick-start keeps working with zero configuration. Anything not listed
# here falls back to auto-discovery.
LAB_PRESETS: dict[str, dict[str, Any]] = register_aliases(
    {
        "dvwa": {
            **dvwa_login(),
            "exec_path": "/vulnerabilities/exec/",
            "parameter": "ip",
            "submit_field": "Submit",
            "submit_value": "Submit",
        },
    }
)
