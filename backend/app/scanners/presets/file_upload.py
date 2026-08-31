"""Lab presets for the file-upload detector."""

from __future__ import annotations

from typing import Any

from app.scanners.presets.common import dvwa_login, register_aliases

GENERIC_DEFAULTS: dict[str, Any] = {
    "request_timeout": 15.0,
    "max_candidates": 3,
}

LAB_PRESETS: dict[str, dict[str, Any]] = register_aliases(
    {
        "dvwa": {
            **dvwa_login(),
            "upload_path": "/vulnerabilities/upload/",
            "file_field": "uploaded",
            "submit_field": "Upload",
            "submit_value": "Upload",
            "public_base_path": "/hackable/uploads/",
        },
    }
)
