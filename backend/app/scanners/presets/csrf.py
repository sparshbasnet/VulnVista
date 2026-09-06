"""Lab presets for the CSRF detector."""

from __future__ import annotations

from typing import Any

from app.scanners.presets.common import dvwa_login, register_aliases

GENERIC_DEFAULTS: dict[str, Any] = {
    "request_timeout": 15.0,
    "forged_origin": "https://csrf-poc.vulnvista.invalid",
}

# Convenience preset for the bundled DVWA lab container. Its CSRF exercise is a
# password-change form that, at low security, carries no anti-CSRF token and
# accepts a plain GET — deliberately vulnerable so the active proof always has
# something real to demonstrate against.
LAB_PRESETS: dict[str, dict[str, Any]] = register_aliases(
    {
        "dvwa": {
            **dvwa_login(),
            "action_path": "/vulnerabilities/csrf/",
            "method": "GET",
            "password_field": "password_new",
            "confirm_field": "password_conf",
            "submit_field": "Change",
            "submit_value": "Change",
            "new_value": "vulnvista-csrf-{token}",
            "success_indicator": "Password Changed.",
            "reset_value": "password",
        },
    }
)
