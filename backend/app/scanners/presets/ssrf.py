"""Lab presets for the SSRF detector."""

from __future__ import annotations

from typing import Any

from app.scanners.presets.common import juice_shop_rest_login, register_aliases

GENERIC_DEFAULTS: dict[str, Any] = {
    "request_timeout": 15.0,
    "callback_wait_seconds": 5.0,
    "callback_host": "backend",
    "request_method": "POST",
    "request_style": "form",
    "parameter": "url",
}

LAB_PRESETS: dict[str, dict[str, Any]] = register_aliases(
    {
        "juice-shop": {
            **juice_shop_rest_login(),
            "ssrf_endpoint": "/profile/image/url",
            "parameter": "imageUrl",
            "request_method": "POST",
            "request_style": "form",
            "username": "admin@juice-sh.op",
            "password": "admin123",
            "token_json_path": "authentication.token",
            "token_cookie": "token",
            "profile_path": "/rest/user/whoami",
            "profile_json_path": "user.profileImage",
            "restore_parameter": "imageUrl",
        }
    }
)
