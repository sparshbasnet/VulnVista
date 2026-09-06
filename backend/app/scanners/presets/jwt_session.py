"""Lab presets for the JWT / session detector."""

from __future__ import annotations

from typing import Any

from app.scanners.presets.common import (
    juice_shop_register,
    juice_shop_rest_login,
    register_aliases,
)

GENERIC_DEFAULTS: dict[str, Any] = {
    "request_timeout": 15.0,
    "login_username_field": "username",
    "login_password_field": "password",
    "login_request_style": "form",
    "register_request_style": "json",
    "token_submission": "header",
    "token_header": "Authorization",
    "token_header_prefix": "Bearer ",
    "session_check_method": "GET",
}

LAB_PRESETS: dict[str, dict[str, Any]] = register_aliases(
    {
        "juice-shop": {
            **juice_shop_rest_login(),
            **juice_shop_register(),
            "token_json_path": "authentication.token",
            "token_submission": "cookie",
            "token_cookie": "token",
            "session_check_path": "/rest/user/whoami",
            "session_marker_json_path": "user.email",
            "tamper_claim_path": "data.email",
            "username": "vulnvista.jwt@lab.invalid",
            "password": "VulnVistaJwt1!",
        }
    }
)
