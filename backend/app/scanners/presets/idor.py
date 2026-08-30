"""Lab presets for the IDOR / broken-access-control detector."""

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
    "object_request_method": "GET",
    "evidence_body_limit": 400,
}

LAB_PRESETS: dict[str, dict[str, Any]] = register_aliases(
    {
        "juice-shop": {
            **juice_shop_rest_login(),
            **juice_shop_register(),
            "token_json_path": "authentication.token",
            "token_header": "Authorization",
            "token_cookie": "token",
            "object_id_json_path": "authentication.bid",
            "object_path_template": "/rest/basket/{object_id}",
            "owner_marker_json_path": "data.UserId",
            "user_a_username": "vulnvista.idor.a@lab.invalid",
            "user_a_password": "VulnVistaLabA1!",
            "user_b_username": "vulnvista.idor.b@lab.invalid",
            "user_b_password": "VulnVistaLabB1!",
        }
    }
)
