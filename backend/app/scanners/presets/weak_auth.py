"""Lab presets for the weak-authentication detector.

Juice Shop is a pure JSON REST API with no server-rendered login form to
discover, and its enumeration oracle lives on a separate endpoint from the
login one — so it uses its own field names rather than the shared REST-login
fragment.
"""

from __future__ import annotations

from typing import Any

from app.scanners.presets.common import register_aliases

GENERIC_DEFAULTS: dict[str, Any] = {
    "rate_limit_attempts": 12,
    "request_timeout": 15.0,
}

LAB_PRESETS: dict[str, dict[str, Any]] = register_aliases(
    {
        "juice-shop": {
            "login_path": "/rest/user/login",
            "request_style": "json",
            "username_field": "email",
            "password_field": "password",
            "known_username": "admin@juice-sh.op",
            "enumeration_path": "/rest/user/security-question",
            "enumeration_param": "email",
            "enumeration_response_key": "question",
        },
        # DVWA's login form lives at /login.php, which isn't in
        # COMMON_LOGIN_PATHS, so auto-discovery needs an explicit login_path.
        # No dedicated enumeration oracle endpoint exists, so this falls back
        # to the generic login_differential method: submit "admin" (one of
        # DVWA's hardcoded seed users, same one dvwa_login() authenticates
        # with) against the login form with a bogus password, and compare the
        # response to an unknown username.
        "dvwa": {
            "login_path": "/login.php",
            "known_username": "admin",
        },
    }
)
