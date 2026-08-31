"""Shared building blocks for the per-detector lab presets.

These capture the facts that recur across detectors — the bundled lab hosts'
Docker Compose service-name aliases and their login/registration flows — so a
change to (say) the DVWA quick-start credentials is made in exactly one place.

Login/registration fragments are exposed as factory functions that return a
fresh deep copy, so a detector can never mutate another detector's preset
through a shared nested object.
"""

from __future__ import annotations

from copy import deepcopy
from typing import Any

# Canonical lab host -> the Docker Compose service-name alias the backend sees
# for it on vulnvista_net. Presets are written against the canonical host name;
# register_aliases() mirrors each present entry onto its service-name key.
HOST_ALIASES: dict[str, str] = {
    "dvwa": "vulnvista_dvwa",
    "juice-shop": "vulnvista_juice_shop",
}


def register_aliases(presets: dict[str, Any]) -> dict[str, Any]:
    """Return ``presets`` with a service-name alias added for every known host.

    Replaces the ``LAB_PRESETS["vulnvista_dvwa"] = LAB_PRESETS["dvwa"]`` line
    each detector used to repeat. The alias points at the same object, exactly
    as before, so behaviour is unchanged.
    """
    for canonical, alias in HOST_ALIASES.items():
        if canonical in presets:
            presets[alias] = presets[canonical]
    return presets


# --- Shared login / registration flows --------------------------------------

# DVWA's low-security login, shared by every detector that drives DVWA.
_DVWA_LAB_LOGIN: dict[str, Any] = {
    "login_path": "/login.php",
    "login_submit_field": "Login",
    "login_submit_value": "Login",
    "username": "admin",
    "password": "password",
    "post_login_cookies": {"security": "low"},
}

# Juice Shop's JSON REST login, shared by the IDOR, JWT, and SSRF detectors.
_JUICE_SHOP_REST_LOGIN: dict[str, Any] = {
    "login_path": "/rest/user/login",
    "login_username_field": "email",
    "login_password_field": "password",
    "login_request_style": "json",
}

# Juice Shop's account-registration flow, shared by IDOR and JWT for
# provisioning synthetic @lab.invalid accounts.
_JUICE_SHOP_REGISTER: dict[str, Any] = {
    "register_path": "/api/Users/",
    "register_request_style": "json",
    "register_password_repeat_field": "passwordRepeat",
    "register_extra_fields": {
        "securityQuestion": {"id": 1},
        "securityAnswer": "vulnvista lab",
    },
}


def dvwa_login() -> dict[str, Any]:
    """Fresh copy of DVWA's low-security login fields."""
    return deepcopy(_DVWA_LAB_LOGIN)


def juice_shop_rest_login() -> dict[str, Any]:
    """Fresh copy of Juice Shop's JSON REST login fields."""
    return deepcopy(_JUICE_SHOP_REST_LOGIN)


def juice_shop_register() -> dict[str, Any]:
    """Fresh copy of Juice Shop's account-registration fields."""
    return deepcopy(_JUICE_SHOP_REGISTER)
