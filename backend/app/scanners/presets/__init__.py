"""Centralized lab-target presets.

Each detector's convenience presets for the bundled lab containers (DVWA,
Juice Shop) live in a sibling module here, built from the shared fragments in
``common``. Detectors import their ``GENERIC_DEFAULTS`` / ``LAB_PRESETS`` from
the matching module; nothing about the detection logic changes.

Anything not listed in a preset falls back to auto-discovery, so these are a
zero-config convenience for the bundled labs, not a requirement.
"""

from app.scanners.presets.common import (
    HOST_ALIASES,
    dvwa_login,
    juice_shop_register,
    juice_shop_rest_login,
    register_aliases,
)

__all__ = [
    "HOST_ALIASES",
    "dvwa_login",
    "juice_shop_register",
    "juice_shop_rest_login",
    "register_aliases",
]
