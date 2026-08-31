"""Lab presets for the XSS detector."""

from __future__ import annotations

from typing import Any

from app.scanners.presets.common import dvwa_login, register_aliases

GENERIC_DEFAULTS: dict[str, Any] = {
    "request_timeout": 15.0,
    "browser_timeout_ms": 10_000,
    "max_candidates": 5,
    "headless": True,
}

LAB_PRESETS: dict[str, dict[str, Any]] = register_aliases(
    {
        "dvwa": {
            **dvwa_login(),
            "exec_path": "/vulnerabilities/xss_r/",
            "parameter": "name",
            "method": "GET",
        },
        # Juice Shop's search input is an Angular route, so it is invisible to
        # server-rendered form discovery. The `q` value is deliberately passed to
        # an [innerHTML] sink via bypassSecurityTrustHtml in the bundled lab.
        "juice-shop": {
            "exec_path": "/#/search",
            "parameter": "q",
            "method": "GET",
        },
    }
)
