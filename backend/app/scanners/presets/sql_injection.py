"""Lab presets for the SQL-injection detector."""

from __future__ import annotations

from typing import Any

from app.scanners.presets.common import dvwa_login, register_aliases

GENERIC_DEFAULTS: dict[str, Any] = {
    "benign_value": "1",
    "quote_char": "'",
    "request_timeout": 20.0,
    "max_candidates": 3,
}

# Convenience presets for the bundled lab containers, so their quick-starts keep
# working with zero configuration. Anything not listed here falls back to
# auto-discovery.
LAB_PRESETS: dict[str, dict[str, Any]] = register_aliases(
    {
        "dvwa": {
            **dvwa_login(),
            "injection_paths": [
                "/vulnerabilities/sqli/",
                "/vulnerabilities/sqli_blind/",
            ],
            "parameter": "id",
            "submit_field": "Submit",
            "submit_value": "Submit",
            "method": "GET",
        },
        # Juice Shop's search box is an Angular route (`/#/search?q=`), so the
        # query string never reaches the server and the page itself is a static
        # SPA shell with no server-rendered forms — invisible to auto-discovery
        # either way. The `q` value it types into actually lands, unescaped, in
        # the product-search endpoint's own SQL query (the classic UNION-SQLi
        # challenge), so point straight at that REST endpoint instead of the
        # browser route.
        "juice-shop": {
            "injection_path": "/rest/products/search",
            "parameter": "q",
            "method": "GET",
        },
    }
)
