"""Lab presets for the discovery crawler (``app.services.crawler``).

Juice Shop is an Angular single-page app: its ``index.html`` is a bootstrap
script tag with no ``<a href>`` links, and Angular injects the real navigation
at runtime in a browser. The crawler only parses static HTML, so it can never
find Juice Shop's pages by following links. ``extra_seeds`` lists the REST/API
paths already trusted elsewhere in this codebase (see the per-detector presets
in this package) so discovery at least surfaces the real server-side attack
surface. Angular's client-only hash routes (``/#/login`` etc.) are omitted —
the crawler strips URL fragments everywhere, so they would all collapse onto
the same ``/`` entry rather than showing up as distinct paths.
"""

from __future__ import annotations

from typing import Any

from app.scanners.presets.common import register_aliases

LAB_PRESETS: dict[str, dict[str, Any]] = register_aliases(
    {
        "juice-shop": {
            "extra_seeds": [
                "/rest/user/login",
                "/rest/user/whoami",
                "/rest/user/security-question",
                "/rest/products/search",
                "/rest/basket",
                "/api/Users/",
                "/profile/image/url",
                "/file-upload",
            ],
        },
    }
)
