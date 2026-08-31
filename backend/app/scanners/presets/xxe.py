"""Lab presets for the XXE detector.

The Juice Shop preset targets its deprecated B2B file-upload endpoint
(routes/fileUpload.ts -> handleXmlUpload): a multipart upload accepting a .xml
file, parsed with entity resolution enabled before being rejected with a 410.
No authentication required. Juice Shop disables this code path by default when
it detects it is running in a container — see lab/docker-compose.yml for the
override that re-enables it.
"""

from __future__ import annotations

from typing import Any

from app.scanners.presets.common import register_aliases

GENERIC_DEFAULTS: dict[str, Any] = {
    "request_timeout": 15.0,
    "oob_wait_seconds": 3.0,
    "request_style": "raw",
    "callback_host": "backend",
    # A file present on virtually every Linux container, containing nothing
    # but public OS branding info — never sensitive data. Set either to a
    # falsy value in scan config to skip this probe.
    "local_file_path": "/etc/os-release",
    "local_file_fingerprint": "PRETTY_NAME=",
}

LAB_PRESETS: dict[str, dict[str, Any]] = register_aliases(
    {
        "juice-shop": {
            "xml_endpoint": "/file-upload",
            "request_style": "multipart",
            "upload_field": "file",
            "upload_filename": "probe.xml",
        },
    }
)
