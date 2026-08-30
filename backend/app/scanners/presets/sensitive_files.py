"""Lab presets and candidate paths for the sensitive-file-exposure detector.

The generic candidate list applies to any target regardless of stack; lab
presets layer extra host-specific paths on top. Only status/content-type/
content-length are ever recorded as evidence — response bodies are never
captured — so no unrelated data is collected.
"""

from __future__ import annotations

from typing import Any

from app.scanners.presets.common import register_aliases

DEFAULTS: dict[str, Any] = {
    "request_timeout": 15.0,
}

# Well-known paths that apply to any target, regardless of stack, plus the
# category of sensitive data each would expose if actually reachable.
# Evidence-based: a candidate that doesn't exist is simply absent from the
# finding, never reported.
GENERIC_CANDIDATE_FILES: list[dict[str, str]] = [
    # version control
    {"path": "/.git/HEAD", "category": "repository_metadata"},
    {"path": "/.git/config", "category": "repository_metadata"},
    {"path": "/.git/logs/HEAD", "category": "repository_metadata"},
    {"path": "/.svn/entries", "category": "repository_metadata"},
    {"path": "/.hg/hgrc", "category": "repository_metadata"},
    # environment / configuration
    {"path": "/.env", "category": "configuration_file"},
    {"path": "/.env.local", "category": "configuration_file"},
    {"path": "/.env.production", "category": "configuration_file"},
    {"path": "/config.php.bak", "category": "configuration_file"},
    {"path": "/wp-config.php.bak", "category": "configuration_file"},
    {"path": "/web.config.bak", "category": "configuration_file"},
    {"path": "/appsettings.json", "category": "configuration_file"},
    {"path": "/docker-compose.yml", "category": "configuration_file"},
    {"path": "/Dockerfile", "category": "configuration_file"},
    # backups
    {"path": "/backup.zip", "category": "backup_file"},
    {"path": "/backup.sql", "category": "backup_file"},
    {"path": "/database.sql", "category": "backup_file"},
    {"path": "/dump.sql", "category": "backup_file"},
    {"path": "/site.tar.gz", "category": "backup_file"},
    # credential stores
    {"path": "/.aws/credentials", "category": "credential_store"},
    {"path": "/id_rsa", "category": "credential_store"},
    {"path": "/.ssh/id_rsa", "category": "credential_store"},
    {"path": "/.htpasswd", "category": "credential_store"},
    # source maps
    {"path": "/main.js.map", "category": "source_map"},
    {"path": "/vendor.js.map", "category": "source_map"},
    {"path": "/runtime.js.map", "category": "source_map"},
    {"path": "/app.js.map", "category": "source_map"},
    {"path": "/bundle.js.map", "category": "source_map"},
    # logs
    {"path": "/error.log", "category": "log_file"},
    {"path": "/debug.log", "category": "log_file"},
    {"path": "/npm-debug.log", "category": "log_file"},
    # hidden internal / IDE files
    {"path": "/.DS_Store", "category": "hidden_internal_file"},
    {"path": "/.idea/workspace.xml", "category": "hidden_internal_file"},
    {"path": "/.vscode/settings.json", "category": "hidden_internal_file"},
]

# Extra candidates layered on top of GENERIC_CANDIDATE_FILES for known lab
# hosts, keyed by hostname — Juice Shop deliberately seeds these under /ftp.
LAB_PRESETS: dict[str, list[dict[str, str]]] = register_aliases(
    {
        "juice-shop": [
            {"path": "/ftp/acquisitions.md", "category": "confidential_document"},
            {"path": "/ftp/eastere.gg", "category": "hidden_internal_file"},
            {"path": "/ftp/package.json.bak", "category": "backup_file"},
            {"path": "/ftp/coupons_2013.md.bak", "category": "backup_file"},
            {"path": "/ftp/suspicious_errors.yml", "category": "log_file"},
            {"path": "/ftp/incident-support.kdbx", "category": "credential_store"},
        ],
    }
)
