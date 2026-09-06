"""Sensitive-file-exposure detector.

Evidence-based, same as ``command_injection.py`` / ``weak_auth.py``: it never
assumes a file is exposed just because a GET returns HTTP 200 — a
single-page app's server can fall back to serving ``index.html`` for
unmatched routes, which would otherwise look like a false positive for
every candidate path. Instead, each candidate is compared against a
baseline probe of a random, guaranteed-nonexistent path. Only a response
that actually differs from that "not found" fingerprint (different status
code, or same 200 status but different body) counts as a real exposure.

The candidate list is generic — well-known backup, environment/config,
credential-store, source-map, log, and repository-metadata paths that
apply to any web stack (Git, PHP, Node, .NET, Docker, ...). A known lab
host (Juice Shop) additionally gets its own intentionally-seeded ``/ftp``
files layered on top via ``LAB_PRESETS``, so its quick-start keeps
surfacing those without special-casing the detection logic itself. Only
status/content-type/content-length are recorded as evidence — response
bodies are never captured or stored, so no unrelated data (personal or
otherwise) is collected. The full candidate list can be overridden outright
via ``ScanContext.extra['candidate_files']``.
"""

from __future__ import annotations

import secrets
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlparse

import httpx

from app.scanners.base import BaseDetector, DetectorResult, ScanContext
from app.scanners.presets.sensitive_files import DEFAULTS, GENERIC_CANDIDATE_FILES, LAB_PRESETS

CATEGORY_SEVERITY: dict[str, str] = {
    "credential_store": "CRITICAL",
    "configuration_file": "HIGH",
    "repository_metadata": "HIGH",
    "backup_file": "MEDIUM",
    "log_file": "MEDIUM",
    "confidential_document": "MEDIUM",
    "source_map": "LOW",
    "hidden_internal_file": "LOW",
}

CATEGORY_CWE: dict[str, str] = {
    "credential_store": "CWE-538",
    "configuration_file": "CWE-538",
    "repository_metadata": "CWE-527",
    "backup_file": "CWE-530",
    "log_file": "CWE-532",
    "confidential_document": "CWE-538",
    "source_map": "CWE-540",
    "hidden_internal_file": "CWE-538",
}

_SEVERITY_RANK: dict[str, int] = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
_SEVERITY_CVSS: dict[str, float] = {
    "INFO": 0.0, "LOW": 3.1, "MEDIUM": 5.3, "HIGH": 7.5, "CRITICAL": 9.1,
}


@dataclass
class Decision:
    detected: bool
    validation_status: str
    confidence: str
    severity: str
    reason: str
    worst_category: str | None


def is_exposed(
    status_code: int,
    content_length: int,
    baseline_status: int,
    baseline_length: int,
) -> bool:
    """Whether a candidate response is a real exposure, not the target's
    generic "not found" behaviour (404, or an SPA's catch-all 200 fallback).

    Kept pure (no I/O) so the comparison policy can be unit-tested directly.
    """
    if status_code == 404 or status_code >= 400:
        return False
    return not (status_code == baseline_status and content_length == baseline_length)


def classify(exposed_categories: list[str]) -> Decision:
    """Turn the list of confirmed-exposed categories into a validation verdict.

    Kept pure (no I/O) so the decision policy can be unit-tested directly.
    """
    if not exposed_categories:
        return Decision(
            detected=False,
            validation_status="NOT_DETECTED",
            confidence="LOW",
            severity="INFO",
            reason="no sensitive files were exposed among the candidates checked",
            worst_category=None,
        )

    worst = max(exposed_categories, key=lambda c: _SEVERITY_RANK[CATEGORY_SEVERITY.get(c, "LOW")])
    return Decision(
        detected=True,
        validation_status="CONFIRMED",
        confidence="HIGH",
        severity=CATEGORY_SEVERITY.get(worst, "LOW"),
        reason=(
            f"{len(exposed_categories)} sensitive file(s) directly retrievable "
            f"over HTTP, worst category '{worst}'"
        ),
        worst_category=worst,
    )


class SensitiveFilesDetector(BaseDetector):
    detector_id = "sensitive_files"
    name = "Sensitive File Exposure"
    vulnerability_type = "sensitive_files"
    scan_scope = "host"
    supported_targets = ["webapp"]

    async def check(self, context: ScanContext) -> DetectorResult:
        cfg = {**DEFAULTS, **context.extra}
        parsed = urlparse(context.base_url)
        host = parsed.hostname or ""
        base = f"{parsed.scheme}://{parsed.netloc}"
        candidate_files = cfg.get("candidate_files") or [
            *GENERIC_CANDIDATE_FILES,
            *LAB_PRESETS.get(host, []),
        ]

        try:
            async with httpx.AsyncClient(timeout=cfg["request_timeout"]) as client:
                baseline_status, baseline_length = await self._probe_baseline(client, base)

                exposed: list[dict[str, Any]] = []
                checked: list[str] = []
                for candidate in candidate_files:
                    resp = await client.get(f"{base}{candidate['path']}")
                    checked.append(candidate["path"])
                    content_length = len(resp.content)
                    exposed_now = is_exposed(
                        resp.status_code, content_length, baseline_status, baseline_length
                    )
                    if exposed_now:
                        exposed.append(
                            {
                                "path": candidate["path"],
                                "category": candidate["category"],
                                "status_code": resp.status_code,
                                "content_type": resp.headers.get("content-type", ""),
                                "content_length": content_length,
                            }
                        )

            decision = classify([item["category"] for item in exposed])
            return self._result(context, decision, exposed, checked, base)
        except httpx.HTTPError as exc:
            return self._error_result(
                context, base, f"Could not reach the target ({type(exc).__name__}: {exc})."
            )

    async def _probe_baseline(self, client: httpx.AsyncClient, base: str) -> tuple[int, int]:
        """Fetch a random, guaranteed-nonexistent path once, to fingerprint
        the target's genuine "not found" response (status + body length)."""
        probe_path = f"/vulnvista-sensitive-files-probe-{secrets.token_hex(8)}.txt"
        resp = await client.get(f"{base}{probe_path}")
        return resp.status_code, len(resp.content)

    def _result(
        self,
        context: ScanContext,
        decision: Decision,
        exposed: list[dict[str, Any]],
        checked: list[str],
        base: str,
    ) -> DetectorResult:
        endpoint = f"{base}{exposed[0]['path']}" if exposed else f"{base}/"
        summary = (
            f"{decision.reason}. Checked {len(checked)} candidate path(s); "
            f"exposed: {[item['path'] for item in exposed]}."
        )
        cwe = "CWE-538"
        if decision.worst_category:
            cwe = CATEGORY_CWE.get(decision.worst_category, "CWE-538")
        return DetectorResult(
            detector=self.detector_id,
            vulnerability=self.name,
            detected=decision.detected,
            validation_status=decision.validation_status,
            severity=decision.severity,
            confidence=decision.confidence,
            endpoint=endpoint,
            parameter=None,
            description=(
                "The target exposes sensitive files — backups, configuration, "
                "repository metadata, source maps, or internal documents — "
                "directly over HTTP, allowing an unauthenticated attacker to "
                "retrieve information that should never be publicly reachable."
            ),
            evidence_summary=summary,
            evidence={
                "exposed_files": exposed,
                "checked_paths": checked,
                "checked_count": len(checked),
            },
            remediation=(
                "Remove backup, configuration, and version-control artifacts "
                "from the web root and deployment bundle; disable directory "
                "listing; exclude source maps from production builds; and add "
                "an automated pre-deploy check that fails the build if "
                "disallowed file extensions (.bak, .env, .map, .git/*, .kdbx, "
                ".yml) are publicly reachable."
            ),
            cwe=cwe,
            cvss_score=_SEVERITY_CVSS[decision.severity],
            owasp_category="A05:2021 - Security Misconfiguration",
        )

    def _error_result(self, context: ScanContext, base: str, message: str) -> DetectorResult:
        return DetectorResult(
            detector=self.detector_id,
            vulnerability=self.name,
            detected=False,
            validation_status="ERROR",
            severity="INFO",
            confidence="LOW",
            endpoint=f"{base}/",
            parameter=None,
            description="Detector could not complete against the target.",
            evidence_summary=f"Scan error: {message}",
            evidence={"error": message},
            cwe="CWE-538",
            owasp_category="A05:2021 - Security Misconfiguration",
        )
