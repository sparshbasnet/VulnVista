from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any


@dataclass
class ScanContext:
    """Everything a detector needs to run against one target."""

    target_id: str
    base_url: str
    timeout_seconds: float = 15.0
    extra: dict[str, Any] = field(default_factory=dict)


def scope_cfg_to_path(
    cfg: dict[str, Any],
    context: ScanContext,
    primary_key: str,
    *alt_keys: str,
) -> None:
    """Make a scoped run attack exactly its in-scope path, in place on ``cfg``.

    A scoped scan runs a path-level detector once per in-scope path, passing that
    path as ``context.extra['discovery_path']``. Without this, a lab preset's
    fixed endpoint (e.g. DVWA's ``injection_paths``) overrides the scoped path, so
    every in-scope path re-probes the same preset endpoint(s) and the same
    finding is reported once per path. Here we point the detector's endpoint at
    the scoped path and drop the preset's endpoint overrides (``primary_key`` and
    any ``alt_keys``), so each in-scope path is attacked once. No-op when the run
    isn't scoped (no ``discovery_path`` in ``extra``).
    """
    scoped_path = context.extra.get("discovery_path")
    if not scoped_path:
        return
    for key in alt_keys:
        cfg.pop(key, None)
    cfg[primary_key] = scoped_path


@dataclass
class DetectorResult:
    """Common result contract every detector must return (plan section 6)."""

    detector: str
    vulnerability: str
    detected: bool
    validation_status: str
    severity: str
    confidence: str
    endpoint: str | None = None
    parameter: str | None = None
    description: str | None = None
    evidence_summary: str | None = None
    evidence: dict[str, Any] = field(default_factory=dict)
    remediation: str | None = None
    cwe: str | None = None
    cve: str | None = None
    cvss_score: float | None = None
    owasp_category: str | None = None


class BaseDetector(ABC):
    """Shared interface implemented by every vulnerability-specific detector module."""

    detector_id: str
    name: str
    vulnerability_type: str
    supported_targets: list[str] = []
    # How a scoped scan (one with an in-scope path list) should invoke this
    # detector. "path": run once per in-scope path, with that path passed as
    # ``discovery_path`` — for detectors that probe a specific page/endpoint.
    # "host": run once for the whole target regardless of path — for host- or
    # network-level detectors (TLS, open services, misconfig) where per-path
    # runs would just duplicate the same finding.
    scan_scope: str = "path"

    @abstractmethod
    async def check(self, context: ScanContext) -> DetectorResult:
        """Execute the detector's safe test(s) against the target."""

    async def check_many(self, context: ScanContext) -> list[DetectorResult]:
        """Execute the detector and return one or more result records.

        Most detectors emit exactly one result and rely on this default
        wrapper. Detectors that can produce multiple independent findings
        from one run (e.g. multiple explicit endpoints) should override this.
        """
        return [await self.check(context)]

    async def validate(self, context: ScanContext, result: DetectorResult) -> DetectorResult:
        """Optional secondary validation pass (e.g. cross-checking against an
        external scanner); defaults to a no-op."""
        return result

    def build_finding(self, scan_id: str, target_id: str, result: DetectorResult) -> dict[str, Any]:
        """Map a DetectorResult onto the shared Finding schema (scalar columns only).

        Evidence detail (payloads, timings, response snippets) is persisted
        separately as Evidence rows by the scan runner.
        """
        return {
            "scan_id": scan_id,
            "target_id": target_id,
            "detector_id": self.detector_id,
            "vulnerability_name": result.vulnerability,
            "severity": result.severity,
            "confidence": result.confidence,
            "validation_status": result.validation_status,
            "description": result.description,
            "affected_endpoint": result.endpoint,
            "parameter": result.parameter,
            "evidence_summary": result.evidence_summary,
            "remediation": result.remediation,
            "cwe": result.cwe,
            "cve": result.cve,
            "cvss_score": result.cvss_score,
            "owasp_category": result.owasp_category,
        }
