from __future__ import annotations

import uuid
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

    @abstractmethod
    async def check(self, context: ScanContext) -> DetectorResult:
        """Execute the detector's safe test(s) against the target."""

    async def validate(self, result: DetectorResult) -> DetectorResult:
        """Optional secondary validation pass; defaults to a no-op."""
        return result

    async def check_all(self, context: ScanContext) -> list[DetectorResult]:
        """Run every safe check for a target; detectors normally return one result."""
        return [await self.check(context)]

    def build_finding(
        self,
        scan_id: uuid.UUID,
        target_id: uuid.UUID,
        result: DetectorResult,
    ) -> dict[str, Any]:
        """Map a DetectorResult onto the shared Finding schema."""
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