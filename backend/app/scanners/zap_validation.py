from __future__ import annotations

import asyncio
from typing import Any

from app.scanners.base import DetectorResult, ScanContext
from app.services.zap_client import zap_client

ZAP_SUPPORTED_DETECTORS = {
    "file_upload",
    "path_traversal",
    "csrf",
    "jwt_session",
    "misconfiguration",
}

_ALERT_TERMS = {
    "file_upload": ("upload",),
    "path_traversal": ("path traversal", "directory traversal", "remote file inclusion"),
    "csrf": ("csrf", "cross-site request forgery", "anti-csrf"),
    "jwt_session": ("cookie", "session", "jwt", "authentication"),
    "misconfiguration": (
        "content security policy",
        "cross-domain",
        "cors",
        "header",
        "server leaks",
        "timestamp disclosure",
        "x-powered-by",
    ),
}

_RISK_SEVERITY = {
    "informational": "INFO",
    "low": "LOW",
    "medium": "MEDIUM",
    "high": "HIGH",
}


def _matching_alerts(detector_id: str, alerts: list[dict[str, Any]]) -> list[dict[str, str]]:
    terms = _ALERT_TERMS[detector_id]
    matches = []
    for alert in alerts:
        name = str(alert.get("alert", ""))
        if not any(term in name.lower() for term in terms):
            continue
        matches.append(
            {
                key: str(alert[key])
                for key in ("alert", "risk", "confidence", "url", "param", "cweid")
                if alert.get(key) not in (None, "")
            }
        )
    return matches


async def corroborate_with_zap(
    detector_id: str,
    context: ScanContext,
    result: DetectorResult,
) -> DetectorResult:
    """Add optional ZAP passive evidence without replacing the primary detector."""
    if detector_id not in ZAP_SUPPORTED_DETECTORS or not context.extra.get("use_zap"):
        return result

    zap_evidence: dict[str, Any] = {"enabled": True, "mode": "passive"}
    try:
        ready = await asyncio.to_thread(zap_client.is_ready)
        if not ready:
            zap_evidence.update(reachable=False, message="ZAP did not respond")
            result.evidence["zap_validation"] = zap_evidence
            return result

        alerts = await asyncio.to_thread(zap_client.passive_scan, context.base_url)
        matches = _matching_alerts(detector_id, alerts)
        zap_evidence.update(reachable=True, matching_alerts=matches)
        result.evidence["zap_validation"] = zap_evidence

        if not matches:
            return result

        if result.detected:
            result.validation_status = "CONFIRMED"
            result.confidence = "HIGH"
            result.evidence_summary = (
                f"{result.evidence_summary or 'Primary detector identified the issue.'} "
                f"ZAP independently reported {len(matches)} relevant passive alert(s)."
            )
            return result

        result.detected = True
        result.validation_status = "SUSPECTED"
        result.confidence = "MEDIUM"
        result.severity = _RISK_SEVERITY.get(matches[0].get("risk", "").lower(), "MEDIUM")
        result.evidence_summary = (
            f"ZAP reported {len(matches)} relevant passive alert(s); "
            "manual confirmation is required."
        )
        return result
    except Exception as exc:
        zap_evidence.update(reachable=False, message=f"ZAP validation unavailable: {exc}")
        result.evidence["zap_validation"] = zap_evidence
        return result
