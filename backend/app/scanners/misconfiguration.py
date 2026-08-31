"""Safe HTTP security-misconfiguration checks for authorized web targets."""

from __future__ import annotations

from typing import Any

import httpx

from app.scanners.base import BaseDetector, DetectorResult, ScanContext

REQUIRED_HEADERS = {
    "content-security-policy": "Content-Security-Policy",
    "x-content-type-options": "X-Content-Type-Options",
    "x-frame-options": "X-Frame-Options",
    "referrer-policy": "Referrer-Policy",
}
PROBE_ORIGIN = "https://vulnvista.invalid"


def classify_headers(headers: httpx.Headers, is_https: bool) -> list[dict[str, str]]:
    issues = [
        {"code": "missing_security_header", "severity": "LOW", "detail": name}
        for key, name in REQUIRED_HEADERS.items()
        if key not in headers
    ]
    if is_https and "strict-transport-security" not in headers:
        issues.append(
            {"code": "missing_hsts", "severity": "MEDIUM", "detail": "Strict-Transport-Security"}
        )
    for key in ("server", "x-powered-by"):
        value = headers.get(key, "")
        if any(char.isdigit() for char in value):
            issues.append(
                {"code": "version_disclosure", "severity": "LOW", "detail": f"{key}: {value}"}
            )
    return issues


def classify_cors(headers: httpx.Headers) -> list[dict[str, str]]:
    allowed_origin = headers.get("access-control-allow-origin", "")
    credentials = headers.get("access-control-allow-credentials", "").lower() == "true"
    if allowed_origin == PROBE_ORIGIN and credentials:
        return [
            {"code": "credentialed_origin_reflection", "severity": "HIGH", "detail": allowed_origin}
        ]
    if allowed_origin == "*":
        return [{"code": "wildcard_cors", "severity": "MEDIUM", "detail": "*"}]
    return []


class MisconfigurationDetector(BaseDetector):
    detector_id = "misconfiguration"
    name = "Security Misconfiguration"
    vulnerability_type = "misconfiguration"
    supported_targets = ["webapp", "juice-shop"]

    async def check(self, context: ScanContext) -> DetectorResult:
        try:
            async with httpx.AsyncClient(
                timeout=context.timeout_seconds,
                follow_redirects=True,
                headers=context.extra.get("headers", {}),
            ) as client:
                response = await client.get(context.base_url)
                cors_response = await client.options(
                    context.base_url,
                    headers={
                        "Origin": PROBE_ORIGIN,
                        "Access-Control-Request-Method": "GET",
                    },
                )
        except httpx.HTTPError as exc:
            return self._error_result(str(exc))

        issues = classify_headers(response.headers, response.url.scheme == "https")
        issues.extend(classify_cors(cors_response.headers))
        severity = _worst_severity(issues)
        detected = bool(issues)
        return DetectorResult(
            detector=self.detector_id,
            vulnerability=self.name,
            detected=detected,
            validation_status="CONFIRMED" if detected else "NOT_DETECTED",
            severity=severity,
            confidence="HIGH" if detected else "LOW",
            endpoint=str(response.url),
            description=(
                "The web application exposes unsafe HTTP defaults or overly permissive "
                "cross-origin access."
            ),
            evidence_summary=(
                f"Detected {len(issues)} configuration issue(s): "
                f"{', '.join(issue['code'] for issue in issues)}."
                if issues
                else "Required browser security headers and CORS controls were present."
            ),
            evidence={
                "issues": issues,
                "status_code": response.status_code,
                "cors_status_code": cors_response.status_code,
                "probe_origin": PROBE_ORIGIN,
                "probe": "safe GET and preflight OPTIONS requests only",
            },
            remediation=(
                "Set explicit CSP, anti-framing, MIME-sniffing, referrer, and HSTS policies; "
                "remove framework version headers and allow only trusted CORS origins."
            ),
            cwe="CWE-16",
            cvss_score={"HIGH": 7.5, "MEDIUM": 5.3, "LOW": 3.1, "INFO": 0.0}[severity],
            owasp_category="A05:2021 - Security Misconfiguration",
        )

    def _error_result(self, error: str) -> DetectorResult:
        return DetectorResult(
            detector=self.detector_id,
            vulnerability=self.name,
            detected=False,
            validation_status="ERROR",
            severity="INFO",
            confidence="LOW",
            evidence={"error": error},
            evidence_summary=error,
            cwe="CWE-16",
            owasp_category="A05:2021 - Security Misconfiguration",
        )


def _worst_severity(issues: list[dict[str, Any]]) -> str:
    rank = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
    return max((str(issue["severity"]) for issue in issues), key=rank.get, default="INFO")
