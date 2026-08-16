"""Passive security-misconfiguration detector for HTTP applications.

The detector uses only GET requests and evaluates six independent groups of
configuration controls: response security headers, session-cookie attributes,
directory indexes, default server pages, verbose error responses, and exposed
diagnostic/management endpoints.  A random missing path is used as a baseline
so a single-page application's catch-all response is not treated as an exposed
endpoint.  Response bodies are inspected in memory for narrow signatures but
are never retained; evidence contains only the matching signature and a short,
centred snippet.
"""

from __future__ import annotations

import re
import secrets
from dataclasses import asdict, dataclass
from typing import Any
from urllib.parse import urlparse

import httpx

from app.scanners.base import BaseDetector, DetectorResult, ScanContext

DEFAULTS: dict[str, Any] = {
    "request_timeout": 15.0,
    "directory_paths": ["/uploads/", "/backup/", "/logs/", "/ftp/"],
    "diagnostic_paths": [
        "/server-status",
        "/actuator",
        "/actuator/env",
        "/debug/vars",
        "/phpinfo.php",
    ],
}

_SEVERITY_RANK = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
_SEVERITY_CVSS = {"INFO": 0.0, "LOW": 3.1, "MEDIUM": 5.3, "HIGH": 7.5, "CRITICAL": 9.1}

_DIRECTORY_SIGNATURES = (
    "<title>index of /",
    "<h1>index of /",
    "directory listing for /",
)
_DEFAULT_PAGE_SIGNATURES = (
    "apache2 debian default page",
    "apache http server test page",
    "welcome to nginx!",
    "internet information services",
    "iis windows server",
)
_ERROR_SIGNATURES = (
    "traceback (most recent call last)",
    "werkzeug debugger",
    "django debug mode",
    "the debugger caught an exception",
    "stack trace:",
    "system.nullreferenceexception",
    "org.springframework.web.util.nestedservletexception",
)
_SERVICE_SIGNATURES: dict[str, tuple[tuple[str, ...], str, str]] = {
    "/server-status": (("apache server status for",), "MEDIUM", "CWE-200"),
    "/actuator": (('"_links"', '"health"'), "MEDIUM", "CWE-200"),
    "/actuator/env": (('"propertysources"',), "HIGH", "CWE-200"),
    "/debug/vars": (('"cmdline"', '"memstats"'), "HIGH", "CWE-489"),
    "/phpinfo.php": (("<title>phpinfo()", "php version"), "HIGH", "CWE-200"),
}
_SESSION_COOKIE_RE = re.compile(r"(?:session|sess|sid|auth|token|jwt)", re.I)
_VERSION_RE = re.compile(r"\b\d+\.\d+(?:\.\d+)?\b")


@dataclass
class Weakness:
    check: str
    detail: str
    severity: str
    cwe: str
    endpoint: str
    evidence: dict[str, Any]


@dataclass
class Decision:
    detected: bool
    validation_status: str
    confidence: str
    severity: str
    reason: str
    worst: Weakness | None


def classify(weaknesses: list[Weakness]) -> Decision:
    """Reduce independently observed weaknesses to the shared verdict."""
    if not weaknesses:
        return Decision(
            detected=False,
            validation_status="NOT_DETECTED",
            confidence="MEDIUM",
            severity="INFO",
            reason="no defined configuration weakness was observed",
            worst=None,
        )

    worst = max(weaknesses, key=lambda item: _SEVERITY_RANK[item.severity])
    return Decision(
        detected=True,
        validation_status="CONFIRMED",
        confidence="HIGH",
        severity=worst.severity,
        reason=f"{len(weaknesses)} configuration weakness(es) directly observed",
        worst=worst,
    )


def check_security_headers(headers: httpx.Headers, scheme: str, endpoint: str) -> list[Weakness]:
    """Check browser-facing defensive headers without inflating their severity."""
    missing: list[str] = []
    csp = headers.get("content-security-policy", "")
    if not csp:
        missing.append("Content-Security-Policy")
    if headers.get("x-content-type-options", "").lower() != "nosniff":
        missing.append("X-Content-Type-Options: nosniff")
    if not headers.get("x-frame-options") and "frame-ancestors" not in csp.lower():
        missing.append("X-Frame-Options or CSP frame-ancestors")
    if not headers.get("referrer-policy"):
        missing.append("Referrer-Policy")
    if scheme == "https" and not headers.get("strict-transport-security"):
        missing.append("Strict-Transport-Security")

    weaknesses: list[Weakness] = []
    if missing:
        severity = "MEDIUM" if len(missing) >= 3 else "LOW"
        weaknesses.append(
            Weakness(
                check="security_headers",
                detail=f"Missing or ineffective headers: {', '.join(missing)}",
                severity=severity,
                cwe="CWE-693",
                endpoint=endpoint,
                evidence={"missing_headers": missing},
            )
        )

    disclosures = {
        name: value
        for name in ("server", "x-powered-by")
        if (value := headers.get(name)) and (_VERSION_RE.search(value) or name == "x-powered-by")
    }
    if disclosures:
        weaknesses.append(
            Weakness(
                check="version_disclosure",
                detail="Technology or precise server version disclosed in response headers",
                severity="LOW",
                cwe="CWE-200",
                endpoint=endpoint,
                evidence={"disclosed_headers": disclosures},
            )
        )
    return weaknesses


def check_cookie_attributes(set_cookie_headers: list[str], endpoint: str) -> list[Weakness]:
    """Evaluate only session-like cookies and never retain their values."""
    weaknesses: list[Weakness] = []
    for raw_cookie in set_cookie_headers:
        first = raw_cookie.split(";", 1)[0]
        name = first.split("=", 1)[0].strip()
        if not name or not _SESSION_COOKIE_RE.search(name):
            continue
        attributes = {part.strip().lower() for part in raw_cookie.split(";")[1:]}
        missing = []
        if "secure" not in attributes:
            missing.append("Secure")
        if "httponly" not in attributes:
            missing.append("HttpOnly")
        if not any(attribute.startswith("samesite=") for attribute in attributes):
            missing.append("SameSite")
        if missing:
            severity = "MEDIUM" if {"Secure", "HttpOnly"} & set(missing) else "LOW"
            weaknesses.append(
                Weakness(
                    check="cookie_attributes",
                    detail=f"Session-like cookie '{name}' is missing: {', '.join(missing)}",
                    severity=severity,
                    cwe="CWE-614" if "Secure" in missing else "CWE-1004",
                    endpoint=endpoint,
                    evidence={"cookie_name": name, "missing_attributes": missing},
                )
            )
    return weaknesses


def _matching_signature(body: str, signatures: tuple[str, ...]) -> str | None:
    lowered = body.lower()
    return next((signature for signature in signatures if signature in lowered), None)


def _snippet(body: str, signature: str, radius: int = 80) -> str:
    lowered = body.lower()
    index = lowered.find(signature)
    if index < 0:
        return ""
    start = max(0, index - radius)
    end = min(len(body), index + len(signature) + radius)
    return re.sub(r"\s+", " ", body[start:end]).strip()


def _normalise_paths(value: Any, defaults: list[str]) -> list[str]:
    paths = value if isinstance(value, list) else defaults
    result: list[str] = []
    for item in paths:
        if not isinstance(item, str) or not item.strip():
            continue
        path = item.strip()
        result.append(path if path.startswith("/") else f"/{path}")
    return result


class MisconfigurationDetector(BaseDetector):
    detector_id = "misconfiguration"
    name = "Security Misconfiguration"
    vulnerability_type = "misconfiguration"
    supported_targets = ["webapp"]

    async def check(self, context: ScanContext) -> DetectorResult:
        parsed = urlparse(context.base_url)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            return self._error_result(context, "Target must be an absolute HTTP(S) URL.")

        cfg = {**DEFAULTS, **context.extra}
        origin = f"{parsed.scheme}://{parsed.netloc}"
        start_url = context.base_url.rstrip("/") or origin
        directory_paths = _normalise_paths(cfg.get("directory_paths"), DEFAULTS["directory_paths"])
        diagnostic_paths = _normalise_paths(
            cfg.get("diagnostic_paths"), DEFAULTS["diagnostic_paths"]
        )
        checked = {
            "base_url": start_url,
            "directory_paths": directory_paths,
            "diagnostic_paths": diagnostic_paths,
        }

        try:
            async with httpx.AsyncClient(
                timeout=cfg["request_timeout"],
                follow_redirects=True,
                headers={"User-Agent": "VulnVista-Misconfiguration-Detector/1.0"},
            ) as client:
                base_response = await client.get(start_url)
                weaknesses = check_security_headers(
                    base_response.headers, parsed.scheme, str(base_response.url)
                )
                weaknesses.extend(
                    check_cookie_attributes(
                        base_response.headers.get_list("set-cookie"), str(base_response.url)
                    )
                )
                weaknesses.extend(self._check_default_page(base_response))

                baseline_path = f"/vulnvista-misconfiguration-{secrets.token_hex(8)}"
                baseline = await client.get(f"{origin}{baseline_path}")
                weaknesses.extend(self._check_error_leakage(baseline))

                for path in directory_paths:
                    response = await client.get(f"{origin}{path}")
                    weaknesses.extend(self._check_directory_listing(response))

                for path in diagnostic_paths:
                    response = await client.get(f"{origin}{path}")
                    if self._is_baseline_match(response, baseline):
                        continue
                    weaknesses.extend(self._check_exposed_service(path, response))

            decision = classify(weaknesses)
            return self._result(decision, weaknesses, checked, start_url)
        except httpx.HTTPError as exc:
            return self._error_result(
                context, f"Could not reach the target ({type(exc).__name__}: {exc})."
            )

    @staticmethod
    def _is_baseline_match(response: httpx.Response, baseline: httpx.Response) -> bool:
        return response.status_code == baseline.status_code and response.content == baseline.content

    @staticmethod
    def _check_directory_listing(response: httpx.Response) -> list[Weakness]:
        signature = _matching_signature(response.text, _DIRECTORY_SIGNATURES)
        if response.status_code >= 400 or not signature:
            return []
        return [
            Weakness(
                check="directory_listing",
                detail="Web-server directory index is publicly exposed",
                severity="MEDIUM",
                cwe="CWE-548",
                endpoint=str(response.url),
                evidence={
                    "status_code": response.status_code,
                    "matched_signature": signature,
                    "response_snippet": _snippet(response.text, signature),
                },
            )
        ]

    @staticmethod
    def _check_default_page(response: httpx.Response) -> list[Weakness]:
        signature = _matching_signature(response.text, _DEFAULT_PAGE_SIGNATURES)
        if response.status_code >= 400 or not signature:
            return []
        return [
            Weakness(
                check="default_page",
                detail="Default web-server installation page is exposed",
                severity="LOW",
                cwe="CWE-1188",
                endpoint=str(response.url),
                evidence={
                    "status_code": response.status_code,
                    "matched_signature": signature,
                    "response_snippet": _snippet(response.text, signature),
                },
            )
        ]

    @staticmethod
    def _check_error_leakage(response: httpx.Response) -> list[Weakness]:
        signature = _matching_signature(response.text, _ERROR_SIGNATURES)
        if not signature:
            return []
        return [
            Weakness(
                check="error_information_leakage",
                detail="Verbose framework or stack-trace information appears in an error response",
                severity="MEDIUM",
                cwe="CWE-209",
                endpoint=str(response.url),
                evidence={
                    "status_code": response.status_code,
                    "matched_signature": signature,
                    "response_snippet": _snippet(response.text, signature),
                },
            )
        ]

    @staticmethod
    def _check_exposed_service(path: str, response: httpx.Response) -> list[Weakness]:
        matches = [
            (signature, severity, cwe)
            for signatures, severity, cwe in _SERVICE_SIGNATURES.values()
            if (signature := _matching_signature(response.text, signatures))
        ]
        if response.status_code >= 400 or not matches:
            return []
        signature, severity, cwe = max(matches, key=lambda item: _SEVERITY_RANK[item[1]])
        return [
            Weakness(
                check="exposed_service",
                detail=f"Diagnostic or management endpoint exposed at {path}",
                severity=severity,
                cwe=cwe,
                endpoint=str(response.url),
                evidence={
                    "status_code": response.status_code,
                    "matched_signature": signature,
                    "response_snippet": _snippet(response.text, signature),
                },
            )
        ]

    def _result(
        self,
        decision: Decision,
        weaknesses: list[Weakness],
        checked: dict[str, Any],
        start_url: str,
    ) -> DetectorResult:
        worst = decision.worst
        checks = sorted({item.check for item in weaknesses})
        summary = f"{decision.reason}. Checks with findings: {checks or ['none']}."
        return DetectorResult(
            detector=self.detector_id,
            vulnerability=self.name,
            detected=decision.detected,
            validation_status=decision.validation_status,
            severity=decision.severity,
            confidence=decision.confidence,
            endpoint=worst.endpoint if worst else start_url,
            parameter=None,
            description=(
                "The target has one or more clearly defined deployment weaknesses, such as "
                "missing browser protections, insecure session-cookie attributes, directory "
                "indexes, default pages, verbose errors, or exposed diagnostic services."
            ),
            evidence_summary=summary,
            evidence={
                "weaknesses": [asdict(item) for item in weaknesses],
                "weakness_count": len(weaknesses),
                "checks": checked,
                "request_methods": ["GET"],
            },
            remediation=(
                "Apply a hardened production configuration: set CSP, nosniff, anti-framing, "
                "Referrer-Policy, and HSTS on HTTPS; mark session cookies Secure, HttpOnly, "
                "and SameSite; disable directory indexes and default pages; return generic "
                "error responses; suppress product/version banners; and restrict diagnostic "
                "or management endpoints to an authenticated administration network."
            ),
            cwe=worst.cwe if worst else "CWE-16",
            cvss_score=_SEVERITY_CVSS[decision.severity],
            owasp_category="A05:2021 - Security Misconfiguration",
        )

    def _error_result(self, context: ScanContext, message: str) -> DetectorResult:
        return DetectorResult(
            detector=self.detector_id,
            vulnerability=self.name,
            detected=False,
            validation_status="ERROR",
            severity="INFO",
            confidence="LOW",
            endpoint=context.base_url,
            description="Detector could not complete against the target.",
            evidence_summary=f"Scan error: {message}",
            evidence={"error": message},
            cwe="CWE-16",
            owasp_category="A05:2021 - Security Misconfiguration",
        )
