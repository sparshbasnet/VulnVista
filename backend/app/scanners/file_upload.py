"""Unrestricted file-upload detector using non-executable canary files.

The detector checks extension and MIME validation with plain-text markers. Its
``.php`` probe contains no PHP tags or executable code; the extension exists
only to verify whether a script-capable filename is accepted. A vulnerability
is confirmed only when the exact marker can be retrieved from a public URL.
"""

from __future__ import annotations

import re
import secrets
from dataclasses import dataclass
from typing import Any
from urllib.parse import urljoin, urlparse

import httpx

from app.scanners.base import (
    BaseDetector,
    DetectorResult,
    ScanContext,
    scope_cfg_to_path,
)
from app.scanners.command_injection import FormSpec, parse_forms
from app.scanners.presets.file_upload import GENERIC_DEFAULTS, LAB_PRESETS

_REJECTION_RE = re.compile(
    r"not\s+allowed|invalid\s+file|unsupported|forbidden|upload\s+failed|"
    r"not\s+uploaded|only\s+(?:image|jpg|jpeg|png|gif)",
    re.IGNORECASE,
)
_HREF_RE = re.compile(r"href=[\"']([^\"']+)[\"']", re.IGNORECASE)


class DetectorError(Exception):
    """The detector could not produce a trustworthy verdict."""


@dataclass
class UploadTarget:
    url: str
    file_field: str
    fixed_fields: dict[str, str]
    source: str


@dataclass(frozen=True)
class ProbeSpec:
    key: str
    filename: str
    content_type: str
    content: bytes
    script_extension: bool = False
    mime_mismatch: bool = False


@dataclass
class Decision:
    detected: bool
    validation_status: str
    confidence: str
    severity: str
    reason: str


def build_probes(marker: str) -> list[ProbeSpec]:
    """Build harmless controls for ordinary, extension, and MIME validation."""
    content = f"{marker}\nHarmless VulnVista upload-validation canary.\n".encode()
    return [
        ProbeSpec(
            key="plain_text_control",
            filename="vulnvista-upload-canary.txt",
            content_type="text/plain",
            content=content,
        ),
        ProbeSpec(
            key="script_extension_plain_text",
            filename="vulnvista-upload-canary.php",
            content_type="text/plain",
            content=content,
            script_extension=True,
            mime_mismatch=True,
        ),
        ProbeSpec(
            key="script_mime_text_extension",
            filename="vulnvista-upload-mime-canary.txt",
            content_type="application/x-httpd-php",
            content=content,
            mime_mismatch=True,
        ),
    ]


def classify(probes: list[dict[str, Any]]) -> Decision:
    script_public = any(
        probe["script_extension"] and probe["publicly_accessible"] for probe in probes
    )
    unsafe_stored = any(
        (probe["script_extension"] or probe["mime_mismatch"]) and probe["upload_accepted"]
        for probe in probes
    )
    if script_public:
        return Decision(
            True,
            "CONFIRMED",
            "HIGH",
            "CRITICAL",
            "a harmless plain-text canary using a script-capable extension was accepted "
            "and retrieved from a public URL",
        )
    if unsafe_stored:
        return Decision(
            True,
            "SUSPECTED",
            "MEDIUM",
            "HIGH",
            "an extension/MIME-mismatch upload appeared accepted, but public retrieval "
            "could not be verified",
        )
    return Decision(
        False,
        "NOT_DETECTED",
        "HIGH",
        "INFO",
        "no script-extension canary was both accepted and publicly retrievable",
    )


def extract_marker_snippet(body: str, marker: str, radius: int = 80) -> str | None:
    index = body.find(marker)
    if index < 0:
        return None
    return body[max(0, index - radius) : index + len(marker) + radius]


def extract_upload_response_snippet(body: str, filename: str, radius: int = 180) -> str:
    """Prefer the upload result surrounding our filename over page boilerplate."""
    index = body.find(filename)
    if index < 0:
        return body[:500]
    return body[max(0, index - radius) : index + len(filename) + radius]


class FileUploadDetector(BaseDetector):
    detector_id = "file_upload"
    name = "Unrestricted File Upload"
    vulnerability_type = "file_upload"
    supported_targets = ["webapp"]

    async def check(self, context: ScanContext) -> DetectorResult:
        parsed = urlparse(context.base_url)
        host = parsed.hostname or ""
        base = f"{parsed.scheme}://{parsed.netloc}"
        cfg = {**GENERIC_DEFAULTS, **LAB_PRESETS.get(host, {}), **context.extra}
        scope_cfg_to_path(cfg, context, "upload_path", "upload_url")
        discovery_path = cfg.get("discovery_path") or parsed.path or "/"

        try:
            async with httpx.AsyncClient(
                follow_redirects=True,
                timeout=cfg["request_timeout"],
                cookies=cfg.get("cookies", {}),
                headers=cfg.get("headers", {}),
            ) as client:
                if cfg.get("login_path") and cfg.get("username") and cfg.get("password"):
                    await self._authenticate(client, base, host, cfg)

                target = await self._resolve_target(client, base, discovery_path, cfg, host)
                marker = f"UPLOAD-{secrets.token_hex(8)}"
                evidence_probes: list[dict[str, Any]] = []
                for probe in build_probes(marker):
                    evidence_probes.append(
                        await self._run_probe(client, target, probe, marker, base, cfg)
                    )

                decision = classify(evidence_probes)
                evidence = {
                    "marker": marker,
                    "form_discovery": target.source,
                    "file_field": target.file_field,
                    "probes": evidence_probes,
                    "contains_executable_code": False,
                    "destructive_payloads_used": False,
                }
                return self._result(target, decision, evidence)
        except DetectorError as exc:
            return self._error_result(context, str(exc))
        except httpx.HTTPError as exc:
            return self._error_result(
                context, f"Could not reach the target ({type(exc).__name__}: {exc})."
            )

    async def _authenticate(
        self, client: httpx.AsyncClient, base: str, host: str, cfg: dict[str, Any]
    ) -> None:
        login_url = urljoin(base + "/", str(cfg["login_path"]).lstrip("/"))
        page = await client.get(login_url)
        page.raise_for_status()
        forms = parse_forms(page.text, str(page.url))
        form = forms[0] if forms else None
        data = (
            {field.name: field.value for field in form.fields if field.type == "hidden"}
            if form
            else {}
        )
        data[cfg.get("username_field", "username")] = cfg["username"]
        data[cfg.get("password_field", "password")] = cfg["password"]
        if cfg.get("login_submit_field"):
            data[cfg["login_submit_field"]] = cfg.get("login_submit_value", "")
        response = await client.post(form.action if form else login_url, data=data)
        if "setup.php" in str(response.url):
            raise DetectorError("DVWA is not initialized; create/reset its database first.")
        if str(cfg["login_path"]) in str(response.url) or "login failed" in response.text.lower():
            raise DetectorError(f"Login failed for user '{cfg['username']}' at {login_url}.")
        for name, value in cfg.get("post_login_cookies", {}).items():
            client.cookies.set(name, value, domain=host, path="/")

    async def _resolve_target(
        self,
        client: httpx.AsyncClient,
        base: str,
        discovery_path: str,
        cfg: dict[str, Any],
        host: str,
    ) -> UploadTarget:
        explicit = bool(cfg.get("upload_url") or cfg.get("upload_path"))
        if cfg.get("upload_url"):
            page_url = str(cfg["upload_url"])
        elif cfg.get("upload_path"):
            page_url = urljoin(base + "/", str(cfg["upload_path"]).lstrip("/"))
        else:
            page_url = urljoin(base + "/", discovery_path.lstrip("/"))

        page = await client.get(page_url)
        page.raise_for_status()
        forms = parse_forms(page.text, str(page.url))
        form = self._select_upload_form(forms, cfg.get("file_field"))
        if form is None:
            raise DetectorError(
                f"No multipart file-upload form was found at {page_url}. Provide "
                "'upload_path'/'upload_url' and 'file_field' in the target scan configuration."
            )
        file_field = str(cfg.get("file_field") or self._file_field(form))
        fixed = {
            field.name: field.value
            for field in form.fields
            if field.type not in {"file", "password", "checkbox", "radio"}
        }
        if cfg.get("submit_field"):
            fixed[str(cfg["submit_field"])] = str(cfg.get("submit_value", ""))
        source = (
            "lab preset"
            if host in LAB_PRESETS and explicit
            else ("explicit configuration" if explicit else "auto-discovered")
        )
        return UploadTarget(form.action, file_field, fixed, source)

    @staticmethod
    def _file_field(form: FormSpec) -> str | None:
        return next((field.name for field in form.fields if field.type == "file"), None)

    def _select_upload_form(
        self, forms: list[FormSpec], configured_field: str | None
    ) -> FormSpec | None:
        if configured_field:
            matched = next(
                (
                    form
                    for form in forms
                    if any(
                        field.name == configured_field and field.type == "file"
                        for field in form.fields
                    )
                ),
                None,
            )
            if matched is not None:
                return matched
        return next((form for form in forms if self._file_field(form)), None)

    async def _run_probe(
        self,
        client: httpx.AsyncClient,
        target: UploadTarget,
        probe: ProbeSpec,
        marker: str,
        base: str,
        cfg: dict[str, Any],
    ) -> dict[str, Any]:
        response = await client.post(
            target.url,
            data=target.fixed_fields,
            files={
                target.file_field: (
                    probe.filename,
                    probe.content,
                    probe.content_type,
                )
            },
        )
        accepted = response.status_code < 400 and not _REJECTION_RE.search(response.text)
        retrieval_url = self._retrieval_url(response.text, probe.filename, base, cfg)
        retrieval_status: int | None = None
        retrieval_content_type: str | None = None
        publicly_accessible = False
        marker_snippet = None
        if retrieval_url:
            retrieved = await client.get(retrieval_url)
            retrieval_status = retrieved.status_code
            retrieval_content_type = retrieved.headers.get("content-type")
            marker_snippet = extract_marker_snippet(retrieved.text, marker)
            publicly_accessible = retrieved.status_code < 400 and marker_snippet is not None

        return {
            "key": probe.key,
            "filename": probe.filename,
            "declared_content_type": probe.content_type,
            "script_extension": probe.script_extension,
            "mime_mismatch": probe.mime_mismatch,
            "contains_executable_code": False,
            "upload_status": response.status_code,
            "upload_accepted": accepted,
            "upload_response_snippet": extract_upload_response_snippet(
                response.text, probe.filename
            ),
            "retrieval_url": retrieval_url,
            "retrieval_status": retrieval_status,
            "retrieval_content_type": retrieval_content_type,
            "publicly_accessible": publicly_accessible,
            "marker_snippet": marker_snippet,
        }

    @staticmethod
    def _retrieval_url(
        upload_body: str, filename: str, base: str, cfg: dict[str, Any]
    ) -> str | None:
        if cfg.get("public_base_url"):
            return urljoin(str(cfg["public_base_url"]).rstrip("/") + "/", filename)
        if cfg.get("public_base_path"):
            root = urljoin(base + "/", str(cfg["public_base_path"]).lstrip("/"))
            return urljoin(root.rstrip("/") + "/", filename)
        for href in _HREF_RE.findall(upload_body):
            if filename in href:
                return urljoin(base + "/", href)
        return None

    def _result(
        self, target: UploadTarget, decision: Decision, evidence: dict[str, Any]
    ) -> DetectorResult:
        public = [probe for probe in evidence["probes"] if probe["publicly_accessible"]]
        return DetectorResult(
            detector=self.detector_id,
            vulnerability=self.name,
            detected=decision.detected,
            validation_status=decision.validation_status,
            severity=decision.severity,
            confidence=decision.confidence,
            endpoint=target.url,
            parameter=target.file_field,
            description=(
                "The application accepts files with a script-capable extension and makes "
                "them publicly retrievable without adequate extension/MIME validation."
            ),
            evidence_summary=(
                f"{decision.reason}; publicly_accessible={[probe['filename'] for probe in public]}."
            ),
            evidence=evidence,
            remediation=(
                "Allowlist required extensions and MIME types, validate file signatures, "
                "generate server-side filenames, store uploads outside the web root, disable "
                "script execution in upload directories, and serve files through a download "
                "handler with safe Content-Disposition and Content-Type headers."
            ),
            cwe="CWE-434",
            cvss_score=9.8
            if decision.detected
            else (7.5 if decision.validation_status == "SUSPECTED" else 0.0),
            owasp_category="A04:2021 - Insecure Design",
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
            description="Detector could not complete harmless file-upload validation.",
            evidence_summary=f"Scan error: {message}",
            evidence={"error": message},
            cwe="CWE-434",
            owasp_category="A04:2021 - Insecure Design",
        )
