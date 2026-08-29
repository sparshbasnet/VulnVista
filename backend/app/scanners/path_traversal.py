"""Path traversal / local file inclusion detector.

Only a caller-controlled canary file is requested. The bundled DVWA lab
mounts that canary outside its web root; arbitrary targets must provide their
own ``canary_path`` and ``canary_marker`` in ``Target.scan_config``. A finding
is confirmed only when the exact marker is returned for a traversal payload
and was absent from the permitted baseline response.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any
from urllib.parse import urljoin, urlparse

import httpx

from app.scanners.base import BaseDetector, DetectorResult, ScanContext
from app.scanners.command_injection import (
    Candidate,
    _candidates_from_form,
    _candidates_from_query,
    _explicit_candidate,
    parse_forms,
)
from app.scanners.presets.path_traversal import GENERIC_DEFAULTS, LAB_PRESETS


class DetectorError(Exception):
    """The detector could not produce a trustworthy verdict."""


@dataclass
class Decision:
    detected: bool
    validation_status: str
    confidence: str
    reason: str


def build_traversal_variants(canary_path: str, max_depth: int) -> list[str]:
    """Create absolute and relative variants that all target only the canary."""
    normalized = canary_path.replace("\\", "/")
    relative = normalized.lstrip("/")
    variants = [f"{'../' * depth}{relative}" for depth in range(1, max_depth + 1)]
    variants.append(normalized)
    return list(dict.fromkeys(variants))


def extract_marker_snippet(body: str, marker: str, radius: int = 80) -> str | None:
    """Capture only a small window around the controlled marker."""
    index = body.find(marker)
    if index < 0:
        return None
    start = max(0, index - radius)
    end = min(len(body), index + len(marker) + radius)
    return body[start:end]


def classify(successful_payloads: list[str]) -> Decision:
    if successful_payloads:
        return Decision(
            detected=True,
            validation_status="CONFIRMED",
            confidence="HIGH",
            reason=(
                "the exact controlled canary marker was returned from a file "
                "outside the intended content directory"
            ),
        )
    return Decision(
        detected=False,
        validation_status="NOT_DETECTED",
        confidence="HIGH",
        reason="the controlled canary marker was not returned by any traversal variant",
    )


class PathTraversalDetector(BaseDetector):
    detector_id = "path_traversal"
    name = "Path Traversal / Local File Inclusion"
    vulnerability_type = "path_traversal"
    supported_targets = ["webapp"]

    async def check(self, context: ScanContext) -> DetectorResult:
        parsed = urlparse(context.base_url)
        host = parsed.hostname or ""
        base = f"{parsed.scheme}://{parsed.netloc}"
        cfg = {**GENERIC_DEFAULTS, **LAB_PRESETS.get(host, {}), **context.extra}
        discovery_path = cfg.get("discovery_path") or parsed.path or "/"

        if not cfg.get("canary_path") or not cfg.get("canary_marker"):
            return self._error_result(
                context,
                "A controlled canary is required. Configure both 'canary_path' and "
                "'canary_marker'; the bundled DVWA target provides these automatically.",
            )

        try:
            async with httpx.AsyncClient(
                follow_redirects=True,
                timeout=cfg["request_timeout"],
                cookies=cfg.get("cookies", {}),
                headers=cfg.get("headers", {}),
            ) as client:
                if cfg.get("login_path") and cfg.get("username") and cfg.get("password"):
                    await self._authenticate(client, base, host, cfg)

                explicit = _explicit_candidate(base, cfg)
                if explicit is not None:
                    candidates = [explicit]
                    source = (
                        "explicit configuration" if "parameter" in context.extra else "lab preset"
                    )
                else:
                    candidates = await self._discover_candidates(
                        client, context, base, discovery_path
                    )
                    source = "auto-discovered"
                if not candidates:
                    raise DetectorError(
                        "No form fields or query parameters were found to test. Provide "
                        "'parameter' and 'exec_path'/'injection_url' in the target's scan "
                        "configuration."
                    )

                variants = build_traversal_variants(str(cfg["canary_path"]), int(cfg["max_depth"]))
                successful: list[dict[str, Any]] = []
                probes_run = 0
                last_candidate: Candidate | None = None

                for raw_candidate in candidates[: int(cfg["max_candidates"])]:
                    candidate = await self._prime_candidate(client, raw_candidate)
                    last_candidate = candidate
                    baseline = await self._submit(client, candidate, str(cfg["benign_value"]))
                    if str(cfg["canary_marker"]) in baseline.text:
                        raise DetectorError(
                            "The canary marker already appears in the permitted baseline "
                            "response, so traversal cannot be distinguished safely."
                        )

                    for payload in variants:
                        response = await self._submit(client, candidate, payload)
                        probes_run += 1
                        snippet = extract_marker_snippet(response.text, str(cfg["canary_marker"]))
                        if snippet is not None:
                            successful.append(
                                {
                                    "payload": payload,
                                    "status_code": response.status_code,
                                    "marker_snippet": snippet,
                                }
                            )
                            break
                    if successful:
                        break

                assert last_candidate is not None
                decision = classify([item["payload"] for item in successful])
                evidence = {
                    "canary_path": cfg["canary_path"],
                    "canary_marker": cfg["canary_marker"],
                    "benign_value": cfg["benign_value"],
                    "successful_probes": successful,
                    "variants_attempted": probes_run,
                    "candidate_source": source,
                    "candidates_probed": min(len(candidates), int(cfg["max_candidates"])),
                    "sensitive_system_files_probed": False,
                }
                return self._result(last_candidate, decision, evidence)
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
        data = {f.name: f.value for f in form.fields if f.type == "hidden"} if form else {}
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

    async def _discover_candidates(
        self,
        client: httpx.AsyncClient,
        context: ScanContext,
        base: str,
        discovery_path: str,
    ) -> list[Candidate]:
        candidates = _candidates_from_query(context.base_url)
        page = await client.get(urljoin(base + "/", discovery_path.lstrip("/")))
        page.raise_for_status()
        for form in parse_forms(page.text, str(page.url)):
            candidates.extend(_candidates_from_form(form))
        return candidates

    async def _prime_candidate(self, client: httpx.AsyncClient, candidate: Candidate) -> Candidate:
        if candidate.method.upper() != "POST":
            return candidate
        page = await client.get(candidate.url)
        page.raise_for_status()
        forms = parse_forms(page.text, str(page.url))
        form = next((item for item in forms if item.action == candidate.url), None)
        form = form or (forms[0] if forms else None)
        hidden = {f.name: f.value for f in form.fields if f.type == "hidden"} if form else {}
        return Candidate(
            candidate.method,
            candidate.url,
            candidate.param,
            {**hidden, **candidate.fixed_fields},
        )

    async def _submit(
        self, client: httpx.AsyncClient, candidate: Candidate, value: str
    ) -> httpx.Response:
        fields = {**candidate.fixed_fields, candidate.param: value}
        if candidate.method.upper() == "GET":
            return await client.get(candidate.url, params=fields)
        return await client.post(candidate.url, data=fields)

    def _result(
        self, candidate: Candidate, decision: Decision, evidence: dict[str, Any]
    ) -> DetectorResult:
        successful = evidence["successful_probes"]
        payload = successful[0]["payload"] if successful else None
        return DetectorResult(
            detector=self.detector_id,
            vulnerability=self.name,
            detected=decision.detected,
            validation_status=decision.validation_status,
            severity="HIGH" if decision.detected else "INFO",
            confidence=decision.confidence,
            endpoint=candidate.url,
            parameter=candidate.param,
            description=(
                "Attacker-controlled path input can escape its intended directory and read "
                "a file from elsewhere on the server."
            ),
            evidence_summary=(
                f"{decision.reason}; parameter={candidate.param}, "
                f"successful_payload={payload!r}, variants_attempted="
                f"{evidence['variants_attempted']}."
            ),
            evidence=evidence,
            remediation=(
                "Do not construct filesystem paths directly from user input. Resolve paths "
                "against a fixed base directory, reject absolute paths, canonicalize once, "
                "verify the resolved path remains beneath the base, and use an allowlist of "
                "server-side file identifiers instead of client-supplied filenames."
            ),
            cwe="CWE-22",
            cvss_score=7.5 if decision.detected else 0.0,
            owasp_category="A01:2021 - Broken Access Control",
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
            description="Detector could not complete controlled path-traversal validation.",
            evidence_summary=f"Scan error: {message}",
            evidence={"error": message},
            cwe="CWE-22",
            owasp_category="A01:2021 - Broken Access Control",
        )
