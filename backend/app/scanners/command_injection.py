"""OS command-injection detector.

The detection *technique* here is generic and evidence-based — it never assumes
a vulnerability exists, it proves one by observing the target actually execute
an injected shell command. Two independent signals are used:

  1. Output-based: inject ``; echo <random-marker>`` and look for the marker
     reflected in the response body. A marker we generated at runtime can only
     appear if the shell ran our ``echo``.
  2. Time-based (blind): inject ``; sleep N`` and compare the response time
     against a benign baseline. A delay of ~N seconds that the baseline does
     not have means the shell ran our ``sleep``.

The DVWA-specific bits (login flow, the ``exec`` endpoint, the ``ip`` field)
live in overridable defaults, not in the detection logic, so the same detector
can be pointed at another target by passing overrides through
``ScanContext.extra``. A ZAP-backed detector can be added later alongside this
one without touching this file.
"""

from __future__ import annotations

import re
import secrets
import time
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlparse

import httpx

from app.scanners.base import BaseDetector, DetectorResult, ScanContext

# Tuning constants for the time-based signal.
SLEEP_SECONDS = 5
# The benign baseline for DVWA already runs `ping -c 4`, which costs a few
# seconds, so we compare *deltas* rather than absolute time. Require most of the
# injected sleep to show up before we trust the blind signal.
TIME_THRESHOLD_MS = 4000

# Lab defaults target DVWA's "Command Injection" exercise at the low security
# level. Everything here is overridable via ScanContext.extra.
DEFAULTS: dict[str, Any] = {
    "login_path": "/login.php",
    "exec_path": "/vulnerabilities/exec/",
    "parameter": "ip",
    "submit_field": "Submit",
    "submit_value": "Submit",
    "username": "admin",
    "password": "password",
    "security": "low",
    "benign_value": "127.0.0.1",
    "separator": ";",
    "request_timeout": 20.0,
}

_USER_TOKEN_RE = re.compile(
    r"name=['\"]user_token['\"]\s+value=['\"]([0-9a-fA-F]+)['\"]"
)
_PRE_BLOCK_RE = re.compile(r"<pre[^>]*>(.*?)</pre>", re.IGNORECASE | re.DOTALL)


class DetectorError(Exception):
    """A detector could not run to completion — carries a human-readable reason
    that is surfaced to the user (distinct from a raw transport error)."""


def extract_user_token(html: str) -> str | None:
    """Pull DVWA's anti-CSRF ``user_token`` out of a form, if present."""
    match = _USER_TOKEN_RE.search(html)
    return match.group(1) if match else None


def extract_command_output(html: str) -> str | None:
    """Return the text of the first ``<pre>`` block — where DVWA renders the
    output of the executed command."""
    match = _PRE_BLOCK_RE.search(html)
    if not match:
        return None
    return re.sub(r"<[^>]+>", "", match.group(1)).strip()


@dataclass
class Decision:
    detected: bool
    validation_status: str
    confidence: str
    reason: str


def classify(marker_reflected: bool, time_delta_ms: float, threshold_ms: float) -> Decision:
    """Turn the two raw signals into a validation verdict.

    Kept pure (no I/O) so the decision policy can be unit-tested directly.
    """
    if marker_reflected and time_delta_ms >= threshold_ms:
        return Decision(True, "CONFIRMED", "HIGH", "output marker reflected and response delayed")
    if marker_reflected:
        return Decision(True, "CONFIRMED", "HIGH", "injected output marker reflected in response")
    if time_delta_ms >= threshold_ms:
        return Decision(True, "CONFIRMED", "MEDIUM", "blind time-based delay observed")
    return Decision(
        False, "NOT_DETECTED", "LOW", "no injected command output or timing delay observed"
    )


class CommandInjectionDetector(BaseDetector):
    detector_id = "command_injection"
    name = "OS Command Injection"
    vulnerability_type = "command_injection"
    supported_targets = ["dvwa", "webapp"]

    async def check(self, context: ScanContext) -> DetectorResult:
        cfg = {**DEFAULTS, **context.extra}
        # Normalise to scheme://host — DVWA's login/exec paths hang off the site
        # root, so we ignore any path the user pasted (e.g. .../vulnerabilities/exec).
        parsed = urlparse(context.base_url)
        base = f"{parsed.scheme}://{parsed.netloc}"
        host = parsed.hostname or ""

        try:
            async with httpx.AsyncClient(
                follow_redirects=True, timeout=cfg["request_timeout"]
            ) as client:
                await self._authenticate(client, base, host, cfg)

                exec_url = f"{base}{cfg['exec_path']}"
                page = await client.get(exec_url)
                page.raise_for_status()
                if cfg["login_path"] in str(page.url):
                    raise DetectorError(
                        "Redirected to the login page when opening the command-injection "
                        "page — the session is not authenticated. Verify credentials and "
                        "that the target is DVWA."
                    )
                exec_token = extract_user_token(page.text)

                benign = cfg["benign_value"]
                sep = cfg["separator"]

                # 1. Baseline (benign input) — gives us the "normal" response time.
                _, baseline_ms = await self._submit(client, exec_url, cfg, benign, exec_token)

                # 2. Output-based probe with a runtime-random marker.
                marker = f"CMDINJ-{secrets.token_hex(4)}"
                out_body, marker_ms = await self._submit(
                    client, exec_url, cfg, f"{benign}{sep} echo {marker}", exec_token
                )
                output = extract_command_output(out_body) or ""
                marker_reflected = marker in out_body

                # 3. Blind time-based probe.
                _, blind_ms = await self._submit(
                    client, exec_url, cfg, f"{benign}{sep} sleep {SLEEP_SECONDS}", exec_token
                )
                time_delta_ms = blind_ms - baseline_ms

            decision = classify(marker_reflected, time_delta_ms, TIME_THRESHOLD_MS)
            return self._result(context, cfg, decision, {
                "marker": marker,
                "marker_reflected": marker_reflected,
                "output_snippet": output[:500],
                "baseline_ms": round(baseline_ms, 1),
                "marker_probe_ms": round(marker_ms, 1),
                "blind_probe_ms": round(blind_ms, 1),
                "time_delta_ms": round(time_delta_ms, 1),
                "time_threshold_ms": TIME_THRESHOLD_MS,
                "payloads": {
                    "baseline": benign,
                    "output": f"{benign}{sep} echo {marker}",
                    "blind": f"{benign}{sep} sleep {SLEEP_SECONDS}",
                },
                "auth": f"form login as '{cfg['username']}' at security level '{cfg['security']}'",
            })
        except DetectorError as exc:
            return self._error_result(context, cfg, str(exc))
        except httpx.HTTPError as exc:
            return self._error_result(
                context, cfg, f"Could not reach the target ({type(exc).__name__}: {exc})."
            )

    async def _authenticate(
        self, client: httpx.AsyncClient, base: str, host: str, cfg: dict[str, Any]
    ) -> None:
        """Log into DVWA and pin the security level cookie for the session."""
        login_url = f"{base}{cfg['login_path']}"
        page = await client.get(login_url)
        page.raise_for_status()

        data = {
            "username": cfg["username"],
            "password": cfg["password"],
            "Login": "Login",
        }
        token = extract_user_token(page.text)
        if token:
            data["user_token"] = token

        resp = await client.post(login_url, data=data)
        final_url = str(resp.url)

        # DVWA redirects every request to setup.php until its database exists.
        if "setup.php" in final_url:
            raise DetectorError(
                "DVWA's database is not initialized. In your browser open DVWA's setup page "
                "(e.g. http://localhost:8081/setup.php) and click 'Create / Reset Database', "
                "then run the scan again."
            )
        if cfg["login_path"] in final_url or "login failed" in resp.text.lower():
            raise DetectorError(
                f"Login failed for user '{cfg['username']}'. Check the credentials "
                "(DVWA's default is admin / password)."
            )

        # DVWA reads the security level from this cookie on every request.
        client.cookies.set("security", cfg["security"], domain=host, path="/")

    async def _submit(
        self,
        client: httpx.AsyncClient,
        exec_url: str,
        cfg: dict[str, Any],
        payload: str,
        token: str | None,
    ) -> tuple[str, float]:
        """POST one payload to the vulnerable parameter, returning (body, elapsed_ms)."""
        data = {cfg["parameter"]: payload, cfg["submit_field"]: cfg["submit_value"]}
        if token:
            data["user_token"] = token
        start = time.perf_counter()
        resp = await client.post(exec_url, data=data)
        elapsed_ms = (time.perf_counter() - start) * 1000
        resp.raise_for_status()
        return resp.text, elapsed_ms

    def _result(
        self,
        context: ScanContext,
        cfg: dict[str, Any],
        decision: Decision,
        evidence: dict[str, Any],
    ) -> DetectorResult:
        endpoint = f"{context.base_url.rstrip('/')}{cfg['exec_path']}"
        summary = (
            f"{decision.reason}. "
            f"baseline={evidence['baseline_ms']}ms, blind={evidence['blind_probe_ms']}ms "
            f"(Δ{evidence['time_delta_ms']}ms), marker_reflected={evidence['marker_reflected']}."
        )
        return DetectorResult(
            detector=self.detector_id,
            vulnerability=self.name,
            detected=decision.detected,
            validation_status=decision.validation_status,
            severity="CRITICAL" if decision.detected else "INFO",
            confidence=decision.confidence,
            endpoint=endpoint,
            parameter=cfg["parameter"],
            description=(
                "The target executes attacker-controlled input as an OS shell "
                "command. An injected command's output was reflected in the "
                "response and/or a timing delay confirmed execution."
            ),
            evidence_summary=summary,
            evidence=evidence,
            remediation=(
                "Never pass user input to a shell. Use parameterised APIs that "
                "invoke binaries directly without a shell (e.g. execve with an "
                "argument vector), validate/allowlist input, and drop shell "
                "metacharacters."
            ),
            cwe="CWE-78",
            cvss_score=9.8 if decision.detected else 0.0,
            owasp_category="A03:2021 - Injection",
        )

    def _error_result(
        self, context: ScanContext, cfg: dict[str, Any], message: str
    ) -> DetectorResult:
        return DetectorResult(
            detector=self.detector_id,
            vulnerability=self.name,
            detected=False,
            validation_status="ERROR",
            severity="INFO",
            confidence="LOW",
            endpoint=f"{context.base_url.rstrip('/')}{cfg['exec_path']}",
            parameter=cfg["parameter"],
            description="Detector could not complete against the target.",
            evidence_summary=f"Scan error: {message}",
            evidence={"error": message},
            cwe="CWE-78",
            owasp_category="A03:2021 - Injection",
        )
