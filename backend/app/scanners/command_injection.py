"""OS command-injection detector.

The detection *technique* is generic and evidence-based — it never assumes a
vulnerability exists, it proves one by observing the target actually execute an
injected shell command. Two independent signals are used:

  1. Output-based: inject ``; echo <random-marker>`` and look for the marker
     reflected in the response body. A marker we generated at runtime can only
     appear if the shell ran our ``echo``.
  2. Time-based (blind): inject ``; sleep N`` and compare the response time
     against a benign baseline. A delay of ~N seconds that the baseline does
     not have means the shell ran our ``sleep``.

The injection point itself is generic too: given no override, the detector
fetches the target page, parses its HTML forms (and any query-string
parameters already on the pasted URL) with a small stdlib-only parser, and
probes each candidate text field/parameter in turn. A known lab host (DVWA)
gets a preset pointing straight at its exercise instead of discovery, and any
host can be pointed at an explicit parameter/path/login via
``ScanContext.extra`` (populated from ``Target.scan_config``), which always
wins over both the generic defaults and the lab preset.
"""

from __future__ import annotations

import asyncio
import logging
import re
import secrets
import time
from dataclasses import dataclass, replace
from html.parser import HTMLParser
from typing import Any
from urllib.parse import parse_qs, urlencode, urljoin, urlparse

import httpx

from app.scanners.base import BaseDetector, DetectorResult, ScanContext
from app.scanners.presets.command_injection import GENERIC_DEFAULTS, LAB_PRESETS

logger = logging.getLogger(__name__)

# Tuning constants for the time-based signal.
SLEEP_SECONDS = 5
# Some targets already run a slow benign command (e.g. DVWA's baseline runs
# `ping -c 4`), so we compare *deltas* rather than absolute time. Require most
# of the injected sleep to show up before we trust the blind signal.
TIME_THRESHOLD_MS = 4000

_PRE_BLOCK_RE = re.compile(r"<pre[^>]*>(.*?)</pre>", re.IGNORECASE | re.DOTALL)
_TAG_RE = re.compile(r"<[^>]+>")

# Text-like input types (and textareas) are candidate injection points.
# Everything else (password/hidden/submit/checkbox/radio/file/...) is either
# excluded outright or carried through unchanged as a fixed field.
_CANDIDATE_TYPES = {"text", "search", "url", "tel", "email", "number", "textarea"}
_SKIP_FIXED_TYPES = {"password", "checkbox", "radio", "file", "image", "reset"}


class DetectorError(Exception):
    """A detector could not run to completion — carries a human-readable reason
    that is surfaced to the user (distinct from a raw transport error)."""


@dataclass
class FormField:
    name: str
    type: str
    value: str = ""


@dataclass
class FormSpec:
    action: str
    method: str
    fields: list[FormField]


class _FormHTMLParser(HTMLParser):
    """Collects <form> elements (action, method, input/textarea/select fields)."""

    def __init__(self, page_url: str) -> None:
        super().__init__(convert_charrefs=True)
        self.page_url = page_url
        self.forms: list[FormSpec] = []
        self._in_form = False
        self._action = ""
        self._method = "GET"
        self._fields: list[FormField] = []
        self._select_name: str | None = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attrs_d = {k: (v or "") for k, v in attrs}
        if tag == "form":
            self._in_form = True
            self._action = urljoin(self.page_url, attrs_d.get("action") or self.page_url)
            self._method = (attrs_d.get("method") or "GET").upper()
            self._fields = []
        elif tag == "input" and self._in_form:
            name = attrs_d.get("name")
            if name:
                field_type = (attrs_d.get("type") or "text").lower()
                value = attrs_d.get("value", "")
                self._fields.append(FormField(name=name, type=field_type, value=value))
        elif tag == "textarea" and self._in_form:
            name = attrs_d.get("name")
            if name:
                self._fields.append(FormField(name=name, type="textarea"))
        elif tag == "select" and self._in_form:
            self._select_name = attrs_d.get("name") or None
            if self._select_name:
                self._fields.append(FormField(name=self._select_name, type="select"))
        elif tag == "option" and self._select_name:
            value = attrs_d.get("value")
            last = self._fields[-1] if self._fields else None
            if value and last is not None and last.name == self._select_name and not last.value:
                last.value = value

    def handle_endtag(self, tag: str) -> None:
        if tag == "form" and self._in_form:
            self._in_form = False
            form = FormSpec(action=self._action, method=self._method, fields=self._fields)
            self.forms.append(form)
            self._fields = []
        elif tag == "select":
            self._select_name = None


def parse_forms(html: str, page_url: str) -> list[FormSpec]:
    """Parse every <form> on a page into (action, method, fields), resolving
    relative actions against ``page_url``. Stdlib-only — no HTML dependency."""
    parser = _FormHTMLParser(page_url)
    parser.feed(html)
    return parser.forms


def extract_evidence_snippet(html: str, marker: str) -> str | None:
    """Return readable evidence around the injected marker: the first <pre>
    block if the target renders command output that way (DVWA does), else a
    stripped window of body text around the marker's position — works
    regardless of how an arbitrary target formats its output."""
    match = _PRE_BLOCK_RE.search(html)
    if match:
        return _TAG_RE.sub("", match.group(1)).strip()
    idx = html.find(marker)
    if idx == -1:
        return None
    window = html[max(0, idx - 100) : idx + len(marker) + 100]
    return _TAG_RE.sub(" ", window).strip()


@dataclass
class Candidate:
    """One injectable field this detector will probe: submit ``param`` inside
    ``fixed_fields`` (the form/query's other fields, held at their default or
    benign values) to ``url`` via ``method``."""

    method: str
    url: str
    param: str
    fixed_fields: dict[str, str]


def _candidates_from_query(target_url: str) -> list[Candidate]:
    """If the pasted target URL already has a query string (e.g.
    ``?ip=1.1.1.1``), treat each param as a high-priority GET candidate."""
    parsed = urlparse(target_url)
    if not parsed.query:
        return []
    params = parse_qs(parsed.query, keep_blank_values=True)
    path_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
    return [
        Candidate(
            method="GET",
            url=path_url,
            param=name,
            fixed_fields={k: v[0] for k, v in params.items() if k != name},
        )
        for name in params
    ]


def _candidates_from_form(form: FormSpec) -> list[Candidate]:
    injectable = [f for f in form.fields if f.type in _CANDIDATE_TYPES]
    candidates = []
    for target in injectable:
        fixed = {
            f.name: f.value
            for f in form.fields
            if f is not target and f.type not in _SKIP_FIXED_TYPES
        }
        candidates.append(
            Candidate(method=form.method, url=form.action, param=target.name, fixed_fields=fixed)
        )
    return candidates


def _explicit_candidate(base: str, cfg: dict[str, Any]) -> Candidate | None:
    """Build the single targeted candidate when the caller (a lab preset or an
    explicit ScanContext.extra override) names an exact parameter/path."""
    if "parameter" not in cfg:
        return None
    if "injection_url" in cfg:
        url = cfg["injection_url"]
    elif "exec_path" in cfg:
        url = f"{base}{cfg['exec_path']}"
    else:
        return None
    fixed = {}
    if cfg.get("submit_field"):
        fixed[cfg["submit_field"]] = cfg.get("submit_value", "")
    method = cfg.get("method", "POST")
    return Candidate(method=method, url=url, param=cfg["parameter"], fixed_fields=fixed)


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


# --- Optional OWASP ZAP cross-check -----------------------------------------
#
# Opt-in (``ScanContext.extra['use_zap']``): runs ZAP's active scanner — an
# independent engine with its own OS-command-injection payload library (scan
# rule 90020) — against the same endpoint/parameter the manual probes already
# identified, purely as a second opinion. Manual evidence always stands on its
# own; ZAP either raises confidence when it agrees or is reported as a
# disagreement, never silently overrides what the manual probes already proved.
# Requires the separate `tools/docker-compose.yml` ZAP service to be running
# and reachable — if it isn't, the cross-check is skipped and the manual result
# is returned as-is. Mirrors the SQL-injection detector's cross-check.

ZAP_CMDI_CWE = "78"
ZAP_CMDI_PLUGIN_ID = "90020"  # ZAP's "Remote OS Command Injection" active scan rule
ZAP_DEFAULT_TIMEOUT_SECONDS = 90.0
ZAP_POLL_INTERVAL_SECONDS = 2.0


def _is_cmdi_alert(alert: dict[str, Any]) -> bool:
    if str(alert.get("cweid", "")) == ZAP_CMDI_CWE:
        return True
    if str(alert.get("pluginId", "")) == ZAP_CMDI_PLUGIN_ID:
        return True
    return "command injection" in str(alert.get("alert", "")).lower()


@dataclass
class ZapOutcome:
    used: bool
    reachable: bool
    completed: bool
    detected: bool
    alerts: list[dict[str, Any]]
    note: str

    def to_evidence(self) -> dict[str, Any]:
        return {
            "used": self.used,
            "reachable": self.reachable,
            "scan_completed": self.completed,
            "detected": self.detected,
            "alert_count": len(self.alerts),
            "alerts": [
                {
                    "name": a.get("alert"),
                    "risk": a.get("risk"),
                    "confidence": a.get("confidence"),
                    "param": a.get("param"),
                    "cweid": a.get("cweid"),
                    "evidence": a.get("evidence"),
                }
                for a in self.alerts[:5]
            ],
            "note": self.note,
        }


def combine_with_zap(
    manual_detected: bool,
    manual_confidence: str,
    zap_used: bool,
    zap_reachable: bool,
    zap_detected: bool,
) -> tuple[bool, str, str]:
    """Fold an optional ZAP cross-check into the manual result, returning
    (detected, validation_status, confidence).

    Kept pure (no I/O) so the merge policy can be unit-tested directly.
    Manual evidence always stands: if ZAP wasn't used or isn't reachable,
    the manual verdict passes through completely unchanged.
    """
    if not zap_used or not zap_reachable:
        return (
            manual_detected,
            ("CONFIRMED" if manual_detected else "NOT_DETECTED"),
            manual_confidence,
        )
    if manual_detected and zap_detected:
        return True, "CONFIRMED", "HIGH"
    if manual_detected and not zap_detected:
        return True, "CONFIRMED", manual_confidence
    if not manual_detected and zap_detected:
        return True, "CONFIRMED", "MEDIUM"
    return False, "NOT_DETECTED", "LOW"


class CommandInjectionDetector(BaseDetector):
    detector_id = "command_injection"
    name = "OS Command Injection"
    vulnerability_type = "command_injection"

    async def check(self, context: ScanContext) -> DetectorResult:
        parsed = urlparse(context.base_url)
        host = parsed.hostname or ""
        base = f"{parsed.scheme}://{parsed.netloc}"
        cfg = {**GENERIC_DEFAULTS, **LAB_PRESETS.get(host, {}), **context.extra}
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

                explicit = _explicit_candidate(base, cfg)
                if explicit is not None:
                    candidates = [explicit]
                    source = "explicit configuration"
                else:
                    candidates = await self._discover_candidates(
                        client, context, cfg, base, discovery_path
                    )
                    source = "auto-discovered"
                    if not candidates:
                        raise DetectorError(
                            f"No form fields or query parameters were found at "
                            f"{base}{discovery_path} to test for command injection. Provide "
                            "an explicit 'parameter' and 'exec_path'/'injection_url' override "
                            "in the target's scan configuration if the injectable field isn't "
                            "reachable from there."
                        )

                candidate = evidence = decision = None
                for raw_candidate in candidates[: cfg["max_candidates"]]:
                    candidate = await self._prime_candidate(client, raw_candidate, cfg)
                    decision, evidence = await self._probe(client, candidate, cfg)
                    if decision.detected:
                        break

                assert candidate is not None and decision is not None and evidence is not None
                evidence["candidates_probed"] = min(len(candidates), cfg["max_candidates"])
                evidence["candidate_source"] = source
                return self._result(context, candidate, decision, evidence)
        except DetectorError as exc:
            return self._error_result(context, str(exc))
        except httpx.HTTPError as exc:
            return self._error_result(
                context, f"Could not reach the target ({type(exc).__name__}: {exc})."
            )

    async def validate(self, context: ScanContext, result: DetectorResult) -> DetectorResult:
        """Optional OWASP ZAP cross-check — see the "Optional OWASP ZAP
        cross-check" section for ``ScanContext.extra['use_zap']``. Never raises:
        any failure reaching or running ZAP degrades to "cross-check
        unavailable", leaving the manual result exactly as ``check()`` produced
        it."""
        if not context.extra.get("use_zap") or result.validation_status == "ERROR":
            return result

        zap = await self._run_zap_cross_check(context, result)
        detected, validation_status, confidence = combine_with_zap(
            manual_detected=result.detected,
            manual_confidence=result.confidence,
            zap_used=zap.used,
            zap_reachable=zap.reachable,
            zap_detected=zap.detected,
        )

        if not zap.reachable:
            note = f" OWASP ZAP cross-check requested but unavailable: {zap.note}."
        elif result.detected and zap.detected:
            note = (
                " OWASP ZAP's active scanner independently confirmed OS command injection "
                "on this endpoint."
            )
        elif result.detected and not zap.detected:
            note = " OWASP ZAP's active scanner did not corroborate this — manual evidence stands."
        elif not result.detected and zap.detected:
            note = (
                " Manual probing found nothing, but OWASP ZAP's active scanner flagged command "
                "injection here — recommend manual follow-up."
            )
        else:
            note = " OWASP ZAP's active scanner also found nothing."

        return replace(
            result,
            detected=detected,
            validation_status=validation_status,
            confidence=confidence,
            severity="CRITICAL" if detected else result.severity,
            cvss_score=9.8 if detected else result.cvss_score,
            evidence_summary=(result.evidence_summary or "") + note,
            evidence={**result.evidence, "zap": zap.to_evidence()},
        )

    async def _run_zap_cross_check(
        self, context: ScanContext, result: DetectorResult
    ) -> ZapOutcome:
        try:
            from app.services.zap_client import zap_client
        except Exception as exc:  # missing dependency, bad config, etc.
            logger.warning("ZAP cross-check unavailable: %s", exc)
            return ZapOutcome(True, False, False, False, [], f"ZAP client unavailable ({exc})")

        if not result.endpoint or not result.parameter:
            return ZapOutcome(True, False, False, False, [], "no endpoint/parameter to hand to ZAP")

        loop = asyncio.get_running_loop()
        timeout_seconds = float(
            context.extra.get("zap_timeout_seconds", ZAP_DEFAULT_TIMEOUT_SECONDS)
        )

        try:
            reachable = await loop.run_in_executor(None, zap_client.is_ready)
        except Exception as exc:
            return ZapOutcome(True, False, False, False, [], f"ZAP health check failed ({exc})")
        if not reachable:
            return ZapOutcome(
                True, False, False, False, [], "ZAP daemon not reachable at the configured API URL"
            )

        method = str(result.evidence.get("method", "GET")).upper()
        fixed_fields = result.evidence.get("fixed_fields") or {}
        baseline_value = result.evidence.get("payloads", {}).get("baseline", "127.0.0.1")
        params = {**fixed_fields, result.parameter: baseline_value}

        try:
            if method == "GET":
                scan_id = await loop.run_in_executor(
                    None,
                    lambda: zap_client.zap.ascan.scan(url=f"{result.endpoint}?{urlencode(params)}"),
                )
            else:
                scan_id = await loop.run_in_executor(
                    None,
                    lambda: zap_client.zap.ascan.scan(
                        url=result.endpoint, method=method, postdata=urlencode(params)
                    ),
                )
        except Exception as exc:
            return ZapOutcome(
                True, True, False, False, [], f"could not start ZAP active scan ({exc})"
            )

        completed = False
        started = loop.time()
        try:
            while True:
                status = await loop.run_in_executor(
                    None, lambda: zap_client.zap.ascan.status(scan_id)
                )
                if int(status) >= 100:
                    completed = True
                    break
                if loop.time() - started >= timeout_seconds:
                    break
                await asyncio.sleep(ZAP_POLL_INTERVAL_SECONDS)
        except Exception as exc:
            return ZapOutcome(
                True, True, False, False, [], f"ZAP active scan polling failed ({exc})"
            )

        try:
            alerts = await loop.run_in_executor(
                None, lambda: zap_client.zap.core.alerts(baseurl=result.endpoint)
            )
        except Exception as exc:
            return ZapOutcome(
                True, True, completed, False, [], f"could not retrieve ZAP alerts ({exc})"
            )

        cmdi_alerts = [a for a in alerts if _is_cmdi_alert(a)]
        note = (
            "scan completed"
            if completed
            else (
                f"scan did not finish within {timeout_seconds:.0f}s — "
                "reporting alerts found so far"
            )
        )
        return ZapOutcome(True, True, completed, bool(cmdi_alerts), cmdi_alerts, note)

    async def _authenticate(
        self, client: httpx.AsyncClient, base: str, host: str, cfg: dict[str, Any]
    ) -> None:
        """Best-effort form login: GET the login page, resubmit its hidden
        fields unchanged (carries any CSRF token regardless of its field name)
        plus the given username/password. Only ever runs when the caller
        (a lab preset or an explicit override) supplied login_path/username/password."""
        login_url = urljoin(base + "/", cfg["login_path"])
        page = await client.get(login_url)
        page.raise_for_status()

        forms = parse_forms(page.text, str(page.url))
        login_form = forms[0] if forms else None

        data: dict[str, str] = {}
        if login_form:
            data.update({f.name: f.value for f in login_form.fields if f.type == "hidden"})
        data[cfg.get("username_field", "username")] = cfg["username"]
        data[cfg.get("password_field", "password")] = cfg["password"]
        if cfg.get("login_submit_field"):
            data[cfg["login_submit_field"]] = cfg.get("login_submit_value", "")

        post_url = login_form.action if login_form else login_url
        resp = await client.post(post_url, data=data)
        final_url = str(resp.url)

        # DVWA redirects every request to setup.php until its database exists.
        if "setup.php" in final_url:
            raise DetectorError(
                "DVWA's database is not initialized. In your browser open DVWA's setup page "
                "(e.g. http://localhost:8080/setup.php) and click 'Create / Reset Database', "
                "then run the scan again."
            )
        if cfg["login_path"] in final_url or "login failed" in resp.text.lower():
            raise DetectorError(
                f"Login failed for user '{cfg['username']}' at {login_url}. Check the credentials."
            )

        for name, value in cfg.get("post_login_cookies", {}).items():
            client.cookies.set(name, value, domain=host, path="/")

    async def _discover_candidates(
        self,
        client: httpx.AsyncClient,
        context: ScanContext,
        cfg: dict[str, Any],
        base: str,
        discovery_path: str,
    ) -> list[Candidate]:
        candidates = _candidates_from_query(context.base_url)
        discovery_url = urljoin(base + "/", discovery_path)
        try:
            page = await client.get(discovery_url)
            page.raise_for_status()
        except httpx.HTTPError:
            pass
        else:
            for form in parse_forms(page.text, str(page.url)):
                candidates.extend(_candidates_from_form(form))
        return candidates

    async def _prime_candidate(
        self, client: httpx.AsyncClient, candidate: Candidate, cfg: dict[str, Any]
    ) -> Candidate:
        """GET the candidate's own page first so any hidden/CSRF fields on its
        form are captured and carried through on the probe requests. Skipped
        for GET candidates (no form submission, nothing to carry)."""
        if candidate.method != "POST":
            return candidate

        page = await client.get(candidate.url)
        page.raise_for_status()
        if cfg.get("login_path") and cfg["login_path"] in str(page.url):
            raise DetectorError(
                "Redirected to the login page when opening the target form — the session "
                "is not authenticated. Verify the credentials and login path."
            )

        forms = parse_forms(page.text, str(page.url))
        by_action = next((f for f in forms if f.action == candidate.url), None)
        matched = by_action or (forms[0] if forms else None)
        hidden = {f.name: f.value for f in matched.fields if f.type == "hidden"} if matched else {}
        merged_fields = {**hidden, **candidate.fixed_fields}
        return Candidate(candidate.method, candidate.url, candidate.param, merged_fields)

    async def _probe(
        self, client: httpx.AsyncClient, candidate: Candidate, cfg: dict[str, Any]
    ) -> tuple[Decision, dict[str, Any]]:
        """Run the baseline / marker-echo / blind-timing probes against one candidate."""
        benign = cfg["benign_value"]
        sep = cfg["separator"]

        _, baseline_ms = await self._submit(client, candidate, benign)

        marker = f"CMDINJ-{secrets.token_hex(4)}"
        out_body, marker_ms = await self._submit(client, candidate, f"{benign}{sep} echo {marker}")
        output = extract_evidence_snippet(out_body, marker) or ""
        marker_reflected = marker in out_body

        _, blind_ms = await self._submit(client, candidate, f"{benign}{sep} sleep {SLEEP_SECONDS}")
        time_delta_ms = blind_ms - baseline_ms

        decision = classify(marker_reflected, time_delta_ms, TIME_THRESHOLD_MS)
        evidence = {
            "marker": marker,
            "marker_reflected": marker_reflected,
            "method": candidate.method,
            "fixed_fields": candidate.fixed_fields,
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
        }
        return decision, evidence

    async def _submit(
        self, client: httpx.AsyncClient, candidate: Candidate, payload: str
    ) -> tuple[str, float]:
        """Submit one payload into the candidate's parameter, returning (body, elapsed_ms)."""
        data = {**candidate.fixed_fields, candidate.param: payload}
        start = time.perf_counter()
        if candidate.method == "GET":
            resp = await client.get(candidate.url, params=data)
        else:
            resp = await client.post(candidate.url, data=data)
        elapsed_ms = (time.perf_counter() - start) * 1000
        resp.raise_for_status()
        return resp.text, elapsed_ms

    def _result(
        self,
        context: ScanContext,
        candidate: Candidate,
        decision: Decision,
        evidence: dict[str, Any],
    ) -> DetectorResult:
        summary = (
            f"{decision.reason} (probed {evidence['candidates_probed']} candidate field(s), "
            f"{evidence['candidate_source']}). "
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
            endpoint=candidate.url,
            parameter=candidate.param,
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

    def _error_result(self, context: ScanContext, message: str) -> DetectorResult:
        return DetectorResult(
            detector=self.detector_id,
            vulnerability=self.name,
            detected=False,
            validation_status="ERROR",
            severity="INFO",
            confidence="LOW",
            endpoint=context.base_url,
            parameter=None,
            description="Detector could not complete against the target.",
            evidence_summary=f"Scan error: {message}",
            evidence={"error": message},
            cwe="CWE-78",
            owasp_category="A03:2021 - Injection",
        )
