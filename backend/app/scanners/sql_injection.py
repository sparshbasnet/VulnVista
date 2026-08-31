"""SQL injection detector.

Generic and evidence-based, same technique as ``command_injection.py``: it
never assumes a vulnerability exists, it proves one by observing the target's
own query actually change behaviour under attacker-controlled input. Three
independent signals are used, any one of which is sufficient, matching how a
manual SQLi assessment layers evidence:

  1. Error-based: inject a lone quote character and look for a database error
     signature (MySQL/PostgreSQL/MSSQL/SQLite/Oracle) in the response that was
     not present in the baseline — a broken query string leaking a driver
     error can only happen if the input reached the SQL parser unescaped.
  2. Boolean-based (blind): inject an always-true (``' AND '1'='1``, which
     preserves the original condition) and an always-false (``' AND
     '1'='2``, which nullifies it) condition and compare responses. The true
     condition should behave just like the baseline; the false one should
     not. A response pair that actually diverges — true resembling baseline,
     false differing from it — means the query's result set is being
     controlled by the input.
  3. Time-based (blind): inject a conditional sleep across the handful of SQL
     dialects likely to appear (MySQL/MariaDB, PostgreSQL, MSSQL) and compare
     response time against a benign baseline — a delay that matches the
     injected sleep and the baseline does not have means the database
     executed it.

All payloads are non-destructive: no INSERT/UPDATE/DELETE/DROP, only
boolean conditions, comment sequences, and read-only sleep functions.

The injection point itself is generic too: given no override, the detector
fetches the target page, parses its HTML forms (and any query-string
parameters already on the pasted URL) with the same stdlib-only parser
``command_injection.py`` uses, and probes each candidate field/parameter in
turn. A known lab host (DVWA) gets a preset pointing straight at its
exercise endpoints instead of discovery, and any host can be pointed at an explicit
parameter/path/login via ``ScanContext.extra`` (populated from
``Target.scan_config``), which always wins over both the generic defaults
and the lab preset.
"""

from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import dataclass, replace
from typing import Any
from urllib.parse import urlencode, urljoin, urlparse

import httpx

from app.scanners.base import (
    BaseDetector,
    DetectorResult,
    ScanContext,
    scope_cfg_to_path,
)
from app.scanners.command_injection import (
    Candidate,
    _candidates_from_form,
    _candidates_from_query,
    parse_forms,
)
from app.scanners.presets.sql_injection import GENERIC_DEFAULTS, LAB_PRESETS

logger = logging.getLogger(__name__)

# Tuning constants for the time-based signal.
SLEEP_SECONDS = 5
TIME_THRESHOLD_MS = 4000

# Boolean-response lengths within this many characters of each other are
# treated as "the same", to absorb trivial noise (timestamps, CSRF tokens).
BOOLEAN_LENGTH_TOLERANCE = 5

# Well-known driver/engine error fragments. Lowercase, matched against a
# lowercased response body — a hit here that wasn't already in the baseline
# response is a broken query string leaking a real driver error.
_SQL_ERROR_SIGNATURES = (
    "you have an error in your sql syntax",
    "warning: mysql",
    "mysql_fetch",
    "mysqli_fetch",
    "unknown column",
    "sqlstate[",
    "pg_query(): query failed",
    "postgresql query failed",
    "unterminated quoted string",
    "syntax error at or near",
    "sqlite3::query",
    "sqlite_error",
    'near "',
    "unclosed quotation mark",
    "quoted string not properly terminated",
    "microsoft odbc",
    "odbc sql server driver",
    "ora-00933",
    "ora-01756",
    "supplied argument is not a valid",
)

# (dialect, payload template) — {q} is the configured quote_char, {s} is
# SLEEP_SECONDS. Tried in order until one clears TIME_THRESHOLD_MS.
#
# Deliberately AND, not OR: an OR-joined SLEEP()/PG_SLEEP() is evaluated once
# per row the query scans (WHERE id = 'x' OR SLEEP(5) sleeps once for every
# row, not once total), which can multiply the delay far past any sane
# request timeout on a table with more than a couple of rows. AND bounds the
# sleep to the row(s) that already match the benign value, since the
# database short-circuits before evaluating SLEEP() on non-matching rows.
_TIME_PAYLOAD_TEMPLATES: tuple[tuple[str, str], ...] = (
    ("mysql/mariadb", "{benign}{q} AND SLEEP({s})-- -"),
    ("postgresql", "{benign}{q} AND (SELECT 1 FROM PG_SLEEP({s}))>0-- -"),
    ("mssql", "{benign}{q};WAITFOR DELAY '0:0:{s}'-- -"),
)


class DetectorError(Exception):
    """A detector could not run to completion — carries a human-readable reason
    that is surfaced to the user (distinct from a raw transport error)."""


def _explicit_candidates(base: str, cfg: dict[str, Any]) -> list[Candidate]:
    """Build targeted candidates when the caller (a lab preset or explicit
    ScanContext.extra overrides) names exact parameter/path values."""
    if "parameter" not in cfg:
        return []

    urls: list[str] = []
    if "injection_urls" in cfg:
        urls.extend(str(value) for value in cfg["injection_urls"])
    elif "injection_paths" in cfg:
        urls.extend(f"{base}{value}" for value in cfg["injection_paths"])
    elif "injection_url" in cfg:
        urls.append(str(cfg["injection_url"]))
    elif "injection_path" in cfg:
        urls.append(f"{base}{cfg['injection_path']}")
    else:
        return []

    fixed = {}
    if cfg.get("submit_field"):
        fixed[cfg["submit_field"]] = cfg.get("submit_value", "")
    method = cfg.get("method", "GET")
    return [
        Candidate(method=method, url=url, param=cfg["parameter"], fixed_fields=fixed)
        for url in urls
    ]


def _find_sql_error(body: str, baseline_body: str) -> str | None:
    lowered = body.lower()
    baseline_lowered = baseline_body.lower()
    for signature in _SQL_ERROR_SIGNATURES:
        if signature in lowered and signature not in baseline_lowered:
            return signature
    return None


def _boolean_diff(baseline_body: str, true_body: str, false_body: str) -> bool:
    """The true condition (``AND '1'='1'``) is logically equivalent to the
    unmodified query, so its response should reproduce the baseline (exactly,
    or within a small length tolerance to absorb incidental noise like
    timestamps); the false condition (``AND '1'='2'``) nullifies it, so its
    response should differ from the true one by more than that same noise
    floor. A response pair that actually diverges this way means the input
    is steering the query's result set, not just producing arbitrary noise."""
    true_matches_baseline = (
        true_body == baseline_body
        or abs(len(true_body) - len(baseline_body)) <= BOOLEAN_LENGTH_TOLERANCE
    )
    return true_matches_baseline and false_body != true_body


# --- Optional OWASP ZAP cross-check -----------------------------------------
#
# Opt-in (``ScanContext.extra['use_zap']``): runs ZAP's active scanner — an
# independent engine with its own payload library — against the same
# endpoint/parameter the manual probes already identified, purely as a second
# opinion. Manual evidence always stands on its own; ZAP either raises
# confidence when it agrees or is reported as a disagreement, never silently
# overrides what the manual probes already proved. Requires the separate
# `tools/docker-compose.yml` ZAP service to be running and reachable — if it
# isn't, the cross-check is skipped and the manual result is returned as-is.

ZAP_SQLI_CWE = "89"
ZAP_DEFAULT_TIMEOUT_SECONDS = 90.0
ZAP_POLL_INTERVAL_SECONDS = 2.0


def _is_sqli_alert(alert: dict[str, Any]) -> bool:
    if str(alert.get("cweid", "")) == ZAP_SQLI_CWE:
        return True
    return "sql injection" in str(alert.get("alert", "")).lower()


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


@dataclass
class Decision:
    detected: bool
    validation_status: str
    confidence: str
    reason: str


def classify(
    error_signature: str | None,
    boolean_diff: bool,
    time_delta_ms: float,
    threshold_ms: float = TIME_THRESHOLD_MS,
) -> Decision:
    """Turn the raw signals into a validation verdict.

    Kept pure (no I/O) so the decision policy can be unit-tested directly.
    """
    error_found = error_signature is not None
    time_hit = time_delta_ms >= threshold_ms

    if error_found and (boolean_diff or time_hit):
        return Decision(
            True, "CONFIRMED", "HIGH",
            "SQL error signature returned and an independent boolean/timing "
            "signal confirmed control over the query",
        )
    if error_found:
        return Decision(
            True, "CONFIRMED", "HIGH",
            "SQL error signature returned for a single-quote probe, absent "
            "from the baseline response",
        )
    if boolean_diff and time_hit:
        return Decision(
            True, "CONFIRMED", "HIGH",
            "boolean-based and time-based blind signals both confirmed query manipulation",
        )
    if boolean_diff:
        return Decision(
            True, "CONFIRMED", "MEDIUM",
            "boolean-based blind signal confirmed query manipulation (true/false "
            "conditions produced different responses)",
        )
    if time_hit:
        return Decision(
            True, "CONFIRMED", "MEDIUM",
            "time-based blind delay observed for an injected sleep condition",
        )
    return Decision(
        False, "NOT_DETECTED", "LOW",
        "no SQL error signature, boolean differential, or timing delay observed",
    )


class SQLInjectionDetector(BaseDetector):
    detector_id = "sql_injection"
    name = "SQL Injection"
    vulnerability_type = "sql_injection"
    supported_targets = ["webapp"]

    async def check(self, context: ScanContext) -> DetectorResult:
        """Compatibility wrapper: return the first detected result, else the
        last probed result (matching historical single-result behavior)."""
        results = await self.check_many(context)
        for result in results:
            if result.detected:
                return result
        return results[-1]

    async def check_many(self, context: ScanContext) -> list[DetectorResult]:
        parsed = urlparse(context.base_url)
        host = parsed.hostname or ""
        base = f"{parsed.scheme}://{parsed.netloc}"
        cfg = {**GENERIC_DEFAULTS, **LAB_PRESETS.get(host, {}), **context.extra}
        scope_cfg_to_path(
            cfg, context, "injection_path", "injection_paths", "injection_urls", "injection_url"
        )
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

                explicit = _explicit_candidates(base, cfg)
                if explicit:
                    candidates = explicit
                    source = "explicit configuration"
                else:
                    candidates = await self._discover_candidates(
                        client, context, cfg, base, discovery_path
                    )
                    source = "auto-discovered"
                    if not candidates:
                        raise DetectorError(
                            f"No form fields or query parameters were found at "
                            f"{base}{discovery_path} to test for SQL injection. Provide "
                            "an explicit 'parameter' and 'injection_path'/'injection_url' "
                            "override in the target's scan configuration if the injectable "
                            "field isn't reachable from there."
                        )

                results: list[DetectorResult] = []
                active_candidates = candidates[: cfg["max_candidates"]]
                for idx, raw_candidate in enumerate(active_candidates, start=1):
                    candidate = await self._prime_candidate(client, raw_candidate, cfg)
                    decision, evidence = await self._probe(client, candidate, cfg)
                    evidence["candidates_probed"] = len(active_candidates)
                    evidence["candidate_source"] = source
                    evidence["candidate_index"] = idx
                    results.append(self._result(candidate, decision, evidence))

                if not results:
                    raise DetectorError("No probe candidates were available after discovery.")
                return results
        except DetectorError as exc:
            return [self._error_result(context, str(exc))]
        except httpx.HTTPError as exc:
            return [
                self._error_result(
                    context, f"Could not reach the target ({type(exc).__name__}: {exc})."
                )
            ]

    async def validate(self, context: ScanContext, result: DetectorResult) -> DetectorResult:
        """Optional OWASP ZAP cross-check — see the module docstring for
        `ScanContext.extra['use_zap']`. Never raises: any failure reaching or
        running ZAP degrades to "cross-check unavailable", leaving the manual
        result exactly as `check()` produced it."""
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
                " OWASP ZAP's active scanner independently confirmed SQL injection "
                "on this endpoint."
            )
        elif result.detected and not zap.detected:
            note = " OWASP ZAP's active scanner did not corroborate this — manual evidence stands."
        elif not result.detected and zap.detected:
            note = (
                " Manual probing found nothing, but OWASP ZAP's active scanner flagged SQL "
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
            evidence_summary=result.evidence_summary + note,
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
        baseline_value = result.evidence.get("payloads", {}).get("baseline", "1")
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

        sqli_alerts = [a for a in alerts if _is_sqli_alert(a)]
        note = (
            "scan completed"
            if completed
            else (
                f"scan did not finish within {timeout_seconds:.0f}s — "
                "reporting alerts found so far"
            )
        )
        return ZapOutcome(True, True, completed, bool(sqli_alerts), sqli_alerts, note)

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
        """Run the baseline / error / boolean-true / boolean-false / time-based
        probes against one candidate."""
        benign = cfg["benign_value"]
        q = cfg["quote_char"]

        baseline_body, baseline_ms, baseline_status = await self._submit(client, candidate, benign)

        error_payload = f"{benign}{q}"
        error_body, error_ms, error_status = await self._submit(client, candidate, error_payload)
        error_signature = _find_sql_error(error_body, baseline_body)

        true_payload = f"{benign}{q} AND '1'='1"
        false_payload = f"{benign}{q} AND '1'='2"
        true_body, true_ms, true_status = await self._submit(client, candidate, true_payload)
        false_body, false_ms, false_status = await self._submit(client, candidate, false_payload)
        boolean_diff = _boolean_diff(baseline_body, true_body, false_body)

        time_dialect: str | None = None
        time_payload: str | None = None
        time_delta_ms = 0.0
        for dialect, template in _TIME_PAYLOAD_TEMPLATES:
            payload = template.format(benign=benign, q=q, s=SLEEP_SECONDS)
            _, elapsed_ms, _ = await self._submit(client, candidate, payload)
            delta = elapsed_ms - baseline_ms
            if delta > time_delta_ms:
                time_delta_ms = delta
                time_dialect = dialect
                time_payload = payload
            if delta >= TIME_THRESHOLD_MS:
                break

        decision = classify(error_signature, boolean_diff, time_delta_ms, TIME_THRESHOLD_MS)
        evidence = {
            "method": candidate.method,
            "fixed_fields": candidate.fixed_fields,
            "error_signature": error_signature,
            "boolean_diff": boolean_diff,
            "time_dialect": time_dialect,
            "baseline_ms": round(baseline_ms, 1),
            "error_probe_ms": round(error_ms, 1),
            "boolean_true_ms": round(true_ms, 1),
            "boolean_false_ms": round(false_ms, 1),
            "time_delta_ms": round(time_delta_ms, 1),
            "time_threshold_ms": TIME_THRESHOLD_MS,
            "status_codes": {
                "baseline": baseline_status,
                "error": error_status,
                "boolean_true": true_status,
                "boolean_false": false_status,
            },
            "response_lengths": {
                "baseline": len(baseline_body),
                "error": len(error_body),
                "boolean_true": len(true_body),
                "boolean_false": len(false_body),
            },
            "payloads": {
                "baseline": benign,
                "error": error_payload,
                "boolean_true": true_payload,
                "boolean_false": false_payload,
                "time_based": time_payload,
            },
        }
        return decision, evidence

    async def _submit(
        self, client: httpx.AsyncClient, candidate: Candidate, payload: str
    ) -> tuple[str, float, int]:
        """Submit one payload into the candidate's parameter, returning
        (body, elapsed_ms, status_code). Never raises on a non-2xx response —
        an error status is itself one of the signals this detector looks for,
        not a transport failure (a genuine transport failure, e.g. connection
        refused, still propagates as httpx.HTTPError)."""
        data = {**candidate.fixed_fields, candidate.param: payload}
        start = time.perf_counter()
        if candidate.method == "GET":
            resp = await client.get(candidate.url, params=data)
        else:
            resp = await client.post(candidate.url, data=data)
        elapsed_ms = (time.perf_counter() - start) * 1000
        return resp.text, elapsed_ms, resp.status_code

    def _result(
        self,
        candidate: Candidate,
        decision: Decision,
        evidence: dict[str, Any],
    ) -> DetectorResult:
        summary = (
            f"{decision.reason} (probed {evidence['candidates_probed']} candidate field(s), "
            f"{evidence['candidate_source']}). "
            f"error_signature={evidence['error_signature']!r}, "
            f"boolean_diff={evidence['boolean_diff']}, "
            f"time_delta={evidence['time_delta_ms']}ms."
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
                "The target incorporates attacker-controlled input directly into "
                "a SQL query. An injected condition changed the query's result "
                "and/or a database error and/or a timing delay confirmed the "
                "database executed attacker-controlled SQL."
            ),
            evidence_summary=summary,
            evidence=evidence,
            remediation=(
                "Use parameterised queries / prepared statements (or an ORM that "
                "does so) for all database access — never build SQL by string "
                "concatenation or formatting with user input. Apply least-"
                "privilege database accounts and disable verbose driver error "
                "messages in production."
            ),
            cwe="CWE-89",
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
            cwe="CWE-89",
            owasp_category="A03:2021 - Injection",
        )
