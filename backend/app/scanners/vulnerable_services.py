"""Vulnerable-network-services detector.

Unlike the other detectors, this one isn't scoped to a single known web app —
it targets *any* host and has to discover what's actually running on it
first. Three tools are chained, each doing the part it's actually good at:

  1. ``nmap`` (``-sV``, plus a curated ``default,safe`` set of NSE scripts)
     for port discovery and service/version fingerprinting, including CPE
     identifiers where it can determine one. Reimplementing per-protocol
     handshake probing for FTP/SSH/SMB/MySQL/RMI/IRC/etc. in pure Python
     would mean re-deriving a large, well-tested fingerprint database from
     scratch.
  2. The NVD CVE API, queried by CPE, for "is this version actually
     vulnerable, and to what." This is what makes the detector general —
     it isn't limited to a small hardcoded list of known lab CVEs, it can
     flag *any* fingerprinted product/version NVD has a record for.
  3. ``searchsploit`` (a local, offline Exploit-DB mirror) per CVE found, to
     answer "is there a public exploit for this" — a real risk signal, since
     an exploitable-in-theory CVE is a different threat than one with a
     working public PoC. Checking availability is never the same as running
     one: nothing here downloads, compiles, or executes an exploit.

Not every service gets a CPE from nmap (distccd and the ingreslock backdoor
below are both examples), and NVD has no CVE for lab-only artifacts like a
raw backdoor listener anyway — so a small curated fallback table covers
those specific cases and a short list of protocols that are insecure by
design regardless of version (telnet, rsh/rlogin/rexec, unauthenticated
VNC).

Explicitly out of scope, by design: nmap's ``vuln``/``exploit``/``intrusive``
script categories are never run (several, like the distcc CVE-2004-2687
script, execute a command on the target by default to *prove* RCE — that's
exploitation, which this project's safety rules forbid), and searchsploit
results are only ever read for their metadata, never executed. Every finding
here is proven by version fingerprint, CVE record, or protocol presence
alone, never by actually exploiting anything.
"""

from __future__ import annotations

import asyncio
import json
import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlparse

import httpx

from app.core.config import get_settings
from app.scanners.base import BaseDetector, DetectorResult, ScanContext

NVD_CVE_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

DEFAULTS: dict[str, Any] = {
    # nmap's own "top N most common ports" list. None + "ports" set below
    # scans an explicit range/list instead.
    "top_ports": 1000,
    "ports": None,
    # default,safe only — never vuln/exploit/intrusive/dos/brute. These two
    # categories are read-only/banner-based by nmap's own classification.
    "nse_scripts": "default,safe",
    # A busy target (many open services, e.g. Metasploitable2's ~20) with
    # default,safe NSE scripts running against every one of them can
    # genuinely take several minutes — 5 targeted ports alone took up to
    # 235s in testing. Generous on purpose: thoroughness over speed.
    "nmap_timeout_seconds": 900.0,
    # NVD lookups, one per fingerprinted application CPE.
    "nvd_api_key": None,  # filled from Settings at check()-time; override to test a different key
    "nvd_results_per_cpe": 20,
    "max_cves_per_service": 5,
    # searchsploit exploit-availability enrichment, one lookup per CVE found.
    "use_searchsploit": True,
    "searchsploit_timeout_seconds": 20.0,
}


class DetectorError(Exception):
    """A detector could not run to completion — carries a human-readable reason
    that is surfaced to the user (distinct from a raw transport error)."""


@dataclass
class ObservedService:
    port: int
    protocol: str
    service: str
    product: str
    version: str
    extrainfo: str
    cpes: list[str]
    script_output: dict[str, str]


@dataclass
class Signature:
    """A known-vulnerable fingerprint that doesn't depend on NVD/CPE lookup —
    for lab-only artifacts (no CVE exists) and version-independent protocols.
    Every non-None field must match."""

    cve: str | None
    cwe: str
    severity: str
    description: str
    port: int | None = None
    service_pattern: re.Pattern[str] | None = None
    product_pattern: re.Pattern[str] | None = None
    version_pattern: re.Pattern[str] | None = None


@dataclass
class VulnerabilityMatch:
    port: int
    service: str
    product: str
    version: str
    category: str  # "known_cve" | "heuristic"
    cve: str | None
    cwe: str
    severity: str
    description: str
    exploit_available: bool = False
    exploit_refs: list[dict[str, Any]] = field(default_factory=list)


@dataclass
class Decision:
    detected: bool
    validation_status: str
    confidence: str
    severity: str
    reason: str
    worst: VulnerabilityMatch | None


# Fingerprints for lab-only backdoors NVD has no CVE record for, plus
# protocols that are insecure by design independent of version. Matched with
# MEDIUM confidence and SUSPECTED status (except the two source-compromise
# backdoors below, which are CONFIRMED/HIGH — the version string alone is
# damning) — presence/version is the signal, not an NVD-verified record.
KNOWN_CVE_SIGNATURES: list[Signature] = [
    Signature(
        cve="CVE-2011-2523", cwe="CWE-78", severity="CRITICAL",
        description=(
            "vsftpd 2.3.4's source was maliciously modified to include a backdoor: "
            "a username containing \")\":)\" triggers a root shell on port 6200."
        ),
        service_pattern=re.compile(r"ftp", re.I),
        product_pattern=re.compile(r"vsftpd", re.I),
        version_pattern=re.compile(r"^2\.3\.4$"),
    ),
    Signature(
        cve="CVE-2010-4221", cwe="CWE-78", severity="CRITICAL",
        description=(
            "This ProFTPD 1.3.3c build's source was compromised to include a backdoor "
            "granting unauthenticated remote command execution."
        ),
        service_pattern=re.compile(r"ftp", re.I),
        product_pattern=re.compile(r"proftpd", re.I),
        version_pattern=re.compile(r"^1\.3\.3c$"),
    ),
    Signature(
        cve="CVE-2010-2075", cwe="CWE-78", severity="CRITICAL",
        description=(
            "This UnrealIRCd build's source was compromised to include a backdoor "
            "granting unauthenticated remote command execution via a crafted DEBUG3 "
            "message."
        ),
        service_pattern=re.compile(r"irc", re.I),
        product_pattern=re.compile(r"unrealircd", re.I),
    ),
    Signature(
        cve="CVE-2004-2687", cwe="CWE-78", severity="CRITICAL",
        description=(
            "distccd accepts and executes arbitrary compilation commands from any "
            "network client with no authentication — direct remote code execution."
        ),
        service_pattern=re.compile(r"distccd", re.I),
    ),
    Signature(
        cve=None, cwe="CWE-912", severity="CRITICAL",
        description=(
            "Port 1524 is open with a listener consistent with the classic "
            "\"ingreslock\" backdoor, which hands an unauthenticated root shell to "
            "any connecting client."
        ),
        port=1524,
    ),
]

INSECURE_PROTOCOLS: dict[str, dict[str, str]] = {
    "telnet": {
        "cwe": "CWE-319", "severity": "MEDIUM",
        "description": "Telnet transmits all traffic, including credentials, in cleartext.",
    },
    "shell": {
        "cwe": "CWE-306", "severity": "HIGH",
        "description": (
            "rsh grants remote command execution based on trusted-host/IP "
            "authentication rather than a password."
        ),
    },
    "exec": {
        "cwe": "CWE-306", "severity": "HIGH",
        "description": (
            "rexec authenticates over a cleartext, trivially sniffable/spoofable channel."
        ),
    },
    "login": {
        "cwe": "CWE-306", "severity": "HIGH",
        "description": (
            "rlogin grants remote login based on trusted-host/IP authentication "
            "rather than a password."
        ),
    },
    "vnc": {
        "cwe": "CWE-319", "severity": "MEDIUM",
        "description": "VNC here offers no or weak authentication over an unencrypted channel.",
    },
}

_SEVERITY_RANK: dict[str, int] = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
_SEVERITY_CVSS: dict[str, float] = {
    "INFO": 0.0, "LOW": 3.1, "MEDIUM": 5.3, "HIGH": 7.5, "CRITICAL": 9.8,
}


def _service_attr(service_el: ET.Element | None, name: str) -> str:
    return (service_el.get(name) if service_el is not None else None) or ""


def parse_nmap_xml(xml_text: str) -> list[ObservedService]:
    """Extract open-port service/version/CPE data from nmap's ``-oX -`` output.

    Kept pure (no I/O) so parsing can be unit-tested against fixture XML.
    """
    root = ET.fromstring(xml_text)
    services: list[ObservedService] = []
    for host_el in root.findall("host"):
        ports_el = host_el.find("ports")
        if ports_el is None:
            continue
        for port_el in ports_el.findall("port"):
            state_el = port_el.find("state")
            if state_el is None or state_el.get("state") != "open":
                continue
            service_el = port_el.find("service")
            cpes = [
                (cpe_el.text or "").strip()
                for cpe_el in (service_el.findall("cpe") if service_el is not None else [])
                if (cpe_el.text or "").strip()
            ]
            scripts = {
                script_el.get("id", ""): script_el.get("output", "")
                for script_el in port_el.findall("script")
            }
            services.append(
                ObservedService(
                    port=int(port_el.get("portid", 0)),
                    protocol=port_el.get("protocol", "tcp"),
                    service=_service_attr(service_el, "name"),
                    product=_service_attr(service_el, "product"),
                    version=_service_attr(service_el, "version"),
                    extrainfo=_service_attr(service_el, "extrainfo"),
                    cpes=cpes,
                    script_output=scripts,
                )
            )
    return services


def cpe22_to_cpe23(cpe22: str) -> str | None:
    """Convert nmap's CPE 2.2 URI binding (``cpe:/a:vendor:product:version``)
    to the CPE 2.3 formatted string NVD's API expects. Kept pure/testable."""
    if not cpe22.startswith("cpe:/"):
        return None
    fields = cpe22[len("cpe:/") :].split(":")
    fields = (fields + ["*"] * 11)[:11]
    fields = [f if f else "*" for f in fields]
    return "cpe:2.3:" + ":".join(fields)


def best_application_cpe(cpes: list[str]) -> str | None:
    """Prefer an application CPE (``/a:``) over OS/hardware ones — those are
    usually version-less and too broad to attribute a finding to this port."""
    return next((c for c in cpes if c.startswith("cpe:/a:")), None)


def _score_to_severity(score: float) -> str:
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    if score > 0.0:
        return "LOW"
    return "INFO"


def _extract_cwe(cve: dict[str, Any]) -> str:
    for weakness in cve.get("weaknesses", []):
        for desc in weakness.get("description", []):
            value = desc.get("value", "")
            if value.startswith("CWE-"):
                return value
    return "CWE-1104"  # fallback: "Use of Unmaintained Third Party Components"


def parse_nvd_vulnerability(vuln: dict[str, Any]) -> tuple[str, float, str, str, str]:
    """Extract (cve_id, cvss_score, severity, cwe, description) from one NVD
    API 2.0 ``vulnerabilities[]`` entry. Kept pure/testable against fixture JSON."""
    cve = vuln.get("cve", {})
    cve_id = cve.get("id", "UNKNOWN")
    metrics = cve.get("metrics", {})
    score, severity = 0.0, ""
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(key)
        if entries:
            data = entries[0].get("cvssData", {})
            score = float(data.get("baseScore", 0.0))
            severity = (data.get("baseSeverity") or entries[0].get("baseSeverity") or "").upper()
            break
    if not severity:
        severity = _score_to_severity(score)
    descriptions = cve.get("descriptions", [])
    desc = next((d.get("value", "") for d in descriptions if d.get("lang") == "en"), "")
    return cve_id, score, severity, _extract_cwe(cve), desc


def _signature_matches(sig: Signature, svc: ObservedService) -> bool:
    if sig.port is not None and svc.port != sig.port:
        return False
    if sig.service_pattern is not None and not sig.service_pattern.search(svc.service):
        return False
    if sig.product_pattern is not None and not sig.product_pattern.search(svc.product):
        return False
    if sig.version_pattern is not None and not sig.version_pattern.search(svc.version):
        return False
    return True


def match_heuristics(services: list[ObservedService]) -> list[VulnerabilityMatch]:
    """Match observed services against the curated fallback table (lab-only
    backdoors with no CVE, and version-independent insecure protocols).

    Kept pure (no I/O) so the matching policy can be unit-tested directly.
    """
    matches: list[VulnerabilityMatch] = []
    for svc in services:
        cve_sig = next((s for s in KNOWN_CVE_SIGNATURES if _signature_matches(s, svc)), None)
        if cve_sig is not None:
            matches.append(
                VulnerabilityMatch(
                    port=svc.port, service=svc.service, product=svc.product, version=svc.version,
                    category="known_cve", cve=cve_sig.cve, cwe=cve_sig.cwe,
                    severity=cve_sig.severity, description=cve_sig.description,
                )
            )
            continue
        insecure = INSECURE_PROTOCOLS.get(svc.service.lower())
        if insecure is not None:
            matches.append(
                VulnerabilityMatch(
                    port=svc.port, service=svc.service, product=svc.product, version=svc.version,
                    category="heuristic", cve=None, cwe=insecure["cwe"],
                    severity=insecure["severity"], description=insecure["description"],
                )
            )
    return matches


def classify(matches: list[VulnerabilityMatch]) -> Decision:
    """Turn matched vulnerabilities into a validation verdict.

    Kept pure (no I/O) so the decision policy can be unit-tested directly.
    """
    if not matches:
        return Decision(
            detected=False, validation_status="NOT_DETECTED", confidence="LOW", severity="INFO",
            reason=(
                "no known-vulnerable services or insecure protocols identified "
                "among the open ports scanned"
            ),
            worst=None,
        )

    def rank(m: VulnerabilityMatch) -> tuple[int, int]:
        severity = "CRITICAL" if m.exploit_available and m.category == "known_cve" else m.severity
        return (_SEVERITY_RANK[severity], 1 if m.exploit_available else 0)

    worst = max(matches, key=rank)
    is_confirmed = worst.category == "known_cve"
    severity = "CRITICAL" if worst.exploit_available else worst.severity
    label = worst.cve or worst.cwe
    exploit_note = " — public exploit available" if worst.exploit_available else ""
    return Decision(
        detected=True,
        validation_status="CONFIRMED" if is_confirmed else "SUSPECTED",
        confidence="HIGH" if is_confirmed else "MEDIUM",
        severity=severity,
        reason=(
            f"{len(matches)} vulnerable/insecure service(s) identified; worst: "
            f"{worst.product or worst.service} on port {worst.port} ({label}){exploit_note}"
        ),
        worst=worst,
    )


class VulnerableServicesDetector(BaseDetector):
    detector_id = "vulnerable_services"
    name = "Vulnerable Services"
    vulnerability_type = "vulnerable_services"
    supported_targets = ["metasploitable2", "host", "webapp"]

    async def check(self, context: ScanContext) -> DetectorResult:
        cfg = {**DEFAULTS, "nvd_api_key": get_settings().nvd_api_key, **context.extra}
        host = urlparse(context.base_url).hostname or context.base_url

        try:
            xml_text = await self._run_nmap(host, cfg)
            try:
                services = parse_nmap_xml(xml_text)
            except ET.ParseError as exc:
                raise DetectorError(f"Could not parse nmap output: {exc}") from exc

            matches = await self._gather_matches(services, cfg)
            decision = classify(matches)
            return self._result(host, decision, matches, services)
        except DetectorError as exc:
            return self._error_result(host, str(exc))

    async def _run_nmap(self, host: str, cfg: dict[str, Any]) -> str:
        if cfg.get("ports"):
            port_args = ["-p", cfg["ports"]]
        else:
            port_args = ["--top-ports", str(cfg["top_ports"])]
        args = [
            "nmap", "-sV", "-Pn", "-T3", "--script", cfg["nse_scripts"],
            *port_args, "-oX", "-", "--", host,
        ]
        try:
            proc = await asyncio.create_subprocess_exec(
                *args, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
            )
        except FileNotFoundError as exc:
            raise DetectorError("nmap is not installed in this environment.") from exc

        try:
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(), timeout=cfg["nmap_timeout_seconds"]
            )
        except TimeoutError as exc:
            proc.kill()
            await proc.wait()
            raise DetectorError(
                f"nmap scan of {host} did not finish within "
                f"{cfg['nmap_timeout_seconds']:.0f}s."
            ) from exc

        if proc.returncode != 0:
            raise DetectorError(
                f"nmap exited with code {proc.returncode}: "
                f"{stderr.decode(errors='replace').strip()[:300]}"
            )
        return stdout.decode(errors="replace")

    async def _gather_matches(
        self, services: list[ObservedService], cfg: dict[str, Any]
    ) -> list[VulnerabilityMatch]:
        heuristic_matches = match_heuristics(services)
        covered = {(m.port, m.cve) for m in heuristic_matches if m.cve}
        min_interval = 30.0 / 45 if cfg.get("nvd_api_key") else 30.0 / 4

        nvd_matches: list[VulnerabilityMatch] = []
        async with httpx.AsyncClient(timeout=15.0) as client:
            for svc in services:
                cpe23 = None
                app_cpe = best_application_cpe(svc.cpes)
                if app_cpe:
                    cpe23 = cpe22_to_cpe23(app_cpe)
                if not cpe23:
                    continue

                try:
                    vulns = await self._query_nvd(client, cpe23, cfg)
                except httpx.HTTPError:
                    continue  # NVD unreachable/rate-limited — enrichment is best-effort
                finally:
                    await asyncio.sleep(min_interval)

                parsed = sorted(
                    (parse_nvd_vulnerability(v) for v in vulns),
                    key=lambda t: t[1], reverse=True,
                )[: cfg["max_cves_per_service"]]

                for cve_id, _score, severity, cwe, desc in parsed:
                    if (svc.port, cve_id) in covered:
                        continue
                    exploit_refs = (
                        await self._run_searchsploit(cve_id, cfg)
                        if cfg.get("use_searchsploit")
                        else []
                    )
                    nvd_matches.append(
                        VulnerabilityMatch(
                            port=svc.port, service=svc.service, product=svc.product,
                            version=svc.version, category="known_cve", cve=cve_id, cwe=cwe,
                            severity=severity, description=desc[:400],
                            exploit_available=bool(exploit_refs),
                            exploit_refs=[
                                {"edb_id": r.get("EDB-ID"), "title": r.get("Title")}
                                for r in exploit_refs[:5]
                            ],
                        )
                    )
                    covered.add((svc.port, cve_id))

        return heuristic_matches + nvd_matches

    async def _query_nvd(
        self, client: httpx.AsyncClient, cpe23: str, cfg: dict[str, Any]
    ) -> list[dict[str, Any]]:
        headers = {"apiKey": cfg["nvd_api_key"]} if cfg.get("nvd_api_key") else {}
        resp = await client.get(
            NVD_CVE_API_URL,
            params={"virtualMatchString": cpe23, "resultsPerPage": cfg["nvd_results_per_cpe"]},
            headers=headers,
        )
        if resp.status_code == 404:
            return []
        resp.raise_for_status()
        return resp.json().get("vulnerabilities", [])

    async def _run_searchsploit(self, cve_id: str, cfg: dict[str, Any]) -> list[dict[str, Any]]:
        try:
            proc = await asyncio.create_subprocess_exec(
                "searchsploit", "--cve", cve_id, "--json",
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
            )
        except FileNotFoundError:
            return []

        try:
            stdout, _stderr = await asyncio.wait_for(
                proc.communicate(), timeout=cfg["searchsploit_timeout_seconds"]
            )
        except TimeoutError:
            proc.kill()
            await proc.wait()
            return []

        if proc.returncode != 0:
            return []
        try:
            data = json.loads(stdout.decode(errors="replace"))
        except json.JSONDecodeError:
            return []
        return data.get("RESULTS_EXPLOIT") or data.get("RESULTS") or []

    def _result(
        self,
        host: str,
        decision: Decision,
        matches: list[VulnerabilityMatch],
        services: list[ObservedService],
    ) -> DetectorResult:
        endpoint = f"{host}:{decision.worst.port}" if decision.worst else host
        summary = f"{decision.reason}. Scanned {len(services)} open port(s) on {host}."
        return DetectorResult(
            detector=self.detector_id,
            vulnerability=self.name,
            detected=decision.detected,
            validation_status=decision.validation_status,
            severity=decision.severity,
            confidence=decision.confidence,
            endpoint=endpoint,
            parameter=None,
            description=(
                "The target runs one or more network services with a known-vulnerable "
                "version (matched by CPE fingerprint to a specific NVD CVE record) or an "
                "insecure, cleartext/trust-based protocol, exposing it to compromise."
            ),
            evidence_summary=summary,
            evidence={
                "host": host,
                "open_ports": [
                    {
                        "port": s.port, "protocol": s.protocol, "service": s.service,
                        "product": s.product, "version": s.version, "cpes": s.cpes,
                    }
                    for s in services
                ],
                "vulnerabilities": [
                    {
                        "port": m.port, "service": m.service, "product": m.product,
                        "version": m.version, "category": m.category, "cve": m.cve,
                        "cwe": m.cwe, "severity": m.severity, "description": m.description,
                        "exploit_available": m.exploit_available, "exploit_refs": m.exploit_refs,
                    }
                    for m in matches
                ],
            },
            remediation=(
                "Patch or replace any service matched to a specific CVE — prioritize ones "
                "with a public exploit available; disable insecure-by-design protocols "
                "(telnet, rsh/rlogin/rexec, unauthenticated VNC) in favor of encrypted, "
                "authenticated equivalents (SSH, SFTP, VNC-over-SSH); remove unused or "
                "backdoored listeners (e.g. ingreslock, distccd) entirely."
            ),
            cwe=decision.worst.cwe if decision.worst else "CWE-1104",
            cve=decision.worst.cve if decision.worst else None,
            cvss_score=_SEVERITY_CVSS[decision.severity],
            owasp_category="A06:2021 - Vulnerable and Outdated Components",
        )

    def _error_result(self, host: str, message: str) -> DetectorResult:
        return DetectorResult(
            detector=self.detector_id,
            vulnerability=self.name,
            detected=False,
            validation_status="ERROR",
            severity="INFO",
            confidence="LOW",
            endpoint=host,
            parameter=None,
            description="Detector could not complete against the target.",
            evidence_summary=f"Scan error: {message}",
            evidence={"error": message},
            cwe="CWE-1104",
            owasp_category="A06:2021 - Vulnerable and Outdated Components",
        )
