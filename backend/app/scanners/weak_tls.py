"""Weak-TLS-configuration detector.

Targets any TLS-speaking service, not just Juice Shop or Metasploitable2.
Detection is delegated to SSLyze (a Python library, not a subprocess tool
like ``nmap``/``searchsploit``) — it runs every scan command by default:
protocol/cipher-suite enumeration for SSL 2.0 through TLS 1.3, certificate
chain validation, and read-only probes for named vulnerabilities (Heartbleed,
ROBOT, OpenSSL CCS injection, insecure renegotiation). Every one of those is
a passive/read-only TLS handshake — nothing here sends a payload intended to
crash, exploit, or gain access to anything; a "vulnerable" verdict comes from
observing what the server negotiates or from a scripted-safe protocol probe
that SSLyze itself implements, the same technique any TLS client library
uses to negotiate a connection.

SSLyze's own object graph (certificates, enums, cipher-suite records) isn't
directly JSON-serializable, so ``_observe()`` — the only I/O-touching part of
this module — reduces a raw ``ServerScanResult`` down to a plain-data
``TLSObservation`` first. Everything past that point, including all of the
severity judgment, is pure and unit-testable without a real TLS connection.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any
from urllib.parse import urlparse

from sslyze import (
    ScanCommandAttemptStatusEnum,
    Scanner,
    ServerNetworkLocation,
    ServerScanRequest,
    ServerScanResult,
    ServerScanStatusEnum,
)
from sslyze.errors import ServerHostnameCouldNotBeResolved

from app.scanners.base import BaseDetector, DetectorResult, ScanContext

DEFAULTS: dict[str, Any] = {
    "port": 443,
    # Guards the whole (blocking, run in a thread) SSLyze scan — a target
    # that never completes a TLS handshake would otherwise hang the scan.
    "scan_timeout_seconds": 120.0,
}


class DetectorError(Exception):
    """A detector could not run to completion — carries a human-readable reason
    that is surfaced to the user (distinct from a raw transport error)."""


# (scan_result attribute, protocol label, severity if any cipher is accepted)
_PROTOCOL_ATTRS: list[tuple[str, str, str]] = [
    ("ssl_2_0_cipher_suites", "SSLv2", "CRITICAL"),
    ("ssl_3_0_cipher_suites", "SSLv3", "CRITICAL"),
    ("tls_1_0_cipher_suites", "TLSv1.0", "HIGH"),
    ("tls_1_1_cipher_suites", "TLSv1.1", "MEDIUM"),
    ("tls_1_2_cipher_suites", "TLSv1.2", "INFO"),
    ("tls_1_3_cipher_suites", "TLSv1.3", "INFO"),
]

# Substrings of a cipher suite name (upper-cased) that mark it as weak,
# independent of which protocol version offered it.
_WEAK_CIPHER_MARKERS: list[tuple[str, str]] = [
    ("NULL", "CRITICAL"),
    ("EXPORT", "CRITICAL"),
    ("ANON", "CRITICAL"),
    ("RC4", "HIGH"),
    ("DES", "HIGH"),
    ("MD5", "MEDIUM"),
]

_SEVERITY_RANK: dict[str, int] = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
_SEVERITY_CVSS: dict[str, float] = {
    "INFO": 0.0, "LOW": 3.1, "MEDIUM": 5.3, "HIGH": 7.5, "CRITICAL": 9.8,
}


@dataclass
class TLSObservation:
    """Plain-data reduction of a ServerScanResult — no sslyze/cryptography
    objects, so this (and everything downstream of it) is trivially testable
    with hand-built fixtures and safe to drop straight into JSON evidence."""

    host: str
    port: int
    # protocol label -> accepted cipher suite names
    accepted_protocols: dict[str, list[str]] = field(default_factory=dict)
    certificate_subject: str = ""
    certificate_is_trusted: bool | None = None
    certificate_is_expired: bool | None = None
    certificate_signed_with_sha1: bool | None = None
    certificate_key_type: str = ""
    certificate_key_bits: int = 0
    heartbleed_vulnerable: bool | None = None
    ccs_injection_vulnerable: bool | None = None
    robot_vulnerable: bool | None = None
    supports_secure_renegotiation: bool | None = None


@dataclass
class Finding:
    category: str  # "protocol" | "cipher" | "certificate" | "vulnerability"
    detail: str
    cwe: str
    cve: str | None
    severity: str
    description: str


@dataclass
class Decision:
    detected: bool
    validation_status: str
    confidence: str
    severity: str
    reason: str
    worst: Finding | None


def _cert_key_info(public_key: Any) -> tuple[str, int]:
    type_name = public_key.__class__.__name__
    key_size = getattr(public_key, "key_size", 0)
    if "RSA" in type_name:
        return "RSA", key_size
    if "EllipticCurve" in type_name or "EC" in type_name:
        return "EC", key_size
    if "DSA" in type_name:
        return "DSA", key_size
    return type_name, key_size


def classify_ciphers(accepted_protocols: dict[str, list[str]]) -> list[Finding]:
    """Flag deprecated protocol versions and individually weak cipher suites.

    Kept pure (no I/O) so the decision policy can be unit-tested directly.
    """
    findings: list[Finding] = []
    protocol_severity = {label: sev for _attr, label, sev in _PROTOCOL_ATTRS}

    for protocol, ciphers in accepted_protocols.items():
        if not ciphers:
            continue
        severity = protocol_severity.get(protocol, "INFO")
        if severity != "INFO":
            findings.append(
                Finding(
                    category="protocol", detail=protocol, cwe="CWE-327", cve=None,
                    severity=severity,
                    description=(
                        f"The server accepts connections using {protocol}, a deprecated protocol."
                    ),
                )
            )
        for cipher in ciphers:
            upper = cipher.upper()
            marker_severity = next(
                (sev for marker, sev in _WEAK_CIPHER_MARKERS if marker in upper), None
            )
            if marker_severity:
                findings.append(
                    Finding(
                        category="cipher", detail=f"{protocol}: {cipher}", cwe="CWE-327", cve=None,
                        severity=marker_severity,
                        description=(
                            f"The server accepts the weak cipher suite {cipher} over {protocol}."
                        ),
                    )
                )
    return findings


def classify_certificate(obs: TLSObservation) -> list[Finding]:
    """Flag certificate trust/expiry/signature/key-strength issues.

    Kept pure (no I/O) so the decision policy can be unit-tested directly.
    """
    findings: list[Finding] = []
    if obs.certificate_is_trusted is False:
        findings.append(
            Finding(
                category="certificate", detail=obs.certificate_subject, cwe="CWE-295", cve=None,
                severity="MEDIUM",
                description=(
                    "The server's certificate is not signed by a trusted CA "
                    "(self-signed or broken chain)."
                ),
            )
        )
    if obs.certificate_is_expired:
        findings.append(
            Finding(
                category="certificate", detail=obs.certificate_subject, cwe="CWE-298", cve=None,
                severity="HIGH",
                description="The server's certificate has expired.",
            )
        )
    if obs.certificate_signed_with_sha1:
        findings.append(
            Finding(
                category="certificate", detail=obs.certificate_subject, cwe="CWE-327", cve=None,
                severity="MEDIUM",
                description=(
                    "The server's certificate chain is signed using the deprecated SHA-1 algorithm."
                ),
            )
        )
    if obs.certificate_key_type == "RSA" and 0 < obs.certificate_key_bits < 2048:
        findings.append(
            Finding(
                category="certificate", detail=f"RSA-{obs.certificate_key_bits}",
                cwe="CWE-326", cve=None, severity="HIGH",
                description=(
                    f"The server's RSA key is only {obs.certificate_key_bits} bits "
                    "(2048+ expected)."
                ),
            )
        )
    elif obs.certificate_key_type == "EC" and 0 < obs.certificate_key_bits < 224:
        findings.append(
            Finding(
                category="certificate", detail=f"EC-{obs.certificate_key_bits}",
                cwe="CWE-326", cve=None, severity="HIGH",
                description=(
                    f"The server's EC key is only {obs.certificate_key_bits} bits (224+ expected)."
                ),
            )
        )
    return findings


def classify_vulnerabilities(obs: TLSObservation) -> list[Finding]:
    """Flag named, SSLyze-detected TLS implementation vulnerabilities.

    Kept pure (no I/O) so the decision policy can be unit-tested directly.
    """
    findings: list[Finding] = []
    if obs.heartbleed_vulnerable:
        findings.append(
            Finding(
                category="vulnerability", detail="Heartbleed", cwe="CWE-125",
                cve="CVE-2014-0160", severity="CRITICAL",
                description=(
                    "The server is vulnerable to Heartbleed — an out-of-bounds read "
                    "that leaks process memory."
                ),
            )
        )
    if obs.ccs_injection_vulnerable:
        findings.append(
            Finding(
                category="vulnerability", detail="OpenSSL CCS Injection", cwe="CWE-295",
                cve="CVE-2014-0224", severity="HIGH",
                description=(
                    "The server is vulnerable to OpenSSL CCS injection, allowing "
                    "MITM key-material recovery."
                ),
            )
        )
    if obs.robot_vulnerable:
        findings.append(
            Finding(
                category="vulnerability", detail="ROBOT", cwe="CWE-203", cve=None,
                severity="CRITICAL",
                description=(
                    "The server is vulnerable to ROBOT — an RSA PKCS#1 v1.5 padding "
                    "oracle allowing decryption."
                ),
            )
        )
    if obs.supports_secure_renegotiation is False:
        findings.append(
            Finding(
                category="vulnerability", detail="Insecure renegotiation", cwe="CWE-295",
                cve="CVE-2009-3555", severity="MEDIUM",
                description=(
                    "The server does not support secure renegotiation, "
                    "enabling MITM data injection."
                ),
            )
        )
    return findings


def classify(obs: TLSObservation) -> Decision:
    """Turn every finding category into a single validation verdict.

    Kept pure (no I/O) so the decision policy can be unit-tested directly.
    """
    findings = (
        classify_ciphers(obs.accepted_protocols)
        + classify_certificate(obs)
        + classify_vulnerabilities(obs)
    )
    if not findings:
        return Decision(
            detected=False, validation_status="NOT_DETECTED", confidence="LOW", severity="INFO",
            reason=(
                "no weak protocols, ciphers, certificate issues, or known TLS vulnerabilities found"
            ),
            worst=None,
        )

    worst = max(findings, key=lambda f: _SEVERITY_RANK[f.severity])
    is_confirmed = worst.category in ("protocol", "cipher", "vulnerability")
    label = worst.cve or worst.cwe
    return Decision(
        detected=True,
        validation_status="CONFIRMED" if is_confirmed else "SUSPECTED",
        confidence="HIGH" if is_confirmed else "MEDIUM",
        severity=worst.severity,
        reason=f"{len(findings)} TLS weakness(es) found; worst: {worst.detail} ({label})",
        worst=worst,
    )


class WeakTLSDetector(BaseDetector):
    detector_id = "weak_tls"
    name = "Weak TLS Configuration"
    vulnerability_type = "weak_tls"
    scan_scope = "host"
    supported_targets = ["host", "webapp"]

    async def check(self, context: ScanContext) -> DetectorResult:
        cfg = {**DEFAULTS, **context.extra}
        parsed = urlparse(context.base_url)
        host = parsed.hostname or context.base_url
        port = parsed.port or cfg["port"]

        try:
            obs = await asyncio.wait_for(
                asyncio.to_thread(self._scan, host, port), timeout=cfg["scan_timeout_seconds"]
            )
            decision = classify(obs)
            return self._result(obs, decision)
        except DetectorError as exc:
            return self._error_result(host, port, str(exc))
        except TimeoutError:
            return self._error_result(
                host, port, f"TLS scan did not finish within {cfg['scan_timeout_seconds']:.0f}s."
            )

    def _scan(self, host: str, port: int) -> TLSObservation:
        """Blocking — SSLyze's Scanner API is synchronous. Run via asyncio.to_thread."""
        location = ServerNetworkLocation(hostname=host, port=port)
        try:
            request = ServerScanRequest(server_location=location)
        except ServerHostnameCouldNotBeResolved as exc:
            raise DetectorError(f"Could not resolve hostname {host}.") from exc

        scanner = Scanner()
        scanner.queue_scans([request])
        result = next(iter(scanner.get_results()))

        if result.scan_status == ServerScanStatusEnum.ERROR_NO_CONNECTIVITY:
            raise DetectorError(
                f"Could not establish a TLS connection to {host}:{port}: "
                f"{result.connectivity_error_trace}"
            )
        return self._observe(host, port, result)

    def _observe(self, host: str, port: int, result: ServerScanResult) -> TLSObservation:
        assert result.scan_result is not None
        scan = result.scan_result
        obs = TLSObservation(host=host, port=port)

        for attr, label, _severity in _PROTOCOL_ATTRS:
            attempt = getattr(scan, attr)
            if attempt.status == ScanCommandAttemptStatusEnum.COMPLETED and attempt.result:
                obs.accepted_protocols[label] = [
                    c.cipher_suite.name for c in attempt.result.accepted_cipher_suites
                ]

        cert_attempt = scan.certificate_info
        if cert_attempt.status == ScanCommandAttemptStatusEnum.COMPLETED and cert_attempt.result:
            deployments = cert_attempt.result.certificate_deployments
            if deployments:
                deployment = deployments[0]
                leaf = deployment.received_certificate_chain[0]
                obs.certificate_subject = leaf.subject.rfc4514_string()
                obs.certificate_is_trusted = deployment.verified_certificate_chain is not None
                # verified_chain_has_sha1_signature is only populated when SSLyze can
                # build a CA-trusted chain, which never happens for a self-signed cert
                # — check the received leaf's own signature algorithm too, so this
                # isn't silently blind for exactly the certs most likely to be weak.
                leaf_sig_algo = getattr(leaf.signature_hash_algorithm, "name", "") or ""
                obs.certificate_signed_with_sha1 = (
                    leaf_sig_algo.lower() == "sha1"
                    or bool(deployment.verified_chain_has_sha1_signature)
                )
                not_after = getattr(leaf, "not_valid_after_utc", None)
                if not_after is None:
                    not_after = leaf.not_valid_after.replace(tzinfo=UTC)
                obs.certificate_is_expired = not_after < datetime.now(UTC)
                key_type, key_bits = _cert_key_info(leaf.public_key())
                obs.certificate_key_type = key_type
                obs.certificate_key_bits = key_bits

        heartbleed_attempt = scan.heartbleed
        heartbleed_done = heartbleed_attempt.status == ScanCommandAttemptStatusEnum.COMPLETED
        if heartbleed_done and heartbleed_attempt.result:
            obs.heartbleed_vulnerable = heartbleed_attempt.result.is_vulnerable_to_heartbleed

        ccs_attempt = scan.openssl_ccs_injection
        if ccs_attempt.status == ScanCommandAttemptStatusEnum.COMPLETED and ccs_attempt.result:
            obs.ccs_injection_vulnerable = ccs_attempt.result.is_vulnerable_to_ccs_injection

        robot_attempt = scan.robot
        if robot_attempt.status == ScanCommandAttemptStatusEnum.COMPLETED and robot_attempt.result:
            obs.robot_vulnerable = robot_attempt.result.robot_result.name.startswith("VULNERABLE")

        reneg_attempt = scan.session_renegotiation
        if reneg_attempt.status == ScanCommandAttemptStatusEnum.COMPLETED and reneg_attempt.result:
            obs.supports_secure_renegotiation = reneg_attempt.result.supports_secure_renegotiation

        return obs

    def _result(self, obs: TLSObservation, decision: Decision) -> DetectorResult:
        endpoint = f"{obs.host}:{obs.port}"
        summary = f"{decision.reason}."
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
                "The target's TLS configuration accepts deprecated protocol versions, weak "
                "cipher suites, an untrustworthy certificate, or is vulnerable to a known "
                "TLS implementation flaw, exposing traffic to interception or decryption."
            ),
            evidence_summary=summary,
            evidence={
                "host": obs.host,
                "port": obs.port,
                "accepted_protocols": obs.accepted_protocols,
                "certificate": {
                    "subject": obs.certificate_subject,
                    "is_trusted": obs.certificate_is_trusted,
                    "is_expired": obs.certificate_is_expired,
                    "signed_with_sha1": obs.certificate_signed_with_sha1,
                    "key_type": obs.certificate_key_type,
                    "key_bits": obs.certificate_key_bits,
                },
                "vulnerabilities": {
                    "heartbleed": obs.heartbleed_vulnerable,
                    "ccs_injection": obs.ccs_injection_vulnerable,
                    "robot": obs.robot_vulnerable,
                    "supports_secure_renegotiation": obs.supports_secure_renegotiation,
                },
            },
            remediation=(
                "Disable SSLv2/SSLv3/TLSv1.0/TLSv1.1 and any NULL/EXPORT/anonymous/RC4/DES/MD5 "
                "cipher suites, keeping only TLS 1.2+ with modern AEAD ciphers; replace "
                "self-signed/expired/SHA-1-signed certificates and undersized keys "
                "(RSA <2048, EC <224 bits); patch the TLS stack if vulnerable to Heartbleed, "
                "ROBOT, or CCS injection; enable secure renegotiation."
            ),
            cwe=decision.worst.cwe if decision.worst else "CWE-327",
            cve=decision.worst.cve if decision.worst else None,
            cvss_score=_SEVERITY_CVSS[decision.severity],
            owasp_category="A02:2021 - Cryptographic Failures",
        )

    def _error_result(self, host: str, port: int, message: str) -> DetectorResult:
        return DetectorResult(
            detector=self.detector_id,
            vulnerability=self.name,
            detected=False,
            validation_status="ERROR",
            severity="INFO",
            confidence="LOW",
            endpoint=f"{host}:{port}",
            parameter=None,
            description="Detector could not complete against the target.",
            evidence_summary=f"Scan error: {message}",
            evidence={"error": message},
            cwe="CWE-327",
            owasp_category="A02:2021 - Cryptographic Failures",
        )
