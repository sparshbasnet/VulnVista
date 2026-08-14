from app.scanners import get_detectors_for_profile
from app.scanners.weak_tls import (
    TLSObservation,
    classify,
    classify_certificate,
    classify_ciphers,
    classify_vulnerabilities,
)


def test_classify_ciphers_flags_sslv3_as_critical() -> None:
    findings = classify_ciphers({"SSLv3": ["TLS_RSA_WITH_AES_128_CBC_SHA"]})
    protocol_findings = [f for f in findings if f.category == "protocol"]
    assert protocol_findings[0].severity == "CRITICAL"
    assert protocol_findings[0].detail == "SSLv3"


def test_classify_ciphers_flags_tls_1_0_as_high() -> None:
    findings = classify_ciphers({"TLSv1.0": ["TLS_RSA_WITH_AES_128_CBC_SHA"]})
    protocol_findings = [f for f in findings if f.category == "protocol"]
    assert protocol_findings[0].severity == "HIGH"


def test_classify_ciphers_does_not_flag_tls_1_3() -> None:
    findings = classify_ciphers({"TLSv1.3": ["TLS_AES_128_GCM_SHA256"]})
    assert findings == []


def test_classify_ciphers_flags_rc4_regardless_of_protocol() -> None:
    findings = classify_ciphers({"TLSv1.2": ["TLS_RSA_WITH_RC4_128_SHA"]})
    cipher_findings = [f for f in findings if f.category == "cipher"]
    assert cipher_findings[0].severity == "HIGH"
    assert "RC4" in cipher_findings[0].detail


def test_classify_ciphers_flags_null_cipher_as_critical() -> None:
    findings = classify_ciphers({"TLSv1.2": ["TLS_RSA_WITH_NULL_SHA"]})
    cipher_findings = [f for f in findings if f.category == "cipher"]
    assert cipher_findings[0].severity == "CRITICAL"


def test_classify_ciphers_ignores_strong_cipher() -> None:
    findings = classify_ciphers({"TLSv1.3": ["TLS_AES_256_GCM_SHA384"]})
    assert findings == []


def test_classify_certificate_flags_untrusted() -> None:
    obs = TLSObservation(
        host="h", port=443, certificate_is_trusted=False, certificate_subject="CN=h"
    )
    findings = classify_certificate(obs)
    assert any(f.cwe == "CWE-295" for f in findings)


def test_classify_certificate_flags_expired() -> None:
    obs = TLSObservation(host="h", port=443, certificate_is_expired=True)
    findings = classify_certificate(obs)
    assert any(f.severity == "HIGH" and f.cwe == "CWE-298" for f in findings)


def test_classify_certificate_flags_sha1_signature() -> None:
    obs = TLSObservation(host="h", port=443, certificate_signed_with_sha1=True)
    findings = classify_certificate(obs)
    assert any(f.cwe == "CWE-327" for f in findings)


def test_classify_certificate_flags_weak_rsa_key() -> None:
    obs = TLSObservation(host="h", port=443, certificate_key_type="RSA", certificate_key_bits=1024)
    findings = classify_certificate(obs)
    assert any(f.severity == "HIGH" and f.cwe == "CWE-326" for f in findings)


def test_classify_certificate_does_not_flag_strong_rsa_key() -> None:
    obs = TLSObservation(host="h", port=443, certificate_key_type="RSA", certificate_key_bits=2048)
    findings = classify_certificate(obs)
    assert findings == []


def test_classify_certificate_all_clean_has_no_findings() -> None:
    obs = TLSObservation(
        host="h", port=443, certificate_is_trusted=True, certificate_is_expired=False,
        certificate_signed_with_sha1=False, certificate_key_type="RSA", certificate_key_bits=2048,
    )
    assert classify_certificate(obs) == []


def test_classify_vulnerabilities_flags_heartbleed() -> None:
    obs = TLSObservation(host="h", port=443, heartbleed_vulnerable=True)
    findings = classify_vulnerabilities(obs)
    assert findings[0].cve == "CVE-2014-0160"
    assert findings[0].severity == "CRITICAL"


def test_classify_vulnerabilities_flags_ccs_injection() -> None:
    obs = TLSObservation(host="h", port=443, ccs_injection_vulnerable=True)
    findings = classify_vulnerabilities(obs)
    assert findings[0].cve == "CVE-2014-0224"


def test_classify_vulnerabilities_flags_robot() -> None:
    obs = TLSObservation(host="h", port=443, robot_vulnerable=True)
    findings = classify_vulnerabilities(obs)
    assert findings[0].detail == "ROBOT"


def test_classify_vulnerabilities_flags_insecure_renegotiation() -> None:
    obs = TLSObservation(host="h", port=443, supports_secure_renegotiation=False)
    findings = classify_vulnerabilities(obs)
    assert findings[0].cve == "CVE-2009-3555"


def test_classify_vulnerabilities_clean_has_no_findings() -> None:
    obs = TLSObservation(
        host="h", port=443, heartbleed_vulnerable=False, ccs_injection_vulnerable=False,
        robot_vulnerable=False, supports_secure_renegotiation=True,
    )
    assert classify_vulnerabilities(obs) == []


def test_classify_no_findings_is_not_detected() -> None:
    obs = TLSObservation(
        host="h", port=443, accepted_protocols={"TLSv1.3": ["TLS_AES_128_GCM_SHA256"]},
        certificate_is_trusted=True, certificate_is_expired=False,
        certificate_signed_with_sha1=False,
        certificate_key_type="RSA", certificate_key_bits=2048,
        heartbleed_vulnerable=False, ccs_injection_vulnerable=False, robot_vulnerable=False,
        supports_secure_renegotiation=True,
    )
    decision = classify(obs)
    assert decision.detected is False
    assert decision.validation_status == "NOT_DETECTED"


def test_classify_heartbleed_is_confirmed_critical_high_confidence() -> None:
    obs = TLSObservation(host="h", port=443, heartbleed_vulnerable=True)
    decision = classify(obs)
    assert decision.detected is True
    assert decision.validation_status == "CONFIRMED"
    assert decision.confidence == "HIGH"
    assert decision.severity == "CRITICAL"


def test_classify_untrusted_cert_only_is_suspected_medium_confidence() -> None:
    obs = TLSObservation(
        host="h", port=443, certificate_is_trusted=False, certificate_subject="CN=h"
    )
    decision = classify(obs)
    assert decision.detected is True
    assert decision.validation_status == "SUSPECTED"
    assert decision.confidence == "MEDIUM"


def test_profile_resolves_to_weak_tls_detector() -> None:
    detectors = get_detectors_for_profile("weak_tls")
    assert [d.detector_id for d in detectors] == ["weak_tls"]
