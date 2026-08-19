from app.scanners import get_detectors_for_profile
from app.scanners.vulnerable_services import (
    ObservedService,
    VulnerabilityMatch,
    best_application_cpe,
    classify,
    cpe22_to_cpe23,
    match_heuristics,
    parse_nmap_xml,
    parse_nvd_vulnerability,
)

SAMPLE_NMAP_XML = """<?xml version="1.0"?>
<nmaprun>
<host>
<status state="up"/>
<address addr="127.0.0.1" addrtype="ipv4"/>
<ports>
<port protocol="tcp" portid="21">
  <state state="open"/>
  <service name="ftp" product="vsftpd" version="2.3.4" extrainfo="" method="probed" conf="10">
    <cpe>cpe:/a:vsftpd:vsftpd:2.3.4</cpe>
  </service>
</port>
<port protocol="tcp" portid="22">
  <state state="open"/>
  <service name="ssh" product="OpenSSH" version="4.7p1" extrainfo="Ubuntu" method="probed">
    <cpe>cpe:/a:openbsd:openssh:4.7p1</cpe>
    <cpe>cpe:/o:linux:linux_kernel</cpe>
  </service>
</port>
<port protocol="tcp" portid="23">
  <state state="open"/>
  <service name="telnet" product="" version="" method="probed" conf="10"/>
</port>
<port protocol="tcp" portid="1524">
  <state state="open"/>
  <service name="ingreslock" method="table" conf="3"/>
</port>
<port protocol="tcp" portid="80">
  <state state="filtered"/>
  <service name="http" method="table" conf="3"/>
</port>
</ports>
</host>
</nmaprun>
"""

SAMPLE_NVD_VULNERABILITY = {
    "cve": {
        "id": "CVE-2011-2523",
        "descriptions": [{"lang": "en", "value": "Backdoor in vsftpd 2.3.4."}],
        "weaknesses": [{"description": [{"lang": "en", "value": "CWE-78"}]}],
        "metrics": {
            "cvssMetricV31": [{"cvssData": {"baseScore": 9.8, "baseSeverity": "CRITICAL"}}],
        },
    }
}


def test_parse_nmap_xml_only_returns_open_ports() -> None:
    services = parse_nmap_xml(SAMPLE_NMAP_XML)
    assert [s.port for s in services] == [21, 22, 23, 1524]


def test_parse_nmap_xml_extracts_cpes() -> None:
    services = parse_nmap_xml(SAMPLE_NMAP_XML)
    ssh = next(s for s in services if s.port == 22)
    assert ssh.cpes == ["cpe:/a:openbsd:openssh:4.7p1", "cpe:/o:linux:linux_kernel"]


def test_parse_nmap_xml_handles_service_with_no_cpe() -> None:
    services = parse_nmap_xml(SAMPLE_NMAP_XML)
    ingreslock = next(s for s in services if s.port == 1524)
    assert ingreslock.cpes == []


def test_best_application_cpe_prefers_a_over_o() -> None:
    cpes = ["cpe:/o:linux:linux_kernel", "cpe:/a:openbsd:openssh:4.7p1"]
    assert best_application_cpe(cpes) == "cpe:/a:openbsd:openssh:4.7p1"


def test_best_application_cpe_none_when_no_application_cpe() -> None:
    assert best_application_cpe(["cpe:/o:linux:linux_kernel"]) is None


def test_cpe22_to_cpe23_pads_and_prefixes() -> None:
    assert (
        cpe22_to_cpe23("cpe:/a:vsftpd:vsftpd:2.3.4")
        == "cpe:2.3:a:vsftpd:vsftpd:2.3.4:*:*:*:*:*:*:*"
    )


def test_cpe22_to_cpe23_rejects_non_cpe22_input() -> None:
    assert cpe22_to_cpe23("not-a-cpe") is None


def test_parse_nvd_vulnerability_extracts_cve_score_severity_cwe() -> None:
    cve_id, score, severity, cwe, desc = parse_nvd_vulnerability(SAMPLE_NVD_VULNERABILITY)
    assert cve_id == "CVE-2011-2523"
    assert score == 9.8
    assert severity == "CRITICAL"
    assert cwe == "CWE-78"
    assert "Backdoor" in desc


def test_match_heuristics_flags_vsftpd_backdoor_as_known_cve() -> None:
    services = parse_nmap_xml(SAMPLE_NMAP_XML)
    matches = match_heuristics(services)
    ftp_match = next(m for m in matches if m.port == 21)
    assert ftp_match.category == "known_cve"
    assert ftp_match.cve == "CVE-2011-2523"
    assert ftp_match.severity == "CRITICAL"


def test_match_heuristics_flags_ingreslock_by_port_with_no_cpe() -> None:
    services = parse_nmap_xml(SAMPLE_NMAP_XML)
    matches = match_heuristics(services)
    ingreslock_match = next(m for m in matches if m.port == 1524)
    assert ingreslock_match.category == "known_cve"
    assert ingreslock_match.cve is None
    assert ingreslock_match.cwe == "CWE-912"


def test_match_heuristics_flags_telnet_as_heuristic() -> None:
    services = parse_nmap_xml(SAMPLE_NMAP_XML)
    matches = match_heuristics(services)
    telnet_match = next(m for m in matches if m.port == 23)
    assert telnet_match.category == "heuristic"
    assert telnet_match.cwe == "CWE-319"


def test_match_heuristics_does_not_flag_current_openssh() -> None:
    services = parse_nmap_xml(SAMPLE_NMAP_XML)
    matches = match_heuristics(services)
    assert not any(m.port == 22 for m in matches)


def test_match_heuristics_does_not_flag_patched_vsftpd() -> None:
    services = [
        ObservedService(
            port=21, protocol="tcp", service="ftp", product="vsftpd",
            version="3.0.5", extrainfo="", cpes=[], script_output={},
        )
    ]
    assert match_heuristics(services) == []


def test_classify_no_matches_is_not_detected() -> None:
    decision = classify([])
    assert decision.detected is False
    assert decision.validation_status == "NOT_DETECTED"
    assert decision.severity == "INFO"


def test_classify_known_cve_is_confirmed_high_confidence() -> None:
    services = parse_nmap_xml(SAMPLE_NMAP_XML)
    matches = match_heuristics(services)
    decision = classify(matches)
    assert decision.detected is True
    assert decision.validation_status == "CONFIRMED"
    assert decision.confidence == "HIGH"
    assert decision.severity == "CRITICAL"
    assert decision.worst is not None


def test_classify_heuristic_only_is_suspected_medium_confidence() -> None:
    services = [
        ObservedService(
            port=23, protocol="tcp", service="telnet", product="", version="",
            extrainfo="", cpes=[], script_output={},
        )
    ]
    decision = classify(match_heuristics(services))
    assert decision.detected is True
    assert decision.validation_status == "SUSPECTED"
    assert decision.confidence == "MEDIUM"


def test_classify_escalates_severity_when_exploit_available() -> None:
    matches = [
        VulnerabilityMatch(
            port=22, service="ssh", product="OpenSSH", version="4.7p1",
            category="known_cve", cve="CVE-2008-5161", cwe="CWE-200", severity="MEDIUM",
            description="...", exploit_available=True,
            exploit_refs=[{"edb_id": 123, "title": "OpenSSH exploit"}],
        )
    ]
    decision = classify(matches)
    assert decision.severity == "CRITICAL"
    assert "public exploit available" in decision.reason


def test_profile_resolves_to_vulnerable_services_detector() -> None:
    detectors = get_detectors_for_profile("vulnerable_services")
    assert [d.detector_id for d in detectors] == ["vulnerable_services"]
