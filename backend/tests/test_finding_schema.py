import uuid
from datetime import UTC, datetime

from app.models.finding import FindingStatus, ValidationStatus
from app.schemas.finding import EvidenceRead, FindingRead


def test_finding_read_includes_evidence_and_updated_at() -> None:
    now = datetime.now(UTC)
    finding_id = uuid.uuid4()

    finding = FindingRead(
        id=finding_id,
        scan_id=uuid.uuid4(),
        target_id=uuid.uuid4(),
        detector_id="weak_tls",
        vulnerability_name="Weak TLS Configuration",
        severity="HIGH",
        confidence="HIGH",
        validation_status=ValidationStatus.CONFIRMED,
        description=None,
        affected_endpoint="example.test:443",
        parameter=None,
        evidence_summary="Deprecated protocol accepted.",
        remediation="Disable deprecated TLS protocols.",
        cwe="CWE-327",
        cve=None,
        cvss_score=8.1,
        owasp_category="A02:2021 Cryptographic Failures",
        finding_status=FindingStatus.OPEN,
        created_at=now,
        updated_at=now,
        evidence=[
            EvidenceRead(
                id=uuid.uuid4(),
                finding_id=finding_id,
                evidence_type="detector_probe",
                content={"accepted_protocols": {"TLSv1.0": ["AES128-SHA"]}},
                created_at=now,
            )
        ],
    )

    payload = finding.model_dump(mode="json")

    assert payload["updated_at"] == now.isoformat().replace("+00:00", "Z")
    assert payload["evidence"][0]["content"]["accepted_protocols"]["TLSv1.0"] == [
        "AES128-SHA"
    ]
