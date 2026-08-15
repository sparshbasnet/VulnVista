import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field

from app.models.finding import FindingStatus, ValidationStatus


class EvidenceRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    finding_id: uuid.UUID
    evidence_type: str
    content: dict
    created_at: datetime


class FindingRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    scan_id: uuid.UUID
    target_id: uuid.UUID
    detector_id: str
    vulnerability_name: str
    severity: str
    confidence: str
    validation_status: ValidationStatus
    description: str | None
    affected_endpoint: str | None
    parameter: str | None
    evidence_summary: str | None
    remediation: str | None
    cwe: str | None
    cve: str | None
    cvss_score: float | None
    owasp_category: str | None
    finding_status: FindingStatus
    created_at: datetime
    updated_at: datetime
    evidence: list[EvidenceRead] = Field(default_factory=list)


class FindingStatusUpdate(BaseModel):
    finding_status: FindingStatus
