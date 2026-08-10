import enum
import uuid
from datetime import datetime

from sqlalchemy import JSON, DateTime, Enum, Float, ForeignKey, String, Text, func
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base, TimestampMixin


class FindingStatus(enum.StrEnum):
    OPEN = "OPEN"
    IN_PROGRESS = "IN_PROGRESS"
    REMEDIATED = "REMEDIATED"
    ACCEPTED_RISK = "ACCEPTED_RISK"
    FALSE_POSITIVE = "FALSE_POSITIVE"


class ValidationStatus(enum.StrEnum):
    NOT_DETECTED = "NOT_DETECTED"
    SUSPECTED = "SUSPECTED"
    CONFIRMED = "CONFIRMED"
    INCONCLUSIVE = "INCONCLUSIVE"
    ERROR = "ERROR"


class Finding(Base, TimestampMixin):
    """A vulnerability reported by a detector (plan section 4.4)."""

    __tablename__ = "findings"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    scan_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("scans.id", ondelete="CASCADE"))
    target_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("targets.id", ondelete="CASCADE"))
    detector_id: Mapped[str] = mapped_column(String(128), nullable=False)
    vulnerability_name: Mapped[str] = mapped_column(String(255), nullable=False)
    severity: Mapped[str] = mapped_column(String(32), nullable=False)
    confidence: Mapped[str] = mapped_column(String(32), nullable=False)
    validation_status: Mapped[ValidationStatus] = mapped_column(
        Enum(ValidationStatus, name="validation_status"), default=ValidationStatus.SUSPECTED
    )
    description: Mapped[str | None] = mapped_column(Text)
    affected_endpoint: Mapped[str | None] = mapped_column(String(512))
    parameter: Mapped[str | None] = mapped_column(String(255))
    evidence_summary: Mapped[str | None] = mapped_column(Text)
    remediation: Mapped[str | None] = mapped_column(Text)
    cwe: Mapped[str | None] = mapped_column(String(32))
    cve: Mapped[str | None] = mapped_column(String(32))
    cvss_score: Mapped[float | None] = mapped_column(Float)
    owasp_category: Mapped[str | None] = mapped_column(String(128))
    finding_status: Mapped[FindingStatus] = mapped_column(
        Enum(FindingStatus, name="finding_status"), default=FindingStatus.OPEN, nullable=False
    )

    evidence: Mapped[list["Evidence"]] = relationship(
        back_populates="finding", cascade="all, delete-orphan"
    )


class Evidence(Base):
    """Evidence supporting a finding (plan section 4.5), stored separately from the finding."""

    __tablename__ = "evidence"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    finding_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("findings.id", ondelete="CASCADE"))
    evidence_type: Mapped[str] = mapped_column(String(64), nullable=False)
    content: Mapped[dict] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    finding: Mapped["Finding"] = relationship(back_populates="evidence")
