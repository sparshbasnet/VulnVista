import enum
import uuid
from datetime import datetime

from sqlalchemy import JSON, DateTime, Enum, Float, ForeignKey, String, Text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base, TimestampMixin


class ScanStatus(enum.StrEnum):
    QUEUED = "QUEUED"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    PARTIAL = "PARTIAL"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"


class Scan(Base, TimestampMixin):
    """One execution of selected detectors against a target (plan section 4.2)."""

    __tablename__ = "scans"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    target_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("targets.id", ondelete="CASCADE"))
    scan_profile: Mapped[str] = mapped_column(String(64), default="default")
    status: Mapped[ScanStatus] = mapped_column(
        Enum(ScanStatus, name="scan_status"), default=ScanStatus.QUEUED, nullable=False
    )
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    duration_seconds: Mapped[float | None] = mapped_column(Float)
    initiated_by: Mapped[str | None] = mapped_column(String(255))
    error_summary: Mapped[str | None] = mapped_column(Text)
    # Path scope chosen from a discovery tree. When in_scope_paths is set, the
    # runner attacks only those paths (see scan_runner); out_of_scope_paths is
    # kept for the report. Both null => legacy behavior (detectors self-discover).
    in_scope_paths: Mapped[list | None] = mapped_column(JSON, nullable=True)
    out_of_scope_paths: Mapped[list | None] = mapped_column(JSON, nullable=True)
