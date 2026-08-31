import enum
import uuid
from datetime import datetime

from sqlalchemy import JSON, DateTime, Enum, ForeignKey, Integer, Text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base, TimestampMixin


class DiscoveryStatus(enum.StrEnum):
    QUEUED = "QUEUED"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"


class Discovery(Base, TimestampMixin):
    """One crawl of a target that maps its reachable paths so the operator can
    pick which are in-scope before scanning. Runs detached from the request that
    created it (FastAPI BackgroundTask), like a scan."""

    __tablename__ = "discoveries"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    target_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("targets.id", ondelete="CASCADE"))
    status: Mapped[DiscoveryStatus] = mapped_column(
        Enum(DiscoveryStatus, name="discovery_status"),
        default=DiscoveryStatus.QUEUED,
        nullable=False,
    )
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    initiated_by: Mapped[str | None] = mapped_column(Text)
    error_summary: Mapped[str | None] = mapped_column(Text)
    page_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    # Flat list of discovered entries: {url, path, methods, has_form, params, depth}.
    # The client nests these into a tree for scope selection.
    paths: Mapped[list | None] = mapped_column(JSON, nullable=True)
