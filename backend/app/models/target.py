import uuid

from sqlalchemy import JSON, Boolean, String
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base, TimestampMixin


class Target(Base, TimestampMixin):
    """A scannable host/application — either a bundled lab container or any
    other target the requester has confirmed they're authorized to test."""

    __tablename__ = "targets"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    target_type: Mapped[str] = mapped_column(String(64), nullable=False)
    base_url: Mapped[str | None] = mapped_column(String(512))
    ip_address: Mapped[str | None] = mapped_column(String(64))
    environment: Mapped[str] = mapped_column(String(64), default="lab", nullable=False)
    is_allowed: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    # Self-declared by the requester for non-trusted hosts; kept for audit/display
    # even though it isn't the sole basis for is_allowed (see targets.py).
    authorization_confirmed: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    # Optional per-target detector overrides (login fields, cookies, headers,
    # explicit parameter/path) forwarded to detectors as ScanContext.extra.
    # Never returned to the client — see TargetRead — since it may hold credentials.
    scan_config: Mapped[dict | None] = mapped_column(JSON, nullable=True)
