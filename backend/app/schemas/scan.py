import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict

from app.models.scan import ScanStatus


class ScanCreate(BaseModel):
    target_id: uuid.UUID
    scan_profile: str = "default"
    # Optional path scope from a discovery tree. When in_scope_paths is set, the
    # runner attacks only those paths; out_of_scope_paths is kept for the report.
    in_scope_paths: list[str] | None = None
    out_of_scope_paths: list[str] | None = None


class ScanRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    target_id: uuid.UUID
    scan_profile: str
    status: ScanStatus
    started_at: datetime | None
    completed_at: datetime | None
    duration_seconds: float | None
    initiated_by: str | None
    error_summary: str | None
    in_scope_paths: list[str] | None
    out_of_scope_paths: list[str] | None
    created_at: datetime
