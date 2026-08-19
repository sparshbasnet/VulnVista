import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict

from app.models.scan import ScanStatus


class ScanCreate(BaseModel):
    target_id: uuid.UUID
    scan_profile: str = "default"
    initiated_by: str | None = None


class ScanRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    target_id: uuid.UUID
    scan_profile: str
    status: ScanStatus
    started_at: datetime | None
    completed_at: datetime | None
    duration_seconds: float | None
    pages_scanned: int
    initiated_by: str | None
    error_summary: str | None
    created_at: datetime
