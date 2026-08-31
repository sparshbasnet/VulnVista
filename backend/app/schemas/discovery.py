import uuid
from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict

from app.models.discovery import DiscoveryStatus


class DiscoveryCreate(BaseModel):
    target_id: uuid.UUID


class DiscoveryRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    target_id: uuid.UUID
    status: DiscoveryStatus
    started_at: datetime | None
    completed_at: datetime | None
    initiated_by: str | None
    error_summary: str | None
    page_count: int
    # Flat discovered-path records; the client nests them into a tree. Safe to
    # return (no credentials) unlike Target.scan_config.
    paths: list[dict[str, Any]] | None
    created_at: datetime
