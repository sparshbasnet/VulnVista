import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict


class TargetBase(BaseModel):
    name: str
    target_type: str
    base_url: str | None = None
    ip_address: str | None = None
    environment: str = "lab"


class TargetCreate(TargetBase):
    pass


class TargetRead(TargetBase):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    is_allowed: bool
    created_at: datetime
    updated_at: datetime
