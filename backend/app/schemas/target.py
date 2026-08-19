import uuid
from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict


class TargetBase(BaseModel):
    name: str
    target_type: str
    base_url: str | None = None
    ip_address: str | None = None
    environment: str = "lab"


class TargetCreate(TargetBase):
    # Self-declared authorization to test a non-trusted host — required to get
    # is_allowed=True for anything outside the bundled lab hosts (see targets.py).
    authorization_confirmed: bool = False
    # Optional detector overrides (login credentials, cookies, headers, explicit
    # parameter/path). Write-only — never echoed back via TargetRead.
    scan_config: dict[str, Any] | None = None


class TargetRead(TargetBase):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    is_allowed: bool
    authorization_confirmed: bool
    created_at: datetime
    updated_at: datetime
