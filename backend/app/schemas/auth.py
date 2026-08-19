import uuid
from datetime import datetime
from typing import Annotated

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.models.user import UserRole


class LoginRequest(BaseModel):
    username: str
    password: str


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"


class UserCreate(BaseModel):
    username: Annotated[str, Field(min_length=3, max_length=64, pattern=r"^[A-Za-z0-9_.-]+$")]
    email: Annotated[str, Field(min_length=3, max_length=255)]
    password: Annotated[str, Field(min_length=12, max_length=72)]
    role: UserRole = UserRole.VIEWER

    @field_validator("username", "email")
    @classmethod
    def normalize_identity(cls, value: str) -> str:
        return value.strip().lower()

    @field_validator("email")
    @classmethod
    def validate_email_shape(cls, value: str) -> str:
        if value.count("@") != 1 or value.startswith("@") or value.endswith("@"):
            raise ValueError("Invalid email address")
        return value

    @field_validator("password")
    @classmethod
    def validate_password_bytes(cls, value: str) -> str:
        if len(value.encode("utf-8")) > 72:
            raise ValueError("Password must be at most 72 UTF-8 bytes")
        return value


class UserRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    username: str
    email: str
    role: UserRole
    is_active: bool
    last_login_at: datetime | None
    created_at: datetime
