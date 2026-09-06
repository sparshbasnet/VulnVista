import uuid
from datetime import datetime
from typing import Annotated

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from app.core.security import MAX_PASSWORD_BYTES, MIN_PASSWORD_LENGTH, validate_password_policy
from app.models.user import UserRole

Password = Annotated[str, Field(min_length=MIN_PASSWORD_LENGTH, max_length=MAX_PASSWORD_BYTES)]
Username = Annotated[str, Field(min_length=3, max_length=64, pattern=r"^[A-Za-z0-9_.-]+$")]
Email = Annotated[str, Field(min_length=3, max_length=255)]


def normalize_identity(value: str) -> str:
    return value.strip().lower()


def validate_email_shape(value: str) -> str:
    if value.count("@") != 1 or value.startswith("@") or value.endswith("@"):
        raise ValueError("Invalid email address")
    return value


class LoginRequest(BaseModel):
    username: str
    password: str


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    # Set when the account is on an administrator-issued temporary password and
    # must choose a new one before the session is good for anything else.
    must_change_password: bool = False


class UserCreate(BaseModel):
    username: Username
    email: Email
    password: Password
    role: UserRole = UserRole.VIEWER

    @field_validator("username", "email")
    @classmethod
    def normalize(cls, value: str) -> str:
        return normalize_identity(value)

    @field_validator("email")
    @classmethod
    def check_email_shape(cls, value: str) -> str:
        return validate_email_shape(value)

    @field_validator("password")
    @classmethod
    def check_password_policy(cls, value: str) -> str:
        return validate_password_policy(value)


class UserUpdate(BaseModel):
    """Administrator edit of another account. Omitted fields are left alone."""

    role: UserRole | None = None
    is_active: bool | None = None

    @model_validator(mode="after")
    def require_a_change(self) -> "UserUpdate":
        if self.role is None and self.is_active is None:
            raise ValueError("Provide at least one of: role, is_active")
        return self


class PasswordChangeRequest(BaseModel):
    """Self-service change; the current password is the proof of ownership."""

    current_password: str
    new_password: Password

    @field_validator("new_password")
    @classmethod
    def check_password_policy(cls, value: str) -> str:
        return validate_password_policy(value)

    @model_validator(mode="after")
    def reject_unchanged_password(self) -> "PasswordChangeRequest":
        if self.current_password == self.new_password:
            raise ValueError("New password must differ from the current password")
        return self


class PasswordResetRequest(BaseModel):
    """Start self-service recovery. `identity` is a username or an email address."""

    identity: Annotated[str, Field(min_length=1, max_length=255)]

    @field_validator("identity")
    @classmethod
    def normalize(cls, value: str) -> str:
        return normalize_identity(value)


class PasswordResetConfirm(BaseModel):
    token: Annotated[str, Field(min_length=16, max_length=256)]
    new_password: Password

    @field_validator("new_password")
    @classmethod
    def check_password_policy(cls, value: str) -> str:
        return validate_password_policy(value)


class PasswordResetIssued(BaseModel):
    """An administrator-issued reset token, to be delivered out of band."""

    user_id: uuid.UUID
    username: str
    reset_token: str
    expires_at: datetime


class UserRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    username: str
    email: str
    role: UserRole
    is_active: bool
    last_login_at: datetime | None
    created_at: datetime
    must_change_password: bool = False
    locked_until: datetime | None = None
    password_changed_at: datetime | None = None
