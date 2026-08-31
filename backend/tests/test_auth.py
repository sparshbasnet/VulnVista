import uuid
from datetime import timedelta

import pytest
from fastapi import HTTPException

from app.api.auth_deps import require_roles
from app.core.security import (
    create_access_token,
    decode_access_token,
    hash_password,
    verify_password,
)
from app.models.user import User, UserRole
from app.schemas.auth import UserCreate


def test_password_hash_round_trip() -> None:
    hashed = hash_password("A-strong-test-password-1")

    assert hashed != "A-strong-test-password-1"
    assert verify_password("A-strong-test-password-1", hashed)
    assert not verify_password("wrong-password", hashed)


def test_access_token_round_trip() -> None:
    user_id = uuid.uuid4()

    claims = decode_access_token(create_access_token(user_id, token_version=3))

    assert claims.user_id == user_id
    assert claims.token_version == 3


def test_expired_access_token_is_rejected() -> None:
    token = create_access_token(uuid.uuid4(), expires_delta=timedelta(seconds=-1))

    with pytest.raises(ValueError, match="Invalid or expired"):
        decode_access_token(token)


def test_user_creation_normalizes_identity() -> None:
    payload = UserCreate(
        username="Test.Admin",
        email="Test.Admin@Example.test",
        password="A-strong-test-password-1",
        role=UserRole.ADMIN,
    )

    assert payload.username == "test.admin"
    assert payload.email == "test.admin@example.test"


@pytest.mark.asyncio
async def test_viewer_is_denied_operator_role() -> None:
    dependency = require_roles(UserRole.ADMIN, UserRole.ANALYST)
    viewer = User(
        username="viewer",
        email="viewer@example.test",
        hashed_password="unused",
        role=UserRole.VIEWER,
    )

    with pytest.raises(HTTPException) as exc_info:
        await dependency(viewer)

    assert exc_info.value.status_code == 403
