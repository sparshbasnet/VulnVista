import uuid
from datetime import UTC, datetime, timedelta

import pytest
from fastapi import HTTPException
from fastapi.security import HTTPAuthorizationCredentials
from jose import jwt

from app.api.auth_deps import get_current_user
from app.core.config import get_settings
from app.core.security import ALGORITHM, create_access_token, decode_access_token
from app.models.user import User, UserRole


def _bearer(token: str) -> HTTPAuthorizationCredentials:
    return HTTPAuthorizationCredentials(scheme="Bearer", credentials=token)


class FakeUserDb:
    def __init__(self, user: User | None) -> None:
        self.user = user
        self.requested_user_id: uuid.UUID | None = None

    async def get(self, _model: type[User], user_id: uuid.UUID) -> User | None:
        self.requested_user_id = user_id
        if self.user is not None and self.user.id == user_id:
            return self.user
        return None


def _user(
    *, user_id: uuid.UUID | None = None, active: bool = True, token_version: int = 1
) -> User:
    return User(
        id=user_id or uuid.uuid4(),
        username="session.user",
        email="session.user@example.test",
        hashed_password="unused",
        role=UserRole.VIEWER,
        is_active=active,
        token_version=token_version,
        created_at=datetime.now(UTC),
    )


def _signed_payload(payload: dict[str, object], secret: str | None = None) -> str:
    return jwt.encode(payload, secret or get_settings().secret_key, algorithm=ALGORITHM)


def test_tampered_access_token_is_rejected() -> None:
    token = create_access_token(uuid.uuid4())
    header, payload, signature = token.split(".")
    replacement = "a" if signature[0] != "a" else "b"
    tampered = f"{header}.{payload}.{replacement}{signature[1:]}"

    with pytest.raises(ValueError, match="Invalid or expired"):
        decode_access_token(tampered)


def test_access_token_signed_with_wrong_secret_is_rejected() -> None:
    token = _signed_payload(
        {
            "sub": str(uuid.uuid4()),
            "iat": datetime.now(UTC),
            "exp": datetime.now(UTC) + timedelta(minutes=5),
            "type": "access",
        },
        secret="not-the-application-secret",
    )

    with pytest.raises(ValueError, match="Invalid or expired"):
        decode_access_token(token)


def test_non_access_token_type_is_rejected() -> None:
    token = _signed_payload(
        {
            "sub": str(uuid.uuid4()),
            "iat": datetime.now(UTC),
            "exp": datetime.now(UTC) + timedelta(minutes=5),
            "type": "refresh",
        }
    )

    with pytest.raises(ValueError, match="Invalid or expired"):
        decode_access_token(token)


@pytest.mark.parametrize(
    "payload",
    [
        {
            "iat": datetime.now(UTC),
            "exp": datetime.now(UTC) + timedelta(minutes=5),
            "type": "access",
        },
        {
            "sub": "not-a-uuid",
            "iat": datetime.now(UTC),
            "exp": datetime.now(UTC) + timedelta(minutes=5),
            "type": "access",
        },
    ],
)
def test_access_token_requires_valid_subject_claim(payload: dict[str, object]) -> None:
    token = _signed_payload(payload)

    with pytest.raises(ValueError, match="Invalid or expired"):
        decode_access_token(token)


@pytest.mark.asyncio
async def test_current_user_accepts_active_user_session() -> None:
    user = _user()
    db = FakeUserDb(user)

    current = await get_current_user(credentials=_bearer(create_access_token(user.id)), db=db)  # type: ignore[arg-type]

    assert current is user
    assert db.requested_user_id == user.id


@pytest.mark.asyncio
async def test_current_user_rejects_token_for_missing_user() -> None:
    missing_user_id = uuid.uuid4()

    with pytest.raises(HTTPException) as exc_info:
        await get_current_user(
            credentials=_bearer(create_access_token(missing_user_id)), db=FakeUserDb(None)
        )  # type: ignore[arg-type]

    assert exc_info.value.status_code == 401
    assert exc_info.value.headers == {"WWW-Authenticate": "Bearer"}


@pytest.mark.asyncio
async def test_current_user_rejects_inactive_user_session() -> None:
    inactive_user = _user(active=False)

    with pytest.raises(HTTPException) as exc_info:
        await get_current_user(
            credentials=_bearer(create_access_token(inactive_user.id)),
            db=FakeUserDb(inactive_user),  # type: ignore[arg-type]
        )

    assert exc_info.value.status_code == 401
    assert exc_info.value.headers == {"WWW-Authenticate": "Bearer"}


@pytest.mark.asyncio
async def test_current_user_rejects_token_from_before_a_password_change() -> None:
    # The user changed their password (or was deactivated and reinstated), which
    # bumped token_version; tokens minted against the old version are dead.
    user = _user(token_version=2)
    stale_token = create_access_token(user.id, token_version=1)

    with pytest.raises(HTTPException) as exc_info:
        await get_current_user(credentials=_bearer(stale_token), db=FakeUserDb(user))  # type: ignore[arg-type]

    assert exc_info.value.status_code == 401
    assert exc_info.value.headers == {"WWW-Authenticate": "Bearer"}


@pytest.mark.asyncio
async def test_current_user_accepts_a_token_at_the_current_version() -> None:
    user = _user(token_version=7)

    current = await get_current_user(
        credentials=_bearer(create_access_token(user.id, token_version=7)),
        db=FakeUserDb(user),  # type: ignore[arg-type]
    )

    assert current is user
