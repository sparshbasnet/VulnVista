import uuid
from datetime import UTC, datetime, timedelta

import pytest
from fastapi import HTTPException
from pydantic import ValidationError

from app.api.auth_deps import require_usable_session
from app.core.config import get_settings
from app.core.security import (
    generate_reset_token,
    hash_reset_token,
    reset_tokens_match,
    validate_password_policy,
)
from app.models.user import User, UserRole
from app.schemas.auth import (
    PasswordChangeRequest,
    PasswordResetConfirm,
    PasswordResetRequest,
    UserUpdate,
)
from app.services import accounts

STRONG_PASSWORD = "Correct-Horse-9"


def make_user(**overrides) -> User:
    defaults = dict(
        id=uuid.uuid4(),
        username="operator",
        email="operator@example.test",
        hashed_password="unused",
        role=UserRole.ANALYST,
        is_active=True,
        token_version=1,
        must_change_password=False,
        failed_login_attempts=0,
        locked_until=None,
    )
    return User(**{**defaults, **overrides})


# --- password policy ---------------------------------------------------------


def test_policy_accepts_a_strong_password() -> None:
    assert validate_password_policy(STRONG_PASSWORD) == STRONG_PASSWORD


def test_policy_rejects_a_short_password() -> None:
    with pytest.raises(ValueError, match="at least 12 characters"):
        validate_password_policy("Short-1a")


def test_policy_rejects_too_few_character_classes() -> None:
    with pytest.raises(ValueError, match="at least three of"):
        validate_password_policy("alllowercaseletters")


def test_policy_rejects_more_than_72_bytes() -> None:
    with pytest.raises(ValueError, match="72 UTF-8 bytes"):
        validate_password_policy("Aa1-" + "é" * 40)


# --- request schemas ---------------------------------------------------------


def test_password_change_rejects_reusing_the_current_password() -> None:
    with pytest.raises(ValidationError, match="must differ"):
        PasswordChangeRequest(current_password=STRONG_PASSWORD, new_password=STRONG_PASSWORD)


def test_password_change_accepts_a_different_strong_password() -> None:
    payload = PasswordChangeRequest(current_password="old-one", new_password=STRONG_PASSWORD)

    assert payload.new_password == STRONG_PASSWORD


def test_password_change_enforces_the_policy_on_the_new_password() -> None:
    with pytest.raises(ValidationError):
        PasswordChangeRequest(current_password="old-one", new_password="weakweakweak")


def test_reset_request_normalizes_the_identity() -> None:
    assert PasswordResetRequest(identity="  Jane.Smith  ").identity == "jane.smith"


def test_reset_confirm_rejects_an_implausibly_short_token() -> None:
    with pytest.raises(ValidationError):
        PasswordResetConfirm(token="tiny", new_password=STRONG_PASSWORD)


def test_user_update_requires_at_least_one_field() -> None:
    with pytest.raises(ValidationError, match="at least one of"):
        UserUpdate()


def test_user_update_accepts_a_role_only_edit() -> None:
    payload = UserUpdate(role=UserRole.VIEWER)

    assert payload.role is UserRole.VIEWER
    assert payload.is_active is None


# --- login throttling --------------------------------------------------------


def test_failed_logins_lock_the_account_at_the_configured_ceiling() -> None:
    settings = get_settings()
    user = make_user()

    for _ in range(settings.max_failed_logins):
        accounts.register_failed_login(user)

    assert user.failed_login_attempts == settings.max_failed_logins
    assert accounts.is_locked_out(user)


def test_a_single_failure_does_not_lock_the_account() -> None:
    user = make_user()

    accounts.register_failed_login(user)

    assert not accounts.is_locked_out(user)


def test_successful_login_clears_the_lockout() -> None:
    user = make_user(failed_login_attempts=4, locked_until=datetime.now(UTC) + timedelta(minutes=5))

    accounts.register_successful_login(user)

    assert user.failed_login_attempts == 0
    assert not accounts.is_locked_out(user)
    assert user.last_login_at is not None


def test_an_expired_lockout_no_longer_blocks_login() -> None:
    user = make_user(locked_until=datetime.now(UTC) - timedelta(seconds=1))

    assert not accounts.is_locked_out(user)


def test_naive_lockout_timestamps_are_read_as_utc() -> None:
    user = make_user(locked_until=datetime.now(UTC).replace(tzinfo=None) + timedelta(minutes=5))

    assert accounts.is_locked_out(user)


# --- reset tokens ------------------------------------------------------------


def test_reset_token_is_stored_only_as_a_digest() -> None:
    raw, digest = generate_reset_token()

    assert raw != digest
    assert digest == hash_reset_token(raw)
    assert len(digest) == 64


def test_reset_tokens_are_unique_per_issue() -> None:
    assert generate_reset_token()[0] != generate_reset_token()[0]


def test_reset_token_comparison_rejects_a_wrong_token() -> None:
    raw, digest = generate_reset_token()

    assert reset_tokens_match(raw, digest)
    assert not reset_tokens_match(raw + "x", digest)


# --- session gating ----------------------------------------------------------


@pytest.mark.asyncio
async def test_temporary_password_blocks_everything_but_a_password_change() -> None:
    user = make_user(must_change_password=True)

    with pytest.raises(HTTPException) as exc_info:
        await require_usable_session(user)

    assert exc_info.value.status_code == 403
    assert "Password change required" in exc_info.value.detail


@pytest.mark.asyncio
async def test_an_ordinary_session_passes_the_gate() -> None:
    user = make_user()

    assert await require_usable_session(user) is user
