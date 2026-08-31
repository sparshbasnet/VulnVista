"""Credential lifecycle: login throttling, password changes, and reset tokens.

The endpoints in `api/v1/auth.py` stay thin and HTTP-shaped; the rules that must
hold no matter which route reaches them live here.
"""

import logging
import secrets
import uuid
from datetime import UTC, datetime, timedelta
from functools import cache

from sqlalchemy import or_, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import get_settings
from app.core.security import (
    generate_reset_token,
    hash_password,
    hash_reset_token,
    verify_password,
)
from app.models.user import PasswordResetToken, User

logger = logging.getLogger(__name__)


def _as_utc(value: datetime | None) -> datetime | None:
    """Postgres hands back aware datetimes; SQLite and in-memory objects may not."""
    if value is None:
        return None
    return value if value.tzinfo is not None else value.replace(tzinfo=UTC)


def is_locked_out(user: User, now: datetime | None = None) -> bool:
    locked_until = _as_utc(user.locked_until)
    if locked_until is None:
        return False
    return locked_until > (now or datetime.now(UTC))


async def find_by_identity(db: AsyncSession, identity: str) -> User | None:
    """Look a user up by either username or email, both stored lower-cased."""
    normalized = identity.strip().lower()
    result = await db.execute(
        select(User).where(or_(User.username == normalized, User.email == normalized))
    )
    return result.scalar_one_or_none()


@cache
def _dummy_password_hash() -> str:
    """A real bcrypt hash of a value nobody can supply.

    Computed on first use rather than at import so the cost lands on a request
    instead of application startup.
    """
    return hash_password(secrets.token_urlsafe(24))


def waste_password_comparison(password: str) -> None:
    """Spend a password check's worth of time without having a user to check.

    Without this the "no such username" path returns an order of magnitude faster
    than a wrong password, which is enough to enumerate accounts.
    """
    verify_password(password, _dummy_password_hash())


def register_failed_login(user: User) -> None:
    """Count a bad password and lock the account once the ceiling is reached."""
    settings = get_settings()
    user.failed_login_attempts += 1
    if settings.max_failed_logins > 0 and user.failed_login_attempts >= settings.max_failed_logins:
        user.locked_until = datetime.now(UTC) + timedelta(minutes=settings.lockout_minutes)
        logger.warning(
            "Account '%s' locked for %d minutes after %d failed logins",
            user.username,
            settings.lockout_minutes,
            user.failed_login_attempts,
        )


def register_successful_login(user: User) -> None:
    user.last_login_at = datetime.now(UTC)
    user.failed_login_attempts = 0
    user.locked_until = None


async def invalidate_reset_tokens(db: AsyncSession, user_id: uuid.UUID) -> None:
    """Consume every outstanding reset token for a user.

    Called on any password change so a reset link that is still in someone's
    inbox cannot be redeemed after the fact.
    """
    await db.execute(
        update(PasswordResetToken)
        .where(PasswordResetToken.user_id == user_id, PasswordResetToken.used_at.is_(None))
        .values(used_at=datetime.now(UTC))
    )

async def set_password(
    db: AsyncSession,
    user: User,
    new_password: str,
    *,
    must_change: bool = False,
) -> None:
    """Apply a new password and revoke everything the old one authorized.

    Bumping token_version logs out every existing session, including any the
    attacker may hold if the change is happening because of a compromise.
    """
    user.hashed_password = hash_password(new_password)
    user.password_changed_at = datetime.now(UTC)
    user.token_version += 1
    user.must_change_password = must_change
    user.failed_login_attempts = 0
    user.locked_until = None
    await invalidate_reset_tokens(db, user.id)


async def issue_reset_token(
    db: AsyncSession,
    user: User,
    *,
    issued_by: User | None = None,
) -> tuple[str, datetime]:
    """Mint a single-use reset token, superseding any still outstanding."""
    settings = get_settings()
    await invalidate_reset_tokens(db, user.id)
    raw_token, token_hash = generate_reset_token()
    expires_at = datetime.now(UTC) + timedelta(minutes=settings.password_reset_token_ttl_minutes)
    db.add(
        PasswordResetToken(
            user_id=user.id,
            token_hash=token_hash,
            expires_at=expires_at,
            issued_by_id=issued_by.id if issued_by else None,
        )
    )
    return raw_token, expires_at


async def consume_reset_token(db: AsyncSession, raw_token: str) -> User | None:
    """Return the user a valid, unused, unexpired token belongs to, marking it used.

    The lookup is by digest, so an invalid token costs one indexed query and
    reveals nothing about which accounts exist.
    """
    result = await db.execute(
        select(PasswordResetToken).where(
            PasswordResetToken.token_hash == hash_reset_token(raw_token)
        )
    )
    token = result.scalar_one_or_none()
    if token is None or token.used_at is not None:
        return None
    if _as_utc(token.expires_at) <= datetime.now(UTC):
        return None
    user = await db.get(User, token.user_id)
    if user is None or not user.is_active:
        return None
    token.used_at = datetime.now(UTC)
    return user


def deliver_reset_token(user: User, raw_token: str, expires_at: datetime) -> None:
    """Hand a self-service reset token to the account owner.

    VulnVista has no mail transport, so the token goes to the application log for
    an operator to relay. Swapping this one function for an SMTP call is the only
    change needed to make recovery fully self-service.
    """
    logger.warning(
        "Password reset requested for '%s' (%s). Token valid until %s: %s",
        user.username,
        user.email,
        expires_at.isoformat(),
        raw_token,
    )
