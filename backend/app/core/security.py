import hashlib
import hmac
import secrets
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

import bcrypt
from jose import JWTError, jwt

from app.core.config import get_settings

ALGORITHM = "HS256"

MIN_PASSWORD_LENGTH = 12
MAX_PASSWORD_BYTES = 72
# Enough entropy that guessing is hopeless, short enough to paste out-of-band.
RESET_TOKEN_BYTES = 32


@dataclass(frozen=True)
class AccessTokenClaims:
    """The parts of a decoded access token the application acts on."""

    user_id: uuid.UUID
    token_version: int


def validate_password_policy(password: str) -> str:
    """Return the password unchanged, or raise ValueError describing the first rule it breaks.

    bcrypt silently truncates anything past 72 bytes, so that ceiling is a hard
    limit rather than a style preference.
    """
    if len(password) < MIN_PASSWORD_LENGTH:
        raise ValueError(f"Password must be at least {MIN_PASSWORD_LENGTH} characters")
    if len(password.encode("utf-8")) > MAX_PASSWORD_BYTES:
        raise ValueError(f"Password must be at most {MAX_PASSWORD_BYTES} UTF-8 bytes")
    character_classes = (
        any(character.islower() for character in password),
        any(character.isupper() for character in password),
        any(character.isdigit() for character in password),
        any(not character.isalnum() for character in password),
    )
    if sum(character_classes) < 3:
        raise ValueError(
            "Password must combine at least three of: lowercase, uppercase, digits, symbols"
        )
    return password


def hash_password(password: str) -> str:
    encoded = password.encode("utf-8")
    if len(encoded) > MAX_PASSWORD_BYTES:
        raise ValueError(f"Password must be at most {MAX_PASSWORD_BYTES} UTF-8 bytes")
    return bcrypt.hashpw(encoded, bcrypt.gensalt(rounds=12)).decode("ascii")


def verify_password(password: str, hashed_password: str) -> bool:
    try:
        return bcrypt.checkpw(password.encode("utf-8"), hashed_password.encode("ascii"))
    except (ValueError, TypeError):
        return False


def create_access_token(
    user_id: uuid.UUID,
    token_version: int = 1,
    expires_delta: timedelta | None = None,
) -> str:
    settings = get_settings()
    now = datetime.now(UTC)
    expires = now + (expires_delta or timedelta(minutes=settings.access_token_expire_minutes))
    return jwt.encode(
        {
            "sub": str(user_id),
            "ver": token_version,
            "iat": now,
            "exp": expires,
            "type": "access",
        },
        settings.secret_key,
        algorithm=ALGORITHM,
    )


def decode_access_token(token: str) -> AccessTokenClaims:
    settings = get_settings()
    try:
        payload = jwt.decode(token, settings.secret_key, algorithms=[ALGORITHM])
        if payload.get("type") != "access":
            raise ValueError("Invalid token type")
        # Tokens minted before token versioning existed carry no "ver" claim; treat
        # them as version 1 so an in-flight session survives the upgrade.
        token_version = payload.get("ver", 1)
        if not isinstance(token_version, int) or isinstance(token_version, bool):
            raise ValueError("Invalid token version claim")
        return AccessTokenClaims(user_id=uuid.UUID(payload["sub"]), token_version=token_version)
    except (JWTError, KeyError, TypeError, ValueError) as exc:
        raise ValueError("Invalid or expired access token") from exc


def generate_reset_token() -> tuple[str, str]:
    """Return (token to hand to the user, digest to persist).

    Only the digest is stored, so a leaked database dump cannot be replayed as a
    password reset.
    """
    raw = secrets.token_urlsafe(RESET_TOKEN_BYTES)
    return raw, hash_reset_token(raw)


def hash_reset_token(raw_token: str) -> str:
    return hashlib.sha256(raw_token.encode("utf-8")).hexdigest()


def reset_tokens_match(raw_token: str, stored_hash: str) -> bool:
    return hmac.compare_digest(hash_reset_token(raw_token), stored_hash)
