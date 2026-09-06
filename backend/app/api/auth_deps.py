from collections.abc import Callable

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_db
from app.core.security import decode_access_token
from app.models.user import User, UserRole

bearer_scheme = HTTPBearer()


async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(bearer_scheme),
    db: AsyncSession = Depends(get_db),
) -> User:
    credentials_error = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid or expired authentication credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        claims = decode_access_token(credentials.credentials)
    except ValueError as exc:
        raise credentials_error from exc
    user = await db.get(User, claims.user_id)
    if user is None or not user.is_active:
        raise credentials_error
    # A password change or a deactivation bumps token_version, which retires every
    # token minted before it.
    if claims.token_version != user.token_version:
        raise credentials_error
    return user


async def require_usable_session(user: User = Depends(get_current_user)) -> User:
    """A signed-in user whose session can do more than fix its own password.

    An account on an administrator-issued temporary password can reach /auth/me
    and /auth/me/password and nothing else, so a handover credential cannot be
    left in place indefinitely.
    """
    if user.must_change_password:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Password change required before using this account",
        )
    return user


def require_roles(*roles: UserRole) -> Callable:
    async def role_dependency(user: User = Depends(require_usable_session)) -> User:
        if user.role not in roles:
            raise HTTPException(status_code=403, detail="Insufficient permissions")
        return user

    return role_dependency


require_operator = require_roles(UserRole.ADMIN, UserRole.ANALYST)
require_admin = require_roles(UserRole.ADMIN)
