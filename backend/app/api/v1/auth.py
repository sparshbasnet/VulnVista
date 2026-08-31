import uuid

from fastapi import APIRouter, Depends, HTTPException, Response, status
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.auth_deps import get_current_user, require_admin
from app.api.deps import get_db
from app.core.security import create_access_token, hash_password, verify_password
from app.models.user import User
from app.schemas.auth import (
    LoginRequest,
    PasswordChangeRequest,
    PasswordResetConfirm,
    PasswordResetIssued,
    PasswordResetRequest,
    TokenResponse,
    UserCreate,
    UserRead,
    UserUpdate,
)
from app.services import accounts

router = APIRouter(prefix="/auth", tags=["auth"])

INVALID_CREDENTIALS = HTTPException(
    status_code=status.HTTP_401_UNAUTHORIZED,
    detail="Invalid username or password",
    headers={"WWW-Authenticate": "Bearer"},
)


@router.post("/login", response_model=TokenResponse)
async def login(payload: LoginRequest, db: AsyncSession = Depends(get_db)) -> TokenResponse:
    user = await accounts.find_by_identity(db, payload.username)
    if user is None or not user.is_active:
        # Burn a comparable amount of time before the generic failure, so response
        # latency does not reveal which usernames exist.
        accounts.waste_password_comparison(payload.password)
        raise INVALID_CREDENTIALS

    password_matches = verify_password(payload.password, user.hashed_password)

    if accounts.is_locked_out(user):
        if not password_matches:
            # Answering "this account is locked" to a wrong password would turn the
            # lockout into a user-enumeration oracle. Attempts made during a lockout
            # also do not extend it, or an attacker could keep someone out forever.
            raise INVALID_CREDENTIALS
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many failed attempts. Try again later or ask an administrator to reset.",
        )

    if not password_matches:
        accounts.register_failed_login(user)
        await db.commit()
        raise INVALID_CREDENTIALS

    accounts.register_successful_login(user)
    await db.commit()
    return TokenResponse(
        access_token=create_access_token(user.id, user.token_version),
        must_change_password=user.must_change_password,
    )


@router.get("/me", response_model=UserRead)
async def me(user: User = Depends(get_current_user)) -> User:
    return user


@router.post("/logout", status_code=204)
async def logout(_: User = Depends(get_current_user)) -> Response:
    # Access tokens are short lived and stateless; logout removes the token client-side.
    return Response(status_code=204)


@router.post("/me/password", response_model=TokenResponse)
async def change_own_password(
    payload: PasswordChangeRequest,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
) -> TokenResponse:
    """Change your own password, proving ownership with the current one."""
    if not verify_password(payload.current_password, user.hashed_password):
        raise HTTPException(status_code=400, detail="Current password is incorrect")

    await accounts.set_password(db, user, payload.new_password)
    await db.commit()
    # The change revoked every token including the caller's, so hand back a fresh
    # one rather than bouncing someone out of the app for updating their password.
    return TokenResponse(access_token=create_access_token(user.id, user.token_version))


@router.post("/password-reset/request", status_code=202)
async def request_password_reset(
    payload: PasswordResetRequest, db: AsyncSession = Depends(get_db)
) -> dict[str, str]:
    """Start self-service recovery.

    Always reports the same result: a response that varied by whether the account
    existed would turn this into a user-enumeration oracle.
    """
    user = await accounts.find_by_identity(db, payload.identity)
    if user is not None and user.is_active:
        raw_token, expires_at = await accounts.issue_reset_token(db, user)
        await db.commit()
        accounts.deliver_reset_token(user, raw_token, expires_at)
    return {"detail": "If that account exists, a reset token has been issued."}


@router.post("/password-reset/confirm", status_code=204)
async def confirm_password_reset(
    payload: PasswordResetConfirm, db: AsyncSession = Depends(get_db)
) -> Response:
    """Redeem a reset token and set a new password."""
    user = await accounts.consume_reset_token(db, payload.token)
    if user is None:
        raise HTTPException(status_code=400, detail="Reset token is invalid, used, or expired")

    await accounts.set_password(db, user, payload.new_password)
    await db.commit()
    return Response(status_code=204)


@router.get("/users", response_model=list[UserRead])
async def list_users(
    db: AsyncSession = Depends(get_db),
    _: User = Depends(require_admin),
) -> list[User]:
    result = await db.execute(select(User).order_by(User.username))
    return list(result.scalars().all())


@router.post("/users", response_model=UserRead, status_code=201)
async def create_user(
    payload: UserCreate,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(require_admin),
) -> User:
    user = User(
        username=payload.username,
        email=payload.email,
        hashed_password=hash_password(payload.password),
        role=payload.role,
        # The administrator picked this password, so it is a handover credential
        # rather than the account owner's own.
        must_change_password=True,
    )
    db.add(user)
    try:
        await db.commit()
    except IntegrityError as exc:
        await db.rollback()
        raise HTTPException(status_code=409, detail="Username or email already exists") from exc
    await db.refresh(user)
    return user


@router.patch("/users/{user_id}", response_model=UserRead)
async def update_user(
    user_id: uuid.UUID,
    payload: UserUpdate,
    db: AsyncSession = Depends(get_db),
    admin: User = Depends(require_admin),
) -> User:
    """Edit an account's role or activation state."""
    user = await db.get(User, user_id)
    if user is None:
        raise HTTPException(status_code=404, detail="User not found")
    if user.id == admin.id:
        # Self-edit is the easy way to lock yourself out of the platform. Refusing
        # it is also what keeps at least one administrator standing: the caller is
        # necessarily an active admin, so any account they can edit is not the last.
        raise HTTPException(
            status_code=400, detail="Use another administrator to change your own role or status"
        )

    if payload.role is not None:
        user.role = payload.role
    if payload.is_active is not None and payload.is_active != user.is_active:
        user.is_active = payload.is_active
        # Deactivation has to end sessions immediately, or a signed-in user keeps
        # working until their token happens to expire.
        user.token_version += 1
        if payload.is_active:
            user.failed_login_attempts = 0
            user.locked_until = None
        else:
            await accounts.invalidate_reset_tokens(db, user.id)

    await db.commit()
    await db.refresh(user)
    return user


@router.post("/users/{user_id}/password-reset", response_model=PasswordResetIssued)
async def issue_password_reset(
    user_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    admin: User = Depends(require_admin),
) -> PasswordResetIssued:
    """Mint a reset token for an account and return it for out-of-band handover.

    Unlike the self-service route this reveals the token, because the caller is an
    administrator who could set the password directly anyway.
    """
    user = await db.get(User, user_id)
    if user is None:
        raise HTTPException(status_code=404, detail="User not found")
    if not user.is_active:
        raise HTTPException(status_code=409, detail="Reactivate the account before resetting it")

    raw_token, expires_at = await accounts.issue_reset_token(db, user, issued_by=admin)
    # An administrator stepping in also clears a lockout, which is the other half
    # of "I cannot get into my account".
    user.failed_login_attempts = 0
    user.locked_until = None
    await db.commit()
    return PasswordResetIssued(
        user_id=user.id,
        username=user.username,
        reset_token=raw_token,
        expires_at=expires_at,
    )
