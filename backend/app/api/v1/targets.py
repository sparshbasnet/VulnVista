import uuid
from urllib.parse import urlparse

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_db
from app.core.config import get_settings
from app.models.target import Target
from app.schemas.target import TargetCreate, TargetRead

router = APIRouter(prefix="/targets", tags=["targets"])


def _host_of(base_url: str | None) -> str:
    return (urlparse(base_url).hostname or "").lower() if base_url else ""


def _is_trusted_host(base_url: str | None) -> bool:
    """Bundled lab hosts are auto-approved with no acknowledgment needed."""
    return _host_of(base_url) in get_settings().trusted_hosts


def _is_blocked_host(base_url: str | None) -> bool:
    """Hosts that can never be scanned, acknowledgment or not (e.g. cloud
    metadata endpoints) — a baseline SSRF guard since detectors send
    server-side requests to whatever URL the client supplies."""
    return _host_of(base_url) in get_settings().blocklisted_hosts


@router.post("", response_model=TargetRead, status_code=201)
async def create_target(payload: TargetCreate, db: AsyncSession = Depends(get_db)) -> Target:
    if _is_blocked_host(payload.base_url):
        raise HTTPException(status_code=422, detail="This host cannot be scanned")

    target = Target(**payload.model_dump())
    # Approval is server-side only — never trust an is_allowed sent by the client.
    # Trusted lab hosts are auto-approved; anything else needs the requester's
    # own authorization_confirmed acknowledgment.
    target.is_allowed = _is_trusted_host(target.base_url) or payload.authorization_confirmed
    db.add(target)
    await db.commit()
    await db.refresh(target)
    return target


@router.get("", response_model=list[TargetRead])
async def list_targets(db: AsyncSession = Depends(get_db)) -> list[Target]:
    result = await db.execute(select(Target).order_by(Target.created_at.desc()))
    return list(result.scalars().all())


@router.get("/{target_id}", response_model=TargetRead)
async def get_target(target_id: uuid.UUID, db: AsyncSession = Depends(get_db)) -> Target:
    target = await db.get(Target, target_id)
    if target is None:
        raise HTTPException(status_code=404, detail="Target not found")
    return target
