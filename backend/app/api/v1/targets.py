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

def _is_allowed(base_url: str | None) -> bool:
    """A target is scannable only if its host is on the configured lab allowlist.

    The allowlist is default-deny and comes from LAB_ALLOWED_HOSTS (see
    config.Settings), so a target can never be pointed at a public/production
    host without an explicit config change.
    """
    if not base_url:
        return False
    host = (urlparse(base_url).hostname or "").lower()
    return host in get_settings().allowed_hosts


@router.post("", response_model=TargetRead, status_code=201)
async def create_target(payload: TargetCreate, db: AsyncSession = Depends(get_db)) -> Target:
    target = Target(**payload.model_dump())
    # Approval is server-side only — never trust an is_allowed sent by the client.
    target.is_allowed = _is_allowed(target.base_url)
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
