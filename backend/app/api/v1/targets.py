import uuid
from urllib.parse import urlparse
from urllib.parse import urlparse

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_db
from app.core.config import get_settings
from app.models.target import Target
from app.schemas.target import TargetCreate, TargetRead

router = APIRouter(prefix="/targets", tags=["targets"])

# Hostnames of the isolated lab containers/services VulnVista is permitted to
# scan (see README "Approved lab targets"). Anything else is rejected so a
# target can never be pointed at a public/production host.
_ALLOWED_LAB_HOSTS = {"dvwa", "juice-shop", "localhost", "127.0.0.1"}


def _is_allowed(url: str | None) -> bool:
    """Whether a target URL's host is on the approved lab allowlist."""
    if not url:
        return False
    hostname = urlparse(url).hostname
    return hostname is not None and hostname.lower() in _ALLOWED_LAB_HOSTS


@router.post("", response_model=TargetRead, status_code=201)
async def create_target(payload: TargetCreate, db: AsyncSession = Depends(get_db)) -> Target:
    target = Target(**payload.model_dump())
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
