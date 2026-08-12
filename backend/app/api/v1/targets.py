import uuid

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_db
from app.models.target import Target
from app.schemas.target import TargetCreate, TargetRead

router = APIRouter(prefix="/targets", tags=["targets"])


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


@router.patch("/{target_id}/allow", response_model=TargetRead)
async def allow_target(
    target_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
) -> Target:
    target = await db.get(Target, target_id)

    if target is None:
        raise HTTPException(status_code=404, detail="Target not found")

    target.is_allowed = True

    await db.commit()
    await db.refresh(target)

    return target