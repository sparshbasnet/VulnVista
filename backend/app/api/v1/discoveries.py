import uuid

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.auth_deps import require_operator
from app.api.deps import get_db
from app.models.discovery import Discovery
from app.models.target import Target
from app.models.user import User
from app.schemas.discovery import DiscoveryCreate, DiscoveryRead
from app.services.discovery_runner import run_discovery

router = APIRouter(prefix="/discoveries", tags=["discoveries"])


@router.post("", response_model=DiscoveryRead, status_code=201)
async def create_discovery(
    payload: DiscoveryCreate,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_operator),
) -> Discovery:
    target = await db.get(Target, payload.target_id, with_for_update=True)
    if target is None:
        raise HTTPException(status_code=404, detail="Target not found")
    if not target.is_allowed:
        raise HTTPException(status_code=403, detail="Target is not on the approved allowlist")

    discovery = Discovery(target_id=payload.target_id, initiated_by=current_user.username)
    db.add(discovery)
    await db.commit()
    await db.refresh(discovery)

    # Crawl runs asynchronously; the client polls GET /discoveries/{id}.
    background_tasks.add_task(run_discovery, discovery.id)
    return discovery


@router.get("", response_model=list[DiscoveryRead])
async def list_discoveries(
    target_id: uuid.UUID | None = None, db: AsyncSession = Depends(get_db)
) -> list[Discovery]:
    query = select(Discovery).order_by(Discovery.created_at.desc())
    if target_id is not None:
        query = query.where(Discovery.target_id == target_id)
    result = await db.execute(query)
    return list(result.scalars().all())


@router.get("/{discovery_id}", response_model=DiscoveryRead)
async def get_discovery(discovery_id: uuid.UUID, db: AsyncSession = Depends(get_db)) -> Discovery:
    discovery = await db.get(Discovery, discovery_id)
    if discovery is None:
        raise HTTPException(status_code=404, detail="Discovery not found")
    return discovery
