import uuid

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.api.auth_deps import require_operator
from app.api.deps import get_db
from app.models.finding import Finding
from app.models.scan import Scan
from app.models.target import Target
from app.models.user import User
from app.schemas.finding import FindingRead
from app.schemas.scan import ScanCreate, ScanRead
from app.services.scan_runner import run_scan

router = APIRouter(prefix="/scans", tags=["scans"])


@router.post("", response_model=ScanRead, status_code=201)
async def create_scan(
    payload: ScanCreate,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_operator),
) -> Scan:
    target = await db.get(Target, payload.target_id, with_for_update=True)
    if target is None:
        raise HTTPException(status_code=404, detail="Target not found")
    if not target.is_allowed:
        raise HTTPException(status_code=403, detail="Target is not on the approved allowlist")

    scan = Scan(**payload.model_dump(exclude={"initiated_by"}), initiated_by=current_user.username)
    db.add(scan)
    await db.commit()
    await db.refresh(scan)

    # Detectors run asynchronously; the client polls GET /scans/{id} for status
    # and GET /scans/{id}/findings for results.
    background_tasks.add_task(run_scan, scan.id)
    return scan


@router.get("", response_model=list[ScanRead])
async def list_scans(db: AsyncSession = Depends(get_db)) -> list[Scan]:
    result = await db.execute(select(Scan).order_by(Scan.created_at.desc()))
    return list(result.scalars().all())


@router.get("/{scan_id}", response_model=ScanRead)
async def get_scan(scan_id: uuid.UUID, db: AsyncSession = Depends(get_db)) -> Scan:
    scan = await db.get(Scan, scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="Scan not found")
    return scan


@router.get("/{scan_id}/findings", response_model=list[FindingRead])
async def get_scan_findings(
    scan_id: uuid.UUID, db: AsyncSession = Depends(get_db)
) -> list[Finding]:
    query = (
        select(Finding).options(selectinload(Finding.evidence)).where(Finding.scan_id == scan_id)
    )
    result = await db.execute(query)
    return list(result.scalars().all())
