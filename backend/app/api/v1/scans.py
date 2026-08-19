import uuid

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_db
from app.models.finding import Finding
from app.models.scan import Scan
from app.models.target import Target
from app.scanners.detector_registry import get_detectors
from app.schemas.finding import FindingRead
from app.schemas.scan import ScanCreate, ScanRead
from app.services.scan_orchestrator import run_scan

router = APIRouter(prefix="/scans", tags=["scans"])


@router.post("", response_model=ScanRead, status_code=201)
async def create_scan(
    payload: ScanCreate,
    db: AsyncSession = Depends(get_db),
) -> Scan:
    target = await db.get(Target, payload.target_id)

    if target is None:
        raise HTTPException(status_code=404, detail="Target not found")

    if not target.is_allowed:
        raise HTTPException(
            status_code=403,
            detail="Target is not on the approved allowlist",
        )

    if not target.base_url:
        raise HTTPException(
            status_code=400,
            detail="Target does not have a base URL",
        )

    scan = Scan(**payload.model_dump())
    db.add(scan)
    await db.commit()
    await db.refresh(scan)

    detectors = get_detectors(target.base_url)

    await run_scan(
        db=db,
        scan=scan,
        target=target,
        detectors=detectors,
    )

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
    result = await db.execute(select(Finding).where(Finding.scan_id == scan_id))
    return list(result.scalars().all())
