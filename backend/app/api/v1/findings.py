import uuid

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.auth_deps import require_operator
from app.api.deps import get_db
from app.models.finding import Finding
from app.schemas.finding import FindingRead, FindingStatusUpdate

router = APIRouter(prefix="/findings", tags=["findings"])


@router.get("", response_model=list[FindingRead])
async def list_findings(
    target_id: uuid.UUID | None = None,
    severity: str | None = None,
    validation_status: str | None = None,
    db: AsyncSession = Depends(get_db),
) -> list[Finding]:
    query = select(Finding)
    if target_id is not None:
        query = query.where(Finding.target_id == target_id)
    if severity is not None:
        query = query.where(Finding.severity == severity)
    if validation_status is not None:
        query = query.where(Finding.validation_status == validation_status)
    result = await db.execute(query.order_by(Finding.created_at.desc()))
    return list(result.scalars().all())


@router.get("/{finding_id}", response_model=FindingRead)
async def get_finding(finding_id: uuid.UUID, db: AsyncSession = Depends(get_db)) -> Finding:
    finding = await db.get(Finding, finding_id)
    if finding is None:
        raise HTTPException(status_code=404, detail="Finding not found")
    return finding


@router.patch("/{finding_id}/status", response_model=FindingRead)
async def update_finding_status(
    finding_id: uuid.UUID,
    payload: FindingStatusUpdate,
    db: AsyncSession = Depends(get_db),
    _: object = Depends(require_operator),
) -> Finding:
    finding = await db.get(Finding, finding_id)
    if finding is None:
        raise HTTPException(status_code=404, detail="Finding not found")
    finding.finding_status = payload.finding_status
    await db.commit()
    await db.refresh(finding)
    return finding
