import uuid
from typing import Any
from urllib.parse import urlparse

from fastapi import APIRouter, Depends, HTTPException, Response, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.auth_deps import require_operator
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


def _endpoint_identity(base_url: str | None, ip_address: str | None) -> str:
    """A stable key for "the same endpoint", tolerant of spelling differences.

    `http://dvwa`, `http://DVWA/`, and `http://dvwa:80` are one endpoint written
    three ways. The path is kept, because a different entry point is a different
    scan surface.
    """
    if base_url and base_url.strip():
        parsed = urlparse(base_url.strip())
        scheme = (parsed.scheme or "http").lower()
        host = (parsed.hostname or "").lower()
        port = parsed.port or (443 if scheme == "https" else 80)
        return f"{scheme}://{host}:{port}{parsed.path.rstrip('/')}"
    return (ip_address or "").strip().lower()


def _same_scan_config(left: dict[str, Any] | None, right: dict[str, Any] | None) -> bool:
    """Treat SQL NULL, JSON null, and {} as the one "no overrides" value.

    SQLAlchemy's JSON type stores None as JSON null rather than SQL NULL, so both
    spellings are already present in existing rows.
    """
    return (left or None) == (right or None)


async def _find_equivalent_target(db: AsyncSession, payload: TargetCreate) -> Target | None:
    """An existing target that would produce a byte-identical scan, if any.

    Two records with the same endpoint AND the same detector overrides can only
    ever yield the same results, so a second one is duplication rather than a
    distinct assessment context. Differing scan_config — a login, a cookie, an
    explicit parameter — is what makes the same URL a genuinely separate target,
    and is deliberately preserved.

    Scanned in Python rather than SQL because the comparison is on the normalised
    endpoint, which is not a stored column. Target registration is rare and the
    table is small; if it ever grows, persist the key and index it.
    """
    identity = _endpoint_identity(payload.base_url, payload.ip_address)
    if not identity:
        return None
    result = await db.execute(select(Target).where(Target.environment == payload.environment))
    for candidate in result.scalars().all():
        if _endpoint_identity(candidate.base_url, candidate.ip_address) != identity:
            continue
        if _same_scan_config(candidate.scan_config, payload.scan_config):
            return candidate
    return None


@router.post("", response_model=TargetRead, status_code=201)
async def create_target(
    payload: TargetCreate,
    response: Response,
    db: AsyncSession = Depends(get_db),
    _: object = Depends(require_operator),
) -> Target:
    if _is_blocked_host(payload.base_url):
        raise HTTPException(status_code=422, detail="This host cannot be scanned")

    # Registering an endpoint that is already on file returns the existing record
    # instead of a duplicate, so scan history and findings stay on one target
    # rather than fragmenting across a row per scan. 200 rather than 201 tells the
    # caller nothing was created.
    existing = await _find_equivalent_target(db, payload)
    if existing is not None:
        # Reuse may still raise the authorization bar, never lower it: a caller
        # who now confirms authorization approves a target registered before.
        if not existing.is_allowed and (
            _is_trusted_host(existing.base_url) or payload.authorization_confirmed
        ):
            existing.is_allowed = True
            existing.authorization_confirmed = payload.authorization_confirmed
            await db.commit()
            await db.refresh(existing)
        response.status_code = status.HTTP_200_OK
        return existing

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
