from fastapi import APIRouter, Depends

from app.api.auth_deps import require_usable_session
from app.api.v1.auth import router as auth_router
from app.api.v1.findings import router as findings_router
from app.api.v1.scans import router as scans_router
from app.api.v1.targets import router as targets_router

api_router = APIRouter(prefix="/api")
api_router.include_router(auth_router)
protected = [Depends(require_usable_session)]
api_router.include_router(targets_router, dependencies=protected)
api_router.include_router(scans_router, dependencies=protected)
api_router.include_router(findings_router, dependencies=protected)
