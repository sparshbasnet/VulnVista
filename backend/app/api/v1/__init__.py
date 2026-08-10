from fastapi import APIRouter

from app.api.v1.findings import router as findings_router
from app.api.v1.scans import router as scans_router
from app.api.v1.targets import router as targets_router

api_router = APIRouter(prefix="/api")
api_router.include_router(targets_router)
api_router.include_router(scans_router)
api_router.include_router(findings_router)
