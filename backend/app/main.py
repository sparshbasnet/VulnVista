from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.v1 import api_router
from app.core.config import get_settings
from app.core.logging import configure_logging
from app.database.session import AsyncSessionLocal
from app.services.user_seed import seed_initial_admin

settings = get_settings()
configure_logging(settings.log_level)


@asynccontextmanager
async def lifespan(_: FastAPI):
    # The schema is owned by Alembic migrations (`alembic upgrade head`), run by
    # the container entrypoint before the app starts — see backend/entrypoint.sh.
    # For local runs, apply migrations first. Here we only seed the initial admin
    # account, which assumes the schema already exists.
    async with AsyncSessionLocal() as db:
        await seed_initial_admin(db)
    yield


app = FastAPI(title="VulnVista API", version="0.1.0", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(api_router)


@app.get("/api/health", tags=["health"])
async def health() -> dict[str, str]:
    return {"status": "ok", "environment": settings.environment}
