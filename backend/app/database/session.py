from collections.abc import AsyncGenerator
from urllib.parse import parse_qsl, urlsplit

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from app.core.config import get_settings

settings = get_settings()


def _connect_args(database_url: str) -> dict:
    """asyncpg connect args tuned for the target database.

    Managed Postgres hosts (Neon, Supabase) front their pooled endpoints with
    PgBouncer in transaction-pooling mode, which is incompatible with asyncpg's
    prepared-statement cache — reusing a cached statement on a different backend
    connection raises DuplicatePreparedStatementError. Disabling the cache keeps
    pooled connections working. We key off the presence of an SSL request in the
    URL (``?ssl=require``), which those hosts require and local Docker Postgres
    never uses, so the local dev path is untouched.
    """
    query = dict(parse_qsl(urlsplit(database_url).query))
    if "ssl" in query or "sslmode" in query:
        return {"statement_cache_size": 0}
    return {}


engine = create_async_engine(
    settings.database_url,
    echo=False,
    pool_pre_ping=True,
    connect_args=_connect_args(settings.database_url),
)

AsyncSessionLocal = async_sessionmaker(engine, expire_on_commit=False)


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    async with AsyncSessionLocal() as session:
        yield session
