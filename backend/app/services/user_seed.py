import logging

from sqlalchemy import or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import get_settings
from app.core.security import hash_password
from app.models.user import User, UserRole

logger = logging.getLogger(__name__)


async def seed_initial_admin(db: AsyncSession) -> None:
    settings = get_settings()
    username = settings.initial_admin_username
    email = settings.initial_admin_email
    password = settings.initial_admin_password
    if not all((username, email, password)):
        logger.warning("Initial admin not seeded; set all INITIAL_ADMIN_* environment variables")
        return
    username = username.strip().lower()
    email = email.strip().lower()
    existing = await db.execute(
        select(User).where(or_(User.username == username, User.email == email))
    )
    if existing.scalar_one_or_none() is not None:
        return
    db.add(
        User(
            username=username,
            email=email,
            hashed_password=hash_password(password),
            role=UserRole.ADMIN,
        )
    )
    await db.commit()
    logger.info("Seeded initial admin account '%s'", username)
