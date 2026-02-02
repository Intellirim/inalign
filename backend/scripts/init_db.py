"""
Database initialisation script.

Creates all tables defined by the SQLAlchemy declarative base and seeds
an initial admin user. Intended for first-time setup or development
environment bootstrapping.

Usage::

    python -m scripts.init_db
"""

from __future__ import annotations

import asyncio
import logging
import sys
from pathlib import Path

# Ensure the backend package root is on sys.path
_backend_root = Path(__file__).resolve().parent.parent
if str(_backend_root) not in sys.path:
    sys.path.insert(0, str(_backend_root))

from app.config import configure_logging, get_settings
from app.models.database import Base, engine

logger = logging.getLogger("agentshield.scripts.init_db")


async def main() -> None:
    """Create all database tables and seed the admin user."""
    settings = get_settings()
    configure_logging(settings)

    logger.info("Starting database initialisation...")
    logger.info("Database URL: %s", settings.async_database_url.split("@")[-1])

    # ------------------------------------------------------------------
    # Step 1: Create all tables
    # ------------------------------------------------------------------
    from sqlalchemy.ext.asyncio import create_async_engine

    init_engine = create_async_engine(
        settings.async_database_url,
        echo=settings.postgres_echo,
    )

    async with init_engine.begin() as conn:
        # Import all models so they are registered with Base.metadata
        from app.models.user import User  # noqa: F401
        from app.models.api_key import APIKey  # noqa: F401
        from app.models.usage import Usage  # noqa: F401
        from app.models.alert import Alert  # noqa: F401
        from app.models.webhook import Webhook  # noqa: F401

        logger.info("Creating tables: %s", list(Base.metadata.tables.keys()))
        await conn.run_sync(Base.metadata.create_all)

    logger.info("All tables created successfully.")

    # ------------------------------------------------------------------
    # Step 2: Seed admin user
    # ------------------------------------------------------------------
    from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker
    from sqlalchemy import select

    async_session_factory = async_sessionmaker(
        bind=init_engine,
        class_=AsyncSession,
        expire_on_commit=False,
    )

    async with async_session_factory() as session:
        from app.models.user import User, UserRole
        from app.core.security import hash_password

        # Check if admin user already exists
        result = await session.execute(
            select(User).where(User.email == "admin@agentshield.io")
        )
        existing_admin = result.scalar_one_or_none()

        if existing_admin is not None:
            logger.info("Admin user already exists: %s", existing_admin.email)
        else:
            admin_user = User(
                email="admin@agentshield.io",
                name="AgentShield Admin",
                hashed_password=hash_password("Admin@Shield!2024"),
                is_active=True,
                role=UserRole.ADMIN,
            )
            session.add(admin_user)
            await session.commit()
            logger.info(
                "Admin user created: email=%s role=%s",
                admin_user.email,
                admin_user.role.value,
            )

    await init_engine.dispose()
    logger.info("Database initialisation complete.")


if __name__ == "__main__":
    asyncio.run(main())
