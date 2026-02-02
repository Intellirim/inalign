"""
Database configuration and base model for AgentShield.

Provides the async SQLAlchemy engine, session factory, and a declarative
base class with common columns shared by every table (UUID primary key,
created_at, updated_at).
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import AsyncGenerator

from sqlalchemy import DateTime, func
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.ext.asyncio import (
    AsyncAttrs,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.orm import (
    DeclarativeBase,
    Mapped,
    mapped_column,
)

# ---------------------------------------------------------------------------
# Environment-driven configuration
# ---------------------------------------------------------------------------
# The actual DATABASE_URL should be injected via ``core.config``; the
# constant below acts as a fallback for local development.
_DEFAULT_DATABASE_URL = (
    "postgresql+asyncpg://agentshield:agentshield@localhost:5432/agentshield"
)


def _get_database_url() -> str:
    """Return the database URL from application settings.

    Import is deferred so that ``models.database`` can be imported before
    the settings module is fully initialised (e.g. during Alembic
    migrations).
    """
    try:
        from app.core.config import settings  # type: ignore[import-untyped]

        return str(settings.DATABASE_URL)
    except Exception:  # pragma: no cover – fallback for dev / migration
        return _DEFAULT_DATABASE_URL


# ---------------------------------------------------------------------------
# Async engine & session
# ---------------------------------------------------------------------------
engine = create_async_engine(
    _get_database_url(),
    echo=False,
    pool_size=20,
    max_overflow=10,
    pool_pre_ping=True,
    pool_recycle=300,
)

async_session_factory = async_sessionmaker(
    engine,
    class_=AsyncSession,
    expire_on_commit=False,
)


async def get_async_session() -> AsyncGenerator[AsyncSession, None]:
    """FastAPI dependency that yields an async database session.

    The session is automatically closed when the request finishes.

    Yields:
        An ``AsyncSession`` bound to the application engine.
    """
    async with async_session_factory() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()


# ---------------------------------------------------------------------------
# Declarative base with common columns
# ---------------------------------------------------------------------------
class Base(AsyncAttrs, DeclarativeBase):
    """Abstract declarative base carrying columns shared by all models.

    Every table automatically receives:

    * **id** -- a UUID v4 primary key.
    * **created_at** -- server-side ``now()`` timestamp set on INSERT.
    * **updated_at** -- server-side ``now()`` timestamp set on INSERT and
      refreshed on every UPDATE.
    """

    __abstract__ = True

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
        server_default=func.gen_random_uuid(),
        index=True,
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False,
    )

    def __repr__(self) -> str:  # pragma: no cover
        return f"<{self.__class__.__name__}(id={self.id!r})>"
