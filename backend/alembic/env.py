"""
Alembic environment configuration for async migrations.

Uses the async SQLAlchemy engine from application settings and the
declarative Base metadata to auto-generate migration scripts.
"""

from __future__ import annotations

import asyncio
import logging
import sys
from pathlib import Path

from alembic import context
from sqlalchemy import pool
from sqlalchemy.engine import Connection
from sqlalchemy.ext.asyncio import async_engine_from_config, create_async_engine

# ---------------------------------------------------------------------------
# Ensure the backend package is importable
# ---------------------------------------------------------------------------
_backend_root = Path(__file__).resolve().parent.parent
if str(_backend_root) not in sys.path:
    sys.path.insert(0, str(_backend_root))

# ---------------------------------------------------------------------------
# Import application models and settings
# ---------------------------------------------------------------------------
from app.config import get_settings
from app.models.database import Base

# Import all models so their tables are registered with Base.metadata
from app.models.user import User  # noqa: F401
from app.models.api_key import APIKey  # noqa: F401
from app.models.usage import Usage  # noqa: F401
from app.models.alert import Alert  # noqa: F401
from app.models.webhook import Webhook  # noqa: F401
from app.models.agent import Agent  # noqa: F401
from app.models.policy import Policy, PolicyViolation  # noqa: F401
from app.models.activity import Activity, AgentMetrics  # noqa: F401

logger = logging.getLogger("alembic.env")

# ---------------------------------------------------------------------------
# Alembic Config
# ---------------------------------------------------------------------------
config = context.config

# Set the SQLAlchemy URL from application settings
settings = get_settings()
config.set_main_option("sqlalchemy.url", settings.async_database_url)

# Target metadata for auto-generate support
target_metadata = Base.metadata


# ---------------------------------------------------------------------------
# Offline migrations (generate SQL script without connecting)
# ---------------------------------------------------------------------------
def run_migrations_offline() -> None:
    """Run migrations in 'offline' mode.

    This configures the context with just a URL and not an Engine,
    though an Engine is acceptable here as well.  By skipping the Engine
    creation we don't even need a DBAPI to be available.

    Calls to context.execute() here emit the given string to the
    script output.
    """
    url = config.get_main_option("sqlalchemy.url")
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        compare_type=True,
        compare_server_default=True,
    )

    with context.begin_transaction():
        context.run_migrations()


# ---------------------------------------------------------------------------
# Online async migrations
# ---------------------------------------------------------------------------
def do_run_migrations(connection: Connection) -> None:
    """Run migrations with a live database connection."""
    context.configure(
        connection=connection,
        target_metadata=target_metadata,
        compare_type=True,
        compare_server_default=True,
    )

    with context.begin_transaction():
        context.run_migrations()


async def run_async_migrations() -> None:
    """Create an async engine and run migrations in online mode."""
    connectable = create_async_engine(
        settings.async_database_url,
        poolclass=pool.NullPool,
    )

    async with connectable.connect() as connection:
        await connection.run_sync(do_run_migrations)

    await connectable.dispose()


def run_migrations_online() -> None:
    """Run migrations in 'online' mode using an async engine."""
    asyncio.run(run_async_migrations())


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
if context.is_offline_mode():
    logger.info("Running migrations offline.")
    run_migrations_offline()
else:
    logger.info("Running migrations online (async).")
    run_migrations_online()
