"""
FastAPI dependency injection functions.

Provides request-scoped database sessions, Neo4j driver access, Redis
connections, and API-key-based user authentication.
"""

from __future__ import annotations

import logging
from typing import Annotated, AsyncGenerator

from fastapi import Depends, Header, HTTPException, Request, status
from neo4j import AsyncGraphDatabase, AsyncDriver, AsyncSession as Neo4jAsyncSession
from redis.asyncio import ConnectionPool as RedisPool
from redis.asyncio import Redis
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from app.config import Settings, get_settings
from app.core.security import verify_api_key

logger = logging.getLogger("agentshield.dependencies")

# ---------------------------------------------------------------------------
# Module-level singletons (initialised at app startup via lifespan)
# ---------------------------------------------------------------------------
_async_engine: AsyncEngine | None = None
_async_session_factory: async_sessionmaker[AsyncSession] | None = None
_neo4j_driver: AsyncDriver | None = None
_redis_pool: RedisPool | None = None


# ---------------------------------------------------------------------------
# Lifecycle helpers (called from the FastAPI lifespan context manager)
# ---------------------------------------------------------------------------
async def init_db(settings: Settings) -> None:
    """Create the async SQLAlchemy engine and session factory."""
    global _async_engine, _async_session_factory  # noqa: PLW0603

    _async_engine = create_async_engine(
        settings.async_database_url,
        pool_size=settings.postgres_pool_size,
        max_overflow=settings.postgres_max_overflow,
        echo=settings.postgres_echo,
        pool_pre_ping=True,
        pool_recycle=300,
    )
    _async_session_factory = async_sessionmaker(
        bind=_async_engine,
        class_=AsyncSession,
        expire_on_commit=False,
        autoflush=False,
    )
    logger.info("PostgreSQL async engine initialised (pool_size=%d)", settings.postgres_pool_size)


async def shutdown_db() -> None:
    """Dispose of the async engine and release connections."""
    global _async_engine, _async_session_factory  # noqa: PLW0603
    if _async_engine is not None:
        await _async_engine.dispose()
        logger.info("PostgreSQL async engine disposed")
    _async_engine = None
    _async_session_factory = None


async def init_neo4j(settings: Settings) -> None:
    """Create the Neo4j async driver."""
    global _neo4j_driver  # noqa: PLW0603
    _neo4j_driver = AsyncGraphDatabase.driver(
        settings.neo4j_uri,
        auth=(settings.neo4j_user, settings.neo4j_password),
        max_connection_pool_size=settings.neo4j_max_connection_pool_size,
    )
    # Verify connectivity eagerly so we fail fast on bad credentials.
    try:
        await _neo4j_driver.verify_connectivity()
        logger.info("Neo4j driver connected to %s", settings.neo4j_uri)
    except Exception:
        logger.exception("Neo4j connectivity check failed")
        raise


async def shutdown_neo4j() -> None:
    """Close the Neo4j driver."""
    global _neo4j_driver  # noqa: PLW0603
    if _neo4j_driver is not None:
        await _neo4j_driver.close()
        logger.info("Neo4j driver closed")
    _neo4j_driver = None


async def init_redis(settings: Settings) -> None:
    """Create the async Redis connection pool."""
    global _redis_pool  # noqa: PLW0603
    _redis_pool = RedisPool.from_url(
        str(settings.redis_url),
        max_connections=settings.redis_pool_max_connections,
        decode_responses=True,
    )
    # Quick connectivity check
    async with Redis(connection_pool=_redis_pool) as conn:
        await conn.ping()
    logger.info("Redis connection pool initialised")


async def shutdown_redis() -> None:
    """Disconnect the Redis pool."""
    global _redis_pool  # noqa: PLW0603
    if _redis_pool is not None:
        await _redis_pool.aclose()
        logger.info("Redis connection pool closed")
    _redis_pool = None


# ---------------------------------------------------------------------------
# FastAPI Dependencies
# ---------------------------------------------------------------------------

async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """
    Yield an async SQLAlchemy session scoped to the current request.

    The session is committed on successful return and rolled back on exception.
    """
    if _async_session_factory is None:
        logger.error("Database session factory not initialised")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Database unavailable",
        )

    session = _async_session_factory()
    try:
        yield session
        await session.commit()
    except Exception:
        await session.rollback()
        raise
    finally:
        await session.close()


async def get_neo4j_session() -> AsyncGenerator[Neo4jAsyncSession, None]:
    """
    Yield an async Neo4j session scoped to the current request.

    The session is automatically closed after the request completes.
    """
    if _neo4j_driver is None:
        logger.error("Neo4j driver not initialised")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Graph database unavailable",
        )

    settings = get_settings()
    session = _neo4j_driver.session(database=settings.neo4j_database)
    try:
        yield session
    finally:
        await session.close()


async def get_neo4j_driver() -> AsyncDriver:
    """Return the singleton Neo4j async driver."""
    if _neo4j_driver is None:
        logger.error("Neo4j driver not initialised")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Graph database unavailable",
        )
    return _neo4j_driver


async def get_redis() -> AsyncGenerator[Redis, None]:
    """Yield an async Redis client scoped to the current request."""
    if _redis_pool is None:
        logger.error("Redis pool not initialised")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Cache unavailable",
        )

    client = Redis(connection_pool=_redis_pool)
    try:
        yield client
    finally:
        await client.aclose()


def get_redis_pool() -> RedisPool:
    """Return the raw Redis connection pool (for rate limiter etc.)."""
    if _redis_pool is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Cache unavailable",
        )
    return _redis_pool


async def get_current_user(
    x_api_key: Annotated[str, Header(description="API key for authentication")],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> dict:
    """
    Authenticate the request via API key and return the associated user record.

    The API key is expected in the ``X-API-Key`` header. The key is hashed and
    looked up in the ``api_keys`` table. If the key is invalid or revoked, an
    HTTP 401 is raised.

    Returns a dict with at least ``user_id``, ``org_id``, and ``scopes``.
    """
    from sqlalchemy import select, text

    key_hash = verify_api_key(x_api_key)

    # Look up the hashed key in the database.  We use a raw text query here to
    # avoid coupling to the ORM model that lives in app.models — that module
    # may import *this* module, creating a circular dependency.
    result = await db.execute(
        text(
            "SELECT id, user_id, org_id, scopes, is_active "
            "FROM api_keys WHERE key_hash = :key_hash"
        ),
        {"key_hash": key_hash},
    )
    row = result.mappings().first()

    if row is None or not row["is_active"]:
        logger.warning("Authentication failed: invalid or revoked API key")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or revoked API key",
        )

    # Optionally bump last_used_at (fire-and-forget, non-blocking)
    try:
        await db.execute(
            text("UPDATE api_keys SET last_used_at = NOW() WHERE id = :id"),
            {"id": row["id"]},
        )
    except Exception:
        logger.debug("Failed to update last_used_at for key %s", row["id"], exc_info=True)

    scopes = row["scopes"] if row["scopes"] else []

    return {
        "api_key_id": row["id"],
        "user_id": row["user_id"],
        "org_id": row["org_id"],
        "scopes": scopes,
    }


# Convenience type alias for use in route signatures
CurrentUser = Annotated[dict, Depends(get_current_user)]
DBSession = Annotated[AsyncSession, Depends(get_db)]
Neo4jSession = Annotated[Neo4jAsyncSession, Depends(get_neo4j_session)]
RedisClient = Annotated[Redis, Depends(get_redis)]
