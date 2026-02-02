"""
Health-check endpoints.

Provides a lightweight liveness probe and a detailed readiness probe that
verifies connectivity to PostgreSQL, Neo4j, and Redis.
"""

from __future__ import annotations

import logging

from fastapi import APIRouter, status

logger = logging.getLogger("agentshield.api.health")

router = APIRouter(tags=["Health"])


# --------------------------------------------------------------------------
# Liveness probe
# --------------------------------------------------------------------------


@router.get(
    "/",
    status_code=status.HTTP_200_OK,
    summary="Liveness probe",
    description="Returns a simple JSON payload confirming the service is running.",
    response_model=dict,
)
async def root() -> dict:
    """Lightweight liveness check -- always returns healthy if the process
    is up and the event loop is responsive."""
    return {
        "status": "healthy",
        "version": "1.0.0",
        "service": "AgentShield",
    }


# --------------------------------------------------------------------------
# Readiness probe
# --------------------------------------------------------------------------


@router.get(
    "/health",
    status_code=status.HTTP_200_OK,
    summary="Readiness probe",
    description=(
        "Performs connectivity checks against PostgreSQL, Neo4j, and Redis "
        "and reports individual subsystem health."
    ),
    response_model=dict,
)
async def health_check() -> dict:
    """Deep health check that verifies all backing services are reachable."""
    db_ok = await _check_postgres()
    neo4j_ok = await _check_neo4j()
    redis_ok = await _check_redis()

    all_ok = db_ok and neo4j_ok and redis_ok
    overall_status = "healthy" if all_ok else "degraded"

    return {
        "status": overall_status,
        "version": "1.0.0",
        "service": "AgentShield",
        "checks": {
            "database": db_ok,
            "neo4j": neo4j_ok,
            "redis": redis_ok,
        },
    }


# --------------------------------------------------------------------------
# Internal connectivity helpers
# --------------------------------------------------------------------------


async def _check_postgres() -> bool:
    """Attempt a trivial query against PostgreSQL."""
    try:
        from app.dependencies import _async_session_factory  # noqa: WPS436

        if _async_session_factory is None:
            return False
        async with _async_session_factory() as session:
            from sqlalchemy import text
            await session.execute(text("SELECT 1"))
        return True
    except Exception:
        logger.warning("PostgreSQL health check failed", exc_info=True)
        return False


async def _check_neo4j() -> bool:
    """Attempt a lightweight query against Neo4j."""
    try:
        from app.dependencies import _neo4j_driver  # noqa: WPS436

        if _neo4j_driver is None:
            return False
        async with _neo4j_driver.session() as session:
            result = await session.run("RETURN 1 AS n")
            await result.consume()
        return True
    except Exception:
        logger.warning("Neo4j health check failed", exc_info=True)
        return False


async def _check_redis() -> bool:
    """Attempt a PING against Redis."""
    try:
        from app.dependencies import _redis_pool  # noqa: WPS436
        from redis.asyncio import Redis

        if _redis_pool is None:
            return False
        async with Redis(connection_pool=_redis_pool) as conn:
            await conn.ping()
        return True
    except Exception:
        logger.warning("Redis health check failed", exc_info=True)
        return False
