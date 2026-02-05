"""
Celery tasks for scheduled maintenance operations.

Provides periodic cleanup of old sessions, expired API keys, usage
logs, and daily statistics aggregation.
"""

from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timedelta, timezone
from typing import Any

from app.workers.celery_app import celery_app

logger = logging.getLogger("inalign.workers.cleanup_worker")


def _run_async(coro: Any) -> Any:
    """Run an async coroutine in a new event loop (for use inside Celery tasks)."""
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


@celery_app.task(
    queue="cleanup",
    name="app.workers.cleanup_worker.cleanup_old_sessions",
)
def cleanup_old_sessions(days: int = 90) -> dict[str, Any]:
    """Remove sessions older than *days* from the graph database.

    Sessions in ``closed`` status that have not been updated within the
    retention window are deleted along with their associated action and
    threat nodes.

    Parameters
    ----------
    days:
        Retention period in days.  Sessions older than this are removed.

    Returns
    -------
    dict
        Summary with ``deleted_sessions`` count and ``retention_days``.
    """
    logger.info("Starting session cleanup: retention_days=%d", days)

    deleted_sessions = 0

    try:
        from app.config import get_settings
        from app.graph.neo4j_client import Neo4jClient
        from app.graph import queries

        settings = get_settings()
        client = Neo4jClient(
            uri=settings.neo4j_uri,
            username=settings.neo4j_user,
            password=settings.neo4j_password,
            database=settings.neo4j_database,
        )

        async def _cleanup() -> int:
            await client.connect()
            try:
                records = await client._execute_write(
                    queries.CLEANUP_OLD_SESSIONS,
                    {"retention_days": days},
                )
                count = records[0].get("deleted_sessions", 0) if records else 0
                return int(count)
            finally:
                await client.disconnect()

        deleted_sessions = _run_async(_cleanup())

        logger.info(
            "Session cleanup complete: deleted=%d retention_days=%d",
            deleted_sessions,
            days,
        )

    except Exception as exc:
        logger.error("Session cleanup failed: %s", exc, exc_info=True)

    return {
        "deleted_sessions": deleted_sessions,
        "retention_days": days,
    }


@celery_app.task(
    queue="cleanup",
    name="app.workers.cleanup_worker.cleanup_usage_logs",
)
def cleanup_usage_logs(days: int = 30) -> dict[str, Any]:
    """Delete usage log records older than *days*.

    Parameters
    ----------
    days:
        Retention period in days.

    Returns
    -------
    dict
        Summary with ``deleted_count`` and ``retention_days``.
    """
    logger.info("Starting usage log cleanup: retention_days=%d", days)

    deleted_count = 0

    try:
        from app.config import get_settings
        from sqlalchemy import create_engine, text

        settings = get_settings()
        engine = create_engine(settings.sync_database_url)

        cutoff = datetime.now(timezone.utc) - timedelta(days=days)

        with engine.connect() as conn:
            result = conn.execute(
                text("DELETE FROM usage WHERE timestamp < :cutoff"),
                {"cutoff": cutoff},
            )
            deleted_count = result.rowcount or 0
            conn.commit()

        engine.dispose()

        logger.info(
            "Usage log cleanup complete: deleted=%d retention_days=%d",
            deleted_count,
            days,
        )

    except Exception as exc:
        logger.error("Usage log cleanup failed: %s", exc, exc_info=True)

    return {
        "deleted_count": deleted_count,
        "retention_days": days,
    }


@celery_app.task(
    queue="cleanup",
    name="app.workers.cleanup_worker.cleanup_expired_api_keys",
)
def cleanup_expired_api_keys() -> dict[str, Any]:
    """Deactivate API keys that have passed their expiration date.

    Keys are soft-deleted by setting ``is_active = false`` rather than
    being removed from the database.

    Returns
    -------
    dict
        Summary with ``deactivated_count``.
    """
    logger.info("Starting expired API key cleanup.")

    deactivated_count = 0

    try:
        from app.config import get_settings
        from sqlalchemy import create_engine, text

        settings = get_settings()
        engine = create_engine(settings.sync_database_url)

        now = datetime.now(timezone.utc)

        with engine.connect() as conn:
            result = conn.execute(
                text(
                    "UPDATE api_keys SET is_active = false "
                    "WHERE expires_at IS NOT NULL "
                    "AND expires_at < :now "
                    "AND is_active = true"
                ),
                {"now": now},
            )
            deactivated_count = result.rowcount or 0
            conn.commit()

        engine.dispose()

        logger.info("Expired API key cleanup complete: deactivated=%d", deactivated_count)

    except Exception as exc:
        logger.error("API key cleanup failed: %s", exc, exc_info=True)

    return {
        "deactivated_count": deactivated_count,
    }


@celery_app.task(
    queue="cleanup",
    name="app.workers.cleanup_worker.aggregate_daily_stats",
)
def aggregate_daily_stats() -> dict[str, Any]:
    """Aggregate usage statistics for the previous day.

    Computes per-endpoint request counts, average latency, error rates,
    and total request volume, storing them in a summary table or cache
    for fast dashboard queries.

    Returns
    -------
    dict
        Summary with ``date``, ``total_requests``, ``endpoints``,
        and ``avg_latency_ms``.
    """
    logger.info("Starting daily statistics aggregation.")

    yesterday = datetime.now(timezone.utc).date() - timedelta(days=1)
    total_requests = 0
    avg_latency_ms = 0.0
    endpoints: dict[str, int] = {}

    try:
        from app.config import get_settings
        from sqlalchemy import create_engine, text

        settings = get_settings()
        engine = create_engine(settings.sync_database_url)

        day_start = datetime.combine(yesterday, datetime.min.time(), tzinfo=timezone.utc)
        day_end = day_start + timedelta(days=1)

        with engine.connect() as conn:
            # Total requests and average latency
            row = conn.execute(
                text(
                    "SELECT COUNT(*) AS cnt, COALESCE(AVG(latency_ms), 0) AS avg_lat "
                    "FROM usage WHERE timestamp >= :start AND timestamp < :end"
                ),
                {"start": day_start, "end": day_end},
            ).first()

            if row:
                total_requests = int(row[0])
                avg_latency_ms = float(row[1])

            # Per-endpoint breakdown
            rows = conn.execute(
                text(
                    "SELECT endpoint, COUNT(*) AS cnt "
                    "FROM usage WHERE timestamp >= :start AND timestamp < :end "
                    "GROUP BY endpoint ORDER BY cnt DESC"
                ),
                {"start": day_start, "end": day_end},
            ).fetchall()

            endpoints = {str(r[0]): int(r[1]) for r in rows}

        engine.dispose()

        # Optionally store aggregated stats in Redis for dashboard access
        try:
            import redis

            redis_client = redis.from_url(str(settings.redis_url))
            cache_key = f"stats:daily:{yesterday.isoformat()}"
            import json

            redis_client.setex(
                cache_key,
                86400 * 30,  # 30 days TTL
                json.dumps(
                    {
                        "date": yesterday.isoformat(),
                        "total_requests": total_requests,
                        "avg_latency_ms": round(avg_latency_ms, 2),
                        "endpoints": endpoints,
                    }
                ),
            )
            redis_client.close()
        except Exception as cache_exc:
            logger.warning("Failed to cache daily stats: %s", cache_exc)

        logger.info(
            "Daily stats aggregation complete: date=%s requests=%d avg_latency=%.1fms",
            yesterday.isoformat(),
            total_requests,
            avg_latency_ms,
        )

    except Exception as exc:
        logger.error("Daily stats aggregation failed: %s", exc, exc_info=True)

    return {
        "date": yesterday.isoformat(),
        "total_requests": total_requests,
        "avg_latency_ms": round(avg_latency_ms, 2),
        "endpoints": endpoints,
    }
