"""
Dashboard endpoints.

Provide aggregated statistics, trend data, and top-threat breakdowns
consumed by the InALign web UI.
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import func, select, text
from sqlalchemy.ext.asyncio import AsyncSession

from app.dependencies import CurrentUser, DBSession
from app.services.usage_service import UsageService

logger = logging.getLogger("inalign.api.dashboard")

router = APIRouter()

_ALLOWED_PERIODS = {"1h", "24h", "7d", "30d"}


# --------------------------------------------------------------------------
# GET /stats
# --------------------------------------------------------------------------


@router.get(
    "/stats",
    response_model=dict,
    status_code=status.HTTP_200_OK,
    summary="Dashboard statistics",
    description=(
        "Return aggregate dashboard statistics for the specified time period "
        "including total requests, threats blocked, PII sanitised, "
        "anomalies detected, and risk distribution."
    ),
)
async def dashboard_stats(
    current_user: CurrentUser,
    db: DBSession,
    period: str = Query(
        default="24h",
        description="Time period: 1h, 24h, 7d, or 30d",
    ),
) -> dict:
    """Return aggregated dashboard statistics."""
    if period not in _ALLOWED_PERIODS:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid period '{period}'. Allowed: {', '.join(sorted(_ALLOWED_PERIODS))}",
        )

    logger.info(
        "GET /dashboard/stats  user=%s  period=%s",
        current_user["user_id"],
        period,
    )

    service = UsageService(db_session=db)

    try:
        stats = await service.get_dashboard_stats(period=period)
    except Exception as exc:
        logger.exception("Failed to compute dashboard stats")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to compute statistics: {exc}",
        ) from exc

    return stats


# --------------------------------------------------------------------------
# GET /trends
# --------------------------------------------------------------------------


@router.get(
    "/trends",
    response_model=list[dict],
    status_code=status.HTTP_200_OK,
    summary="Request trends",
    description=(
        "Return time-series data showing request volume over the specified "
        "period, bucketed by hour or day."
    ),
)
async def dashboard_trends(
    current_user: CurrentUser,
    db: DBSession,
    period: str = Query(default="24h", description="Time period: 1h, 24h, 7d, or 30d"),
) -> list[dict]:
    """Return time-bucketed request trend data."""
    if period not in _ALLOWED_PERIODS:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid period '{period}'. Allowed: {', '.join(sorted(_ALLOWED_PERIODS))}",
        )

    logger.info(
        "GET /dashboard/trends  user=%s  period=%s",
        current_user["user_id"],
        period,
    )

    _PERIOD_MAP = {
        "1h": timedelta(hours=1),
        "24h": timedelta(hours=24),
        "7d": timedelta(days=7),
        "30d": timedelta(days=30),
    }
    since = datetime.now(timezone.utc) - _PERIOD_MAP.get(period, timedelta(hours=24))
    bucket = "hour" if period in ("1h", "24h") else "day"

    try:
        result = await db.execute(
            text(
                "SELECT date_trunc(:bucket, timestamp) AS bucket_ts, "
                "count(*) AS cnt "
                "FROM usage "
                "WHERE timestamp >= :since "
                "GROUP BY bucket_ts ORDER BY bucket_ts ASC"
            ),
            {"bucket": bucket, "since": since},
        )
        rows = result.mappings().all()
        return [
            {"timestamp": row["bucket_ts"].isoformat(), "count": row["cnt"]}
            for row in rows
        ]
    except Exception as exc:
        logger.exception("Failed to compute dashboard trends")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to compute trends: {exc}",
        ) from exc


# --------------------------------------------------------------------------
# GET /top-threats
# --------------------------------------------------------------------------


@router.get(
    "/top-threats",
    response_model=list[dict],
    status_code=status.HTTP_200_OK,
    summary="Top threat types",
    description=(
        "Return the most frequently occurring threat types from alerts "
        "within the specified time window."
    ),
)
async def dashboard_top_threats(
    current_user: CurrentUser,
    db: DBSession,
    period: str = Query(default="24h", description="Time period: 1h, 24h, 7d, or 30d"),
    limit: int = Query(default=10, ge=1, le=50, description="Maximum number of results"),
) -> list[dict]:
    """Return top threat types by occurrence count."""
    if period not in _ALLOWED_PERIODS:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid period '{period}'. Allowed: {', '.join(sorted(_ALLOWED_PERIODS))}",
        )

    logger.info(
        "GET /dashboard/top-threats  user=%s  period=%s  limit=%d",
        current_user["user_id"],
        period,
        limit,
    )

    _PERIOD_MAP = {
        "1h": timedelta(hours=1),
        "24h": timedelta(hours=24),
        "7d": timedelta(days=7),
        "30d": timedelta(days=30),
    }
    since = datetime.now(timezone.utc) - _PERIOD_MAP.get(period, timedelta(hours=24))

    try:
        result = await db.execute(
            text(
                "SELECT alert_type, severity, count(*) AS cnt "
                "FROM alerts "
                "WHERE created_at >= :since "
                "GROUP BY alert_type, severity "
                "ORDER BY cnt DESC "
                "LIMIT :limit"
            ),
            {"since": since, "limit": limit},
        )
        rows = result.mappings().all()
        return [
            {
                "type": row["alert_type"],
                "severity": row["severity"],
                "count": row["cnt"],
            }
            for row in rows
        ]
    except Exception as exc:
        logger.exception("Failed to get top threats")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to retrieve top threats: {exc}",
        ) from exc
