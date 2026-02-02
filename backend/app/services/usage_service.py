"""
Usage tracking and dashboard statistics service.

Records per-request usage metrics and provides aggregated statistics
for the dashboard UI.
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from uuid import uuid4

from sqlalchemy import func, select, text
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.usage import Usage

logger = logging.getLogger("agentshield.services.usage")

# Period string -> timedelta mapping
_PERIOD_MAP: dict[str, timedelta] = {
    "1h": timedelta(hours=1),
    "24h": timedelta(hours=24),
    "7d": timedelta(days=7),
    "30d": timedelta(days=30),
}


class UsageService:
    """Records API usage and computes dashboard statistics."""

    def __init__(self, db_session: AsyncSession) -> None:
        self._db = db_session

    # ------------------------------------------------------------------
    # Record
    # ------------------------------------------------------------------

    async def record_usage(
        self,
        user_id: str,
        api_key_id: str | None,
        endpoint: str,
        method: str,
        status_code: int,
        latency_ms: float,
    ) -> None:
        """Persist a single API usage record.

        Parameters
        ----------
        user_id:
            Authenticated user UUID.
        api_key_id:
            API key UUID used (may be ``None`` for JWT-based calls).
        endpoint:
            HTTP path.
        method:
            HTTP method.
        status_code:
            Response status code.
        latency_ms:
            Server-side processing time in milliseconds.
        """
        logger.debug(
            "record_usage  user=%s  endpoint=%s  method=%s  status=%d  latency=%.1fms",
            user_id,
            endpoint,
            method,
            status_code,
            latency_ms,
        )

        record = Usage(
            id=uuid4(),
            user_id=user_id,
            api_key_id=api_key_id,
            endpoint=endpoint,
            method=method,
            status_code=status_code,
            latency_ms=latency_ms,
        )

        self._db.add(record)
        await self._db.flush()

    # ------------------------------------------------------------------
    # Dashboard statistics
    # ------------------------------------------------------------------

    async def get_dashboard_stats(self, period: str = "24h") -> dict:
        """Compute aggregate dashboard statistics for the given period.

        Parameters
        ----------
        period:
            One of ``1h``, ``24h``, ``7d``, or ``30d``.

        Returns
        -------
        dict
            Keys: ``total_requests``, ``threats_blocked``,
            ``pii_sanitized``, ``anomalies_detected``,
            ``reports_generated``, ``trends``, ``top_threats``,
            ``risk_distribution``.
        """
        delta = _PERIOD_MAP.get(period, timedelta(hours=24))
        since = datetime.now(timezone.utc) - delta

        logger.info("get_dashboard_stats  period=%s  since=%s", period, since.isoformat())

        # Total requests -------------------------------------------------------
        total_requests = await self._count_usage(since)

        # Threats blocked (scan/input calls with 4xx/blocked status) -----------
        threats_blocked = await self._count_usage(
            since,
            endpoint_like="/scan/input",
            status_min=200,
            status_max=299,
            extra_filter="blocked",
        )

        # PII sanitized (scan/output calls) ------------------------------------
        pii_sanitized = await self._count_usage(
            since,
            endpoint_like="/scan/output",
        )

        # Anomalies detected (logs/action calls) --------------------------------
        anomalies_detected = await self._count_usage(
            since,
            endpoint_like="/logs/action",
        )

        # Reports generated ----------------------------------------------------
        reports_generated = await self._count_usage(
            since,
            endpoint_like="/reports",
            method="POST",
        )

        # Trends: request counts per interval -----------------------------------
        trends = await self._compute_trends(since, period)

        # Top threats -----------------------------------------------------------
        top_threats = await self._get_top_threats(since)

        # Risk distribution ----------------------------------------------------
        risk_distribution = await self._get_risk_distribution(since)

        return {
            "total_requests": total_requests,
            "threats_blocked": threats_blocked,
            "pii_sanitized": pii_sanitized,
            "anomalies_detected": anomalies_detected,
            "reports_generated": reports_generated,
            "trends": trends,
            "top_threats": top_threats,
            "risk_distribution": risk_distribution,
        }

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    async def _count_usage(
        self,
        since: datetime,
        endpoint_like: str | None = None,
        method: str | None = None,
        status_min: int | None = None,
        status_max: int | None = None,
        extra_filter: str | None = None,
    ) -> int:
        """Return usage row count matching the given criteria."""
        stmt = select(func.count(Usage.id)).where(Usage.timestamp >= since)

        if endpoint_like:
            stmt = stmt.where(Usage.endpoint.ilike(f"%{endpoint_like}%"))

        if method:
            stmt = stmt.where(Usage.method == method)

        if status_min is not None:
            stmt = stmt.where(Usage.status_code >= status_min)

        if status_max is not None:
            stmt = stmt.where(Usage.status_code <= status_max)

        try:
            result = await self._db.execute(stmt)
            return result.scalar() or 0
        except Exception:
            logger.exception("Failed to count usage records")
            return 0

    async def _compute_trends(self, since: datetime, period: str) -> list[dict]:
        """Return time-bucketed request counts for trend graphs."""
        # Choose bucket size based on period
        if period in ("1h", "24h"):
            bucket = "hour"
        elif period == "7d":
            bucket = "day"
        else:
            bucket = "day"

        try:
            result = await self._db.execute(
                text(
                    f"SELECT date_trunc(:bucket, timestamp) AS bucket_ts, "
                    f"count(*) AS cnt "
                    f"FROM usage "
                    f"WHERE timestamp >= :since "
                    f"GROUP BY bucket_ts ORDER BY bucket_ts ASC"
                ),
                {"bucket": bucket, "since": since},
            )
            rows = result.mappings().all()
            return [
                {"timestamp": row["bucket_ts"].isoformat(), "count": row["cnt"]}
                for row in rows
            ]
        except Exception:
            logger.exception("Failed to compute usage trends")
            return []

    async def _get_top_threats(self, since: datetime, limit: int = 10) -> list[dict]:
        """Return the most common threat types from the alerts table."""
        try:
            result = await self._db.execute(
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
        except Exception:
            logger.exception("Failed to get top threats")
            return []

    async def _get_risk_distribution(self, since: datetime) -> dict[str, int]:
        """Return a risk-level distribution from recent alerts."""
        try:
            result = await self._db.execute(
                text(
                    "SELECT severity, count(*) AS cnt "
                    "FROM alerts "
                    "WHERE created_at >= :since "
                    "GROUP BY severity"
                ),
                {"since": since},
            )
            rows = result.mappings().all()
            return {row["severity"]: row["cnt"] for row in rows}
        except Exception:
            logger.exception("Failed to get risk distribution")
            return {}
