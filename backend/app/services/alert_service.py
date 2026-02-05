"""
Alert management service.

Provides CRUD operations for security alerts stored in PostgreSQL.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from uuid import uuid4

from sqlalchemy import select, func, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.alert import Alert, AlertSeverity, AlertType
from app.schemas.alert import AlertListResponse, AlertResponse
from app.schemas.common import Severity

logger = logging.getLogger("inalign.services.alert")


def _alert_to_response(alert: Alert) -> AlertResponse:
    """Convert an ORM :class:`Alert` to the API response schema."""
    return AlertResponse(
        id=str(alert.id),
        session_id=alert.session_id,
        agent_id=alert.agent_id,
        alert_type=alert.alert_type.value if isinstance(alert.alert_type, AlertType) else str(alert.alert_type),
        severity=Severity(
            alert.severity.value if isinstance(alert.severity, AlertSeverity) else str(alert.severity)
        ),
        title=alert.title,
        description=alert.description,
        details=alert.details,
        is_acknowledged=alert.is_acknowledged,
        acknowledged_by=str(alert.acknowledged_by) if alert.acknowledged_by else None,
        acknowledged_at=alert.acknowledged_at,
        created_at=alert.created_at,
    )


class AlertService:
    """Service for creating, querying, and acknowledging security alerts."""

    def __init__(self, db_session: AsyncSession) -> None:
        self._db = db_session

    # ------------------------------------------------------------------
    # Create
    # ------------------------------------------------------------------

    async def create_alert(
        self,
        session_id: str,
        agent_id: str,
        alert_type: str,
        severity: str,
        title: str,
        description: str,
        details: dict | None = None,
    ) -> AlertResponse:
        """Create and persist a new security alert.

        Parameters
        ----------
        session_id:
            Session in which the alert was triggered.
        agent_id:
            Agent involved.
        alert_type:
            One of the :class:`AlertType` enum values.
        severity:
            One of ``critical``, ``high``, ``medium``, ``low``.
        title:
            Short human-readable summary.
        description:
            Longer explanation.
        details:
            Arbitrary JSON payload with detection metadata.

        Returns
        -------
        AlertResponse
            The newly created alert.
        """
        logger.info(
            "create_alert  session=%s  agent=%s  type=%s  severity=%s",
            session_id,
            agent_id,
            alert_type,
            severity,
        )

        alert = Alert(
            id=uuid4(),
            session_id=session_id,
            agent_id=agent_id,
            alert_type=AlertType(alert_type),
            severity=AlertSeverity(severity),
            title=title,
            description=description,
            details=details or {},
        )

        self._db.add(alert)
        await self._db.flush()
        await self._db.refresh(alert)

        logger.info("Alert %s created (severity=%s)", alert.id, severity)
        return _alert_to_response(alert)

    # ------------------------------------------------------------------
    # List with filters
    # ------------------------------------------------------------------

    async def get_alerts(
        self,
        filters: dict[str, object] | None = None,
        page: int = 1,
        size: int = 20,
    ) -> AlertListResponse:
        """Return a filtered, paginated list of alerts.

        Parameters
        ----------
        filters:
            Optional keys: ``severity``, ``alert_type``, ``session_id``,
            ``agent_id``, ``is_acknowledged``.
        page:
            1-based page number.
        size:
            Results per page.

        Returns
        -------
        AlertListResponse
            Paginated alert list.
        """
        filters = filters or {}
        logger.info("get_alerts  filters=%s  page=%d  size=%d", filters, page, size)

        stmt = select(Alert)
        count_stmt = select(func.count(Alert.id))

        if "severity" in filters and filters["severity"]:
            sev = AlertSeverity(str(filters["severity"]))
            stmt = stmt.where(Alert.severity == sev)
            count_stmt = count_stmt.where(Alert.severity == sev)

        if "alert_type" in filters and filters["alert_type"]:
            at = AlertType(str(filters["alert_type"]))
            stmt = stmt.where(Alert.alert_type == at)
            count_stmt = count_stmt.where(Alert.alert_type == at)

        if "session_id" in filters and filters["session_id"]:
            stmt = stmt.where(Alert.session_id == str(filters["session_id"]))
            count_stmt = count_stmt.where(Alert.session_id == str(filters["session_id"]))

        if "agent_id" in filters and filters["agent_id"]:
            stmt = stmt.where(Alert.agent_id == str(filters["agent_id"]))
            count_stmt = count_stmt.where(Alert.agent_id == str(filters["agent_id"]))

        if "is_acknowledged" in filters and filters["is_acknowledged"] is not None:
            ack = bool(filters["is_acknowledged"])
            stmt = stmt.where(Alert.is_acknowledged == ack)
            count_stmt = count_stmt.where(Alert.is_acknowledged == ack)

        # Total count
        total_result = await self._db.execute(count_stmt)
        total = total_result.scalar() or 0

        # Paginated data
        offset = (page - 1) * size
        stmt = stmt.order_by(Alert.created_at.desc()).offset(offset).limit(size)
        result = await self._db.execute(stmt)
        alerts = result.scalars().all()

        items = [_alert_to_response(a) for a in alerts]

        return AlertListResponse(
            items=items,
            total=int(total),
            page=page,
            size=size,
        )

    # ------------------------------------------------------------------
    # Single alert
    # ------------------------------------------------------------------

    async def get_alert(self, alert_id: str) -> AlertResponse:
        """Fetch a single alert by ID.

        Raises
        ------
        ValueError
            If the alert does not exist.
        """
        logger.info("get_alert  alert_id=%s", alert_id)

        result = await self._db.execute(
            select(Alert).where(Alert.id == alert_id)
        )
        alert = result.scalar_one_or_none()

        if alert is None:
            raise ValueError(f"Alert '{alert_id}' not found")

        return _alert_to_response(alert)

    # ------------------------------------------------------------------
    # Acknowledge
    # ------------------------------------------------------------------

    async def acknowledge_alert(
        self,
        alert_id: str,
        acknowledged_by: str = "system",
    ) -> AlertResponse:
        """Mark an alert as acknowledged.

        Parameters
        ----------
        alert_id:
            UUID of the alert to acknowledge.
        acknowledged_by:
            Identifier (user_id or name) of the acknowledging party.

        Returns
        -------
        AlertResponse
            The updated alert.

        Raises
        ------
        ValueError
            If the alert does not exist.
        """
        logger.info(
            "acknowledge_alert  alert_id=%s  by=%s",
            alert_id,
            acknowledged_by,
        )

        result = await self._db.execute(
            select(Alert).where(Alert.id == alert_id)
        )
        alert = result.scalar_one_or_none()

        if alert is None:
            raise ValueError(f"Alert '{alert_id}' not found")

        alert.is_acknowledged = True
        alert.acknowledged_by = acknowledged_by  # type: ignore[assignment]
        alert.acknowledged_at = datetime.now(timezone.utc)

        await self._db.flush()
        await self._db.refresh(alert)

        logger.info("Alert %s acknowledged by %s", alert_id, acknowledged_by)
        return _alert_to_response(alert)
