"""
Session service for querying and summarising monitored agent sessions.

All session data is sourced from the Neo4j graph layer.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone

from app.schemas.common import RiskLevel
from app.schemas.session import (
    GraphSummary,
    SessionListResponse,
    SessionResponse,
    SessionStats,
    TimelineEvent,
)

logger = logging.getLogger("inalign.services.session")


def _parse_risk_level(score: float) -> RiskLevel:
    """Map a numeric risk score to a :class:`RiskLevel` enum value."""
    if score >= 0.9:
        return RiskLevel.CRITICAL
    if score >= 0.7:
        return RiskLevel.HIGH
    if score >= 0.3:
        return RiskLevel.MEDIUM
    if score > 0.0:
        return RiskLevel.LOW
    return RiskLevel.NONE


class SessionService:
    """Read-only service exposing session data from the Neo4j graph."""

    def __init__(self, neo4j_client: object) -> None:
        self._neo4j = neo4j_client

    # ------------------------------------------------------------------
    # Single session
    # ------------------------------------------------------------------

    async def get_session(self, session_id: str) -> SessionResponse:
        """Retrieve a single session by ID.

        Parameters
        ----------
        session_id:
            The unique session identifier stored as a Neo4j node property.

        Returns
        -------
        SessionResponse
            Full session data including statistics and risk assessment.

        Raises
        ------
        ValueError
            If no session with the given *session_id* exists.
        """
        from app.graph import queries  # noqa: WPS433

        logger.info("get_session  session_id=%s", session_id)

        try:
            result = await self._neo4j.execute_read(  # type: ignore[attr-defined]
                queries.GET_SESSION_GRAPH,
                {"session_id": session_id},
            )
        except Exception:
            logger.exception("Failed to query session %s", session_id)
            raise ValueError(f"Session '{session_id}' not found")

        if not result or not result.get("session"):
            raise ValueError(f"Session '{session_id}' not found")

        session_data = result["session"]
        actions = result.get("actions", [])
        threats = result.get("threats", [])
        sequences = result.get("sequences", [])

        risk_score = float(session_data.get("risk_score", 0.0))
        stats = SessionStats(
            total_actions=len(actions),
            threats_detected=len([t for t in threats if t]),
        )

        # Build timeline from actions
        timeline = await self.get_session_timeline(session_id)
        graph_summary = await self.get_session_graph_summary(session_id)

        return SessionResponse(
            session_id=session_id,
            agent_id=session_data.get("agent_id", ""),
            status=session_data.get("status", "active"),
            risk_level=_parse_risk_level(risk_score),
            risk_score=risk_score,
            started_at=session_data.get("started_at"),
            last_activity_at=session_data.get("updated_at"),
            stats=stats,
            timeline=timeline,
            graph_summary=graph_summary,
        )

    # ------------------------------------------------------------------
    # Session listing with filters
    # ------------------------------------------------------------------

    async def list_sessions(
        self,
        filters: dict[str, object],
        page: int = 1,
        size: int = 20,
    ) -> SessionListResponse:
        """Return a paginated list of sessions matching *filters*.

        Parameters
        ----------
        filters:
            Optional filter keys: ``status``, ``risk_level``, ``agent_id``,
            ``date_from``, ``date_to``.
        page:
            1-based page number.
        size:
            Number of results per page.

        Returns
        -------
        SessionListResponse
            Paginated session list.
        """
        logger.info("list_sessions  filters=%s  page=%d  size=%d", filters, page, size)

        # Build a dynamic Cypher WHERE clause based on provided filters
        where_clauses: list[str] = []
        params: dict[str, object] = {}

        if filters.get("status"):
            where_clauses.append("s.status = $status")
            params["status"] = filters["status"]

        if filters.get("agent_id"):
            where_clauses.append("s.agent_id = $agent_id")
            params["agent_id"] = filters["agent_id"]

        if filters.get("risk_level"):
            # Map risk_level to a score range
            level = str(filters["risk_level"]).lower()
            score_ranges: dict[str, tuple[float, float]] = {
                "critical": (0.9, 1.0),
                "high": (0.7, 0.9),
                "medium": (0.3, 0.7),
                "low": (0.01, 0.3),
                "none": (0.0, 0.0),
            }
            low_bound, high_bound = score_ranges.get(level, (0.0, 1.0))
            where_clauses.append("s.risk_score >= $risk_low AND s.risk_score <= $risk_high")
            params["risk_low"] = low_bound
            params["risk_high"] = high_bound

        if filters.get("date_from"):
            where_clauses.append("s.started_at >= datetime($date_from)")
            params["date_from"] = str(filters["date_from"])

        if filters.get("date_to"):
            where_clauses.append("s.started_at <= datetime($date_to)")
            params["date_to"] = str(filters["date_to"])

        where_str = " AND ".join(where_clauses) if where_clauses else "true"
        skip = (page - 1) * size

        # Count query
        count_cypher = f"MATCH (s:Session) WHERE {where_str} RETURN count(s) AS total"
        # Data query
        data_cypher = (
            f"MATCH (s:Session) WHERE {where_str} "
            f"RETURN s ORDER BY s.started_at DESC SKIP $skip LIMIT $limit"
        )
        params["skip"] = skip
        params["limit"] = size

        try:
            count_result = await self._neo4j.execute_read(count_cypher, params)  # type: ignore[attr-defined]
            total = count_result.get("total", 0) if count_result else 0

            data_result = await self._neo4j.execute_read(data_cypher, params)  # type: ignore[attr-defined]
            rows = data_result if isinstance(data_result, list) else []
        except Exception:
            logger.exception("Failed to list sessions")
            rows = []
            total = 0

        items: list[SessionResponse] = []
        for row in rows:
            s = row.get("s", row) if isinstance(row, dict) else row
            risk_score = float(getattr(s, "risk_score", 0.0) if not isinstance(s, dict) else s.get("risk_score", 0.0))
            agent_id = getattr(s, "agent_id", "") if not isinstance(s, dict) else s.get("agent_id", "")
            sid = getattr(s, "session_id", "") if not isinstance(s, dict) else s.get("session_id", "")
            status = getattr(s, "status", "active") if not isinstance(s, dict) else s.get("status", "active")
            items.append(
                SessionResponse(
                    session_id=str(sid),
                    agent_id=str(agent_id),
                    status=str(status),
                    risk_level=_parse_risk_level(risk_score),
                    risk_score=risk_score,
                )
            )

        return SessionListResponse(
            items=items,
            total=int(total),
            page=page,
            size=size,
        )

    # ------------------------------------------------------------------
    # Timeline
    # ------------------------------------------------------------------

    async def get_session_timeline(self, session_id: str) -> list[TimelineEvent]:
        """Return an ordered timeline of events for a session.

        Parameters
        ----------
        session_id:
            Target session identifier.

        Returns
        -------
        list[TimelineEvent]
            Chronologically ordered events.
        """
        from app.graph import queries  # noqa: WPS433

        logger.debug("get_session_timeline  session_id=%s", session_id)

        try:
            result = await self._neo4j.execute_read(  # type: ignore[attr-defined]
                queries.GET_SESSION_ACTIONS,
                {"session_id": session_id},
            )
            actions = result if isinstance(result, list) else []
        except Exception:
            logger.exception("Failed to get timeline for session %s", session_id)
            return []

        events: list[TimelineEvent] = []
        for act in actions:
            data = act if isinstance(act, dict) else {}
            ts = data.get("timestamp")
            if isinstance(ts, str):
                try:
                    ts = datetime.fromisoformat(ts)
                except (ValueError, TypeError):
                    ts = datetime.now(timezone.utc)
            elif ts is None:
                ts = datetime.now(timezone.utc)

            risk = float(data.get("risk_score", 0.0))
            severity = "info"
            if risk >= 0.7:
                severity = "high"
            elif risk >= 0.3:
                severity = "medium"
            elif risk > 0:
                severity = "low"

            events.append(
                TimelineEvent(
                    timestamp=ts,
                    type=data.get("action_type", "action"),
                    severity=severity,
                    description=f"{data.get('action_type', 'action')}: {data.get('input', '')[:120]}",
                )
            )

        return events

    # ------------------------------------------------------------------
    # Graph summary
    # ------------------------------------------------------------------

    async def get_session_graph_summary(self, session_id: str) -> GraphSummary:
        """Return a lightweight graph summary for a session.

        Parameters
        ----------
        session_id:
            Target session identifier.

        Returns
        -------
        GraphSummary
            Node / edge / cluster counts for the session subgraph.
        """
        from app.graph import queries  # noqa: WPS433

        logger.debug("get_session_graph_summary  session_id=%s", session_id)

        try:
            result = await self._neo4j.execute_read(  # type: ignore[attr-defined]
                queries.GET_SESSION_GRAPH,
                {"session_id": session_id},
            )
        except Exception:
            logger.exception("Failed to get graph summary for session %s", session_id)
            return GraphSummary()

        if not result:
            return GraphSummary()

        actions = result.get("actions", [])
        threats = result.get("threats", [])
        sequences = result.get("sequences", [])

        # Nodes = session (1) + actions + threats
        node_count = 1 + len(actions) + len([t for t in threats if t])
        # Edges = CONTAINS (actions) + TRIGGERED (threats) + FOLLOWED_BY (sequences)
        edge_count = len(actions) + len([t for t in threats if t]) + len([s for s in sequences if s.get("from_action")])
        # Simple cluster estimation: unique action types
        unique_types = set()
        for a in actions:
            if isinstance(a, dict):
                unique_types.add(a.get("action_type", "other"))
        cluster_count = max(1, len(unique_types))

        return GraphSummary(
            nodes=node_count,
            edges=edge_count,
            clusters=cluster_count,
        )
