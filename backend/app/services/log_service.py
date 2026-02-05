"""
Action logging service.

Persists agent actions in the Neo4j graph, runs anomaly detection, and
updates per-session risk scores.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from uuid import uuid4

from app.schemas.log import (
    AnomalyInfo,
    LogActionRequest,
    LogActionResponse,
)
from app.schemas.common import Severity

logger = logging.getLogger("inalign.services.log")


class LogService:
    """Writes action entries to Neo4j and triggers anomaly detection."""

    def __init__(
        self,
        neo4j_session: object,
        anomaly_detector: object,
    ) -> None:
        self._neo4j = neo4j_session
        self._anomaly_detector = anomaly_detector

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def log_action(self, request: LogActionRequest) -> LogActionResponse:
        """Persist an action, run anomaly detection, and return results."""
        request_id = str(uuid4())
        action_id = str(uuid4())
        node_id = ""
        timestamp = request.timestamp or datetime.now(timezone.utc)

        logger.info(
            "log_action  request_id=%s  session=%s  agent=%s  type=%s",
            request_id,
            request.session_id,
            request.agent_id,
            request.action.type,
        )

        # 1) Ensure Session+Agent nodes exist, then create Action ----------
        try:
            from app.graph import queries  # noqa: WPS433

            # Auto-create Agent + Session if they don't exist yet
            await self._neo4j.run(
                queries.CREATE_SESSION,
                {
                    "session_id": request.session_id,
                    "agent_id": request.agent_id,
                    "user_id": "",
                    "status": "active",
                    "risk_score": 0.0,
                    "started_at": timestamp.isoformat(),
                    "metadata": "{}",
                },
            )
            # Also ensure Agent node exists
            await self._neo4j.run(
                queries.CREATE_AGENT,
                {
                    "agent_id": request.agent_id,
                    "name": request.agent_id,
                    "description": "",
                    "owner": "",
                    "metadata": "{}",
                },
            )

            params = {
                "action_id": action_id,
                "session_id": request.session_id,
                "action_type": request.action.type,
                "input": json.dumps(request.action.parameters) if request.action.parameters else "",
                "output": request.action.result_summary or "",
                "risk_score": 0.0,
                "latency_ms": request.action.duration_ms or 0,
                "timestamp": timestamp.isoformat(),
                "metadata": json.dumps({
                    "name": request.action.name,
                    "target": request.action.target,
                }),
            }

            result = await self._neo4j.run(queries.CREATE_ACTION, params)
            records = await result.data()
            if records:
                node_id = records[0].get("action_id", action_id)
            logger.debug("Action %s stored in Neo4j (node_id=%s)", action_id, node_id)
        except Exception:
            logger.exception("Failed to store action %s in Neo4j", action_id)

        # 2) Run anomaly detection ------------------------------------------
        anomalies: list[AnomalyInfo] = []
        alerts_triggered: list[str] = []
        try:
            # AnomalyDetector.detect() is synchronous and expects
            # (action: dict, session_context: dict)
            action_dict = request.action.model_dump()
            session_context: dict = {
                "action_timestamps": [],
                "recent_actions": [],
                "failure_count": 0,
                "privilege_changes": [],
            }
            raw_anomalies = self._anomaly_detector.detect(
                action=action_dict,
                session_context=session_context,
            )
            for a in raw_anomalies:
                anomalies.append(
                    AnomalyInfo(
                        type=a.get("rule_name", a.get("type", "unknown")),
                        severity=Severity(a.get("severity", "medium")),
                        description=a.get("description", ""),
                        score=a.get("score", 0.5),
                    )
                )
            alerts_triggered = [a.get("rule_id", "") for a in raw_anomalies if a.get("rule_id")]
        except Exception:
            logger.exception("Anomaly detection failed for action %s", action_id)

        # 3) Update session risk score ---------------------------------------
        session_risk_score = 0.0
        if anomalies:
            session_risk_score = round(max(a.score for a in anomalies), 4)
            try:
                from app.graph import queries as q  # noqa: WPS433

                await self._neo4j.run(
                    q.UPDATE_SESSION_RISK,
                    {
                        "session_id": request.session_id,
                        "risk_score": session_risk_score,
                    },
                )
                logger.info(
                    "Session %s risk score updated to %.4f",
                    request.session_id,
                    session_risk_score,
                )
            except Exception:
                logger.exception(
                    "Failed to update session risk score for %s",
                    request.session_id,
                )

        anomaly_detected = len(anomalies) > 0

        logger.info(
            "log_action  request_id=%s  action_id=%s  anomalies=%d  alerts=%d",
            request_id,
            action_id,
            len(anomalies),
            len(alerts_triggered),
        )

        return LogActionResponse(
            request_id=request_id,
            logged=True,
            action_id=action_id,
            node_id=node_id or action_id,
            anomaly_detected=anomaly_detected,
            anomalies=anomalies,
            session_risk_score=session_risk_score,
            alerts_triggered=alerts_triggered,
        )
