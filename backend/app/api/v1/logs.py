"""
Logging endpoints.

Records agent actions in the Neo4j graph and returns anomaly detection
results.
"""

from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, HTTPException, status

from app.dependencies import CurrentUser, Neo4jSession
from app.schemas.log import LogActionRequest, LogActionResponse

logger = logging.getLogger("agentshield.api.logs")

router = APIRouter()


# --------------------------------------------------------------------------
# POST /action
# --------------------------------------------------------------------------


@router.post(
    "/action",
    response_model=LogActionResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Log an agent action",
    description=(
        "Persist an agent action in the Neo4j behaviour graph, run anomaly "
        "detection, and return any triggered alerts."
    ),
)
async def log_action(
    body: LogActionRequest,
    current_user: CurrentUser,
    neo4j_session: Neo4jSession,
) -> LogActionResponse:
    """Log an agent action and run anomaly detection."""
    logger.info(
        "POST /logs/action  user=%s  session=%s  agent=%s  type=%s",
        current_user["user_id"],
        body.session_id,
        body.agent_id,
        body.action.type,
    )

    from app.detectors import AnomalyDetector  # noqa: WPS433
    from app.services.log_service import LogService  # noqa: WPS433

    service = LogService(
        neo4j_client=neo4j_session,
        anomaly_detector=AnomalyDetector(),
    )

    try:
        result = await service.log_action(body)
    except Exception as exc:
        logger.exception("log_action failed")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Action logging failed: {exc}",
        ) from exc

    return result


# --------------------------------------------------------------------------
# GET /{agent_id}
# --------------------------------------------------------------------------


@router.get(
    "/{agent_id}",
    response_model=list[dict],
    status_code=status.HTTP_200_OK,
    summary="List agent actions",
    description="Retrieve all logged actions for the specified agent from the graph database.",
)
async def list_agent_actions(
    agent_id: str,
    current_user: CurrentUser,
    neo4j_session: Neo4jSession,
) -> list[dict]:
    """Return actions for a specific agent."""
    logger.info(
        "GET /logs/%s  user=%s",
        agent_id,
        current_user["user_id"],
    )

    from app.graph import queries  # noqa: WPS433

    try:
        result = await neo4j_session.run(
            queries.GET_AGENT_SESSIONS,
            {"agent_id": agent_id, "limit": 100},
        )
        records = await result.data()

        # Flatten: for each session, fetch its actions
        actions: list[dict] = []
        for record in records:
            session_node = record.get("s", {})
            sid = (
                session_node.get("session_id", "")
                if isinstance(session_node, dict)
                else getattr(session_node, "session_id", "")
            )
            if not sid:
                continue

            act_result = await neo4j_session.run(
                queries.GET_SESSION_ACTIONS,
                {"session_id": sid},
            )
            act_records = await act_result.data()
            for act_rec in act_records:
                act_node = act_rec.get("act", act_rec)
                actions.append(
                    {
                        "action_id": act_node.get("action_id", ""),
                        "session_id": sid,
                        "action_type": act_node.get("action_type", ""),
                        "timestamp": str(act_node.get("timestamp", "")),
                        "risk_score": act_node.get("risk_score", 0.0),
                    }
                )

        return actions

    except Exception as exc:
        logger.exception("Failed to list actions for agent %s", agent_id)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to retrieve actions: {exc}",
        ) from exc
