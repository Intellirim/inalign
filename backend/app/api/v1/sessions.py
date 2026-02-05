"""
Session endpoints.

Provides list and detail views for monitored agent sessions stored in
the Neo4j graph.
"""

from __future__ import annotations

import logging
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Query, status

from app.dependencies import CurrentUser, Neo4jSession
from app.schemas.session import SessionListResponse, SessionResponse
from app.services.session_service import SessionService

logger = logging.getLogger("inalign.api.sessions")

router = APIRouter()


# --------------------------------------------------------------------------
# GET /
# --------------------------------------------------------------------------


@router.get(
    "/",
    response_model=SessionListResponse,
    status_code=status.HTTP_200_OK,
    summary="List sessions",
    description=(
        "Return a filtered, paginated list of monitored agent sessions. "
        "Supports filtering by status, risk level, agent ID, and date range."
    ),
)
async def list_sessions(
    current_user: CurrentUser,
    neo4j_session: Neo4jSession,
    session_status: str | None = Query(
        default=None, alias="status", description="Filter by session status"
    ),
    risk_level: str | None = Query(
        default=None, description="Filter by risk level (critical/high/medium/low/none)"
    ),
    agent_id: str | None = Query(default=None, description="Filter by agent ID"),
    date_from: datetime | None = Query(default=None, description="Start date (ISO 8601)"),
    date_to: datetime | None = Query(default=None, description="End date (ISO 8601)"),
    page: int = Query(default=1, ge=1, description="Page number"),
    size: int = Query(default=20, ge=1, le=100, description="Page size"),
) -> SessionListResponse:
    """List sessions with optional filtering."""
    logger.info(
        "GET /sessions  user=%s  status=%s  risk=%s  agent=%s  page=%d",
        current_user["user_id"],
        session_status,
        risk_level,
        agent_id,
        page,
    )

    filters: dict[str, object] = {}
    if session_status:
        filters["status"] = session_status
    if risk_level:
        filters["risk_level"] = risk_level
    if agent_id:
        filters["agent_id"] = agent_id
    if date_from:
        filters["date_from"] = date_from.isoformat()
    if date_to:
        filters["date_to"] = date_to.isoformat()

    service = SessionService(neo4j_client=neo4j_session)

    try:
        result = await service.list_sessions(filters=filters, page=page, size=size)
    except Exception as exc:
        logger.exception("Failed to list sessions")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to list sessions: {exc}",
        ) from exc

    return result


# --------------------------------------------------------------------------
# GET /{session_id}
# --------------------------------------------------------------------------


@router.get(
    "/{session_id}",
    response_model=SessionResponse,
    status_code=status.HTTP_200_OK,
    summary="Get session details",
    description=(
        "Retrieve detailed information for a single session including "
        "statistics, timeline, and graph summary."
    ),
)
async def get_session(
    session_id: str,
    current_user: CurrentUser,
    neo4j_session: Neo4jSession,
) -> SessionResponse:
    """Return full session details by session ID."""
    logger.info(
        "GET /sessions/%s  user=%s",
        session_id,
        current_user["user_id"],
    )

    service = SessionService(neo4j_client=neo4j_session)

    try:
        result = await service.get_session(session_id)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(exc),
        ) from exc
    except Exception as exc:
        logger.exception("Failed to get session %s", session_id)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to retrieve session: {exc}",
        ) from exc

    return result
