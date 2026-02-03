"""
Activity monitoring API endpoints.

Provides access to agent activity logs and real-time monitoring.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import func, select, and_
from sqlalchemy.ext.asyncio import AsyncSession

from app.dependencies import get_current_user, get_db
from app.models import Activity, Agent, AgentMetrics, User
from app.schemas.activity import (
    ActivityResponse,
    ActivityListResponse,
    AgentMetricsResponse,
    EfficiencyReport,
)
from app.services.efficiency_service import EfficiencyService

router = APIRouter()


def _activity_to_response(activity: Activity) -> ActivityResponse:
    """Convert Activity model to response schema."""
    return ActivityResponse(
        id=str(activity.id),
        agent_id=activity.agent_id,
        session_id=activity.session_id,
        action_id=activity.action_id,
        activity_type=activity.activity_type,
        name=activity.name,
        target=activity.target,
        input_preview=activity.input_preview,
        output_preview=activity.output_preview,
        duration_ms=activity.duration_ms,
        status=activity.status,
        policy_result=activity.policy_result,
        risk_score=activity.risk_score,
        cost_usd=activity.cost_usd,
        tokens_input=activity.tokens_input,
        tokens_output=activity.tokens_output,
        timestamp=activity.timestamp,
    )


@router.get(
    "",
    response_model=ActivityListResponse,
    summary="List activities",
)
async def list_activities(
    page: int = Query(default=1, ge=1),
    size: int = Query(default=50, ge=1, le=200),
    agent_id: Optional[str] = Query(default=None),
    session_id: Optional[str] = Query(default=None),
    activity_type: Optional[str] = Query(default=None),
    status: Optional[str] = Query(default=None),
    policy_result: Optional[str] = Query(default=None),
    min_risk_score: Optional[float] = Query(default=None, ge=0, le=1),
    start_time: Optional[datetime] = Query(default=None),
    end_time: Optional[datetime] = Query(default=None),
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
) -> ActivityListResponse:
    """List agent activities with filtering."""
    # Get user's agent IDs
    agent_result = await db.execute(
        select(Agent.agent_id).where(Agent.user_id == user.id)
    )
    user_agent_ids = [r[0] for r in agent_result.all()]

    if not user_agent_ids:
        return ActivityListResponse(
            items=[], total=0, page=page, size=size, pages=1
        )

    # Build query
    query = select(Activity).where(Activity.agent_id.in_(user_agent_ids))

    if agent_id:
        if agent_id not in user_agent_ids:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Access denied to this agent",
            )
        query = query.where(Activity.agent_id == agent_id)

    if session_id:
        query = query.where(Activity.session_id == session_id)
    if activity_type:
        query = query.where(Activity.activity_type == activity_type)
    if status:
        query = query.where(Activity.status == status)
    if policy_result:
        query = query.where(Activity.policy_result == policy_result)
    if min_risk_score is not None:
        query = query.where(Activity.risk_score >= min_risk_score)
    if start_time:
        query = query.where(Activity.timestamp >= start_time)
    if end_time:
        query = query.where(Activity.timestamp <= end_time)

    # Get total count
    count_query = select(func.count()).select_from(query.subquery())
    total = (await db.execute(count_query)).scalar() or 0

    # Paginate
    query = query.order_by(Activity.timestamp.desc())
    query = query.offset((page - 1) * size).limit(size)

    result = await db.execute(query)
    activities = result.scalars().all()

    return ActivityListResponse(
        items=[_activity_to_response(a) for a in activities],
        total=total,
        page=page,
        size=size,
        pages=(total + size - 1) // size if total > 0 else 1,
    )


@router.get(
    "/{action_id}",
    response_model=ActivityResponse,
    summary="Get activity details",
)
async def get_activity(
    action_id: str,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
) -> ActivityResponse:
    """Get details of a specific activity."""
    # Get user's agent IDs
    agent_result = await db.execute(
        select(Agent.agent_id).where(Agent.user_id == user.id)
    )
    user_agent_ids = [r[0] for r in agent_result.all()]

    result = await db.execute(
        select(Activity).where(
            Activity.action_id == action_id,
            Activity.agent_id.in_(user_agent_ids),
        )
    )
    activity = result.scalar_one_or_none()

    if not activity:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Activity '{action_id}' not found",
        )

    return _activity_to_response(activity)


@router.get(
    "/metrics/{agent_id}",
    response_model=list[AgentMetricsResponse],
    summary="Get agent metrics",
)
async def get_agent_metrics(
    agent_id: str,
    period_type: str = Query(default="hourly", description="hourly, daily, weekly"),
    start_time: Optional[datetime] = Query(default=None),
    end_time: Optional[datetime] = Query(default=None),
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
) -> list[AgentMetricsResponse]:
    """Get aggregated metrics for an agent."""
    # Verify agent belongs to user
    agent_result = await db.execute(
        select(Agent).where(
            Agent.agent_id == agent_id,
            Agent.user_id == user.id,
        )
    )
    if not agent_result.scalar_one_or_none():
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Agent '{agent_id}' not found",
        )

    # Default time range
    if not end_time:
        end_time = datetime.now(timezone.utc)
    if not start_time:
        if period_type == "hourly":
            start_time = end_time - timedelta(hours=24)
        elif period_type == "daily":
            start_time = end_time - timedelta(days=30)
        else:
            start_time = end_time - timedelta(weeks=12)

    query = select(AgentMetrics).where(
        AgentMetrics.agent_id == agent_id,
        AgentMetrics.period_type == period_type,
        AgentMetrics.period_start >= start_time,
        AgentMetrics.period_end <= end_time,
    ).order_by(AgentMetrics.period_start.asc())

    result = await db.execute(query)
    metrics = result.scalars().all()

    return [
        AgentMetricsResponse(
            agent_id=m.agent_id,
            period_type=m.period_type,
            period_start=m.period_start,
            period_end=m.period_end,
            total_actions=m.total_actions,
            successful_actions=m.successful_actions,
            failed_actions=m.failed_actions,
            blocked_actions=m.blocked_actions,
            tool_calls=m.tool_calls,
            api_calls=m.api_calls,
            llm_calls=m.llm_calls,
            file_accesses=m.file_accesses,
            total_duration_ms=m.total_duration_ms,
            avg_duration_ms=m.avg_duration_ms,
            p95_duration_ms=m.p95_duration_ms,
            total_cost_usd=m.total_cost_usd,
            total_tokens=m.total_tokens,
            threats_detected=m.threats_detected,
            policy_violations=m.policy_violations,
            avg_risk_score=m.avg_risk_score,
            unique_sessions=m.unique_sessions,
            efficiency_score=m.efficiency_score,
            redundancy_ratio=m.redundancy_ratio,
        )
        for m in metrics
    ]


@router.get(
    "/efficiency/{agent_id}",
    response_model=EfficiencyReport,
    summary="Get efficiency analysis",
)
async def get_efficiency_report(
    agent_id: str,
    days: int = Query(default=7, ge=1, le=90),
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
) -> EfficiencyReport:
    """Get an efficiency analysis report for an agent."""
    # Verify agent belongs to user
    agent_result = await db.execute(
        select(Agent).where(
            Agent.agent_id == agent_id,
            Agent.user_id == user.id,
        )
    )
    if not agent_result.scalar_one_or_none():
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Agent '{agent_id}' not found",
        )

    efficiency_service = EfficiencyService(db)
    report = await efficiency_service.analyze_agent(agent_id, days=days)

    return report
