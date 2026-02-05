"""
Agent management API endpoints.

Provides CRUD operations for AI agents registered in InALign.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.dependencies import get_current_user, get_db
from app.models import Agent, User, Activity, PolicyViolation
from app.schemas.agent import (
    AgentCreate,
    AgentUpdate,
    AgentResponse,
    AgentListResponse,
    AgentStatsResponse,
)

router = APIRouter()


def _agent_to_response(agent: Agent) -> AgentResponse:
    """Convert Agent model to response schema."""
    return AgentResponse(
        id=str(agent.id),
        agent_id=agent.agent_id,
        name=agent.name,
        description=agent.description,
        framework=agent.framework,
        status=agent.status,
        config=agent.config,
        created_at=agent.created_at,
        updated_at=agent.updated_at,
        last_active_at=agent.last_active_at,
    )


@router.post(
    "",
    response_model=AgentResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Register a new agent",
)
async def create_agent(
    body: AgentCreate,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
) -> AgentResponse:
    """Register a new AI agent.

    The agent_id must be unique within your account.
    """
    # Check for duplicate agent_id
    existing = await db.execute(
        select(Agent).where(
            Agent.agent_id == body.agent_id,
            Agent.user_id == user.id,
        )
    )
    if existing.scalar_one_or_none():
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Agent with ID '{body.agent_id}' already exists",
        )

    agent = Agent(
        agent_id=body.agent_id,
        user_id=user.id,
        name=body.name,
        description=body.description,
        framework=body.framework,
        config=body.config,
        status="active",
    )
    db.add(agent)
    await db.flush()
    await db.refresh(agent)

    return _agent_to_response(agent)


@router.get(
    "",
    response_model=AgentListResponse,
    summary="List all agents",
)
async def list_agents(
    page: int = Query(default=1, ge=1),
    size: int = Query(default=20, ge=1, le=100),
    status: Optional[str] = Query(default=None),
    framework: Optional[str] = Query(default=None),
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
) -> AgentListResponse:
    """List all agents registered by the current user."""
    query = select(Agent).where(Agent.user_id == user.id)

    if status:
        query = query.where(Agent.status == status)
    if framework:
        query = query.where(Agent.framework == framework)

    # Get total count
    count_query = select(func.count()).select_from(query.subquery())
    total = (await db.execute(count_query)).scalar() or 0

    # Paginate
    query = query.order_by(Agent.created_at.desc())
    query = query.offset((page - 1) * size).limit(size)

    result = await db.execute(query)
    agents = result.scalars().all()

    return AgentListResponse(
        items=[_agent_to_response(a) for a in agents],
        total=total,
        page=page,
        size=size,
        pages=(total + size - 1) // size if total > 0 else 1,
    )


@router.get(
    "/{agent_id}",
    response_model=AgentResponse,
    summary="Get agent details",
)
async def get_agent(
    agent_id: str,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
) -> AgentResponse:
    """Get details of a specific agent."""
    result = await db.execute(
        select(Agent).where(
            Agent.agent_id == agent_id,
            Agent.user_id == user.id,
        )
    )
    agent = result.scalar_one_or_none()

    if not agent:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Agent '{agent_id}' not found",
        )

    return _agent_to_response(agent)


@router.patch(
    "/{agent_id}",
    response_model=AgentResponse,
    summary="Update agent",
)
async def update_agent(
    agent_id: str,
    body: AgentUpdate,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
) -> AgentResponse:
    """Update an agent's configuration."""
    result = await db.execute(
        select(Agent).where(
            Agent.agent_id == agent_id,
            Agent.user_id == user.id,
        )
    )
    agent = result.scalar_one_or_none()

    if not agent:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Agent '{agent_id}' not found",
        )

    # Update fields
    if body.name is not None:
        agent.name = body.name
    if body.description is not None:
        agent.description = body.description
    if body.framework is not None:
        agent.framework = body.framework
    if body.status is not None:
        if body.status not in ("active", "paused", "disabled"):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Status must be 'active', 'paused', or 'disabled'",
            )
        agent.status = body.status
    if body.config is not None:
        agent.config = body.config

    await db.flush()
    await db.refresh(agent)

    return _agent_to_response(agent)


@router.delete(
    "/{agent_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Delete agent",
)
async def delete_agent(
    agent_id: str,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
) -> None:
    """Delete an agent and all associated data."""
    result = await db.execute(
        select(Agent).where(
            Agent.agent_id == agent_id,
            Agent.user_id == user.id,
        )
    )
    agent = result.scalar_one_or_none()

    if not agent:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Agent '{agent_id}' not found",
        )

    await db.delete(agent)


@router.get(
    "/{agent_id}/stats",
    response_model=AgentStatsResponse,
    summary="Get agent statistics",
)
async def get_agent_stats(
    agent_id: str,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
) -> AgentStatsResponse:
    """Get statistics for a specific agent."""
    # Verify agent exists
    result = await db.execute(
        select(Agent).where(
            Agent.agent_id == agent_id,
            Agent.user_id == user.id,
        )
    )
    agent = result.scalar_one_or_none()

    if not agent:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Agent '{agent_id}' not found",
        )

    # Get activity stats
    activity_stats = await db.execute(
        select(
            func.count(Activity.id).label("total_actions"),
            func.count(func.distinct(Activity.session_id)).label("total_sessions"),
            func.avg(Activity.risk_score).label("avg_risk_score"),
            func.sum(Activity.cost_usd).label("total_cost_usd"),
            func.max(Activity.timestamp).label("last_active"),
        ).where(Activity.agent_id == agent_id)
    )
    stats = activity_stats.first()

    # Get threat count (from activities with high risk)
    threat_count = await db.execute(
        select(func.count(Activity.id)).where(
            Activity.agent_id == agent_id,
            Activity.risk_score >= 0.7,
        )
    )
    total_threats = threat_count.scalar() or 0

    # Get policy violation count
    violation_count = await db.execute(
        select(func.count(PolicyViolation.id)).where(
            PolicyViolation.agent_id == agent_id,
        )
    )
    policy_violations = violation_count.scalar() or 0

    return AgentStatsResponse(
        agent_id=agent_id,
        total_sessions=stats.total_sessions or 0 if stats else 0,
        total_actions=stats.total_actions or 0 if stats else 0,
        total_threats=total_threats,
        policy_violations=policy_violations,
        avg_risk_score=float(stats.avg_risk_score or 0) if stats else 0.0,
        total_cost_usd=float(stats.total_cost_usd or 0) if stats else 0.0,
        efficiency_score=0.0,  # Calculated separately
        last_active_at=stats.last_active if stats else None,
    )
