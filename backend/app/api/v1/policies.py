"""
Policy management API endpoints.

Provides CRUD operations for agent policies and policy evaluation.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.dependencies import get_current_user, get_db
from app.models import Agent, Policy, PolicyViolation, User
from app.schemas.policy import (
    PolicyCreate,
    PolicyUpdate,
    PolicyResponse,
    PolicyListResponse,
    PolicyEvalRequest,
    PolicyEvalResponse,
    PolicyViolationResponse,
    DEFAULT_POLICY_RULES,
)

router = APIRouter()


def _policy_to_response(policy: Policy) -> PolicyResponse:
    """Convert Policy model to response schema."""
    return PolicyResponse(
        id=str(policy.id),
        name=policy.name,
        description=policy.description,
        agent_id=policy.agent.agent_id if policy.agent else None,
        user_id=str(policy.user_id),
        priority=policy.priority,
        enabled=policy.enabled,
        policy_type=policy.policy_type,
        rules=policy.rules,
        version=policy.version,
        violation_count=policy.violation_count,
        created_at=policy.created_at,
        updated_at=policy.updated_at,
        last_evaluated_at=policy.last_evaluated_at,
    )


@router.post(
    "",
    response_model=PolicyResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create a new policy",
)
async def create_policy(
    body: PolicyCreate,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
) -> PolicyResponse:
    """Create a new policy for an agent or globally."""
    agent_db_id = None

    if body.agent_id:
        # Verify agent exists and belongs to user
        result = await db.execute(
            select(Agent).where(
                Agent.agent_id == body.agent_id,
                Agent.user_id == user.id,
            )
        )
        agent = result.scalar_one_or_none()
        if not agent:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Agent '{body.agent_id}' not found",
            )
        agent_db_id = agent.id

    policy = Policy(
        name=body.name,
        description=body.description,
        agent_id=agent_db_id,
        user_id=user.id,
        priority=body.priority,
        policy_type="custom",
        rules=body.rules.model_dump() if body.rules else DEFAULT_POLICY_RULES,
    )
    db.add(policy)
    await db.flush()
    await db.refresh(policy)

    return _policy_to_response(policy)


@router.get(
    "",
    response_model=PolicyListResponse,
    summary="List all policies",
)
async def list_policies(
    page: int = Query(default=1, ge=1),
    size: int = Query(default=20, ge=1, le=100),
    agent_id: Optional[str] = Query(default=None),
    enabled: Optional[bool] = Query(default=None),
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
) -> PolicyListResponse:
    """List all policies for the current user."""
    query = select(Policy).where(Policy.user_id == user.id)

    if agent_id:
        # Find agent's internal ID
        agent_result = await db.execute(
            select(Agent.id).where(
                Agent.agent_id == agent_id,
                Agent.user_id == user.id,
            )
        )
        agent_db_id = agent_result.scalar_one_or_none()
        if agent_db_id:
            query = query.where(Policy.agent_id == agent_db_id)
        else:
            # No matching agent, return empty
            return PolicyListResponse(
                items=[], total=0, page=page, size=size, pages=1
            )

    if enabled is not None:
        query = query.where(Policy.enabled == enabled)

    # Get total count
    count_query = select(func.count()).select_from(query.subquery())
    total = (await db.execute(count_query)).scalar() or 0

    # Paginate
    query = query.order_by(Policy.priority.asc(), Policy.created_at.desc())
    query = query.offset((page - 1) * size).limit(size)

    result = await db.execute(query)
    policies = result.scalars().all()

    return PolicyListResponse(
        items=[_policy_to_response(p) for p in policies],
        total=total,
        page=page,
        size=size,
        pages=(total + size - 1) // size if total > 0 else 1,
    )


@router.get(
    "/{policy_id}",
    response_model=PolicyResponse,
    summary="Get policy details",
)
async def get_policy(
    policy_id: str,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
) -> PolicyResponse:
    """Get details of a specific policy."""
    try:
        policy_uuid = uuid.UUID(policy_id)
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid policy ID format",
        )

    result = await db.execute(
        select(Policy).where(
            Policy.id == policy_uuid,
            Policy.user_id == user.id,
        )
    )
    policy = result.scalar_one_or_none()

    if not policy:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Policy '{policy_id}' not found",
        )

    return _policy_to_response(policy)


@router.patch(
    "/{policy_id}",
    response_model=PolicyResponse,
    summary="Update policy",
)
async def update_policy(
    policy_id: str,
    body: PolicyUpdate,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
) -> PolicyResponse:
    """Update a policy."""
    try:
        policy_uuid = uuid.UUID(policy_id)
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid policy ID format",
        )

    result = await db.execute(
        select(Policy).where(
            Policy.id == policy_uuid,
            Policy.user_id == user.id,
        )
    )
    policy = result.scalar_one_or_none()

    if not policy:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Policy '{policy_id}' not found",
        )

    # Update fields
    if body.name is not None:
        policy.name = body.name
    if body.description is not None:
        policy.description = body.description
    if body.priority is not None:
        policy.priority = body.priority
    if body.enabled is not None:
        policy.enabled = body.enabled
    if body.rules is not None:
        policy.rules = body.rules.model_dump()
        policy.version += 1

    await db.flush()
    await db.refresh(policy)

    return _policy_to_response(policy)


@router.delete(
    "/{policy_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Delete policy",
)
async def delete_policy(
    policy_id: str,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
) -> None:
    """Delete a policy."""
    try:
        policy_uuid = uuid.UUID(policy_id)
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid policy ID format",
        )

    result = await db.execute(
        select(Policy).where(
            Policy.id == policy_uuid,
            Policy.user_id == user.id,
        )
    )
    policy = result.scalar_one_or_none()

    if not policy:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Policy '{policy_id}' not found",
        )

    if policy.policy_type == "builtin":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot delete built-in policies",
        )

    await db.delete(policy)


@router.get(
    "/{policy_id}/violations",
    response_model=list[PolicyViolationResponse],
    summary="Get policy violations",
)
async def get_policy_violations(
    policy_id: str,
    page: int = Query(default=1, ge=1),
    size: int = Query(default=20, ge=1, le=100),
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
) -> list[PolicyViolationResponse]:
    """Get violations for a specific policy."""
    try:
        policy_uuid = uuid.UUID(policy_id)
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid policy ID format",
        )

    # Verify policy belongs to user
    policy_result = await db.execute(
        select(Policy).where(
            Policy.id == policy_uuid,
            Policy.user_id == user.id,
        )
    )
    policy = policy_result.scalar_one_or_none()
    if not policy:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Policy '{policy_id}' not found",
        )

    # Get violations
    query = select(PolicyViolation).where(PolicyViolation.policy_id == policy_uuid)
    query = query.order_by(PolicyViolation.created_at.desc())
    query = query.offset((page - 1) * size).limit(size)

    result = await db.execute(query)
    violations = result.scalars().all()

    return [
        PolicyViolationResponse(
            id=str(v.id),
            policy_id=str(v.policy_id),
            policy_name=policy.name,
            agent_id=v.agent_id,
            session_id=v.session_id,
            action_id=v.action_id,
            violation_type=v.violation_type,
            severity=v.severity,
            attempted_action=v.attempted_action,
            violated_rule=v.violated_rule,
            action_taken=v.action_taken,
            notes=v.notes,
            created_at=v.created_at,
        )
        for v in violations
    ]


@router.get(
    "/templates/default",
    response_model=dict,
    summary="Get default policy template",
)
async def get_default_policy_template() -> dict:
    """Get the default policy rules template."""
    return DEFAULT_POLICY_RULES
