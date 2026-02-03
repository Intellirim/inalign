"""
Agent Proxy API endpoints.

Intercepts and evaluates all agent actions before execution.
This is the core of the Agent Governance system.
"""

from __future__ import annotations

import time
import uuid
from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.dependencies import get_api_key_user, get_db
from app.models import Agent, User, Activity
from app.schemas.proxy import (
    ProxyRequest,
    ProxyResponse,
    ConfirmationRequest,
    ConfirmationResponse,
)
from app.services.policy_engine import PolicyEngine
from app.services.activity_service import ActivityService

router = APIRouter()


@router.post(
    "/evaluate",
    response_model=ProxyResponse,
    summary="Evaluate an action before execution",
)
async def evaluate_action(
    body: ProxyRequest,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_api_key_user),
) -> ProxyResponse:
    """Evaluate an agent action against policies before execution.

    This endpoint should be called by the SDK before every:
    - Tool call
    - API request
    - File access
    - LLM call
    - Memory operation
    - Code execution

    Returns whether the action is allowed, blocked, warned, or requires confirmation.
    """
    start_time = time.perf_counter()
    request_id = str(uuid.uuid4())

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

    if agent.status != "active":
        return ProxyResponse(
            request_id=request_id,
            action_id=body.action_id,
            allowed=False,
            action="block",
            reason=f"Agent is {agent.status}",
            evaluation_ms=(time.perf_counter() - start_time) * 1000,
        )

    # Build action context
    action_context = _build_action_context(body)

    # Evaluate against policies
    policy_engine = PolicyEngine(db)
    eval_result = await policy_engine.evaluate(
        user_id=user.id,
        agent_id=body.agent_id,
        session_id=body.session_id,
        action_type=body.action_type,
        action_name=action_context.get("name", ""),
        target=action_context.get("target", ""),
        parameters=action_context.get("parameters", {}),
        session_context=body.session_context,
    )

    # Log the activity
    activity_service = ActivityService(db)
    await activity_service.log_activity(
        agent_id=body.agent_id,
        session_id=body.session_id,
        action_id=body.action_id,
        activity_type=body.action_type,
        name=action_context.get("name", ""),
        target=action_context.get("target", ""),
        input_preview=action_context.get("input_preview", "")[:1000],
        parameters=action_context.get("parameters", {}),
        status="pending" if eval_result["action"] == "require_confirmation" else (
            "blocked" if not eval_result["allowed"] else "pending"
        ),
        policy_result=eval_result["action"],
        policy_id=eval_result.get("policy_id"),
        violation_reason=eval_result.get("reason", ""),
        risk_score=eval_result.get("risk_score", 0.0),
        parent_action_id=body.parent_action_id,
        sequence_number=body.sequence_number,
    )

    # Update agent last_active
    agent.last_active_at = datetime.now(timezone.utc)

    evaluation_ms = (time.perf_counter() - start_time) * 1000

    return ProxyResponse(
        request_id=request_id,
        action_id=body.action_id,
        allowed=eval_result["allowed"],
        action=eval_result["action"],
        reason=eval_result.get("reason", ""),
        policy_id=eval_result.get("policy_id"),
        policy_name=eval_result.get("policy_name"),
        modified_request=eval_result.get("modified_request"),
        confirmation_id=eval_result.get("confirmation_id"),
        confirmation_message=eval_result.get("confirmation_message"),
        risk_score=eval_result.get("risk_score", 0.0),
        risk_factors=eval_result.get("risk_factors", []),
        evaluation_ms=evaluation_ms,
    )


@router.post(
    "/complete",
    response_model=dict,
    summary="Report action completion",
)
async def complete_action(
    agent_id: str,
    session_id: str,
    action_id: str,
    status: str,  # success, failure, timeout
    duration_ms: int = 0,
    output_preview: str = "",
    output_size: int = 0,
    cost_usd: float = 0.0,
    tokens_input: int = 0,
    tokens_output: int = 0,
    error: str = "",
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_api_key_user),
) -> dict:
    """Report that an action has completed.

    Called by SDK after action execution to record results.
    """
    # Update activity record
    result = await db.execute(
        select(Activity).where(Activity.action_id == action_id)
    )
    activity = result.scalar_one_or_none()

    if activity:
        activity.status = status
        activity.duration_ms = duration_ms
        activity.output_preview = output_preview[:1000] if output_preview else ""
        activity.output_size = output_size
        activity.cost_usd = cost_usd
        activity.tokens_input = tokens_input
        activity.tokens_output = tokens_output
        if error:
            activity.metadata = {**activity.metadata, "error": error}

    return {"status": "recorded", "action_id": action_id}


@router.post(
    "/confirm/{confirmation_id}",
    response_model=ProxyResponse,
    summary="Respond to confirmation request",
)
async def respond_to_confirmation(
    confirmation_id: str,
    body: ConfirmationResponse,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_api_key_user),
) -> ProxyResponse:
    """Approve or reject a pending confirmation request."""
    # Find the pending activity
    result = await db.execute(
        select(Activity).where(
            Activity.metadata["confirmation_id"].astext == confirmation_id,
            Activity.status == "pending",
        )
    )
    activity = result.scalar_one_or_none()

    if not activity:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Confirmation '{confirmation_id}' not found or already processed",
        )

    # Update activity based on response
    if body.approved:
        activity.status = "approved"
        activity.policy_result = "allowed"
    else:
        activity.status = "rejected"
        activity.policy_result = "denied"

    activity.metadata = {
        **activity.metadata,
        "confirmation_response": {
            "approved": body.approved,
            "note": body.note,
            "responded_by": body.responded_by,
            "responded_at": datetime.now(timezone.utc).isoformat(),
        },
    }

    return ProxyResponse(
        request_id=str(uuid.uuid4()),
        action_id=activity.action_id,
        allowed=body.approved,
        action="allow" if body.approved else "block",
        reason="" if body.approved else f"Rejected by {body.responded_by}: {body.note}",
        evaluation_ms=0.0,
    )


def _build_action_context(body: ProxyRequest) -> dict[str, Any]:
    """Extract action context from proxy request."""
    context: dict[str, Any] = {
        "name": "",
        "target": "",
        "parameters": {},
        "input_preview": "",
    }

    if body.action_type == "tool_call" and body.tool_call:
        context["name"] = body.tool_call.tool_name
        context["parameters"] = body.tool_call.arguments
        context["input_preview"] = str(body.tool_call.arguments)[:500]
        context["target"] = body.tool_call.tool_name

    elif body.action_type == "api_call" and body.api_call:
        context["name"] = f"{body.api_call.method} {body.api_call.url}"
        context["target"] = body.api_call.url
        context["parameters"] = {
            "method": body.api_call.method,
            "headers": body.api_call.headers,
        }
        context["input_preview"] = str(body.api_call.body)[:500] if body.api_call.body else ""

    elif body.action_type == "file_access" and body.file_access:
        context["name"] = f"{body.file_access.operation} {body.file_access.path}"
        context["target"] = body.file_access.path
        context["parameters"] = {"operation": body.file_access.operation}
        context["input_preview"] = body.file_access.content[:500] if body.file_access.content else ""

    elif body.action_type == "llm_call" and body.llm_call:
        context["name"] = f"LLM: {body.llm_call.model}"
        context["target"] = body.llm_call.model
        context["parameters"] = {
            "model": body.llm_call.model,
            "temperature": body.llm_call.temperature,
            "max_tokens": body.llm_call.max_tokens,
            "tools": [t.get("name", "") for t in body.llm_call.tools],
        }
        if body.llm_call.messages:
            last_msg = body.llm_call.messages[-1]
            context["input_preview"] = str(last_msg.get("content", ""))[:500]

    else:
        # Generic fallback
        context["parameters"] = body.action_data
        context["input_preview"] = str(body.action_data)[:500]

    return context
