"""
Activity Service - Logs and manages agent activities.

Handles logging of all agent actions for monitoring and analysis.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any, Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import Activity


class ActivityService:
    """Service for logging and querying agent activities."""

    def __init__(self, db: AsyncSession):
        self.db = db

    async def log_activity(
        self,
        agent_id: str,
        session_id: str,
        action_id: str,
        activity_type: str,
        name: str,
        target: str = "",
        input_preview: str = "",
        output_preview: str = "",
        input_size: int = 0,
        output_size: int = 0,
        parameters: dict[str, Any] | None = None,
        duration_ms: int = 0,
        status: str = "pending",
        policy_result: str = "allowed",
        policy_id: Optional[uuid.UUID] = None,
        violation_reason: str = "",
        risk_score: float = 0.0,
        risk_factors: dict[str, Any] | None = None,
        cost_usd: float = 0.0,
        tokens_input: int = 0,
        tokens_output: int = 0,
        parent_action_id: Optional[str] = None,
        sequence_number: int = 0,
        metadata: dict[str, Any] | None = None,
    ) -> Activity:
        """Log a new activity.

        Args:
            agent_id: The agent performing the action.
            session_id: Current session ID.
            action_id: Unique ID for this action.
            activity_type: Type (tool_call, api_call, etc.).
            name: Action name.
            target: Target resource.
            input_preview: Truncated input for display.
            output_preview: Truncated output for display.
            input_size: Full input size in bytes.
            output_size: Full output size in bytes.
            parameters: Action parameters.
            duration_ms: Execution time.
            status: Result status.
            policy_result: Policy evaluation result.
            policy_id: ID of matched policy (if any).
            violation_reason: Reason for denial (if any).
            risk_score: Computed risk score.
            risk_factors: Risk factor details.
            cost_usd: LLM cost.
            tokens_input: Input tokens used.
            tokens_output: Output tokens generated.
            parent_action_id: Parent action for nested calls.
            sequence_number: Order within session.
            metadata: Additional metadata.

        Returns:
            The created Activity record.
        """
        activity = Activity(
            agent_id=agent_id,
            session_id=session_id,
            action_id=action_id,
            activity_type=activity_type,
            name=name,
            target=target,
            input_preview=input_preview[:2000] if input_preview else "",
            output_preview=output_preview[:2000] if output_preview else "",
            input_size=input_size,
            output_size=output_size,
            parameters=parameters or {},
            duration_ms=duration_ms,
            status=status,
            policy_result=policy_result,
            policy_id=policy_id,
            violation_reason=violation_reason,
            risk_score=risk_score,
            risk_factors=risk_factors or {},
            cost_usd=cost_usd,
            tokens_input=tokens_input,
            tokens_output=tokens_output,
            parent_action_id=parent_action_id,
            sequence_number=sequence_number,
            metadata=metadata or {},
            timestamp=datetime.now(timezone.utc),
        )

        self.db.add(activity)
        await self.db.flush()

        return activity

    async def update_activity(
        self,
        action_id: str,
        **updates: Any,
    ) -> Optional[Activity]:
        """Update an existing activity.

        Args:
            action_id: The action ID to update.
            **updates: Fields to update.

        Returns:
            Updated Activity or None if not found.
        """
        result = await self.db.execute(
            select(Activity).where(Activity.action_id == action_id)
        )
        activity = result.scalar_one_or_none()

        if not activity:
            return None

        for key, value in updates.items():
            if hasattr(activity, key):
                setattr(activity, key, value)

        await self.db.flush()
        return activity

    async def get_activity(self, action_id: str) -> Optional[Activity]:
        """Get an activity by action_id."""
        result = await self.db.execute(
            select(Activity).where(Activity.action_id == action_id)
        )
        return result.scalar_one_or_none()

    async def get_session_activities(
        self,
        session_id: str,
        limit: int = 100,
    ) -> list[Activity]:
        """Get all activities for a session."""
        result = await self.db.execute(
            select(Activity)
            .where(Activity.session_id == session_id)
            .order_by(Activity.sequence_number.asc())
            .limit(limit)
        )
        return list(result.scalars().all())

    async def get_session_context(
        self,
        session_id: str,
    ) -> dict[str, Any]:
        """Get running totals for a session (for policy evaluation)."""
        activities = await self.get_session_activities(session_id)

        context = {
            "actions_this_session": len(activities),
            "api_calls_this_session": 0,
            "file_reads_this_session": 0,
            "llm_calls_this_session": 0,
            "cost_this_session_usd": 0.0,
            "tokens_this_session": 0,
            "blocked_actions": 0,
        }

        for activity in activities:
            if activity.activity_type == "api_call":
                context["api_calls_this_session"] += 1
            elif activity.activity_type == "file_access":
                context["file_reads_this_session"] += 1
            elif activity.activity_type == "llm_call":
                context["llm_calls_this_session"] += 1

            context["cost_this_session_usd"] += activity.cost_usd
            context["tokens_this_session"] += activity.tokens_input + activity.tokens_output

            if activity.status == "blocked":
                context["blocked_actions"] += 1

        return context
