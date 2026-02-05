"""
Policy Engine - Core policy evaluation system.

Evaluates agent actions against defined policies to determine
if they should be allowed, blocked, warned, or require confirmation.
"""

from __future__ import annotations

import asyncio
import fnmatch
import logging
import re
import uuid
from datetime import datetime, timezone
from typing import Any, Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import Agent, Policy, PolicyViolation


logger = logging.getLogger("inalign.policy_engine")


class PolicyEngine:
    """Evaluates agent actions against policies.

    The evaluation follows this order:
    1. Check agent-specific policies (by priority)
    2. Check global user policies (by priority)
    3. Apply built-in default rules

    A denial always takes precedence over a permission.
    """

    def __init__(self, db: AsyncSession):
        self.db = db

    async def evaluate(
        self,
        user_id: uuid.UUID,
        agent_id: str,
        session_id: str,
        action_type: str,
        action_name: str,
        target: str = "",
        parameters: dict[str, Any] | None = None,
        session_context: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Evaluate an action against all applicable policies.

        Args:
            user_id: The user who owns the agent.
            agent_id: The agent performing the action.
            session_id: Current session ID.
            action_type: Type of action (tool_call, api_call, etc.).
            action_name: Name of the action/tool.
            target: Target resource (URL, file path, etc.).
            parameters: Action parameters.
            session_context: Running session totals (costs, counts, etc.).

        Returns:
            Dict with evaluation result:
            - allowed: bool
            - action: "allow" | "block" | "warn" | "require_confirmation"
            - reason: str (if not allowed)
            - policy_id: str (if matched)
            - policy_name: str (if matched)
            - matched_rule: dict (if matched)
            - risk_score: float
            - risk_factors: list[str]
        """
        parameters = parameters or {}
        session_context = session_context or {}

        # Get agent's internal ID
        agent_result = await self.db.execute(
            select(Agent).where(
                Agent.agent_id == agent_id,
                Agent.user_id == user_id,
            )
        )
        agent = agent_result.scalar_one_or_none()
        agent_db_id = agent.id if agent else None

        # Fetch applicable policies (agent-specific + global), sorted by priority
        policies = await self._get_applicable_policies(user_id, agent_db_id)

        if not policies:
            # No policies defined - allow by default
            return {
                "allowed": True,
                "action": "allow",
                "risk_score": 0.0,
                "risk_factors": [],
            }

        # Evaluate each policy
        for policy in policies:
            result = self._evaluate_policy(
                policy=policy,
                action_type=action_type,
                action_name=action_name,
                target=target,
                parameters=parameters,
                session_context=session_context,
            )

            if result["matched"]:
                # Record violation if blocked or warned
                if result["action"] in ("block", "warn", "require_confirmation"):
                    await self._record_violation(
                        policy=policy,
                        agent_id=agent_id,
                        session_id=session_id,
                        action_type=action_type,
                        action_name=action_name,
                        target=target,
                        parameters=parameters,
                        result=result,
                    )

                return {
                    "allowed": result["action"] in ("allow", "warn"),
                    "action": result["action"],
                    "reason": result.get("reason", ""),
                    "policy_id": str(policy.id),
                    "policy_name": policy.name,
                    "matched_rule": result.get("matched_rule"),
                    "risk_score": result.get("risk_score", 0.0),
                    "risk_factors": result.get("risk_factors", []),
                    "confirmation_id": result.get("confirmation_id"),
                    "confirmation_message": result.get("confirmation_message"),
                }

        # No policy matched - allow by default
        return {
            "allowed": True,
            "action": "allow",
            "risk_score": 0.0,
            "risk_factors": [],
        }

    async def _get_applicable_policies(
        self,
        user_id: uuid.UUID,
        agent_db_id: uuid.UUID | None,
    ) -> list[Policy]:
        """Get all applicable policies for a user/agent, sorted by priority."""
        # Build query for enabled policies
        query = select(Policy).where(
            Policy.user_id == user_id,
            Policy.enabled == True,
        )

        # Include agent-specific and global (agent_id=NULL) policies
        if agent_db_id:
            query = query.where(
                (Policy.agent_id == agent_db_id) | (Policy.agent_id == None)
            )
        else:
            query = query.where(Policy.agent_id == None)

        query = query.order_by(Policy.priority.asc())

        result = await self.db.execute(query)
        return list(result.scalars().all())

    def _evaluate_policy(
        self,
        policy: Policy,
        action_type: str,
        action_name: str,
        target: str,
        parameters: dict[str, Any],
        session_context: dict[str, Any],
    ) -> dict[str, Any]:
        """Evaluate a single policy against an action."""
        rules = policy.rules or {}
        result = {
            "matched": False,
            "action": "allow",
            "risk_score": 0.0,
            "risk_factors": [],
        }

        # 1. Check denials first (always takes precedence)
        denials = rules.get("denials", {})
        denial_result = self._check_denials(denials, action_type, action_name, target, parameters)
        if denial_result["denied"]:
            return {
                "matched": True,
                "action": "block",
                "reason": denial_result["reason"],
                "matched_rule": {"type": "denial", "rule": denial_result["rule"]},
                "risk_score": 0.8,
                "risk_factors": [denial_result["reason"]],
            }

        # 2. Check limits
        limits = rules.get("limits", {})
        limit_result = self._check_limits(limits, action_type, session_context)
        if limit_result["exceeded"]:
            return {
                "matched": True,
                "action": "block",
                "reason": limit_result["reason"],
                "matched_rule": {"type": "limit", "rule": limit_result["rule"]},
                "risk_score": 0.6,
                "risk_factors": [limit_result["reason"]],
            }

        # 3. Check conditions
        conditions = rules.get("conditions", [])
        for condition in conditions:
            cond_result = self._evaluate_condition(
                condition, action_type, action_name, target, parameters
            )
            if cond_result["matched"]:
                action = condition.get("then", "block")
                if action == "require_confirmation":
                    return {
                        "matched": True,
                        "action": "require_confirmation",
                        "reason": condition.get("message", "Action requires confirmation"),
                        "matched_rule": {"type": "condition", "rule": condition},
                        "risk_score": 0.5,
                        "risk_factors": [condition.get("message", "Conditional rule triggered")],
                        "confirmation_id": str(uuid.uuid4()),
                        "confirmation_message": condition.get("message", "This action requires your approval."),
                    }
                elif action == "warn":
                    return {
                        "matched": True,
                        "action": "warn",
                        "reason": condition.get("message", "Action triggered warning"),
                        "matched_rule": {"type": "condition", "rule": condition},
                        "risk_score": 0.3,
                        "risk_factors": [condition.get("message", "Warning rule triggered")],
                    }
                elif action == "block":
                    return {
                        "matched": True,
                        "action": "block",
                        "reason": condition.get("message", "Action blocked by condition"),
                        "matched_rule": {"type": "condition", "rule": condition},
                        "risk_score": 0.7,
                        "risk_factors": [condition.get("message", "Block rule triggered")],
                    }

        # 4. Check permissions (if action type requires it)
        permissions = rules.get("permissions", {})
        if not self._check_permissions(permissions, action_type, action_name, target):
            return {
                "matched": True,
                "action": "block",
                "reason": f"Action '{action_name}' not in allowed list",
                "matched_rule": {"type": "permission", "rule": permissions},
                "risk_score": 0.5,
                "risk_factors": ["Action not permitted"],
            }

        return result

    def _check_denials(
        self,
        denials: dict[str, Any],
        action_type: str,
        action_name: str,
        target: str,
        parameters: dict[str, Any],
    ) -> dict[str, Any]:
        """Check if action matches any denial rule."""
        # Check denied tools
        if action_type == "tool_call":
            denied_tools = denials.get("tools", [])
            for pattern in denied_tools:
                if self._pattern_matches(pattern, action_name):
                    return {
                        "denied": True,
                        "reason": f"Tool '{action_name}' is denied",
                        "rule": {"tools": pattern},
                    }

        # Check denied APIs
        if action_type == "api_call":
            denied_apis = denials.get("apis", [])
            for pattern in denied_apis:
                if self._pattern_matches(pattern, target):
                    return {
                        "denied": True,
                        "reason": f"API '{target}' is denied",
                        "rule": {"apis": pattern},
                    }

        # Check denied files
        if action_type == "file_access":
            denied_files = denials.get("files", [])
            for pattern in denied_files:
                if self._pattern_matches(pattern, target):
                    return {
                        "denied": True,
                        "reason": f"File access to '{target}' is denied",
                        "rule": {"files": pattern},
                    }

        # Check denied keywords in parameters/input
        denied_keywords = denials.get("keywords", [])
        param_str = str(parameters).lower()
        for keyword in denied_keywords:
            if keyword.lower() in param_str:
                return {
                    "denied": True,
                    "reason": f"Action contains denied keyword '{keyword}'",
                    "rule": {"keywords": keyword},
                }

        return {"denied": False}

    def _check_limits(
        self,
        limits: dict[str, Any],
        action_type: str,
        session_context: dict[str, Any],
    ) -> dict[str, Any]:
        """Check if action would exceed any limits."""
        # Check API calls limit
        if action_type == "api_call":
            max_api = limits.get("max_api_calls_per_minute", float("inf"))
            current_api = session_context.get("api_calls_this_minute", 0)
            if current_api >= max_api:
                return {
                    "exceeded": True,
                    "reason": f"API call limit exceeded ({current_api}/{max_api} per minute)",
                    "rule": {"max_api_calls_per_minute": max_api},
                }

        # Check file reads limit
        if action_type == "file_access":
            max_file = limits.get("max_file_reads_per_session", float("inf"))
            current_file = session_context.get("file_reads_this_session", 0)
            if current_file >= max_file:
                return {
                    "exceeded": True,
                    "reason": f"File read limit exceeded ({current_file}/{max_file} per session)",
                    "rule": {"max_file_reads_per_session": max_file},
                }

        # Check cost limit
        max_cost = limits.get("max_cost_per_session_usd", float("inf"))
        current_cost = session_context.get("cost_this_session_usd", 0)
        if current_cost >= max_cost:
            return {
                "exceeded": True,
                "reason": f"Cost limit exceeded (${current_cost:.4f}/${max_cost:.2f})",
                "rule": {"max_cost_per_session_usd": max_cost},
            }

        # Check total actions limit
        max_actions = limits.get("max_actions_per_session", float("inf"))
        current_actions = session_context.get("actions_this_session", 0)
        if current_actions >= max_actions:
            return {
                "exceeded": True,
                "reason": f"Action limit exceeded ({current_actions}/{max_actions} per session)",
                "rule": {"max_actions_per_session": max_actions},
            }

        return {"exceeded": False}

    def _evaluate_condition(
        self,
        condition: dict[str, Any],
        action_type: str,
        action_name: str,
        target: str,
        parameters: dict[str, Any],
    ) -> dict[str, Any]:
        """Evaluate a conditional rule."""
        if_clause = condition.get("if", {})

        # Check action_type match
        if "action_type" in if_clause:
            if if_clause["action_type"] != action_type:
                return {"matched": False}

        # Check action_name match
        if "action_name" in if_clause:
            if not self._pattern_matches(if_clause["action_name"], action_name):
                return {"matched": False}

        # Check target_contains
        if "target_contains" in if_clause:
            if if_clause["target_contains"].lower() not in target.lower():
                return {"matched": False}

        # Check parameter values
        if "parameter_contains" in if_clause:
            param_str = str(parameters).lower()
            if if_clause["parameter_contains"].lower() not in param_str:
                return {"matched": False}

        # All conditions matched
        return {"matched": True}

    def _check_permissions(
        self,
        permissions: dict[str, Any],
        action_type: str,
        action_name: str,
        target: str,
    ) -> bool:
        """Check if action is permitted."""
        # Map action types to permission categories
        type_to_category = {
            "tool_call": "tools",
            "api_call": "apis",
            "file_access": "files",
        }

        category = type_to_category.get(action_type)
        if not category:
            return True  # Unknown types are allowed

        allowed = permissions.get(category, ["*"])

        # Check if "*" wildcard allows all
        if "*" in allowed:
            return True

        # Check if action matches any allowed pattern
        check_value = action_name if category == "tools" else target
        for pattern in allowed:
            if self._pattern_matches(pattern, check_value):
                return True

        return False

    def _pattern_matches(self, pattern: str, value: str) -> bool:
        """Check if a value matches a glob/wildcard pattern."""
        if pattern == "*":
            return True

        # Handle glob patterns
        if "*" in pattern or "?" in pattern:
            return fnmatch.fnmatch(value.lower(), pattern.lower())

        # Exact match (case-insensitive)
        return pattern.lower() == value.lower()

    async def _record_violation(
        self,
        policy: Policy,
        agent_id: str,
        session_id: str,
        action_type: str,
        action_name: str,
        target: str,
        parameters: dict[str, Any],
        result: dict[str, Any],
    ) -> None:
        """Record a policy violation and dispatch notifications."""
        violation = PolicyViolation(
            policy_id=policy.id,
            agent_id=agent_id,
            session_id=session_id,
            action_id=str(uuid.uuid4()),
            violation_type=result.get("matched_rule", {}).get("type", "unknown"),
            severity="high" if result["action"] == "block" else "medium",
            attempted_action={
                "type": action_type,
                "name": action_name,
                "target": target,
                "parameters": parameters,
            },
            violated_rule=result.get("matched_rule", {}),
            action_taken=result["action"],
            notes=result.get("reason", ""),
        )
        self.db.add(violation)

        # Increment violation count
        policy.violation_count += 1
        policy.last_evaluated_at = datetime.now(timezone.utc)

        # Dispatch notification asynchronously (fire-and-forget)
        asyncio.create_task(
            self._send_violation_notification(
                agent_id=agent_id,
                session_id=session_id,
                action_type=action_type,
                action_name=action_name,
                target=target,
                policy_name=policy.name,
                reason=result.get("reason", ""),
                risk_score=result.get("risk_score", 0.0),
            )
        )

    async def _send_violation_notification(
        self,
        agent_id: str,
        session_id: str,
        action_type: str,
        action_name: str,
        target: str,
        policy_name: str,
        reason: str,
        risk_score: float,
    ) -> None:
        """Send notification for policy violation."""
        try:
            from app.services.notification_dispatcher import get_notification_dispatcher

            dispatcher = get_notification_dispatcher()
            await dispatcher.dispatch_policy_violation(
                agent_id=agent_id,
                session_id=session_id,
                action_type=action_type,
                action_target=target or action_name,
                violation_reason=reason,
                policy_name=policy_name,
                risk_score=risk_score,
            )
        except Exception as e:
            logger.warning("Failed to send violation notification: %s", e)
