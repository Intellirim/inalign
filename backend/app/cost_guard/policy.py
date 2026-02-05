"""
Policy Engine - Cost guardrails and budget management.

Features:
- Budget limits (daily, monthly, per-request)
- Automatic cost control actions
- Approval workflows for expensive operations
- Policy evaluation and enforcement
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any, Optional
import threading

from app.cost_guard.models import (
    CostPolicy, PolicyDecision, ModelTier, RequestType,
    ModelConfig, DEFAULT_MODEL_CONFIGS
)
from app.cost_guard.tracker import TokenTracker

logger = logging.getLogger("inalign.cost_guard.policy")


@dataclass
class BudgetStatus:
    """Current budget status."""
    daily_used_usd: float = 0.0
    daily_limit_usd: Optional[float] = None
    daily_remaining_usd: Optional[float] = None
    daily_percent_used: float = 0.0

    monthly_used_usd: float = 0.0
    monthly_limit_usd: Optional[float] = None
    monthly_remaining_usd: Optional[float] = None
    monthly_percent_used: float = 0.0

    is_over_daily: bool = False
    is_over_monthly: bool = False
    alert_level: str = "normal"  # normal, warning, critical, exceeded


class PolicyEngine:
    """
    Evaluates cost policies and makes enforcement decisions.

    Manages:
    - Budget tracking and enforcement
    - Automatic cost reduction actions
    - Policy evaluation for each request
    """

    def __init__(
        self,
        default_policy: Optional[CostPolicy] = None,
        tracker: Optional[TokenTracker] = None,
    ):
        """
        Initialize the policy engine.

        Parameters
        ----------
        default_policy : CostPolicy, optional
            Default policy to apply.
        tracker : TokenTracker, optional
            Token tracker for usage data.
        """
        self.default_policy = default_policy or self._create_default_policy()
        self.tracker = tracker or TokenTracker()

        # Per-org/user policies
        self._policies: dict[str, CostPolicy] = {}
        self._lock = threading.Lock()

        # Pending approvals
        self._pending_approvals: dict[str, dict[str, Any]] = {}

        # Model configs for cost estimation
        self._model_configs = DEFAULT_MODEL_CONFIGS.copy()

        logger.info("PolicyEngine initialized")

    def _create_default_policy(self) -> CostPolicy:
        """Create a sensible default policy."""
        return CostPolicy(
            policy_id="default",
            name="Default Policy",
            enabled=True,
            daily_budget_usd=50.0,
            monthly_budget_usd=500.0,
            per_request_limit_tokens=100000,
            per_request_limit_usd=1.0,
            auto_compress_threshold_tokens=3000,
            auto_downgrade_threshold_usd=0.10,
            auto_cache_enabled=True,
            default_tier=ModelTier.STANDARD,
            allow_expensive_tier=True,
            require_approval_for_expensive=False,
            force_cheap_for_types=[RequestType.SIMPLE],
            alert_at_budget_percent=80.0,
        )

    def set_policy(
        self,
        policy: CostPolicy,
        org_id: Optional[str] = None,
        user_id: Optional[str] = None,
    ) -> None:
        """
        Set policy for an org or user.

        If both org_id and user_id are provided, creates user-specific policy.
        If only org_id, creates org-level policy.
        If neither, updates default policy.
        """
        with self._lock:
            if org_id and user_id:
                key = f"user:{org_id}:{user_id}"
            elif org_id:
                key = f"org:{org_id}"
            else:
                self.default_policy = policy
                return

            self._policies[key] = policy
            logger.info(f"Policy set for {key}")

    def get_policy(
        self,
        org_id: Optional[str] = None,
        user_id: Optional[str] = None,
    ) -> CostPolicy:
        """Get applicable policy (user > org > default)."""
        with self._lock:
            if org_id and user_id:
                key = f"user:{org_id}:{user_id}"
                if key in self._policies:
                    return self._policies[key]

            if org_id:
                key = f"org:{org_id}"
                if key in self._policies:
                    return self._policies[key]

            return self.default_policy

    def get_budget_status(
        self,
        org_id: Optional[str] = None,
        user_id: Optional[str] = None,
    ) -> BudgetStatus:
        """Get current budget status."""
        policy = self.get_policy(org_id, user_id)

        # Get current usage
        daily = self.tracker.get_daily_total()
        monthly = self.tracker.get_monthly_total()

        status = BudgetStatus(
            daily_used_usd=daily["cost"],
            monthly_used_usd=monthly["cost"],
        )

        # Daily budget
        if policy.daily_budget_usd:
            status.daily_limit_usd = policy.daily_budget_usd
            status.daily_remaining_usd = max(0, policy.daily_budget_usd - daily["cost"])
            status.daily_percent_used = (daily["cost"] / policy.daily_budget_usd) * 100
            status.is_over_daily = daily["cost"] >= policy.daily_budget_usd

        # Monthly budget
        if policy.monthly_budget_usd:
            status.monthly_limit_usd = policy.monthly_budget_usd
            status.monthly_remaining_usd = max(0, policy.monthly_budget_usd - monthly["cost"])
            status.monthly_percent_used = (monthly["cost"] / policy.monthly_budget_usd) * 100
            status.is_over_monthly = monthly["cost"] >= policy.monthly_budget_usd

        # Alert level
        max_percent = max(status.daily_percent_used, status.monthly_percent_used)
        if status.is_over_daily or status.is_over_monthly:
            status.alert_level = "exceeded"
        elif max_percent >= 90:
            status.alert_level = "critical"
        elif max_percent >= policy.alert_at_budget_percent:
            status.alert_level = "warning"
        else:
            status.alert_level = "normal"

        return status

    def evaluate(
        self,
        user_message: str,
        model: str,
        estimated_prompt_tokens: int,
        estimated_completion_tokens: int = 1000,
        request_type: RequestType = RequestType.MODERATE,
        org_id: Optional[str] = None,
        user_id: Optional[str] = None,
        session_id: Optional[str] = None,
    ) -> PolicyDecision:
        """
        Evaluate a request against policies.

        Returns PolicyDecision with recommended action.
        """
        policy = self.get_policy(org_id, user_id)
        budget_status = self.get_budget_status(org_id, user_id)

        # Get model config for cost estimation
        config = self._model_configs.get(model)
        if not config:
            # Unknown model, assume standard pricing
            estimated_cost = (estimated_prompt_tokens + estimated_completion_tokens) * 0.000003
            model_tier = ModelTier.STANDARD
        else:
            estimated_cost = config.calculate_cost(
                estimated_prompt_tokens, estimated_completion_tokens
            )
            model_tier = config.tier

        # Check if policy is disabled
        if not policy.enabled:
            return PolicyDecision(
                allowed=True,
                action="allow",
                reason="Policy disabled",
            )

        # Check budget exceeded
        if budget_status.is_over_daily:
            return PolicyDecision(
                allowed=False,
                action="block",
                reason=f"Daily budget exceeded (${budget_status.daily_used_usd:.2f} / ${policy.daily_budget_usd:.2f})",
            )

        if budget_status.is_over_monthly:
            return PolicyDecision(
                allowed=False,
                action="block",
                reason=f"Monthly budget exceeded (${budget_status.monthly_used_usd:.2f} / ${policy.monthly_budget_usd:.2f})",
            )

        # Check per-request token limit
        total_tokens = estimated_prompt_tokens + estimated_completion_tokens
        if policy.per_request_limit_tokens and total_tokens > policy.per_request_limit_tokens:
            return PolicyDecision(
                allowed=False,
                action="block",
                reason=f"Request exceeds token limit ({total_tokens} > {policy.per_request_limit_tokens})",
                compress_prompt=True,  # Suggest compression
            )

        # Check per-request cost limit
        if policy.per_request_limit_usd and estimated_cost > policy.per_request_limit_usd:
            # Try to suggest cheaper alternative
            cheaper_model = self._find_cheaper_model(
                estimated_prompt_tokens, estimated_completion_tokens, policy.per_request_limit_usd
            )

            if cheaper_model:
                return PolicyDecision(
                    allowed=True,
                    action="downgrade",
                    reason=f"Cost (${estimated_cost:.4f}) exceeds limit (${policy.per_request_limit_usd:.2f})",
                    suggested_model=cheaper_model,
                    suggested_tier=self._model_configs.get(cheaper_model, {}).tier if cheaper_model else None,
                )
            else:
                return PolicyDecision(
                    allowed=False,
                    action="block",
                    reason=f"Cost (${estimated_cost:.4f}) exceeds limit and no cheaper alternative",
                )

        # Check expensive tier requirements
        if model_tier == ModelTier.EXPENSIVE:
            if not policy.allow_expensive_tier:
                cheaper = self._find_cheaper_model(
                    estimated_prompt_tokens, estimated_completion_tokens
                )
                return PolicyDecision(
                    allowed=True,
                    action="downgrade",
                    reason="Expensive tier not allowed by policy",
                    suggested_model=cheaper,
                    suggested_tier=ModelTier.STANDARD,
                )

            if policy.require_approval_for_expensive:
                approval_key = self._create_approval_request(
                    session_id, model, estimated_cost, org_id, user_id
                )
                return PolicyDecision(
                    allowed=False,
                    action="require_approval",
                    reason="Expensive model requires approval",
                    metadata={"approval_key": approval_key},
                )

        # Check auto-downgrade threshold
        if policy.auto_downgrade_threshold_usd and estimated_cost > policy.auto_downgrade_threshold_usd:
            if model_tier != ModelTier.CHEAP:
                cheaper = self._find_cheaper_model(
                    estimated_prompt_tokens, estimated_completion_tokens
                )
                if cheaper:
                    return PolicyDecision(
                        allowed=True,
                        action="downgrade",
                        reason=f"Auto-downgrade: cost ${estimated_cost:.4f} > threshold ${policy.auto_downgrade_threshold_usd:.2f}",
                        suggested_model=cheaper,
                        suggested_tier=ModelTier.CHEAP,
                    )

        # Check auto-compress threshold
        compress_prompt = False
        if policy.auto_compress_threshold_tokens and estimated_prompt_tokens > policy.auto_compress_threshold_tokens:
            compress_prompt = True

        # Check force cheap for simple requests
        if request_type in policy.force_cheap_for_types and model_tier != ModelTier.CHEAP:
            cheap_model = self._get_cheap_model()
            return PolicyDecision(
                allowed=True,
                action="downgrade",
                reason=f"Simple request ({request_type.value}) → using cheap model",
                suggested_model=cheap_model,
                suggested_tier=ModelTier.CHEAP,
                compress_prompt=compress_prompt,
                use_cache=policy.auto_cache_enabled,
            )

        # All checks passed
        return PolicyDecision(
            allowed=True,
            action="allow",
            reason="Request within policy limits",
            compress_prompt=compress_prompt,
            use_cache=policy.auto_cache_enabled,
            metadata={
                "estimated_cost_usd": estimated_cost,
                "budget_remaining_daily": budget_status.daily_remaining_usd,
                "budget_remaining_monthly": budget_status.monthly_remaining_usd,
            },
        )

    def _find_cheaper_model(
        self,
        prompt_tokens: int,
        completion_tokens: int,
        max_cost: Optional[float] = None,
    ) -> Optional[str]:
        """Find a cheaper model that fits within cost constraint."""
        candidates = []

        for model_id, config in self._model_configs.items():
            cost = config.calculate_cost(prompt_tokens, completion_tokens)
            candidates.append((model_id, config.tier, cost))

        # Sort by cost
        candidates.sort(key=lambda x: x[2])

        if max_cost:
            for model_id, tier, cost in candidates:
                if cost <= max_cost:
                    return model_id

        # Return cheapest
        return candidates[0][0] if candidates else None

    def _get_cheap_model(self) -> str:
        """Get a cheap tier model."""
        for model_id, config in self._model_configs.items():
            if config.tier == ModelTier.CHEAP:
                return model_id
        return "gpt-4o-mini"  # Fallback

    def _create_approval_request(
        self,
        session_id: Optional[str],
        model: str,
        estimated_cost: float,
        org_id: Optional[str],
        user_id: Optional[str],
    ) -> str:
        """Create an approval request for expensive operations."""
        import uuid
        approval_key = str(uuid.uuid4())[:8]

        self._pending_approvals[approval_key] = {
            "created_at": datetime.utcnow().isoformat(),
            "session_id": session_id,
            "model": model,
            "estimated_cost_usd": estimated_cost,
            "org_id": org_id,
            "user_id": user_id,
            "status": "pending",
        }

        logger.info(f"Approval request created: {approval_key}")
        return approval_key

    def approve_request(self, approval_key: str) -> bool:
        """Approve a pending request."""
        if approval_key in self._pending_approvals:
            self._pending_approvals[approval_key]["status"] = "approved"
            self._pending_approvals[approval_key]["approved_at"] = datetime.utcnow().isoformat()
            logger.info(f"Request approved: {approval_key}")
            return True
        return False

    def reject_request(self, approval_key: str) -> bool:
        """Reject a pending request."""
        if approval_key in self._pending_approvals:
            self._pending_approvals[approval_key]["status"] = "rejected"
            self._pending_approvals[approval_key]["rejected_at"] = datetime.utcnow().isoformat()
            logger.info(f"Request rejected: {approval_key}")
            return True
        return False

    def check_approval_status(self, approval_key: str) -> Optional[str]:
        """Check status of an approval request."""
        if approval_key in self._pending_approvals:
            return self._pending_approvals[approval_key]["status"]
        return None

    def get_policy_summary(
        self,
        org_id: Optional[str] = None,
        user_id: Optional[str] = None,
    ) -> dict[str, Any]:
        """Get human-readable policy summary."""
        policy = self.get_policy(org_id, user_id)
        budget = self.get_budget_status(org_id, user_id)

        return {
            "policy_name": policy.name,
            "enabled": policy.enabled,
            "budget": {
                "daily": {
                    "limit_usd": policy.daily_budget_usd,
                    "used_usd": round(budget.daily_used_usd, 4),
                    "remaining_usd": round(budget.daily_remaining_usd or 0, 4),
                    "percent_used": round(budget.daily_percent_used, 2),
                },
                "monthly": {
                    "limit_usd": policy.monthly_budget_usd,
                    "used_usd": round(budget.monthly_used_usd, 4),
                    "remaining_usd": round(budget.monthly_remaining_usd or 0, 4),
                    "percent_used": round(budget.monthly_percent_used, 2),
                },
            },
            "limits": {
                "per_request_tokens": policy.per_request_limit_tokens,
                "per_request_usd": policy.per_request_limit_usd,
            },
            "auto_actions": {
                "compress_at_tokens": policy.auto_compress_threshold_tokens,
                "downgrade_at_usd": policy.auto_downgrade_threshold_usd,
                "cache_enabled": policy.auto_cache_enabled,
            },
            "model_preferences": {
                "default_tier": policy.default_tier.value,
                "allow_expensive": policy.allow_expensive_tier,
                "require_approval_expensive": policy.require_approval_for_expensive,
            },
            "alert_level": budget.alert_level,
        }
