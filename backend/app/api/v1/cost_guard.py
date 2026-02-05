"""
Cost Guard API endpoints.

Provides:
- Token usage dashboard
- Budget status and alerts
- Policy management
- Cache management
- Runtime Guard status
"""
from __future__ import annotations

import logging
from typing import Any, Optional
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

from app.api.v1.auth import get_api_key
from app.cost_guard import (
    RuntimeGuard, TokenTracker, PolicyEngine,
    CostPolicy, ModelTier, RequestType
)

logger = logging.getLogger(__name__)
router = APIRouter()

# Global instances (singleton pattern)
_runtime_guard: Optional[RuntimeGuard] = None
_token_tracker: Optional[TokenTracker] = None
_policy_engine: Optional[PolicyEngine] = None


def get_runtime_guard() -> RuntimeGuard:
    """Get or create RuntimeGuard singleton."""
    global _runtime_guard
    if _runtime_guard is None:
        _runtime_guard = RuntimeGuard(
            enable_security=True,
            enable_cache=True,
            enable_compression=True,
            enable_routing=True,
            enable_policy=True,
        )
    return _runtime_guard


def get_tracker() -> TokenTracker:
    """Get TokenTracker singleton."""
    global _token_tracker
    if _token_tracker is None:
        _token_tracker = TokenTracker()
    return _token_tracker


def get_policy_engine() -> PolicyEngine:
    """Get PolicyEngine singleton."""
    global _policy_engine
    if _policy_engine is None:
        _policy_engine = PolicyEngine()
    return _policy_engine


# =============================================================================
# Request/Response Models
# =============================================================================

class UsageResponse(BaseModel):
    """Token usage response."""
    period_hours: int
    total_requests: int
    total_tokens: int
    total_prompt_tokens: int
    total_completion_tokens: int
    total_cost_usd: float
    tokens_saved: int
    cost_saved_usd: float
    cache_hit_rate: float
    avg_tokens_per_request: float
    avg_latency_ms: float
    by_model: dict[str, Any]
    by_agent: dict[str, Any]
    by_tier: dict[str, Any]


class BudgetResponse(BaseModel):
    """Budget status response."""
    daily: dict[str, Any]
    monthly: dict[str, Any]
    alert_level: str


class PolicyRequest(BaseModel):
    """Policy configuration request."""
    name: str
    daily_budget_usd: Optional[float] = None
    monthly_budget_usd: Optional[float] = None
    per_request_limit_tokens: Optional[int] = None
    per_request_limit_usd: Optional[float] = None
    auto_compress_threshold_tokens: int = 3000
    auto_downgrade_threshold_usd: float = 0.10
    auto_cache_enabled: bool = True
    default_tier: str = "standard"
    allow_expensive_tier: bool = True
    require_approval_for_expensive: bool = False


class DashboardResponse(BaseModel):
    """Dashboard data response."""
    period_hours: int
    summary: dict[str, Any]
    savings: dict[str, Any]
    breakdown: dict[str, Any]
    budget: Optional[dict[str, Any]]


class CacheStatsResponse(BaseModel):
    """Cache statistics response."""
    entries: int
    max_entries: int
    hits: int
    misses: int
    hit_rate: float
    evictions: int
    expirations: int
    tokens_saved: int
    semantic_enabled: bool


class GuardStatusResponse(BaseModel):
    """Runtime Guard status response."""
    components: dict[str, bool]
    usage_24h: dict[str, Any]
    cache: Optional[dict[str, Any]]
    budget: Optional[dict[str, Any]]


# =============================================================================
# Endpoints
# =============================================================================

@router.get("/dashboard", response_model=DashboardResponse)
async def get_dashboard(
    period_hours: int = Query(24, ge=1, le=720),
    org_id: Optional[str] = Query(None),
    user_id: Optional[str] = Query(None),
    _api_key: str = Depends(get_api_key),
):
    """
    Get dashboard data for cost visualization.

    Returns usage statistics, savings metrics, and budget status.
    """
    guard = get_runtime_guard()
    data = guard.get_dashboard_data(
        period_hours=period_hours,
        org_id=org_id,
        user_id=user_id,
    )
    return DashboardResponse(**data)


@router.get("/usage", response_model=UsageResponse)
async def get_usage_stats(
    period_hours: int = Query(24, ge=1, le=720),
    agent_id: Optional[str] = Query(None),
    model: Optional[str] = Query(None),
    _api_key: str = Depends(get_api_key),
):
    """
    Get detailed token usage statistics.

    Filter by agent_id or model for specific breakdowns.
    """
    tracker = get_tracker()
    stats = tracker.get_stats(
        period_hours=period_hours,
        agent_id=agent_id,
        model=model,
    )

    return UsageResponse(
        period_hours=period_hours,
        total_requests=stats.total_requests,
        total_tokens=stats.total_tokens,
        total_prompt_tokens=stats.total_prompt_tokens,
        total_completion_tokens=stats.total_completion_tokens,
        total_cost_usd=round(stats.total_cost_usd, 6),
        tokens_saved=stats.tokens_saved_by_compression + stats.tokens_saved_by_cache,
        cost_saved_usd=round(stats.cost_saved_usd, 6),
        cache_hit_rate=round(stats.cache_hit_rate, 4),
        avg_tokens_per_request=round(stats.avg_prompt_tokens + stats.avg_completion_tokens, 2),
        avg_latency_ms=round(stats.avg_latency_ms, 2),
        by_model=stats.by_model,
        by_agent=stats.by_agent,
        by_tier=stats.by_tier,
    )


@router.get("/budget", response_model=BudgetResponse)
async def get_budget_status(
    org_id: Optional[str] = Query(None),
    user_id: Optional[str] = Query(None),
    _api_key: str = Depends(get_api_key),
):
    """
    Get current budget status and alerts.
    """
    engine = get_policy_engine()
    summary = engine.get_policy_summary(org_id, user_id)

    return BudgetResponse(
        daily=summary["budget"]["daily"],
        monthly=summary["budget"]["monthly"],
        alert_level=summary["alert_level"],
    )


@router.get("/policy")
async def get_policy(
    org_id: Optional[str] = Query(None),
    user_id: Optional[str] = Query(None),
    _api_key: str = Depends(get_api_key),
):
    """
    Get current cost policy configuration.
    """
    engine = get_policy_engine()
    return engine.get_policy_summary(org_id, user_id)


@router.post("/policy")
async def set_policy(
    request: PolicyRequest,
    org_id: Optional[str] = Query(None),
    user_id: Optional[str] = Query(None),
    _api_key: str = Depends(get_api_key),
):
    """
    Set cost policy configuration.
    """
    engine = get_policy_engine()

    # Create policy object
    policy = CostPolicy(
        policy_id=f"policy-{org_id or 'default'}-{user_id or 'default'}",
        name=request.name,
        enabled=True,
        daily_budget_usd=request.daily_budget_usd,
        monthly_budget_usd=request.monthly_budget_usd,
        per_request_limit_tokens=request.per_request_limit_tokens,
        per_request_limit_usd=request.per_request_limit_usd,
        auto_compress_threshold_tokens=request.auto_compress_threshold_tokens,
        auto_downgrade_threshold_usd=request.auto_downgrade_threshold_usd,
        auto_cache_enabled=request.auto_cache_enabled,
        default_tier=ModelTier(request.default_tier),
        allow_expensive_tier=request.allow_expensive_tier,
        require_approval_for_expensive=request.require_approval_for_expensive,
    )

    engine.set_policy(policy, org_id, user_id)

    return {"status": "ok", "message": "Policy updated"}


@router.get("/cache", response_model=CacheStatsResponse)
async def get_cache_stats(_api_key: str = Depends(get_api_key)):
    """
    Get response cache statistics.
    """
    guard = get_runtime_guard()
    if not guard.cache:
        raise HTTPException(status_code=400, detail="Cache is not enabled")

    stats = guard.cache.get_stats()
    return CacheStatsResponse(**stats)


@router.post("/cache/clear")
async def clear_cache(_api_key: str = Depends(get_api_key)):
    """
    Clear all cached responses.
    """
    guard = get_runtime_guard()
    if not guard.cache:
        raise HTTPException(status_code=400, detail="Cache is not enabled")

    count = guard.cache.clear()
    return {"status": "ok", "entries_cleared": count}


@router.post("/cache/cleanup")
async def cleanup_expired_cache(_api_key: str = Depends(get_api_key)):
    """
    Remove expired cache entries.
    """
    guard = get_runtime_guard()
    if not guard.cache:
        raise HTTPException(status_code=400, detail="Cache is not enabled")

    count = guard.cache.cleanup_expired()
    return {"status": "ok", "entries_removed": count}


@router.get("/status", response_model=GuardStatusResponse)
async def get_guard_status(
    org_id: Optional[str] = Query(None),
    user_id: Optional[str] = Query(None),
    _api_key: str = Depends(get_api_key),
):
    """
    Get Runtime Guard status and health.
    """
    guard = get_runtime_guard()
    status = guard.get_status(org_id, user_id)
    return GuardStatusResponse(**status)


@router.get("/export")
async def export_usage_records(
    period_hours: int = Query(24, ge=1, le=720),
    format: str = Query("json"),
    _api_key: str = Depends(get_api_key),
):
    """
    Export usage records for external analysis.
    """
    tracker = get_tracker()
    data = tracker.export_records(period_hours=period_hours, format=format)
    return {"format": format, "data": data}


@router.post("/approval/{approval_key}/approve")
async def approve_request(
    approval_key: str,
    _api_key: str = Depends(get_api_key),
):
    """
    Approve a pending expensive model request.
    """
    engine = get_policy_engine()
    success = engine.approve_request(approval_key)

    if not success:
        raise HTTPException(status_code=404, detail="Approval request not found")

    return {"status": "ok", "approved": True}


@router.post("/approval/{approval_key}/reject")
async def reject_request(
    approval_key: str,
    _api_key: str = Depends(get_api_key),
):
    """
    Reject a pending expensive model request.
    """
    engine = get_policy_engine()
    success = engine.reject_request(approval_key)

    if not success:
        raise HTTPException(status_code=404, detail="Approval request not found")

    return {"status": "ok", "rejected": True}


@router.get("/approval/{approval_key}")
async def check_approval_status(
    approval_key: str,
    _api_key: str = Depends(get_api_key),
):
    """
    Check status of an approval request.
    """
    engine = get_policy_engine()
    status = engine.check_approval_status(approval_key)

    if status is None:
        raise HTTPException(status_code=404, detail="Approval request not found")

    return {"approval_key": approval_key, "status": status}
