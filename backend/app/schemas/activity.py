"""Activity and monitoring schemas."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field

__all__ = [
    "ActivityCreate",
    "ActivityResponse",
    "ActivityListResponse",
    "ActivityStreamMessage",
    "AgentMetricsResponse",
    "EfficiencyReport",
    "EfficiencySuggestion",
]


class ActivityCreate(BaseModel):
    """Request to log an activity (used internally by proxy)."""

    agent_id: str
    session_id: str
    action_id: str
    activity_type: str  # tool_call, api_call, llm_call, file_access, etc.
    name: str
    target: str = ""
    input_preview: str = ""
    output_preview: str = ""
    input_size: int = 0
    output_size: int = 0
    parameters: dict[str, Any] = Field(default_factory=dict)
    duration_ms: int = 0
    status: str = "success"  # success, failure, blocked, timeout
    policy_result: str = "allowed"  # allowed, denied, warned
    policy_id: str | None = None
    violation_reason: str = ""
    risk_score: float = 0.0
    risk_factors: dict[str, Any] = Field(default_factory=dict)
    cost_usd: float = 0.0
    tokens_input: int = 0
    tokens_output: int = 0
    parent_action_id: str | None = None
    sequence_number: int = 0
    metadata: dict[str, Any] = Field(default_factory=dict)


class ActivityResponse(BaseModel):
    """Single activity response."""

    id: str
    agent_id: str
    session_id: str
    action_id: str
    activity_type: str
    name: str
    target: str
    input_preview: str
    output_preview: str
    duration_ms: int
    status: str
    policy_result: str
    risk_score: float
    cost_usd: float
    tokens_input: int
    tokens_output: int
    timestamp: datetime


class ActivityListResponse(BaseModel):
    """Paginated list of activities."""

    items: list[ActivityResponse]
    total: int
    page: int
    size: int
    pages: int


class ActivityStreamMessage(BaseModel):
    """Real-time activity stream message (WebSocket)."""

    event_type: str = Field(
        ...,
        description="activity, threat, policy_violation, alert, metric",
    )
    timestamp: datetime
    agent_id: str
    session_id: str | None = None
    data: dict[str, Any]


class AgentMetricsResponse(BaseModel):
    """Aggregated metrics for an agent."""

    agent_id: str
    period_type: str
    period_start: datetime
    period_end: datetime

    # Counts
    total_actions: int
    successful_actions: int
    failed_actions: int
    blocked_actions: int

    # By type
    tool_calls: int
    api_calls: int
    llm_calls: int
    file_accesses: int

    # Performance
    total_duration_ms: int
    avg_duration_ms: float
    p95_duration_ms: float

    # Costs
    total_cost_usd: float
    total_tokens: int

    # Security
    threats_detected: int
    policy_violations: int
    avg_risk_score: float

    # Sessions
    unique_sessions: int

    # Efficiency
    efficiency_score: float
    redundancy_ratio: float


class EfficiencySuggestion(BaseModel):
    """A suggestion to improve agent efficiency."""

    suggestion_type: str = Field(
        ...,
        description="caching, batching, redundancy, error_retry, cost, workflow",
    )
    severity: str = Field(default="info", description="info, warning, critical")
    title: str
    description: str
    impact: str = Field(..., description="Estimated impact if fixed")
    affected_actions: list[str] = Field(default_factory=list)
    recommendation: str


class EfficiencyReport(BaseModel):
    """Efficiency analysis report for an agent."""

    agent_id: str
    analysis_period: str
    generated_at: datetime

    # Overall scores (0-100)
    overall_score: float
    cost_efficiency: float
    time_efficiency: float
    success_rate: float
    security_score: float

    # Detailed metrics
    total_actions: int
    total_cost_usd: float
    total_duration_ms: int
    avg_action_duration_ms: float

    # Identified patterns
    redundant_calls: int  # Same call repeated unnecessarily
    failed_retries: int  # Failures that could have been avoided
    expensive_operations: int  # High-cost operations

    # Suggestions
    suggestions: list[EfficiencySuggestion]

    # Top consumers
    top_cost_actions: list[dict[str, Any]]
    top_time_actions: list[dict[str, Any]]
    top_failure_actions: list[dict[str, Any]]
