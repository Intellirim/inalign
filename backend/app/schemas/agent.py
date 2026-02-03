"""Agent request/response schemas."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field

__all__ = [
    "AgentCreate",
    "AgentUpdate",
    "AgentResponse",
    "AgentListResponse",
    "AgentStatsResponse",
]


class AgentCreate(BaseModel):
    """Request to register a new agent."""

    agent_id: str = Field(
        ...,
        min_length=1,
        max_length=64,
        description="Unique identifier for the agent",
        examples=["my-coding-agent", "data-analyst-v2"],
    )
    name: str = Field(
        ...,
        min_length=1,
        max_length=256,
        description="Human-readable agent name",
    )
    description: str = Field(
        default="",
        max_length=2048,
        description="Agent description",
    )
    framework: str = Field(
        default="custom",
        max_length=64,
        description="Agent framework (langchain, autogpt, crewai, custom)",
    )
    config: dict[str, Any] = Field(
        default_factory=dict,
        description="Agent configuration",
    )


class AgentUpdate(BaseModel):
    """Request to update an agent."""

    name: str | None = Field(default=None, max_length=256)
    description: str | None = Field(default=None, max_length=2048)
    framework: str | None = Field(default=None, max_length=64)
    status: str | None = Field(default=None, description="active, paused, disabled")
    config: dict[str, Any] | None = Field(default=None)


class AgentResponse(BaseModel):
    """Agent details response."""

    id: str = Field(..., description="Internal UUID")
    agent_id: str = Field(..., description="User-facing agent ID")
    name: str
    description: str
    framework: str
    status: str
    config: dict[str, Any]
    created_at: datetime
    updated_at: datetime
    last_active_at: datetime | None


class AgentListResponse(BaseModel):
    """Paginated list of agents."""

    items: list[AgentResponse]
    total: int
    page: int
    size: int
    pages: int


class AgentStatsResponse(BaseModel):
    """Statistics for a single agent."""

    agent_id: str
    total_sessions: int = 0
    total_actions: int = 0
    total_threats: int = 0
    policy_violations: int = 0
    avg_risk_score: float = 0.0
    total_cost_usd: float = 0.0
    efficiency_score: float = 0.0
    last_active_at: datetime | None = None
