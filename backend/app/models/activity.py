"""
Activity model for tracking all agent activities in real-time.

This module defines the Activity entity which logs every action
performed by an AI agent for monitoring and analysis.
"""

from __future__ import annotations

from datetime import datetime
import uuid

from sqlalchemy import Boolean, DateTime, Float, Integer, String, Text, func
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.models.database import Base


class Activity(Base):
    """A single activity/action performed by an AI agent.

    This is a denormalized log table optimized for fast writes and
    time-series queries. It captures everything an agent does.

    Attributes:
        agent_id: The agent that performed this activity.
        session_id: The session context.
        activity_type: Type of activity (tool_call, api_call, file_access, etc.).
        name: Name/identifier of the action.
        target: Target resource (URL, file path, tool name, etc.).
        status: Result status (success, failure, blocked, pending).
        policy_result: Policy evaluation result (allowed, denied, warned).
    """

    __tablename__ = "activities"

    # Core identifiers
    agent_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    session_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    action_id: Mapped[str] = mapped_column(
        String(64),
        unique=True,
        nullable=False,
        index=True,
    )

    # Activity classification
    activity_type: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
        index=True,
    )  # tool_call, api_call, llm_call, file_access, db_query, memory_op, code_exec

    # Action details
    name: Mapped[str] = mapped_column(String(256), nullable=False)
    target: Mapped[str] = mapped_column(String(2048), default="", nullable=False)

    # Input/Output (truncated for storage efficiency)
    input_preview: Mapped[str] = mapped_column(Text, default="", nullable=False)
    output_preview: Mapped[str] = mapped_column(Text, default="", nullable=False)
    input_size: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    output_size: Mapped[int] = mapped_column(Integer, default=0, nullable=False)

    # Full parameters (JSON)
    parameters: Mapped[dict] = mapped_column(JSONB, default=dict, nullable=False)

    # Execution metrics
    duration_ms: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    status: Mapped[str] = mapped_column(
        String(32),
        default="success",
        nullable=False,
        index=True,
    )  # success, failure, blocked, timeout, pending

    # Policy evaluation
    policy_result: Mapped[str] = mapped_column(
        String(32),
        default="allowed",
        nullable=False,
        index=True,
    )  # allowed, denied, warned, pending_confirmation
    policy_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        nullable=True,
    )
    violation_reason: Mapped[str] = mapped_column(Text, default="", nullable=False)

    # Risk assessment
    risk_score: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    risk_factors: Mapped[dict] = mapped_column(JSONB, default=dict, nullable=False)

    # Cost tracking (for LLM calls)
    cost_usd: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    tokens_input: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    tokens_output: Mapped[int] = mapped_column(Integer, default=0, nullable=False)

    # Context
    parent_action_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    sequence_number: Mapped[int] = mapped_column(Integer, default=0, nullable=False)

    # Metadata
    metadata: Mapped[dict] = mapped_column(JSONB, default=dict, nullable=False)
    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
        index=True,
    )

    def __repr__(self) -> str:
        return f"<Activity(action_id={self.action_id!r}, type={self.activity_type!r})>"


class AgentMetrics(Base):
    """Aggregated metrics for an agent over a time period.

    Used for efficiency analysis and dashboards. Aggregated hourly/daily.
    """

    __tablename__ = "agent_metrics"

    # Identifiers
    agent_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    period_type: Mapped[str] = mapped_column(
        String(16),
        nullable=False,
        index=True,
    )  # hourly, daily, weekly
    period_start: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        index=True,
    )
    period_end: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
    )

    # Activity counts
    total_actions: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    successful_actions: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    failed_actions: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    blocked_actions: Mapped[int] = mapped_column(Integer, default=0, nullable=False)

    # By type
    tool_calls: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    api_calls: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    llm_calls: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    file_accesses: Mapped[int] = mapped_column(Integer, default=0, nullable=False)

    # Performance
    total_duration_ms: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    avg_duration_ms: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    p95_duration_ms: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)

    # Costs
    total_cost_usd: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    total_tokens: Mapped[int] = mapped_column(Integer, default=0, nullable=False)

    # Security
    threats_detected: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    policy_violations: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    avg_risk_score: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)

    # Sessions
    unique_sessions: Mapped[int] = mapped_column(Integer, default=0, nullable=False)

    # Efficiency indicators (computed)
    efficiency_score: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    redundancy_ratio: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)

    def __repr__(self) -> str:
        return f"<AgentMetrics(agent_id={self.agent_id!r}, period={self.period_type!r})>"
