"""
Policy model for defining agent permissions and rules.

This module defines the Policy entity which controls what actions
an AI agent is allowed to perform.
"""

from __future__ import annotations

from datetime import datetime
from typing import TYPE_CHECKING
import uuid

from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, String, Text, func
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.database import Base

if TYPE_CHECKING:
    from app.models.agent import Agent
    from app.models.user import User


class Policy(Base):
    """A policy that defines permissions and rules for an agent.

    Policies control what actions an agent can perform, what resources
    it can access, and under what conditions.

    Attributes:
        name: Human-readable policy name.
        description: Policy description.
        agent_id: The agent this policy applies to (optional for global policies).
        user_id: Owner of this policy.
        priority: Evaluation priority (lower = evaluated first).
        enabled: Whether the policy is active.
        rules: JSON object containing the policy rules.
    """

    __tablename__ = "policies"

    # Basic info
    name: Mapped[str] = mapped_column(String(256), nullable=False)
    description: Mapped[str] = mapped_column(Text, default="", nullable=False)

    # Scope: agent-specific or global (user-level)
    agent_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("agents.id", ondelete="CASCADE"),
        nullable=True,  # NULL = global policy for all user's agents
        index=True,
    )

    user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    # Priority (lower = higher priority)
    priority: Mapped[int] = mapped_column(Integer, default=100, nullable=False)

    # Status
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)

    # Policy type
    policy_type: Mapped[str] = mapped_column(
        String(64),
        default="custom",
        nullable=False,
    )  # builtin, custom, template

    # Rules configuration (JSON) - the core policy definition
    # Structure:
    # {
    #   "permissions": {
    #     "tools": ["allowed_tool_1", "allowed_tool_2"],
    #     "apis": ["https://api.example.com/*"],
    #     "files": ["/safe/path/*"],
    #     "actions": ["read", "write", "execute"]
    #   },
    #   "denials": {
    #     "tools": ["dangerous_tool"],
    #     "apis": ["https://internal.example.com/*"],
    #     "files": ["/etc/*", "/root/*"],
    #     "keywords": ["password", "secret", "credential"]
    #   },
    #   "conditions": [
    #     {
    #       "if": {"action_type": "api_call", "target_contains": "payment"},
    #       "then": "require_confirmation"
    #     }
    #   ],
    #   "limits": {
    #     "max_api_calls_per_minute": 60,
    #     "max_file_reads_per_session": 100,
    #     "max_cost_per_session_usd": 1.0
    #   }
    # }
    rules: Mapped[dict] = mapped_column(
        JSONB,
        default=dict,
        nullable=False,
    )

    # Metadata
    version: Mapped[int] = mapped_column(Integer, default=1, nullable=False)
    last_evaluated_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    violation_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)

    # Relationships
    agent: Mapped["Agent | None"] = relationship(
        "Agent",
        back_populates="policies",
        lazy="selectin",
    )
    owner: Mapped["User"] = relationship(
        "User",
        back_populates="policies",
        lazy="selectin",
    )

    def __repr__(self) -> str:
        return f"<Policy(name={self.name!r}, agent_id={self.agent_id!r})>"


class PolicyViolation(Base):
    """Record of a policy violation.

    Whenever an agent action violates a policy, a record is created here
    for audit and analysis.
    """

    __tablename__ = "policy_violations"

    # References
    policy_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("policies.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    agent_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    session_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    action_id: Mapped[str] = mapped_column(String(64), nullable=False)

    # Violation details
    violation_type: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
    )  # permission_denied, limit_exceeded, condition_blocked
    severity: Mapped[str] = mapped_column(
        String(32),
        default="medium",
        nullable=False,
    )  # low, medium, high, critical

    # What was attempted
    attempted_action: Mapped[dict] = mapped_column(JSONB, default=dict, nullable=False)

    # Which rule was violated
    violated_rule: Mapped[dict] = mapped_column(JSONB, default=dict, nullable=False)

    # Action taken
    action_taken: Mapped[str] = mapped_column(
        String(32),
        default="blocked",
        nullable=False,
    )  # blocked, warned, logged, required_confirmation

    # Optional notes
    notes: Mapped[str] = mapped_column(Text, default="", nullable=False)

    def __repr__(self) -> str:
        return f"<PolicyViolation(policy_id={self.policy_id!r}, type={self.violation_type!r})>"
