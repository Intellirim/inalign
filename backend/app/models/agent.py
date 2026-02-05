"""
Agent model for tracking registered AI agents and their configurations.

This module defines the Agent entity which represents an AI agent
that is monitored and governed by InALign.
"""

from __future__ import annotations

from datetime import datetime
from typing import TYPE_CHECKING
import uuid

from sqlalchemy import Boolean, DateTime, ForeignKey, String, Text, func
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.database import Base

if TYPE_CHECKING:
    from app.models.user import User
    from app.models.policy import Policy


class Agent(Base):
    """An AI agent registered in the InALign system.

    Agents are the primary entities being monitored. Each agent can have
    policies attached, and all actions are logged against an agent_id.

    Attributes:
        agent_id: Unique identifier for the agent (user-facing ID).
        user_id: Owner of this agent.
        name: Human-readable name.
        description: Optional description.
        framework: Agent framework (e.g., "langchain", "autogpt", "crewai").
        status: Current status ("active", "paused", "disabled").
        config: JSON configuration for the agent.
        policies: Associated policies for this agent.
    """

    __tablename__ = "agents"

    # User-facing agent ID (different from internal UUID)
    agent_id: Mapped[str] = mapped_column(
        String(64),
        unique=True,
        nullable=False,
        index=True,
    )

    # Owner
    user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    # Basic info
    name: Mapped[str] = mapped_column(String(256), nullable=False)
    description: Mapped[str] = mapped_column(Text, default="", nullable=False)
    framework: Mapped[str] = mapped_column(
        String(64),
        default="custom",
        nullable=False,
    )  # langchain, autogpt, crewai, custom

    # Status
    status: Mapped[str] = mapped_column(
        String(32),
        default="active",
        nullable=False,
        index=True,
    )  # active, paused, disabled

    # Configuration (JSON)
    config: Mapped[dict] = mapped_column(
        JSONB,
        default=dict,
        nullable=False,
    )

    # Metadata
    last_active_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )

    # Relationships
    owner: Mapped["User"] = relationship(
        "User",
        back_populates="agents",
        lazy="selectin",
    )
    policies: Mapped[list["Policy"]] = relationship(
        "Policy",
        back_populates="agent",
        lazy="selectin",
        cascade="all, delete-orphan",
    )

    def __repr__(self) -> str:
        return f"<Agent(agent_id={self.agent_id!r}, name={self.name!r})>"
