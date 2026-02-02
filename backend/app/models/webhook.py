"""
Webhook model for AgentShield.

Users can register HTTP endpoints that receive real-time POST notifications
when specific events occur (e.g. a critical alert is raised).  Each webhook
stores a shared secret used to sign outbound payloads via HMAC-SHA256.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Optional

from sqlalchemy import Boolean, DateTime, ForeignKey, String
from sqlalchemy.dialects.postgresql import ARRAY, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.database import Base


class Webhook(Base):
    """Outbound webhook subscription.

    Attributes:
        id: UUID v4 primary key (inherited).
        user_id: Foreign key referencing the owning :class:`User`.
        name: User-provided label (e.g. "Slack - #security-alerts").
        url: HTTPS endpoint that will receive POST payloads.
        events: List of event types this webhook is subscribed to,
            e.g. ``["alert.critical", "alert.high"]``.
        secret: HMAC-SHA256 shared secret for payload verification.
        is_active: Enable / disable toggle.
        last_triggered_at: Timestamp of the most recent delivery attempt.
        created_at: Row creation timestamp (inherited).
    """

    __tablename__ = "webhooks"

    user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="CASCADE"),
        index=True,
        nullable=False,
    )
    name: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
    )
    url: Mapped[str] = mapped_column(
        String(2048),
        nullable=False,
    )
    events: Mapped[list[str]] = mapped_column(
        ARRAY(String(128)),
        default=list,
        nullable=False,
    )
    secret: Mapped[str] = mapped_column(
        String(512),
        nullable=False,
    )
    is_active: Mapped[bool] = mapped_column(
        Boolean,
        default=True,
        server_default="true",
        nullable=False,
    )
    last_triggered_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
        default=None,
    )

    # ---- relationships ----
    user: Mapped["User"] = relationship(  # noqa: F821
        "User",
        back_populates="webhooks",
    )

    def __repr__(self) -> str:  # pragma: no cover
        return f"<Webhook(id={self.id!r}, name={self.name!r}, url={self.url!r})>"
