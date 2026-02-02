"""
API Key model for AgentShield.

Each user may create multiple API keys with scoped permissions.  Only the
SHA-256 hash of the key is stored; the raw key is returned **once** at
creation time.  A short ``key_prefix`` (e.g. ``ask_7f3b...``) is kept for
display purposes so the user can identify which key is which.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any, Optional

from sqlalchemy import Boolean, DateTime, ForeignKey, String, func
from sqlalchemy.dialects.postgresql import JSON, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.database import Base


class APIKey(Base):
    """Hashed API key with scoped permissions.

    Attributes:
        id: UUID v4 primary key (inherited).
        user_id: Foreign key referencing the owning :class:`User`.
        key_hash: SHA-256 hex digest of the raw API key.
        key_prefix: First 8 characters of the key for identification.
        name: User-provided label for the key (e.g. "Production").
        permissions: JSON object mapping permission scopes to booleans,
            e.g. ``{"scan": true, "reports": false}``.
        is_active: Revocation flag; inactive keys are rejected at auth.
        last_used_at: Timestamp of the most recent authenticated request.
        expires_at: Optional hard expiry; ``None`` means the key never
            expires.
        created_at: Row creation timestamp (inherited).
    """

    __tablename__ = "api_keys"

    user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="CASCADE"),
        index=True,
        nullable=False,
    )
    key_hash: Mapped[str] = mapped_column(
        String(128),
        unique=True,
        index=True,
        nullable=False,
    )
    key_prefix: Mapped[str] = mapped_column(
        String(16),
        nullable=False,
    )
    name: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
    )
    permissions: Mapped[dict[str, Any]] = mapped_column(
        JSON,
        default=dict,
        server_default="{}",
        nullable=False,
    )
    is_active: Mapped[bool] = mapped_column(
        Boolean,
        default=True,
        server_default="true",
        nullable=False,
    )
    last_used_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
        default=None,
    )
    expires_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
        default=None,
    )

    # ---- relationships ----
    user: Mapped["User"] = relationship(  # noqa: F821
        "User",
        back_populates="api_keys",
    )

    def __repr__(self) -> str:  # pragma: no cover
        return (
            f"<APIKey(id={self.id!r}, name={self.name!r}, "
            f"prefix={self.key_prefix!r})>"
        )
