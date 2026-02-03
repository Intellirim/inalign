"""
User model for AgentShield.

Stores registered users who interact with the dashboard or manage API keys.
"""

from __future__ import annotations

import enum
from datetime import datetime

from sqlalchemy import Boolean, DateTime, Enum, String, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.database import Base


class UserRole(str, enum.Enum):
    """Roles available to platform users."""

    ADMIN = "admin"
    USER = "user"
    VIEWER = "viewer"


class User(Base):
    """Platform user account.

    Attributes:
        id: UUID v4 primary key (inherited).
        email: Unique, indexed e-mail address used for authentication.
        name: Human-readable display name.
        hashed_password: bcrypt / argon2 password hash.
        is_active: Soft-disable flag; inactive users cannot authenticate.
        role: Authorisation level -- ``admin``, ``user``, or ``viewer``.
        created_at: Row creation timestamp (inherited).
        updated_at: Row last-modification timestamp (inherited).
    """

    __tablename__ = "users"

    email: Mapped[str] = mapped_column(
        String(320),
        unique=True,
        index=True,
        nullable=False,
    )
    name: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
    )
    hashed_password: Mapped[str] = mapped_column(
        String(512),
        nullable=False,
    )
    is_active: Mapped[bool] = mapped_column(
        Boolean,
        default=True,
        server_default="true",
        nullable=False,
    )
    role: Mapped[UserRole] = mapped_column(
        Enum(
            UserRole,
            name="user_role",
            create_constraint=True,
            values_callable=lambda e: [m.value for m in e],
        ),
        default=UserRole.USER,
        server_default=UserRole.USER.value,
        nullable=False,
    )

    # ---- relationships ----
    api_keys: Mapped[list["APIKey"]] = relationship(  # noqa: F821
        "APIKey",
        back_populates="user",
        cascade="all, delete-orphan",
        lazy="selectin",
    )
    webhooks: Mapped[list["Webhook"]] = relationship(  # noqa: F821
        "Webhook",
        back_populates="user",
        cascade="all, delete-orphan",
        lazy="selectin",
    )
    agents: Mapped[list["Agent"]] = relationship(  # noqa: F821
        "Agent",
        back_populates="owner",
        cascade="all, delete-orphan",
        lazy="selectin",
    )
    policies: Mapped[list["Policy"]] = relationship(  # noqa: F821
        "Policy",
        back_populates="owner",
        cascade="all, delete-orphan",
        lazy="selectin",
    )

    def __repr__(self) -> str:  # pragma: no cover
        return f"<User(id={self.id!r}, email={self.email!r}, role={self.role!r})>"
