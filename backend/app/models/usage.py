"""
Usage / request-log model for InALign.

Every authenticated API call is recorded for metering, billing, and
observability.  Rows are append-only and should be periodically aggregated
or partitioned by timestamp in production.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Optional

from sqlalchemy import DateTime, Float, ForeignKey, Integer, String, func
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.database import Base


class Usage(Base):
    """Per-request usage record.

    Attributes:
        id: UUID v4 primary key (inherited).
        user_id: Foreign key referencing the :class:`User` who made the call.
        api_key_id: Foreign key referencing the :class:`APIKey` used.
        endpoint: The request path, e.g. ``/api/v1/scan/input``.
        method: HTTP method (``GET``, ``POST``, etc.).
        status_code: HTTP response status code.
        latency_ms: Server-side processing time in milliseconds.
        request_size: Size of the request body in bytes.
        response_size: Size of the response body in bytes.
        timestamp: When the request was received (server clock).
    """

    __tablename__ = "usage"

    user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="CASCADE"),
        index=True,
        nullable=False,
    )
    api_key_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("api_keys.id", ondelete="SET NULL"),
        index=True,
        nullable=True,
    )
    endpoint: Mapped[str] = mapped_column(
        String(512),
        nullable=False,
    )
    method: Mapped[str] = mapped_column(
        String(10),
        nullable=False,
    )
    status_code: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
    )
    latency_ms: Mapped[float] = mapped_column(
        Float,
        nullable=False,
    )
    request_size: Mapped[int] = mapped_column(
        Integer,
        default=0,
        nullable=False,
    )
    response_size: Mapped[int] = mapped_column(
        Integer,
        default=0,
        nullable=False,
    )
    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        index=True,
        nullable=False,
    )

    # ---- relationships ----
    user: Mapped["User"] = relationship(  # noqa: F821
        "User",
        lazy="joined",
    )
    api_key: Mapped[Optional["APIKey"]] = relationship(  # noqa: F821
        "APIKey",
        lazy="joined",
    )

    def __repr__(self) -> str:  # pragma: no cover
        return (
            f"<Usage(id={self.id!r}, endpoint={self.endpoint!r}, "
            f"status={self.status_code})>"
        )
