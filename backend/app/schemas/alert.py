"""Alert schemas."""

from __future__ import annotations

from datetime import datetime
from typing import Any
from uuid import UUID

from pydantic import BaseModel, Field

from app.schemas.common import Severity

__all__ = [
    "AlertResponse", "AlertListResponse", "AlertAcknowledgeRequest",
]


class AlertResponse(BaseModel):
    id: str
    session_id: str
    agent_id: str
    alert_type: str
    severity: Severity
    title: str
    description: str
    details: dict[str, Any] | None = None
    is_acknowledged: bool = False
    acknowledged_by: str | None = None
    acknowledged_at: datetime | None = None
    created_at: datetime | None = None


class AlertListResponse(BaseModel):
    items: list[AlertResponse]
    total: int
    page: int
    size: int


class AlertAcknowledgeRequest(BaseModel):
    acknowledged_by: str = Field(default="system")
    note: str = Field(default="")
