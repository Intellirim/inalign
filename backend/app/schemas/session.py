"""Session schemas."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field

from app.schemas.common import RiskLevel

__all__ = [
    "SessionStats", "TimelineEvent", "GraphSummary",
    "SessionResponse", "SessionListResponse",
]


class SessionStats(BaseModel):
    total_actions: int = 0
    input_scans: int = 0
    output_scans: int = 0
    threats_detected: int = 0
    pii_detected: int = 0
    anomalies_detected: int = 0


class TimelineEvent(BaseModel):
    timestamp: datetime
    type: str
    severity: str
    description: str


class GraphSummary(BaseModel):
    nodes: int = 0
    edges: int = 0
    clusters: int = 0


class SessionResponse(BaseModel):
    session_id: str
    agent_id: str
    status: str = "active"
    risk_level: RiskLevel = RiskLevel.NONE
    risk_score: float = Field(default=0.0, ge=0, le=1)
    started_at: datetime | None = None
    last_activity_at: datetime | None = None
    stats: SessionStats = Field(default_factory=SessionStats)
    timeline: list[TimelineEvent] = Field(default_factory=list)
    graph_summary: GraphSummary = Field(default_factory=GraphSummary)


class SessionListResponse(BaseModel):
    items: list[SessionResponse]
    total: int
    page: int
    size: int
