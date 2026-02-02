"""Action log schemas."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field

from app.schemas.common import Severity

__all__ = ["ActionInfo", "LogActionRequest", "AnomalyInfo", "LogActionResponse"]


class ActionInfo(BaseModel):
    type: str = Field(..., description="Action type: tool_call, llm_call, api_call, database_query")
    name: str = Field(..., description="Action name")
    target: str = Field(default="", description="Target resource")
    parameters: dict[str, Any] = Field(default_factory=dict)
    result_summary: str = Field(default="")
    duration_ms: int = Field(default=0, ge=0)


class ContextInfo(BaseModel):
    previous_action_id: str | None = None
    user_input_hash: str | None = None
    llm_model: str | None = None


class LogActionRequest(BaseModel):
    agent_id: str
    session_id: str
    action: ActionInfo
    context: ContextInfo | None = None
    timestamp: datetime | None = None


class AnomalyInfo(BaseModel):
    type: str
    severity: Severity
    description: str
    score: float = Field(ge=0, le=1)


class LogActionResponse(BaseModel):
    request_id: str
    logged: bool = True
    action_id: str
    node_id: str = ""
    anomaly_detected: bool = False
    anomalies: list[AnomalyInfo] = Field(default_factory=list)
    session_risk_score: float = Field(default=0.0, ge=0, le=1)
    alerts_triggered: list[str] = Field(default_factory=list)
