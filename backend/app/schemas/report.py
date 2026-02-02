"""Report schemas."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field

from app.schemas.common import RiskLevel, Severity

__all__ = [
    "ReportRequest", "AttackVector", "BehaviorPattern",
    "SimilarAttack", "BehaviorGraphAnalysis", "ReportAnalysis",
    "Recommendation", "ReportSummary", "ReportResponse",
]


class ReportRequest(BaseModel):
    report_type: str = Field(default="security_analysis")
    include_recommendations: bool = True
    language: str = Field(default="ko", description="Report language: ko or en")


class AttackVector(BaseModel):
    type: str
    confidence: float = Field(ge=0, le=1)
    description: str
    evidence: list[str] = Field(default_factory=list)


class BehaviorPattern(BaseModel):
    name: str
    match_score: float = Field(ge=0, le=1)
    path: str = ""


class SimilarAttack(BaseModel):
    session_id: str
    date: str = ""
    similarity: float = Field(ge=0, le=1)
    outcome: str = ""


class BehaviorGraphAnalysis(BaseModel):
    description: str
    patterns: list[BehaviorPattern] = Field(default_factory=list)
    similar_attacks: list[SimilarAttack] = Field(default_factory=list)


class ReportAnalysis(BaseModel):
    attack_vectors: list[AttackVector] = Field(default_factory=list)
    behavior_graph_analysis: BehaviorGraphAnalysis | None = None
    timeline_analysis: str = ""


class Recommendation(BaseModel):
    priority: Severity
    action: str
    reason: str


class ReportSummary(BaseModel):
    risk_level: RiskLevel
    risk_score: float = Field(ge=0, le=1)
    primary_concerns: list[str] = Field(default_factory=list)


class ReportResponse(BaseModel):
    request_id: str = ""
    report_id: str = ""
    session_id: str = ""
    status: str = "completed"
    generated_at: datetime | None = None
    generation_time_ms: float = 0
    summary: ReportSummary | None = None
    analysis: ReportAnalysis | None = None
    recommendations: list[Recommendation] = Field(default_factory=list)
    raw_graph_data: dict[str, Any] | None = None
