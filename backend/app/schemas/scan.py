"""Scan request / response schemas."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field

from app.schemas.common import RiskLevel, Severity

__all__ = [
    "ScanInputRequest", "ScanOutputRequest",
    "ThreatInfo", "PIIInfo",
    "ScanInputResponse", "ScanOutputResponse",
]


class ScanInputRequest(BaseModel):
    text: str = Field(..., min_length=1, max_length=50_000, description="Input text to scan")
    agent_id: str = Field(..., description="Agent identifier")
    session_id: str = Field(..., description="Session identifier")
    metadata: dict[str, Any] | None = Field(default=None, description="Optional metadata")


class ScanOutputRequest(BaseModel):
    text: str = Field(..., min_length=1, max_length=100_000, description="Output text to scan")
    agent_id: str = Field(..., description="Agent identifier")
    session_id: str = Field(..., description="Session identifier")
    auto_sanitize: bool = Field(default=False, description="Auto-replace PII with placeholders")


class ThreatInfo(BaseModel):
    type: str = Field(..., description="Threat category, e.g. prompt_injection")
    subtype: str = Field(..., description="Specific sub-category")
    pattern_id: str = Field(..., description="Pattern ID that matched")
    matched_text: str = Field(..., description="Text fragment that matched")
    position: list[int] = Field(..., description="[start, end] character offsets")
    confidence: float = Field(..., ge=0, le=1)
    severity: Severity
    description: str = Field(..., description="Human-readable description")


class ScanInputResponse(BaseModel):
    request_id: str
    safe: bool
    risk_level: RiskLevel
    risk_score: float = Field(ge=0, le=1)
    latency_ms: float
    threats: list[ThreatInfo] = Field(default_factory=list)
    recommendation: str = Field(default="allow", description="allow | warn | block")
    action_taken: str = Field(default="logged")


class PIIInfo(BaseModel):
    type: str = Field(..., description="PII type, e.g. phone_number, resident_id")
    subtype: str = Field(default="", description="Specific sub-type")
    value: str = Field(..., description="Detected PII value")
    position: list[int] = Field(..., description="[start, end] character offsets")
    confidence: float = Field(ge=0, le=1, default=1.0)
    severity: Severity


class ScanOutputResponse(BaseModel):
    request_id: str
    safe: bool
    risk_level: RiskLevel
    risk_score: float = Field(ge=0, le=1)
    latency_ms: float
    pii_detected: list[PIIInfo] = Field(default_factory=list)
    original_text: str | None = None
    sanitized_text: str | None = None
    recommendation: str = Field(default="allow")
    action_taken: str = Field(default="logged")
