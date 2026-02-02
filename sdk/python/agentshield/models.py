"""Pydantic models for AgentShield SDK responses."""

from __future__ import annotations

from typing import Any, Optional

from pydantic import BaseModel, Field


class ThreatInfo(BaseModel):
    """Information about a detected threat."""

    type: str = Field(description="Type of threat detected (e.g., prompt_injection, jailbreak).")
    severity: str = Field(description="Severity level: low, medium, high, critical.")
    confidence: float = Field(description="Confidence score between 0.0 and 1.0.")
    description: str = Field(default="", description="Human-readable description of the threat.")
    matched_pattern: Optional[str] = Field(default=None, description="Pattern that triggered detection.")


class PIIInfo(BaseModel):
    """Information about detected personally identifiable information."""

    type: str = Field(description="Type of PII (e.g., ssn, email, phone, credit_card).")
    value: str = Field(description="The detected PII value (may be masked).")
    start: int = Field(description="Start character index in the original text.")
    end: int = Field(description="End character index in the original text.")
    confidence: float = Field(default=1.0, description="Detection confidence score.")


class ScanInputResponse(BaseModel):
    """Response from scanning user input."""

    scan_id: str = Field(description="Unique identifier for this scan.")
    is_safe: bool = Field(description="Whether the input is considered safe.")
    risk_level: str = Field(description="Overall risk level: low, medium, high, critical.")
    risk_score: float = Field(default=0.0, description="Numeric risk score from 0.0 to 1.0.")
    threats: list[ThreatInfo] = Field(default_factory=list, description="List of detected threats.")
    pii_detected: list[PIIInfo] = Field(default_factory=list, description="List of detected PII.")
    recommendations: list[str] = Field(default_factory=list, description="Recommended actions.")
    processing_time_ms: int = Field(default=0, description="Processing time in milliseconds.")


class ScanOutputResponse(BaseModel):
    """Response from scanning agent output."""

    scan_id: str = Field(description="Unique identifier for this scan.")
    is_safe: bool = Field(description="Whether the output is considered safe.")
    risk_level: str = Field(description="Overall risk level: low, medium, high, critical.")
    risk_score: float = Field(default=0.0, description="Numeric risk score from 0.0 to 1.0.")
    pii_detected: list[PIIInfo] = Field(default_factory=list, description="List of detected PII in output.")
    data_leakage_risk: bool = Field(default=False, description="Whether data leakage was detected.")
    sanitized_text: Optional[str] = Field(default=None, description="Sanitized version of the text if auto_sanitize was enabled.")
    issues: list[str] = Field(default_factory=list, description="List of issues found.")
    processing_time_ms: int = Field(default=0, description="Processing time in milliseconds.")


class AnomalyInfo(BaseModel):
    """Information about a detected anomaly in agent behavior."""

    type: str = Field(description="Type of anomaly (e.g., unusual_frequency, privilege_escalation).")
    severity: str = Field(description="Severity level: low, medium, high, critical.")
    description: str = Field(default="", description="Human-readable description of the anomaly.")
    score: float = Field(default=0.0, description="Anomaly score.")
    baseline_deviation: Optional[float] = Field(default=None, description="Deviation from baseline behavior.")


class LogActionResponse(BaseModel):
    """Response from logging an agent action."""

    action_id: str = Field(description="Unique identifier for the logged action.")
    status: str = Field(description="Status of the action log (e.g., recorded, flagged).")
    risk_level: str = Field(default="low", description="Risk level assessed for this action.")
    anomalies: list[AnomalyInfo] = Field(default_factory=list, description="Detected anomalies.")
    is_anomalous: bool = Field(default=False, description="Whether the action was flagged as anomalous.")
    recommendations: list[str] = Field(default_factory=list, description="Recommended actions.")


class SessionResponse(BaseModel):
    """Response containing session details."""

    session_id: str = Field(description="The session identifier.")
    agent_id: str = Field(description="The agent identifier.")
    status: str = Field(description="Session status: active, completed, flagged, terminated.")
    risk_level: str = Field(description="Overall session risk level.")
    risk_score: float = Field(default=0.0, description="Overall risk score.")
    start_time: str = Field(description="ISO 8601 timestamp of session start.")
    end_time: Optional[str] = Field(default=None, description="ISO 8601 timestamp of session end.")
    total_actions: int = Field(default=0, description="Total number of actions in the session.")
    total_scans: int = Field(default=0, description="Total number of scans performed.")
    threats_detected: int = Field(default=0, description="Number of threats detected.")
    anomalies_detected: int = Field(default=0, description="Number of anomalies detected.")
    metadata: dict[str, Any] = Field(default_factory=dict, description="Additional session metadata.")


class Recommendation(BaseModel):
    """A security recommendation from a report."""

    priority: str = Field(description="Priority level: low, medium, high, critical.")
    category: str = Field(description="Category of recommendation.")
    title: str = Field(description="Short title of the recommendation.")
    description: str = Field(description="Detailed description and suggested action.")
    affected_actions: list[str] = Field(default_factory=list, description="List of affected action IDs.")


class ReportResponse(BaseModel):
    """Response containing a generated security report."""

    report_id: str = Field(description="Unique identifier for the report.")
    session_id: str = Field(description="The session this report covers.")
    report_type: str = Field(description="Type of report generated.")
    language: str = Field(default="ko", description="Language of the report.")
    title: str = Field(description="Report title.")
    summary: str = Field(description="Executive summary of findings.")
    risk_level: str = Field(description="Overall risk assessment.")
    risk_score: float = Field(default=0.0, description="Overall risk score.")
    total_events: int = Field(default=0, description="Total events analyzed.")
    threats_found: int = Field(default=0, description="Number of threats found.")
    anomalies_found: int = Field(default=0, description="Number of anomalies found.")
    recommendations: list[Recommendation] = Field(default_factory=list, description="Security recommendations.")
    generated_at: str = Field(description="ISO 8601 timestamp of report generation.")
    content: Optional[str] = Field(default=None, description="Full report content in markdown.")


class AlertResponse(BaseModel):
    """Response containing alert details."""

    alert_id: str = Field(description="Unique identifier for the alert.")
    session_id: str = Field(description="Associated session identifier.")
    agent_id: str = Field(description="Associated agent identifier.")
    severity: str = Field(description="Alert severity: low, medium, high, critical.")
    type: str = Field(description="Type of alert (e.g., threat_detected, anomaly_detected).")
    title: str = Field(description="Alert title.")
    description: str = Field(description="Detailed alert description.")
    acknowledged: bool = Field(default=False, description="Whether the alert has been acknowledged.")
    acknowledged_at: Optional[str] = Field(default=None, description="ISO 8601 timestamp of acknowledgement.")
    created_at: str = Field(description="ISO 8601 timestamp of alert creation.")
    metadata: dict[str, Any] = Field(default_factory=dict, description="Additional alert metadata.")
