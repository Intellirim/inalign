"""Pydantic models for InALign SDK responses.

All models are aligned with the backend Pydantic schemas so that
``model_validate(response_json)`` works without field-name mismatches.
"""

from __future__ import annotations

from typing import Any, Optional

from pydantic import BaseModel, Field


# ── Scan ────────────────────────────────────────────────────────────────

class ThreatInfo(BaseModel):
    """Information about a detected threat."""

    type: str = Field(description="Threat category, e.g. prompt_injection.")
    subtype: str = Field(default="", description="Specific sub-category.")
    pattern_id: str = Field(default="", description="Pattern ID that matched.")
    matched_text: str = Field(default="", description="Text fragment that matched.")
    position: list[int] = Field(default_factory=list, description="[start, end] character offsets.")
    confidence: float = Field(default=0.0, ge=0, le=1, description="Confidence score.")
    severity: str = Field(default="low", description="Severity level.")
    description: str = Field(default="", description="Human-readable description.")


class PIIInfo(BaseModel):
    """Information about detected personally identifiable information."""

    type: str = Field(description="PII type, e.g. phone_number, resident_id.")
    subtype: str = Field(default="", description="Specific sub-type.")
    value: str = Field(description="Detected PII value (may be masked).")
    position: list[int] = Field(default_factory=list, description="[start, end] character offsets.")
    confidence: float = Field(default=1.0, ge=0, le=1, description="Detection confidence.")
    severity: str = Field(default="medium", description="Severity level.")


class ScanInputResponse(BaseModel):
    """Response from scanning user input."""

    request_id: str = Field(description="Unique request identifier.")
    safe: bool = Field(description="Whether the input is considered safe.")
    risk_level: str = Field(description="Overall risk level: none, low, medium, high, critical.")
    risk_score: float = Field(default=0.0, ge=0, le=1, description="Numeric risk score.")
    latency_ms: float = Field(default=0.0, description="Processing time in milliseconds.")
    threats: list[ThreatInfo] = Field(default_factory=list, description="List of detected threats.")
    recommendation: str = Field(default="allow", description="allow | warn | block.")
    action_taken: str = Field(default="logged", description="Action taken by the system.")


class ScanOutputResponse(BaseModel):
    """Response from scanning agent output."""

    request_id: str = Field(description="Unique request identifier.")
    safe: bool = Field(description="Whether the output is considered safe.")
    risk_level: str = Field(description="Overall risk level.")
    risk_score: float = Field(default=0.0, ge=0, le=1, description="Numeric risk score.")
    latency_ms: float = Field(default=0.0, description="Processing time in milliseconds.")
    pii_detected: list[PIIInfo] = Field(default_factory=list, description="PII found in output.")
    original_text: Optional[str] = Field(default=None, description="Original text before sanitization.")
    sanitized_text: Optional[str] = Field(default=None, description="Sanitized text if auto_sanitize was enabled.")
    recommendation: str = Field(default="allow", description="allow | warn | block.")
    action_taken: str = Field(default="logged", description="Action taken by the system.")


# ── Log / Action ────────────────────────────────────────────────────────

class AnomalyInfo(BaseModel):
    """Information about a detected anomaly in agent behaviour."""

    type: str = Field(description="Anomaly type.")
    severity: str = Field(description="Severity level.")
    description: str = Field(default="", description="Human-readable description.")
    score: float = Field(default=0.0, ge=0, le=1, description="Anomaly score.")


class LogActionResponse(BaseModel):
    """Response from logging an agent action."""

    request_id: str = Field(description="Unique request identifier.")
    logged: bool = Field(default=True, description="Whether the action was logged.")
    action_id: str = Field(description="Unique identifier for the logged action.")
    node_id: str = Field(default="", description="Neo4j graph node ID.")
    anomaly_detected: bool = Field(default=False, description="Whether the action was flagged as anomalous.")
    anomalies: list[AnomalyInfo] = Field(default_factory=list, description="Detected anomalies.")
    session_risk_score: float = Field(default=0.0, ge=0, le=1, description="Updated session risk score.")
    alerts_triggered: list[str] = Field(default_factory=list, description="Alert IDs triggered by this action.")


# ── Sessions ────────────────────────────────────────────────────────────

class SessionStats(BaseModel):
    """Aggregated session statistics."""

    total_actions: int = 0
    input_scans: int = 0
    output_scans: int = 0
    threats_detected: int = 0
    pii_detected: int = 0
    anomalies_detected: int = 0


class TimelineEvent(BaseModel):
    """A single event in the session timeline."""

    timestamp: str = Field(description="ISO 8601 timestamp.")
    type: str = Field(description="Event type.")
    severity: str = Field(description="Severity level.")
    description: str = Field(default="", description="Event description.")


class GraphSummary(BaseModel):
    """Summary of the session's behaviour graph."""

    nodes: int = 0
    edges: int = 0
    clusters: int = 0


class SessionResponse(BaseModel):
    """Response containing session details."""

    session_id: str = Field(description="Session identifier.")
    agent_id: str = Field(description="Agent identifier.")
    status: str = Field(default="active", description="Session status.")
    risk_level: str = Field(default="none", description="Overall risk level.")
    risk_score: float = Field(default=0.0, ge=0, le=1, description="Overall risk score.")
    started_at: Optional[str] = Field(default=None, description="ISO 8601 session start.")
    last_activity_at: Optional[str] = Field(default=None, description="ISO 8601 last activity.")
    stats: SessionStats = Field(default_factory=SessionStats, description="Aggregated statistics.")
    timeline: list[TimelineEvent] = Field(default_factory=list, description="Event timeline.")
    graph_summary: GraphSummary = Field(default_factory=GraphSummary, description="Behaviour graph summary.")


class SessionListResponse(BaseModel):
    """Paginated list of sessions."""

    items: list[SessionResponse]
    total: int
    page: int
    size: int


# ── Reports ─────────────────────────────────────────────────────────────

class ReportSummary(BaseModel):
    """Executive summary section of a report."""

    risk_level: str = Field(default="none")
    risk_score: float = Field(default=0.0, ge=0, le=1)
    primary_concerns: list[str] = Field(default_factory=list)


class AttackVector(BaseModel):
    type: str
    confidence: float = Field(default=0.0, ge=0, le=1)
    description: str = ""
    evidence: list[str] = Field(default_factory=list)


class BehaviorPattern(BaseModel):
    name: str
    match_score: float = Field(default=0.0, ge=0, le=1)
    path: str = ""


class SimilarAttack(BaseModel):
    session_id: str
    date: str = ""
    similarity: float = Field(default=0.0, ge=0, le=1)
    outcome: str = ""


class BehaviorGraphAnalysis(BaseModel):
    description: str = ""
    patterns: list[BehaviorPattern] = Field(default_factory=list)
    similar_attacks: list[SimilarAttack] = Field(default_factory=list)


class ReportAnalysis(BaseModel):
    attack_vectors: list[AttackVector] = Field(default_factory=list)
    behavior_graph_analysis: Optional[BehaviorGraphAnalysis] = None
    timeline_analysis: str = ""


class Recommendation(BaseModel):
    """A security recommendation from a report."""

    priority: str = Field(description="Priority level.")
    action: str = Field(description="Recommended action.")
    reason: str = Field(description="Reason for the recommendation.")


class ReportResponse(BaseModel):
    """Response containing a generated security report."""

    request_id: str = Field(default="", description="Original request identifier.")
    report_id: str = Field(default="", description="Unique report identifier.")
    session_id: str = Field(default="", description="The session this report covers.")
    status: str = Field(default="completed", description="Report generation status.")
    generated_at: Optional[str] = Field(default=None, description="ISO 8601 generation timestamp.")
    generation_time_ms: float = Field(default=0.0, description="Generation time in ms.")
    summary: Optional[ReportSummary] = Field(default=None, description="Executive summary.")
    analysis: Optional[ReportAnalysis] = Field(default=None, description="Detailed analysis.")
    recommendations: list[Recommendation] = Field(default_factory=list, description="Security recommendations.")
    raw_graph_data: Optional[dict[str, Any]] = Field(default=None, description="Raw graph data.")


# ── Alerts ──────────────────────────────────────────────────────────────

class AlertResponse(BaseModel):
    """Response containing alert details."""

    id: str = Field(description="Unique alert identifier.")
    session_id: str = Field(description="Associated session identifier.")
    agent_id: str = Field(description="Associated agent identifier.")
    alert_type: str = Field(description="Type of alert.")
    severity: str = Field(description="Alert severity.")
    title: str = Field(description="Alert title.")
    description: str = Field(description="Detailed alert description.")
    details: Optional[dict[str, Any]] = Field(default=None, description="Additional details.")
    is_acknowledged: bool = Field(default=False, description="Whether the alert has been acknowledged.")
    acknowledged_by: Optional[str] = Field(default=None, description="Who acknowledged the alert.")
    acknowledged_at: Optional[str] = Field(default=None, description="ISO 8601 acknowledgement timestamp.")
    created_at: Optional[str] = Field(default=None, description="ISO 8601 creation timestamp.")


class AlertListResponse(BaseModel):
    """Paginated list of alerts."""

    items: list[AlertResponse]
    total: int
    page: int
    size: int


# ── Agents ─────────────────────────────────────────────────────────────


class AgentResponse(BaseModel):
    """Response containing agent details."""

    id: str = Field(description="Internal UUID.")
    agent_id: str = Field(description="User-facing agent ID.")
    name: str = Field(description="Human-readable name.")
    description: str = Field(default="")
    framework: str = Field(default="custom")
    status: str = Field(default="active")
    config: dict[str, Any] = Field(default_factory=dict)
    created_at: Optional[str] = Field(default=None)
    updated_at: Optional[str] = Field(default=None)
    last_active_at: Optional[str] = Field(default=None)


class AgentListResponse(BaseModel):
    """Paginated list of agents."""

    items: list[AgentResponse]
    total: int
    page: int
    size: int
    pages: int


class AgentStatsResponse(BaseModel):
    """Statistics for an agent."""

    agent_id: str
    total_sessions: int = 0
    total_actions: int = 0
    total_threats: int = 0
    policy_violations: int = 0
    avg_risk_score: float = 0.0
    total_cost_usd: float = 0.0
    efficiency_score: float = 0.0
    last_active_at: Optional[str] = None


# ── Policies ───────────────────────────────────────────────────────────


class PolicyResponse(BaseModel):
    """Response containing policy details."""

    id: str
    name: str
    description: str = ""
    agent_id: Optional[str] = None
    user_id: str = ""
    priority: int = 100
    enabled: bool = True
    policy_type: str = "custom"
    rules: dict[str, Any] = Field(default_factory=dict)
    version: int = 1
    violation_count: int = 0
    created_at: Optional[str] = None
    updated_at: Optional[str] = None
    last_evaluated_at: Optional[str] = None


class PolicyListResponse(BaseModel):
    """Paginated list of policies."""

    items: list[PolicyResponse]
    total: int
    page: int
    size: int
    pages: int


class PolicyEvalResponse(BaseModel):
    """Result of policy evaluation."""

    allowed: bool = True
    action: str = "allow"  # allow, block, warn, require_confirmation
    reason: str = ""
    matched_policy_id: Optional[str] = None
    matched_policy_name: Optional[str] = None
    matched_rule: Optional[dict[str, Any]] = None
    violations: list[dict[str, Any]] = Field(default_factory=list)


# ── Proxy ──────────────────────────────────────────────────────────────


class ProxyResponse(BaseModel):
    """Response from proxy evaluation."""

    request_id: str
    action_id: str
    allowed: bool = True
    action: str = "allow"  # allow, block, warn, require_confirmation, modify
    reason: str = ""
    policy_id: Optional[str] = None
    policy_name: Optional[str] = None
    modified_request: Optional[dict[str, Any]] = None
    confirmation_id: Optional[str] = None
    confirmation_message: Optional[str] = None
    risk_score: float = 0.0
    risk_factors: list[str] = Field(default_factory=list)
    evaluation_ms: float = 0.0


# ── Activities ─────────────────────────────────────────────────────────


class ActivityResponse(BaseModel):
    """Single activity response."""

    id: str
    agent_id: str
    session_id: str
    action_id: str
    activity_type: str
    name: str
    target: str = ""
    input_preview: str = ""
    output_preview: str = ""
    duration_ms: int = 0
    status: str = "success"
    policy_result: str = "allowed"
    risk_score: float = 0.0
    cost_usd: float = 0.0
    tokens_input: int = 0
    tokens_output: int = 0
    timestamp: Optional[str] = None


class ActivityListResponse(BaseModel):
    """Paginated list of activities."""

    items: list[ActivityResponse]
    total: int
    page: int
    size: int
    pages: int


# ── Efficiency ─────────────────────────────────────────────────────────


class EfficiencySuggestion(BaseModel):
    """A suggestion to improve agent efficiency."""

    suggestion_type: str
    severity: str = "info"
    title: str
    description: str
    impact: str = ""
    affected_actions: list[str] = Field(default_factory=list)
    recommendation: str = ""


class EfficiencyReport(BaseModel):
    """Efficiency analysis report for an agent."""

    agent_id: str
    analysis_period: str = ""
    generated_at: Optional[str] = None
    overall_score: float = 0.0
    cost_efficiency: float = 0.0
    time_efficiency: float = 0.0
    success_rate: float = 0.0
    security_score: float = 0.0
    total_actions: int = 0
    total_cost_usd: float = 0.0
    total_duration_ms: int = 0
    avg_action_duration_ms: float = 0.0
    redundant_calls: int = 0
    failed_retries: int = 0
    expensive_operations: int = 0
    suggestions: list[EfficiencySuggestion] = Field(default_factory=list)
    top_cost_actions: list[dict[str, Any]] = Field(default_factory=list)
    top_time_actions: list[dict[str, Any]] = Field(default_factory=list)
    top_failure_actions: list[dict[str, Any]] = Field(default_factory=list)
