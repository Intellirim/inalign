"""
Pydantic models for Neo4j graph nodes, edges, and composite subgraph data.

These models serve as the canonical schema for data flowing between the
Neo4j graph layer and the rest of the AgentShield backend.  They are used
for serialisation/deserialisation, API responses, and input validation.
"""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field

# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class SessionStatus(str, Enum):
    """Lifecycle states for a monitored session."""

    ACTIVE = "active"
    FLAGGED = "flagged"
    CLOSED = "closed"
    ARCHIVED = "archived"


class ThreatSeverity(str, Enum):
    """Standardised severity levels aligned with CVSS qualitative ratings."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ActionType(str, Enum):
    """Well-known action types observed in agent sessions."""

    LLM_CALL = "llm_call"
    TOOL_CALL = "tool_call"
    API_REQUEST = "api_request"
    FILE_ACCESS = "file_access"
    DB_QUERY = "db_query"
    CODE_EXEC = "code_exec"
    MEMORY_READ = "memory_read"
    MEMORY_WRITE = "memory_write"
    USER_INPUT = "user_input"
    AGENT_RESPONSE = "agent_response"
    PLUGIN_CALL = "plugin_call"
    OTHER = "other"


# ---------------------------------------------------------------------------
# Node models
# ---------------------------------------------------------------------------


class AgentNode(BaseModel):
    """Represents an AI agent registered in the system."""

    agent_id: str = Field(..., description="Unique identifier for the agent")
    name: str = Field(..., max_length=256, description="Human-readable agent name")
    description: str = Field(default="", max_length=2048)
    owner: str = Field(default="", max_length=256, description="Owner or team")
    created_at: datetime | None = Field(default=None)
    updated_at: datetime | None = Field(default=None)
    metadata: str = Field(
        default="{}",
        description="JSON-serialised metadata (Neo4j stores strings natively)",
    )

    class Config:
        from_attributes = True


class SessionNode(BaseModel):
    """A monitored interaction session between a user and an agent."""

    session_id: str = Field(..., description="Unique session identifier")
    agent_id: str = Field(..., description="Owning agent identifier")
    user_id: str = Field(default="", description="End-user or caller identifier")
    status: SessionStatus = Field(default=SessionStatus.ACTIVE)
    risk_score: float = Field(default=0.0, ge=0.0, le=1.0)
    started_at: datetime | None = Field(default=None)
    updated_at: datetime | None = Field(default=None)
    metadata: str = Field(default="{}")

    class Config:
        from_attributes = True


class ActionNode(BaseModel):
    """A single action (step) within an agent session."""

    action_id: str = Field(..., description="Unique action identifier")
    session_id: str = Field(..., description="Parent session identifier")
    action_type: ActionType = Field(default=ActionType.OTHER)
    input: str = Field(default="", description="Serialised action input")
    output: str = Field(default="", description="Serialised action output")
    risk_score: float = Field(default=0.0, ge=0.0, le=1.0)
    latency_ms: float = Field(default=0.0, ge=0.0, description="Execution time in ms")
    timestamp: datetime | None = Field(default=None)
    metadata: str = Field(default="{}")

    class Config:
        from_attributes = True


class ThreatNode(BaseModel):
    """A detected threat linked to a specific action."""

    threat_id: str = Field(..., description="Unique threat identifier")
    threat_type: str = Field(..., max_length=256, description="E.g. prompt_injection, pii_leak")
    severity: ThreatSeverity = Field(default=ThreatSeverity.MEDIUM)
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    description: str = Field(default="", max_length=4096)
    detector: str = Field(default="", max_length=256, description="Detector module name")
    detected_at: datetime | None = Field(default=None)
    metadata: str = Field(default="{}")

    class Config:
        from_attributes = True


class AttackSignatureNode(BaseModel):
    """A known attack signature used for pattern matching."""

    signature_id: str = Field(..., description="Unique signature identifier")
    name: str = Field(..., max_length=256)
    pattern: str = Field(..., description="Regex or structured pattern")
    category: str = Field(default="", max_length=128)
    severity: ThreatSeverity = Field(default=ThreatSeverity.MEDIUM)
    description: str = Field(default="", max_length=4096)
    enabled: bool = Field(default=True)
    created_at: datetime | None = Field(default=None)
    updated_at: datetime | None = Field(default=None)
    metadata: str = Field(default="{}")

    class Config:
        from_attributes = True


# ---------------------------------------------------------------------------
# Edge models
# ---------------------------------------------------------------------------


class SessionContainsEdge(BaseModel):
    """Edge: (Session)-[:CONTAINS]->(Action)."""

    session_id: str
    action_id: str

    class Config:
        from_attributes = True


class ActionFollowedByEdge(BaseModel):
    """Edge: (Action)-[:FOLLOWED_BY]->(Action) representing temporal order."""

    from_action_id: str
    to_action_id: str
    delay_ms: float = Field(default=0.0, ge=0.0)

    class Config:
        from_attributes = True


class ActionTriggeredEdge(BaseModel):
    """Edge: (Action)-[:TRIGGERED]->(Threat)."""

    action_id: str
    threat_id: str

    class Config:
        from_attributes = True


class SessionMatchesEdge(BaseModel):
    """Edge: (Session)-[:MATCHES]->(AttackSignature) for detected patterns."""

    session_id: str
    signature_id: str
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    matched_at: datetime | None = Field(default=None)

    class Config:
        from_attributes = True


# ---------------------------------------------------------------------------
# Composite graph data container
# ---------------------------------------------------------------------------


class GraphData(BaseModel):
    """
    Container for a complete or partial subgraph returned from Neo4j.

    Typically represents all nodes and edges for a single session, but can
    also hold multi-session query results.
    """

    sessions: list[SessionNode] = Field(default_factory=list)
    agents: list[AgentNode] = Field(default_factory=list)
    actions: list[ActionNode] = Field(default_factory=list)
    threats: list[ThreatNode] = Field(default_factory=list)
    attack_signatures: list[AttackSignatureNode] = Field(default_factory=list)

    contains_edges: list[SessionContainsEdge] = Field(default_factory=list)
    followed_by_edges: list[ActionFollowedByEdge] = Field(default_factory=list)
    triggered_edges: list[ActionTriggeredEdge] = Field(default_factory=list)
    matches_edges: list[SessionMatchesEdge] = Field(default_factory=list)

    class Config:
        from_attributes = True

    # -- Convenience helpers ------------------------------------------------

    @property
    def total_actions(self) -> int:
        """Return the number of action nodes in this subgraph."""
        return len(self.actions)

    @property
    def total_threats(self) -> int:
        """Return the number of threat nodes in this subgraph."""
        return len(self.threats)

    @property
    def action_type_counts(self) -> dict[str, int]:
        """Return a mapping of action_type -> count."""
        counts: dict[str, int] = {}
        for action in self.actions:
            key = action.action_type.value if isinstance(action.action_type, Enum) else str(action.action_type)
            counts[key] = counts.get(key, 0) + 1
        return counts

    def merge(self, other: GraphData) -> GraphData:
        """Return a new ``GraphData`` combining *self* and *other* (no dedup)."""
        return GraphData(
            sessions=self.sessions + other.sessions,
            agents=self.agents + other.agents,
            actions=self.actions + other.actions,
            threats=self.threats + other.threats,
            attack_signatures=self.attack_signatures + other.attack_signatures,
            contains_edges=self.contains_edges + other.contains_edges,
            followed_by_edges=self.followed_by_edges + other.followed_by_edges,
            triggered_edges=self.triggered_edges + other.triggered_edges,
            matches_edges=self.matches_edges + other.matches_edges,
        )
