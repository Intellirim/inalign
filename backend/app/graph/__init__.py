"""
Graph layer for AgentShield.

Provides the Neo4j async client and Pydantic graph node/edge models used
throughout the application for session tracking, threat detection, and
behavioural analysis.
"""

from __future__ import annotations

from app.graph.models import (
    ActionFollowedByEdge,
    ActionNode,
    ActionTriggeredEdge,
    ActionType,
    AgentNode,
    AttackSignatureNode,
    GraphData,
    SessionContainsEdge,
    SessionMatchesEdge,
    SessionNode,
    SessionStatus,
    ThreatNode,
    ThreatSeverity,
)
from app.graph.neo4j_client import Neo4jClient

__all__: list[str] = [
    # Client
    "Neo4jClient",
    # Node models
    "AgentNode",
    "SessionNode",
    "ActionNode",
    "ThreatNode",
    "AttackSignatureNode",
    # Edge models
    "SessionContainsEdge",
    "ActionFollowedByEdge",
    "ActionTriggeredEdge",
    "SessionMatchesEdge",
    # Composite
    "GraphData",
    # Enums
    "SessionStatus",
    "ActionType",
    "ThreatSeverity",
]
