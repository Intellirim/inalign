"""Policy request/response schemas."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field

__all__ = [
    "PolicyRules",
    "PolicyCreate",
    "PolicyUpdate",
    "PolicyResponse",
    "PolicyListResponse",
    "PolicyEvalRequest",
    "PolicyEvalResponse",
    "PolicyViolationResponse",
    "DEFAULT_POLICY_RULES",
]


# Default policy rules structure
DEFAULT_POLICY_RULES: dict[str, Any] = {
    "permissions": {
        "tools": ["*"],  # All tools allowed by default
        "apis": ["*"],
        "files": ["*"],
        "actions": ["read", "write", "execute"],
    },
    "denials": {
        "tools": [],
        "apis": [],
        "files": [
            "/etc/passwd",
            "/etc/shadow",
            "~/.ssh/*",
            "*.env",
            "*credentials*",
            "*secret*",
        ],
        "keywords": ["password", "secret", "api_key", "private_key", "credential"],
    },
    "conditions": [],
    "limits": {
        "max_api_calls_per_minute": 100,
        "max_file_reads_per_session": 500,
        "max_cost_per_session_usd": 10.0,
        "max_actions_per_session": 1000,
    },
}


class PermissionRules(BaseModel):
    """What is allowed."""

    tools: list[str] = Field(default_factory=lambda: ["*"])
    apis: list[str] = Field(default_factory=lambda: ["*"])
    files: list[str] = Field(default_factory=lambda: ["*"])
    actions: list[str] = Field(default_factory=lambda: ["read", "write", "execute"])


class DenialRules(BaseModel):
    """What is explicitly denied (overrides permissions)."""

    tools: list[str] = Field(default_factory=list)
    apis: list[str] = Field(default_factory=list)
    files: list[str] = Field(default_factory=list)
    keywords: list[str] = Field(default_factory=list)


class ConditionRule(BaseModel):
    """Conditional rule: if condition met, apply action."""

    if_: dict[str, Any] = Field(..., alias="if")
    then: str = Field(..., description="Action: require_confirmation, block, warn, log")
    message: str = Field(default="", description="Message to show user")

    class Config:
        populate_by_name = True


class LimitRules(BaseModel):
    """Rate and resource limits."""

    max_api_calls_per_minute: int = Field(default=100, ge=0)
    max_file_reads_per_session: int = Field(default=500, ge=0)
    max_cost_per_session_usd: float = Field(default=10.0, ge=0)
    max_actions_per_session: int = Field(default=1000, ge=0)
    max_tokens_per_session: int = Field(default=100000, ge=0)


class PolicyRules(BaseModel):
    """Complete policy rules structure."""

    permissions: PermissionRules = Field(default_factory=PermissionRules)
    denials: DenialRules = Field(default_factory=DenialRules)
    conditions: list[ConditionRule] = Field(default_factory=list)
    limits: LimitRules = Field(default_factory=LimitRules)


class PolicyCreate(BaseModel):
    """Request to create a new policy."""

    name: str = Field(..., min_length=1, max_length=256)
    description: str = Field(default="", max_length=2048)
    agent_id: str | None = Field(
        default=None,
        description="Target agent ID. If null, applies to all user's agents.",
    )
    priority: int = Field(default=100, ge=0, le=1000)
    rules: PolicyRules = Field(default_factory=PolicyRules)


class PolicyUpdate(BaseModel):
    """Request to update a policy."""

    name: str | None = Field(default=None, max_length=256)
    description: str | None = Field(default=None, max_length=2048)
    priority: int | None = Field(default=None, ge=0, le=1000)
    enabled: bool | None = Field(default=None)
    rules: PolicyRules | None = Field(default=None)


class PolicyResponse(BaseModel):
    """Policy details response."""

    id: str
    name: str
    description: str
    agent_id: str | None
    user_id: str
    priority: int
    enabled: bool
    policy_type: str
    rules: dict[str, Any]
    version: int
    violation_count: int
    created_at: datetime
    updated_at: datetime
    last_evaluated_at: datetime | None


class PolicyListResponse(BaseModel):
    """Paginated list of policies."""

    items: list[PolicyResponse]
    total: int
    page: int
    size: int
    pages: int


class PolicyEvalRequest(BaseModel):
    """Request to evaluate an action against policies."""

    agent_id: str = Field(..., description="Agent performing the action")
    session_id: str = Field(..., description="Current session")
    action_type: str = Field(
        ...,
        description="Type: tool_call, api_call, file_access, llm_call, etc.",
    )
    action_name: str = Field(..., description="Name of the action/tool")
    target: str = Field(default="", description="Target resource")
    parameters: dict[str, Any] = Field(default_factory=dict)
    context: dict[str, Any] = Field(
        default_factory=dict,
        description="Session context (costs, counts, etc.)",
    )


class PolicyEvalResponse(BaseModel):
    """Result of policy evaluation."""

    allowed: bool = Field(..., description="Whether the action is allowed")
    action: str = Field(
        default="allow",
        description="allow, block, warn, require_confirmation",
    )
    reason: str = Field(default="", description="Reason if denied/warned")
    matched_policy_id: str | None = Field(default=None)
    matched_policy_name: str | None = Field(default=None)
    matched_rule: dict[str, Any] | None = Field(default=None)
    violations: list[dict[str, Any]] = Field(default_factory=list)


class PolicyViolationResponse(BaseModel):
    """A policy violation record."""

    id: str
    policy_id: str
    policy_name: str
    agent_id: str
    session_id: str
    action_id: str
    violation_type: str
    severity: str
    attempted_action: dict[str, Any]
    violated_rule: dict[str, Any]
    action_taken: str
    notes: str
    created_at: datetime
