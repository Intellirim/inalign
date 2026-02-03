"""Proxy request/response schemas for intercepting agent actions."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field

__all__ = [
    "ProxyRequest",
    "ProxyResponse",
    "ProxyToolCall",
    "ProxyAPICall",
    "ProxyFileAccess",
    "ProxyLLMCall",
    "ConfirmationRequest",
    "ConfirmationResponse",
]


class ProxyToolCall(BaseModel):
    """Tool call to be proxied and evaluated."""

    tool_name: str = Field(..., description="Name of the tool being called")
    arguments: dict[str, Any] = Field(default_factory=dict)
    metadata: dict[str, Any] = Field(default_factory=dict)


class ProxyAPICall(BaseModel):
    """API call to be proxied and evaluated."""

    method: str = Field(..., description="HTTP method")
    url: str = Field(..., description="Full URL")
    headers: dict[str, str] = Field(default_factory=dict)
    body: Any = Field(default=None)
    metadata: dict[str, Any] = Field(default_factory=dict)


class ProxyFileAccess(BaseModel):
    """File access to be proxied and evaluated."""

    operation: str = Field(..., description="read, write, delete, list")
    path: str = Field(..., description="File or directory path")
    content: str | None = Field(default=None, description="Content for write ops")
    metadata: dict[str, Any] = Field(default_factory=dict)


class ProxyLLMCall(BaseModel):
    """LLM call to be proxied and evaluated."""

    model: str = Field(..., description="Model name")
    messages: list[dict[str, Any]] = Field(..., description="Messages")
    temperature: float = Field(default=0.7)
    max_tokens: int | None = Field(default=None)
    tools: list[dict[str, Any]] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)


class ProxyRequest(BaseModel):
    """Unified proxy request for any agent action.

    The SDK sends this before executing any tool/API/file/LLM operation.
    AgentShield evaluates policies and returns whether to proceed.
    """

    agent_id: str = Field(..., description="Agent performing the action")
    session_id: str = Field(..., description="Current session")
    action_id: str = Field(..., description="Unique ID for this action")
    action_type: str = Field(
        ...,
        description="tool_call, api_call, file_access, llm_call, memory_op, code_exec",
    )

    # One of these will be populated based on action_type
    tool_call: ProxyToolCall | None = Field(default=None)
    api_call: ProxyAPICall | None = Field(default=None)
    file_access: ProxyFileAccess | None = Field(default=None)
    llm_call: ProxyLLMCall | None = Field(default=None)

    # Generic fallback
    action_data: dict[str, Any] = Field(
        default_factory=dict,
        description="Generic action data for custom types",
    )

    # Context
    parent_action_id: str | None = Field(default=None)
    sequence_number: int = Field(default=0)
    session_context: dict[str, Any] = Field(
        default_factory=dict,
        description="Running totals: cost, action counts, etc.",
    )

    # Timing
    timestamp: datetime | None = Field(default=None)


class ProxyResponse(BaseModel):
    """Response from proxy evaluation.

    Tells the SDK whether to proceed, block, or request confirmation.
    """

    request_id: str
    action_id: str

    # Decision
    allowed: bool = Field(..., description="Whether the action can proceed")
    action: str = Field(
        default="allow",
        description="allow, block, warn, require_confirmation, modify",
    )

    # If blocked or warned
    reason: str = Field(default="")
    policy_id: str | None = Field(default=None)
    policy_name: str | None = Field(default=None)

    # If modified (sanitized parameters, redacted content, etc.)
    modified_request: dict[str, Any] | None = Field(default=None)

    # If require_confirmation
    confirmation_id: str | None = Field(default=None)
    confirmation_message: str | None = Field(default=None)

    # Risk assessment
    risk_score: float = Field(default=0.0, ge=0, le=1)
    risk_factors: list[str] = Field(default_factory=list)

    # Latency
    evaluation_ms: float = Field(default=0.0)


class ConfirmationRequest(BaseModel):
    """Request user confirmation for a pending action."""

    confirmation_id: str
    agent_id: str
    session_id: str
    action_id: str
    action_type: str
    action_summary: str
    reason: str
    risk_score: float
    policy_name: str


class ConfirmationResponse(BaseModel):
    """User's response to a confirmation request."""

    confirmation_id: str
    approved: bool
    note: str = Field(default="")
    responded_by: str = Field(default="user")
    responded_at: datetime | None = Field(default=None)
