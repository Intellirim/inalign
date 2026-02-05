"""
Agent Governance SDK - Proxy and policy management.

This module provides the governance layer that intercepts and controls
all agent actions through the InALign platform.
"""

from __future__ import annotations

import time
import uuid
from contextlib import contextmanager
from dataclasses import dataclass, field
from functools import wraps
from typing import Any, Callable, Optional, TypeVar, Generic

import httpx

from inalign.client import BaseClient
from inalign.models import (
    AgentResponse,
    AgentListResponse,
    AgentStatsResponse,
    PolicyResponse,
    PolicyListResponse,
    ProxyResponse,
    ActivityResponse,
    ActivityListResponse,
    EfficiencyReport,
)


F = TypeVar("F", bound=Callable[..., Any])


@dataclass
class SessionContext:
    """Tracks running session state for policy evaluation."""

    session_id: str
    agent_id: str
    action_count: int = 0
    api_calls: int = 0
    file_reads: int = 0
    llm_calls: int = 0
    cost_usd: float = 0.0
    tokens_total: int = 0
    blocked_count: int = 0
    sequence_number: int = 0
    parent_action_id: Optional[str] = None
    _action_stack: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dict for API calls."""
        return {
            "actions_this_session": self.action_count,
            "api_calls_this_minute": self.api_calls,  # Simplified
            "api_calls_this_session": self.api_calls,
            "file_reads_this_session": self.file_reads,
            "llm_calls_this_session": self.llm_calls,
            "cost_this_session_usd": self.cost_usd,
            "tokens_this_session": self.tokens_total,
            "blocked_actions": self.blocked_count,
        }

    def increment(self, action_type: str, cost: float = 0.0, tokens: int = 0) -> None:
        """Increment counters for a new action."""
        self.action_count += 1
        self.sequence_number += 1

        if action_type == "api_call":
            self.api_calls += 1
        elif action_type == "file_access":
            self.file_reads += 1
        elif action_type == "llm_call":
            self.llm_calls += 1

        self.cost_usd += cost
        self.tokens_total += tokens

    def push_action(self, action_id: str) -> None:
        """Push an action onto the stack (for nested calls)."""
        if self._action_stack:
            self.parent_action_id = self._action_stack[-1]
        self._action_stack.append(action_id)

    def pop_action(self) -> None:
        """Pop an action from the stack."""
        if self._action_stack:
            self._action_stack.pop()
        self.parent_action_id = self._action_stack[-1] if self._action_stack else None


class GovernanceClient(BaseClient):
    """Client for Agent Governance features.

    Extends the base InALign client with:
    - Agent registration and management
    - Policy CRUD
    - Action proxy/interception
    - Activity monitoring
    - Efficiency analysis

    Usage::

        from inalign.governance import GovernanceClient

        client = GovernanceClient(api_key="ask_xxx")

        # Register an agent
        agent = client.register_agent(
            agent_id="my-agent",
            name="My AI Agent",
            framework="langchain"
        )

        # Create a session
        with client.session("my-agent", "session-123") as session:
            # Proxy a tool call
            result = session.tool_call(
                tool_name="web_search",
                arguments={"query": "AI news"}
            )
            if result.allowed:
                # Execute the tool
                pass
    """

    def __init__(
        self,
        api_key: str,
        base_url: str = "https://api.inalign.io",
        timeout: int = 30,
        auto_proxy: bool = True,
    ) -> None:
        super().__init__(api_key, base_url, timeout)
        self._client = httpx.Client(
            headers=self._headers,
            timeout=self.timeout,
        )
        self.auto_proxy = auto_proxy

    def __enter__(self) -> "GovernanceClient":
        return self

    def __exit__(self, *args: Any) -> None:
        self.close()

    def close(self) -> None:
        """Close the underlying HTTP client."""
        self._client.close()

    def _request(self, method: str, path: str, **kwargs: Any) -> dict:
        """Make a synchronous HTTP request."""
        url = self._build_url(path)
        response = self._client.request(method, url, **kwargs)
        return self._handle_response(response)

    # ── Agent Management ───────────────────────────────────────────────

    def register_agent(
        self,
        agent_id: str,
        name: str,
        description: str = "",
        framework: str = "custom",
        config: Optional[dict[str, Any]] = None,
    ) -> AgentResponse:
        """Register a new agent.

        Args:
            agent_id: Unique identifier for the agent.
            name: Human-readable name.
            description: Optional description.
            framework: Agent framework (langchain, autogpt, crewai, custom).
            config: Optional configuration dict.

        Returns:
            AgentResponse with the created agent details.
        """
        payload = {
            "agent_id": agent_id,
            "name": name,
            "description": description,
            "framework": framework,
            "config": config or {},
        }
        data = self._request("POST", "/api/v1/agents", json=payload)
        return AgentResponse(**data)

    def get_agent(self, agent_id: str) -> AgentResponse:
        """Get agent details."""
        data = self._request("GET", f"/api/v1/agents/{agent_id}")
        return AgentResponse(**data)

    def list_agents(
        self,
        page: int = 1,
        size: int = 20,
        status: Optional[str] = None,
        framework: Optional[str] = None,
    ) -> AgentListResponse:
        """List all registered agents."""
        params: dict[str, Any] = {"page": page, "size": size}
        if status:
            params["status"] = status
        if framework:
            params["framework"] = framework
        data = self._request("GET", "/api/v1/agents", params=params)
        return AgentListResponse(**data)

    def update_agent(
        self,
        agent_id: str,
        name: Optional[str] = None,
        description: Optional[str] = None,
        status: Optional[str] = None,
        config: Optional[dict[str, Any]] = None,
    ) -> AgentResponse:
        """Update an agent."""
        payload: dict[str, Any] = {}
        if name is not None:
            payload["name"] = name
        if description is not None:
            payload["description"] = description
        if status is not None:
            payload["status"] = status
        if config is not None:
            payload["config"] = config
        data = self._request("PATCH", f"/api/v1/agents/{agent_id}", json=payload)
        return AgentResponse(**data)

    def delete_agent(self, agent_id: str) -> None:
        """Delete an agent."""
        self._request("DELETE", f"/api/v1/agents/{agent_id}")

    def get_agent_stats(self, agent_id: str) -> AgentStatsResponse:
        """Get statistics for an agent."""
        data = self._request("GET", f"/api/v1/agents/{agent_id}/stats")
        return AgentStatsResponse(**data)

    # ── Policy Management ──────────────────────────────────────────────

    def create_policy(
        self,
        name: str,
        rules: dict[str, Any],
        description: str = "",
        agent_id: Optional[str] = None,
        priority: int = 100,
    ) -> PolicyResponse:
        """Create a new policy.

        Args:
            name: Policy name.
            rules: Policy rules dict (permissions, denials, conditions, limits).
            description: Optional description.
            agent_id: Target agent ID (null for global policy).
            priority: Evaluation priority (lower = higher priority).

        Returns:
            PolicyResponse with the created policy.
        """
        payload = {
            "name": name,
            "description": description,
            "agent_id": agent_id,
            "priority": priority,
            "rules": rules,
        }
        data = self._request("POST", "/api/v1/policies", json=payload)
        return PolicyResponse(**data)

    def get_policy(self, policy_id: str) -> PolicyResponse:
        """Get policy details."""
        data = self._request("GET", f"/api/v1/policies/{policy_id}")
        return PolicyResponse(**data)

    def list_policies(
        self,
        page: int = 1,
        size: int = 20,
        agent_id: Optional[str] = None,
        enabled: Optional[bool] = None,
    ) -> PolicyListResponse:
        """List policies."""
        params: dict[str, Any] = {"page": page, "size": size}
        if agent_id:
            params["agent_id"] = agent_id
        if enabled is not None:
            params["enabled"] = enabled
        data = self._request("GET", "/api/v1/policies", params=params)
        return PolicyListResponse(**data)

    def update_policy(
        self,
        policy_id: str,
        name: Optional[str] = None,
        description: Optional[str] = None,
        priority: Optional[int] = None,
        enabled: Optional[bool] = None,
        rules: Optional[dict[str, Any]] = None,
    ) -> PolicyResponse:
        """Update a policy."""
        payload: dict[str, Any] = {}
        if name is not None:
            payload["name"] = name
        if description is not None:
            payload["description"] = description
        if priority is not None:
            payload["priority"] = priority
        if enabled is not None:
            payload["enabled"] = enabled
        if rules is not None:
            payload["rules"] = rules
        data = self._request("PATCH", f"/api/v1/policies/{policy_id}", json=payload)
        return PolicyResponse(**data)

    def delete_policy(self, policy_id: str) -> None:
        """Delete a policy."""
        self._request("DELETE", f"/api/v1/policies/{policy_id}")

    def get_default_policy_template(self) -> dict[str, Any]:
        """Get the default policy rules template."""
        return self._request("GET", "/api/v1/policies/templates/default")

    # ── Session Management ─────────────────────────────────────────────

    @contextmanager
    def session(self, agent_id: str, session_id: Optional[str] = None):
        """Create a governed session context.

        All actions within this context will be proxied through InALign.

        Args:
            agent_id: The agent ID.
            session_id: Optional session ID (auto-generated if not provided).

        Yields:
            GovernedSession instance for proxying actions.
        """
        if not session_id:
            session_id = f"sess-{uuid.uuid4().hex[:12]}"

        session = GovernedSession(
            client=self,
            agent_id=agent_id,
            session_id=session_id,
        )
        try:
            yield session
        finally:
            pass  # Session cleanup if needed

    # ── Activity Monitoring ────────────────────────────────────────────

    def list_activities(
        self,
        agent_id: Optional[str] = None,
        session_id: Optional[str] = None,
        activity_type: Optional[str] = None,
        status: Optional[str] = None,
        page: int = 1,
        size: int = 50,
    ) -> ActivityListResponse:
        """List agent activities."""
        params: dict[str, Any] = {"page": page, "size": size}
        if agent_id:
            params["agent_id"] = agent_id
        if session_id:
            params["session_id"] = session_id
        if activity_type:
            params["activity_type"] = activity_type
        if status:
            params["status"] = status
        data = self._request("GET", "/api/v1/activities", params=params)
        return ActivityListResponse(**data)

    def get_activity(self, action_id: str) -> ActivityResponse:
        """Get activity details."""
        data = self._request("GET", f"/api/v1/activities/{action_id}")
        return ActivityResponse(**data)

    # ── Efficiency Analysis ────────────────────────────────────────────

    def get_efficiency_report(
        self,
        agent_id: str,
        days: int = 7,
    ) -> EfficiencyReport:
        """Get efficiency analysis report for an agent."""
        params = {"days": days}
        data = self._request("GET", f"/api/v1/activities/efficiency/{agent_id}", params=params)
        return EfficiencyReport(**data)


class GovernedSession:
    """A governed session that proxies all agent actions.

    Use this within a `GovernanceClient.session()` context to have
    all actions evaluated against policies before execution.
    """

    def __init__(
        self,
        client: GovernanceClient,
        agent_id: str,
        session_id: str,
    ) -> None:
        self._client = client
        self.agent_id = agent_id
        self.session_id = session_id
        self.context = SessionContext(session_id=session_id, agent_id=agent_id)

    def _proxy_action(
        self,
        action_type: str,
        action_data: dict[str, Any],
    ) -> ProxyResponse:
        """Send action to proxy for evaluation."""
        action_id = f"act-{uuid.uuid4().hex[:12]}"
        self.context.push_action(action_id)

        payload = {
            "agent_id": self.agent_id,
            "session_id": self.session_id,
            "action_id": action_id,
            "action_type": action_type,
            **action_data,
            "parent_action_id": self.context.parent_action_id,
            "sequence_number": self.context.sequence_number,
            "session_context": self.context.to_dict(),
        }

        data = self._client._request("POST", "/api/v1/proxy/evaluate", json=payload)
        response = ProxyResponse(**data)

        # Update context
        self.context.increment(action_type)
        if not response.allowed:
            self.context.blocked_count += 1

        return response

    def _complete_action(
        self,
        action_id: str,
        status: str,
        duration_ms: int = 0,
        output_preview: str = "",
        cost_usd: float = 0.0,
        tokens_input: int = 0,
        tokens_output: int = 0,
        error: str = "",
    ) -> None:
        """Report action completion."""
        self.context.pop_action()

        params = {
            "agent_id": self.agent_id,
            "session_id": self.session_id,
            "action_id": action_id,
            "status": status,
            "duration_ms": duration_ms,
            "output_preview": output_preview[:1000] if output_preview else "",
            "output_size": len(output_preview) if output_preview else 0,
            "cost_usd": cost_usd,
            "tokens_input": tokens_input,
            "tokens_output": tokens_output,
            "error": error,
        }

        try:
            self._client._request("POST", "/api/v1/proxy/complete", params=params)
        except Exception:
            pass  # Best-effort completion reporting

        # Update context with costs
        if cost_usd > 0:
            self.context.cost_usd += cost_usd
        if tokens_input + tokens_output > 0:
            self.context.tokens_total += tokens_input + tokens_output

    def tool_call(
        self,
        tool_name: str,
        arguments: dict[str, Any],
        metadata: Optional[dict[str, Any]] = None,
    ) -> ProxyResponse:
        """Evaluate a tool call before execution.

        Args:
            tool_name: Name of the tool being called.
            arguments: Tool arguments.
            metadata: Optional metadata.

        Returns:
            ProxyResponse indicating if the call is allowed.
        """
        return self._proxy_action(
            action_type="tool_call",
            action_data={
                "tool_call": {
                    "tool_name": tool_name,
                    "arguments": arguments,
                    "metadata": metadata or {},
                }
            },
        )

    def api_call(
        self,
        method: str,
        url: str,
        headers: Optional[dict[str, str]] = None,
        body: Any = None,
        metadata: Optional[dict[str, Any]] = None,
    ) -> ProxyResponse:
        """Evaluate an API call before execution.

        Args:
            method: HTTP method (GET, POST, etc.).
            url: Full URL to call.
            headers: Optional headers.
            body: Optional request body.
            metadata: Optional metadata.

        Returns:
            ProxyResponse indicating if the call is allowed.
        """
        return self._proxy_action(
            action_type="api_call",
            action_data={
                "api_call": {
                    "method": method,
                    "url": url,
                    "headers": headers or {},
                    "body": body,
                    "metadata": metadata or {},
                }
            },
        )

    def file_access(
        self,
        operation: str,
        path: str,
        content: Optional[str] = None,
        metadata: Optional[dict[str, Any]] = None,
    ) -> ProxyResponse:
        """Evaluate a file access before execution.

        Args:
            operation: Operation type (read, write, delete, list).
            path: File or directory path.
            content: Content for write operations.
            metadata: Optional metadata.

        Returns:
            ProxyResponse indicating if the access is allowed.
        """
        return self._proxy_action(
            action_type="file_access",
            action_data={
                "file_access": {
                    "operation": operation,
                    "path": path,
                    "content": content,
                    "metadata": metadata or {},
                }
            },
        )

    def llm_call(
        self,
        model: str,
        messages: list[dict[str, Any]],
        temperature: float = 0.7,
        max_tokens: Optional[int] = None,
        tools: Optional[list[dict[str, Any]]] = None,
        metadata: Optional[dict[str, Any]] = None,
    ) -> ProxyResponse:
        """Evaluate an LLM call before execution.

        Args:
            model: Model name/identifier.
            messages: Message list.
            temperature: Sampling temperature.
            max_tokens: Max tokens to generate.
            tools: Available tools for the model.
            metadata: Optional metadata.

        Returns:
            ProxyResponse indicating if the call is allowed.
        """
        return self._proxy_action(
            action_type="llm_call",
            action_data={
                "llm_call": {
                    "model": model,
                    "messages": messages,
                    "temperature": temperature,
                    "max_tokens": max_tokens,
                    "tools": tools or [],
                    "metadata": metadata or {},
                }
            },
        )

    def generic_action(
        self,
        action_type: str,
        action_data: dict[str, Any],
    ) -> ProxyResponse:
        """Evaluate a generic action.

        Args:
            action_type: Custom action type.
            action_data: Action-specific data.

        Returns:
            ProxyResponse indicating if the action is allowed.
        """
        return self._proxy_action(
            action_type=action_type,
            action_data={"action_data": action_data},
        )

    def execute_with_governance(
        self,
        action_type: str,
        action_data: dict[str, Any],
        executor: Callable[[], Any],
    ) -> tuple[ProxyResponse, Any]:
        """Evaluate and execute an action with full governance.

        Args:
            action_type: Type of action.
            action_data: Action details for proxy.
            executor: Callable that executes the actual action.

        Returns:
            Tuple of (ProxyResponse, execution result or None if blocked).
        """
        # Evaluate
        response = self._proxy_action(action_type, action_data)

        if not response.allowed:
            return response, None

        # Execute
        start_time = time.perf_counter()
        result = None
        status = "success"
        error = ""

        try:
            result = executor()
        except Exception as e:
            status = "failure"
            error = str(e)
            raise
        finally:
            duration_ms = int((time.perf_counter() - start_time) * 1000)
            self._complete_action(
                action_id=response.action_id,
                status=status,
                duration_ms=duration_ms,
                error=error,
            )

        return response, result


def governed(
    client: GovernanceClient,
    agent_id: str,
    action_type: str = "tool_call",
) -> Callable[[F], F]:
    """Decorator to add governance to a function.

    Usage::

        @governed(client, "my-agent", "tool_call")
        def search_web(query: str) -> str:
            # Your implementation
            pass

    Args:
        client: GovernanceClient instance.
        agent_id: Agent ID to use.
        action_type: Type of action for this function.

    Returns:
        Decorated function with governance.
    """
    def decorator(func: F) -> F:
        @wraps(func)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            # Create a temporary session
            session_id = f"sess-{uuid.uuid4().hex[:12]}"
            session = GovernedSession(client, agent_id, session_id)

            # Build action data from function call
            action_data = {
                "tool_call" if action_type == "tool_call" else "action_data": {
                    "tool_name" if action_type == "tool_call" else "name": func.__name__,
                    "arguments" if action_type == "tool_call" else "parameters": kwargs or dict(zip(func.__code__.co_varnames, args)),
                }
            }

            # Evaluate
            response = session._proxy_action(action_type, action_data)

            if not response.allowed:
                raise PermissionError(
                    f"Action blocked by policy: {response.reason}"
                )

            # Execute
            start_time = time.perf_counter()
            try:
                result = func(*args, **kwargs)
                duration_ms = int((time.perf_counter() - start_time) * 1000)
                session._complete_action(
                    response.action_id, "success", duration_ms
                )
                return result
            except Exception as e:
                duration_ms = int((time.perf_counter() - start_time) * 1000)
                session._complete_action(
                    response.action_id, "failure", duration_ms, error=str(e)
                )
                raise

        return wrapper  # type: ignore
    return decorator
