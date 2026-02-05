"""
AutoGPT integration for InALign.

Provides middleware and hooks that automatically proxy all AutoGPT
agent actions through InALign for governance.

AutoGPT is an autonomous agent framework that can execute multi-step tasks.
This integration ensures all commands and actions are policy-checked.

Usage:
    from inalign.integrations.autogpt import (
        InALignMiddleware,
        govern_command,
    )

    # Option 1: Use middleware in AutoGPT configuration
    middleware = InALignMiddleware(api_key="ask_xxx")

    # Option 2: Wrap individual commands
    @govern_command(api_key="ask_xxx", command_name="web_search")
    def web_search(query: str) -> str:
        return do_search(query)
"""
from __future__ import annotations

import functools
import time
import uuid
from dataclasses import dataclass
from typing import Any, Callable, Optional

from inalign.governance import GovernanceClient, GovernedSession


@dataclass
class CommandResult:
    """Result of a governed command execution."""
    success: bool
    output: Any
    blocked: bool = False
    block_reason: str = ""
    duration_ms: int = 0


class InALignMiddleware:
    """
    Middleware for AutoGPT that adds InALign governance.

    This middleware intercepts all command executions and:
    1. Checks them against InALign policies
    2. Blocks unauthorized actions
    3. Logs all activity for monitoring

    Usage in AutoGPT:
        from inalign.integrations.autogpt import InALignMiddleware

        middleware = InALignMiddleware(
            api_key="ask_xxx",
            agent_id="my-autogpt-agent",
        )

        # Before executing any command
        result = middleware.before_command(
            command_name="web_search",
            arguments={"query": "latest news"},
        )
        if not result.allowed:
            # Handle blocked command
            pass

        # After command execution
        middleware.after_command(
            command_name="web_search",
            success=True,
            output="Search results...",
        )
    """

    def __init__(
        self,
        api_key: str,
        agent_id: str = "autogpt-agent",
        session_id: Optional[str] = None,
        base_url: str = "https://api.inalign.io",
        block_on_violation: bool = True,
    ):
        """Initialize the middleware.

        Args:
            api_key: InALign API key
            agent_id: The agent ID registered in InALign
            session_id: Optional session ID (auto-generated if not provided)
            base_url: InALign API base URL
            block_on_violation: Whether to block on policy violations
        """
        self.client = GovernanceClient(api_key=api_key, base_url=base_url)
        self.agent_id = agent_id
        self.session_id = session_id or f"autogpt-{uuid.uuid4().hex[:12]}"
        self.block_on_violation = block_on_violation

        self._session = GovernedSession(
            client=self.client,
            agent_id=agent_id,
            session_id=self.session_id,
        )

        # Track current command for after_command correlation
        self._current_action_id: Optional[str] = None
        self._current_start_time: Optional[float] = None

    def before_command(
        self,
        command_name: str,
        arguments: dict[str, Any],
        metadata: Optional[dict[str, Any]] = None,
    ) -> "CommandCheckResult":
        """
        Check a command before execution.

        Args:
            command_name: Name of the command to execute
            arguments: Command arguments
            metadata: Optional additional metadata

        Returns:
            CommandCheckResult with allowed status and reason
        """
        self._current_start_time = time.perf_counter()

        # Check with InALign
        response = self._session.tool_call(
            tool_name=command_name,
            arguments=arguments,
            metadata=metadata or {},
        )

        self._current_action_id = response.action_id

        return CommandCheckResult(
            allowed=response.allowed,
            reason=response.reason if not response.allowed else "",
            action_id=response.action_id,
            risk_score=getattr(response, "risk_score", 0.0),
        )

    def after_command(
        self,
        command_name: str,
        success: bool,
        output: Any = None,
        error: Optional[str] = None,
    ) -> None:
        """
        Report command completion.

        Args:
            command_name: Name of the executed command
            success: Whether the command succeeded
            output: Command output (if successful)
            error: Error message (if failed)
        """
        if not self._current_action_id or not self._current_start_time:
            return

        duration_ms = int((time.perf_counter() - self._current_start_time) * 1000)

        self._session._complete_action(
            action_id=self._current_action_id,
            status="success" if success else "failure",
            duration_ms=duration_ms,
            output_preview=str(output)[:500] if output else "",
            error=error,
        )

        self._current_action_id = None
        self._current_start_time = None

    def execute_command(
        self,
        command_name: str,
        command_func: Callable,
        arguments: dict[str, Any],
        metadata: Optional[dict[str, Any]] = None,
    ) -> CommandResult:
        """
        Execute a command with full governance lifecycle.

        This is a convenience method that handles before/after automatically.

        Args:
            command_name: Name of the command
            command_func: The function to execute
            arguments: Arguments to pass to the function
            metadata: Optional metadata

        Returns:
            CommandResult with execution details
        """
        # Check before
        check = self.before_command(command_name, arguments, metadata)

        if not check.allowed:
            if self.block_on_violation:
                return CommandResult(
                    success=False,
                    output=None,
                    blocked=True,
                    block_reason=check.reason,
                )
            # Log warning but continue
            print(f"[InALign] Warning: Command '{command_name}' would be blocked: {check.reason}")

        # Execute
        start = time.perf_counter()
        try:
            output = command_func(**arguments)

            self.after_command(command_name, success=True, output=output)

            return CommandResult(
                success=True,
                output=output,
                blocked=False,
                duration_ms=int((time.perf_counter() - start) * 1000),
            )

        except Exception as e:
            self.after_command(command_name, success=False, error=str(e))

            return CommandResult(
                success=False,
                output=None,
                blocked=False,
                duration_ms=int((time.perf_counter() - start) * 1000),
            )

    def log_thought(self, thought: str) -> None:
        """Log an agent thought/reasoning step."""
        self._session._log_event(
            event_type="agent_thought",
            details={"thought": thought[:1000]},
        )

    def log_plan(self, plan: list[str]) -> None:
        """Log an agent's plan."""
        self._session._log_event(
            event_type="agent_plan",
            details={"steps": plan[:20]},
        )

    def log_memory_access(
        self,
        memory_type: str,
        action: str,
        content: str,
    ) -> None:
        """Log memory access (read/write)."""
        self._session._log_event(
            event_type="memory_access",
            details={
                "memory_type": memory_type,
                "action": action,
                "content_preview": content[:200],
            },
        )


@dataclass
class CommandCheckResult:
    """Result of checking a command against policies."""
    allowed: bool
    reason: str
    action_id: str
    risk_score: float = 0.0


def govern_command(
    api_key: str,
    command_name: str,
    agent_id: str = "autogpt-agent",
    base_url: str = "https://api.inalign.io",
    block_on_violation: bool = True,
) -> Callable:
    """
    Decorator to add InALign governance to an AutoGPT command.

    Usage:
        @govern_command(api_key="ask_xxx", command_name="web_search")
        def web_search(query: str) -> str:
            return do_search(query)
    """
    middleware = InALignMiddleware(
        api_key=api_key,
        agent_id=agent_id,
        base_url=base_url,
        block_on_violation=block_on_violation,
    )

    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            # Build arguments dict
            arguments = kwargs.copy()

            # Check before execution
            check = middleware.before_command(command_name, arguments)

            if not check.allowed:
                if block_on_violation:
                    raise PermissionError(
                        f"InALign blocked command '{command_name}': {check.reason}"
                    )

            # Execute
            try:
                result = func(*args, **kwargs)
                middleware.after_command(command_name, success=True, output=result)
                return result

            except Exception as e:
                middleware.after_command(command_name, success=False, error=str(e))
                raise

        return wrapper

    return decorator


class GovernedCommandRegistry:
    """
    Registry for governed AutoGPT commands.

    Usage:
        registry = GovernedCommandRegistry(api_key="ask_xxx")

        @registry.command("web_search", "Search the web")
        def web_search(query: str) -> str:
            return do_search(query)

        # Execute with governance
        result = registry.execute("web_search", query="latest news")
    """

    def __init__(
        self,
        api_key: str,
        agent_id: str = "autogpt-agent",
        base_url: str = "https://api.inalign.io",
        block_on_violation: bool = True,
    ):
        self._middleware = InALignMiddleware(
            api_key=api_key,
            agent_id=agent_id,
            base_url=base_url,
            block_on_violation=block_on_violation,
        )
        self._commands: dict[str, tuple[Callable, str]] = {}

    def command(self, name: str, description: str = "") -> Callable:
        """Decorator to register a governed command."""
        def decorator(func: Callable) -> Callable:
            self._commands[name] = (func, description)

            @functools.wraps(func)
            def wrapper(*args: Any, **kwargs: Any) -> Any:
                return self.execute(name, *args, **kwargs)

            return wrapper

        return decorator

    def execute(self, command_name: str, *args: Any, **kwargs: Any) -> CommandResult:
        """Execute a registered command with governance."""
        if command_name not in self._commands:
            return CommandResult(
                success=False,
                output=None,
                blocked=True,
                block_reason=f"Unknown command: {command_name}",
            )

        func, _ = self._commands[command_name]

        return self._middleware.execute_command(
            command_name=command_name,
            command_func=lambda **kw: func(*args, **kw),
            arguments=kwargs,
        )

    def list_commands(self) -> list[dict[str, str]]:
        """List all registered commands."""
        return [
            {"name": name, "description": desc}
            for name, (_, desc) in self._commands.items()
        ]


# ---------------------------------------------------------------------------
# Forge (AutoGPT's plugin system) Integration
# ---------------------------------------------------------------------------

class ForgeInALignPlugin:
    """
    Plugin for AutoGPT Forge that adds InALign governance.

    This integrates with Forge's plugin architecture to automatically
    govern all agent actions.

    Usage in Forge config:
        plugins:
          - inalign.integrations.autogpt.ForgeInALignPlugin

    Environment variables:
        INALIGN_API_KEY: Your InALign API key
        INALIGN_BASE_URL: API base URL (optional)
    """

    def __init__(self):
        import os

        api_key = os.environ.get("INALIGN_API_KEY", "")
        base_url = os.environ.get("INALIGN_BASE_URL", "https://api.inalign.io")

        if not api_key:
            raise ValueError("INALIGN_API_KEY environment variable required")

        self.middleware = InALignMiddleware(
            api_key=api_key,
            agent_id="forge-agent",
            base_url=base_url,
        )

    def on_command_start(
        self,
        command_name: str,
        arguments: dict[str, Any],
    ) -> Optional[str]:
        """
        Called before a command executes.

        Returns None to allow, or error message to block.
        """
        check = self.middleware.before_command(command_name, arguments)

        if not check.allowed:
            return f"Blocked by InALign: {check.reason}"

        return None

    def on_command_end(
        self,
        command_name: str,
        result: Any,
        error: Optional[str] = None,
    ) -> None:
        """Called after a command completes."""
        self.middleware.after_command(
            command_name=command_name,
            success=error is None,
            output=result,
            error=error,
        )

    def on_thinking(self, thought: str) -> None:
        """Called when agent has a thought."""
        self.middleware.log_thought(thought)

    def on_planning(self, plan: list[str]) -> None:
        """Called when agent creates a plan."""
        self.middleware.log_plan(plan)
