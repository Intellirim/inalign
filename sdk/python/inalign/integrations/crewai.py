"""
CrewAI integration for InALign.

Provides hooks and wrappers that automatically proxy all CrewAI
agent actions through InALign for governance.

CrewAI is a multi-agent framework where agents collaborate to complete tasks.
This integration ensures all tool calls and LLM requests are monitored.

Usage:
    from crewai import Agent, Task, Crew
    from inalign.integrations.crewai import GovernedCrew, govern_agent

    # Option 1: Wrap individual agents
    agent = govern_agent(
        Agent(role="Researcher", goal="Find information", ...),
        api_key="ask_xxx",
    )

    # Option 2: Wrap entire crew
    crew = GovernedCrew(
        agents=[agent1, agent2],
        tasks=[task1, task2],
        api_key="ask_xxx",
    )
    result = crew.kickoff()
"""
from __future__ import annotations

import functools
import time
import uuid
from typing import Any, Callable, Optional

try:
    from crewai import Agent, Task, Crew
    from crewai.tools import BaseTool
    CREWAI_AVAILABLE = True
except ImportError:
    CREWAI_AVAILABLE = False
    Agent = object  # type: ignore
    Task = object  # type: ignore
    Crew = object  # type: ignore
    BaseTool = object  # type: ignore

from inalign.governance import GovernanceClient, GovernedSession


class InALignToolWrapper:
    """Wraps a CrewAI tool to add InALign governance."""

    def __init__(
        self,
        tool: Any,
        session: GovernedSession,
        block_on_violation: bool = True,
    ):
        self._tool = tool
        self._session = session
        self._block_on_violation = block_on_violation

        # Copy tool attributes
        self.name = getattr(tool, "name", "unknown_tool")
        self.description = getattr(tool, "description", "")

    def _run(self, *args: Any, **kwargs: Any) -> Any:
        """Wrapped tool execution with governance check."""
        # Build arguments dict
        arguments = {}
        if args:
            arguments["args"] = args
        arguments.update(kwargs)

        # Check with InALign
        start_time = time.perf_counter()
        response = self._session.tool_call(
            tool_name=self.name,
            arguments=arguments,
        )

        if not response.allowed:
            if self._block_on_violation:
                raise PermissionError(
                    f"InALign blocked tool '{self.name}': {response.reason}"
                )
            print(f"[InALign] Warning: Tool '{self.name}' would be blocked: {response.reason}")

        # Execute original tool
        try:
            result = self._tool._run(*args, **kwargs)

            # Report success
            duration_ms = int((time.perf_counter() - start_time) * 1000)
            self._session._complete_action(
                action_id=response.action_id,
                status="success",
                duration_ms=duration_ms,
                output_preview=str(result)[:500] if result else "",
            )

            return result

        except Exception as e:
            # Report failure
            duration_ms = int((time.perf_counter() - start_time) * 1000)
            self._session._complete_action(
                action_id=response.action_id,
                status="failure",
                duration_ms=duration_ms,
                error=str(e),
            )
            raise

    async def _arun(self, *args: Any, **kwargs: Any) -> Any:
        """Async wrapped tool execution."""
        arguments = {}
        if args:
            arguments["args"] = args
        arguments.update(kwargs)

        start_time = time.perf_counter()
        response = self._session.tool_call(
            tool_name=self.name,
            arguments=arguments,
        )

        if not response.allowed:
            if self._block_on_violation:
                raise PermissionError(
                    f"InALign blocked tool '{self.name}': {response.reason}"
                )

        try:
            if hasattr(self._tool, "_arun"):
                result = await self._tool._arun(*args, **kwargs)
            else:
                result = self._tool._run(*args, **kwargs)

            duration_ms = int((time.perf_counter() - start_time) * 1000)
            self._session._complete_action(
                action_id=response.action_id,
                status="success",
                duration_ms=duration_ms,
                output_preview=str(result)[:500] if result else "",
            )

            return result

        except Exception as e:
            duration_ms = int((time.perf_counter() - start_time) * 1000)
            self._session._complete_action(
                action_id=response.action_id,
                status="failure",
                duration_ms=duration_ms,
                error=str(e),
            )
            raise


def govern_agent(
    agent: Agent,
    api_key: str,
    agent_id: Optional[str] = None,
    base_url: str = "https://api.inalign.io",
    block_on_violation: bool = True,
) -> Agent:
    """
    Wrap a CrewAI Agent with InALign governance.

    Args:
        agent: The CrewAI Agent to wrap
        api_key: InALign API key
        agent_id: Optional agent ID (defaults to agent.role)
        base_url: InALign API base URL
        block_on_violation: Whether to block on policy violations

    Returns:
        The same agent with governed tools
    """
    if not CREWAI_AVAILABLE:
        raise ImportError(
            "CrewAI is required for this integration. "
            "Install it with: pip install crewai"
        )

    # Create governance session
    client = GovernanceClient(api_key=api_key, base_url=base_url)
    session = GovernedSession(
        client=client,
        agent_id=agent_id or agent.role,
        session_id=f"crewai-{uuid.uuid4().hex[:12]}",
    )

    # Wrap all tools
    if hasattr(agent, "tools") and agent.tools:
        wrapped_tools = []
        for tool in agent.tools:
            wrapper = InALignToolWrapper(
                tool=tool,
                session=session,
                block_on_violation=block_on_violation,
            )
            wrapped_tools.append(wrapper)
        agent.tools = wrapped_tools

    return agent


class GovernedCrew(Crew if CREWAI_AVAILABLE else object):
    """
    A CrewAI Crew with built-in InALign governance.

    All agents in the crew will have their tools monitored and
    policy-checked before execution.

    Usage:
        crew = GovernedCrew(
            agents=[agent1, agent2],
            tasks=[task1, task2],
            api_key="ask_xxx",
        )
        result = crew.kickoff()
    """

    def __init__(
        self,
        agents: list[Agent],
        tasks: list[Task],
        api_key: str,
        crew_id: Optional[str] = None,
        base_url: str = "https://api.inalign.io",
        block_on_violation: bool = True,
        **kwargs: Any,
    ):
        if not CREWAI_AVAILABLE:
            raise ImportError(
                "CrewAI is required for this integration. "
                "Install it with: pip install crewai"
            )

        self._api_key = api_key
        self._base_url = base_url
        self._block_on_violation = block_on_violation
        self._crew_id = crew_id or f"crew-{uuid.uuid4().hex[:8]}"

        # Govern all agents
        governed_agents = []
        for agent in agents:
            governed = govern_agent(
                agent=agent,
                api_key=api_key,
                agent_id=f"{self._crew_id}/{agent.role}",
                base_url=base_url,
                block_on_violation=block_on_violation,
            )
            governed_agents.append(governed)

        super().__init__(agents=governed_agents, tasks=tasks, **kwargs)

    def kickoff(self, inputs: Optional[dict[str, Any]] = None) -> Any:
        """Execute the crew with governance tracking."""
        # Log crew start
        client = GovernanceClient(api_key=self._api_key, base_url=self._base_url)
        session = GovernedSession(
            client=client,
            agent_id=self._crew_id,
            session_id=f"kickoff-{uuid.uuid4().hex[:12]}",
        )

        start_time = time.perf_counter()

        try:
            result = super().kickoff(inputs=inputs)

            # Log success
            duration_ms = int((time.perf_counter() - start_time) * 1000)
            session._log_event(
                event_type="crew_complete",
                details={
                    "status": "success",
                    "duration_ms": duration_ms,
                    "tasks_count": len(self.tasks),
                    "agents_count": len(self.agents),
                },
            )

            return result

        except Exception as e:
            # Log failure
            duration_ms = int((time.perf_counter() - start_time) * 1000)
            session._log_event(
                event_type="crew_complete",
                details={
                    "status": "failure",
                    "duration_ms": duration_ms,
                    "error": str(e),
                },
            )
            raise


def create_governed_tool(
    func: Callable,
    name: str,
    description: str,
    api_key: str,
    agent_id: str = "crewai-tool",
    base_url: str = "https://api.inalign.io",
    block_on_violation: bool = True,
) -> Callable:
    """
    Decorator to create a governed CrewAI tool from a function.

    Usage:
        @create_governed_tool(
            name="search",
            description="Search the web",
            api_key="ask_xxx",
        )
        def search(query: str) -> str:
            return do_search(query)
    """
    client = GovernanceClient(api_key=api_key, base_url=base_url)
    session = GovernedSession(
        client=client,
        agent_id=agent_id,
        session_id=f"tool-{uuid.uuid4().hex[:12]}",
    )

    @functools.wraps(func)
    def wrapper(*args: Any, **kwargs: Any) -> Any:
        # Build arguments
        arguments = {}
        if args:
            arguments["args"] = args
        arguments.update(kwargs)

        # Check with InALign
        start_time = time.perf_counter()
        response = session.tool_call(
            tool_name=name,
            arguments=arguments,
        )

        if not response.allowed:
            if block_on_violation:
                raise PermissionError(
                    f"InALign blocked tool '{name}': {response.reason}"
                )

        try:
            result = func(*args, **kwargs)

            duration_ms = int((time.perf_counter() - start_time) * 1000)
            session._complete_action(
                action_id=response.action_id,
                status="success",
                duration_ms=duration_ms,
                output_preview=str(result)[:500] if result else "",
            )

            return result

        except Exception as e:
            duration_ms = int((time.perf_counter() - start_time) * 1000)
            session._complete_action(
                action_id=response.action_id,
                status="failure",
                duration_ms=duration_ms,
                error=str(e),
            )
            raise

    wrapper._name = name
    wrapper._description = description

    return wrapper
