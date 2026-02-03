"""
LangChain integration for AgentShield.

Provides callback handlers that automatically proxy all LangChain
tool calls and LLM requests through AgentShield for governance.
"""

from __future__ import annotations

import time
import uuid
from typing import Any, Dict, List, Optional, Union

try:
    from langchain_core.callbacks import BaseCallbackHandler
    from langchain_core.agents import AgentAction, AgentFinish
    from langchain_core.outputs import LLMResult
    from langchain_core.messages import BaseMessage
    LANGCHAIN_AVAILABLE = True
except ImportError:
    LANGCHAIN_AVAILABLE = False
    BaseCallbackHandler = object  # type: ignore

from agentshield.governance import GovernanceClient, GovernedSession


class AgentShieldCallback(BaseCallbackHandler if LANGCHAIN_AVAILABLE else object):
    """LangChain callback handler that integrates with AgentShield.

    This callback automatically:
    - Evaluates tool calls against policies before execution
    - Logs all LLM calls and their costs
    - Tracks token usage and latency
    - Blocks actions that violate policies

    Usage::

        from langchain.agents import create_react_agent
        from agentshield.integrations import AgentShieldCallback

        callback = AgentShieldCallback(
            api_key="ask_xxx",
            agent_id="my-langchain-agent",
        )

        agent = create_react_agent(llm, tools, prompt)
        agent_executor = AgentExecutor(
            agent=agent,
            tools=tools,
            callbacks=[callback],
        )
    """

    def __init__(
        self,
        api_key: str,
        agent_id: str,
        session_id: Optional[str] = None,
        base_url: str = "https://api.agentshield.io",
        block_on_violation: bool = True,
        log_llm_calls: bool = True,
    ) -> None:
        """Initialize the AgentShield callback.

        Args:
            api_key: AgentShield API key.
            agent_id: The agent ID registered in AgentShield.
            session_id: Optional session ID (auto-generated if not provided).
            base_url: AgentShield API base URL.
            block_on_violation: Whether to raise an exception on policy violations.
            log_llm_calls: Whether to log LLM calls.
        """
        if not LANGCHAIN_AVAILABLE:
            raise ImportError(
                "LangChain is required for this integration. "
                "Install it with: pip install langchain-core"
            )

        super().__init__()
        self.client = GovernanceClient(api_key=api_key, base_url=base_url)
        self.agent_id = agent_id
        self.session_id = session_id or f"sess-{uuid.uuid4().hex[:12]}"
        self.block_on_violation = block_on_violation
        self.log_llm_calls = log_llm_calls

        # Session tracking
        self._session = GovernedSession(
            client=self.client,
            agent_id=agent_id,
            session_id=self.session_id,
        )
        self._current_action_id: Optional[str] = None
        self._action_start_time: Optional[float] = None
        self._llm_start_time: Optional[float] = None
        self._current_llm_action_id: Optional[str] = None

    # ── Tool/Agent Action Callbacks ────────────────────────────────────

    def on_agent_action(
        self,
        action: AgentAction,
        *,
        run_id: uuid.UUID,
        parent_run_id: Optional[uuid.UUID] = None,
        **kwargs: Any,
    ) -> Any:
        """Called when an agent action is about to be executed.

        This is where we evaluate the tool call against policies.
        """
        # Evaluate the tool call
        response = self._session.tool_call(
            tool_name=action.tool,
            arguments=action.tool_input if isinstance(action.tool_input, dict) else {"input": action.tool_input},
            metadata={"run_id": str(run_id)},
        )

        self._current_action_id = response.action_id
        self._action_start_time = time.perf_counter()

        if not response.allowed:
            if self.block_on_violation:
                raise PermissionError(
                    f"AgentShield blocked tool '{action.tool}': {response.reason}"
                )
            # If not blocking, log and continue
            print(f"[AgentShield] Warning: Tool '{action.tool}' would be blocked: {response.reason}")

        return None

    def on_tool_start(
        self,
        serialized: Dict[str, Any],
        input_str: str,
        *,
        run_id: uuid.UUID,
        parent_run_id: Optional[uuid.UUID] = None,
        tags: Optional[List[str]] = None,
        metadata: Optional[Dict[str, Any]] = None,
        inputs: Optional[Dict[str, Any]] = None,
        **kwargs: Any,
    ) -> Any:
        """Called when a tool starts execution."""
        tool_name = serialized.get("name", "unknown_tool")

        # If we haven't already evaluated (via on_agent_action), do it now
        if self._current_action_id is None:
            response = self._session.tool_call(
                tool_name=tool_name,
                arguments=inputs or {"input": input_str},
                metadata={"run_id": str(run_id)},
            )
            self._current_action_id = response.action_id
            self._action_start_time = time.perf_counter()

            if not response.allowed and self.block_on_violation:
                raise PermissionError(
                    f"AgentShield blocked tool '{tool_name}': {response.reason}"
                )

        return None

    def on_tool_end(
        self,
        output: str,
        *,
        run_id: uuid.UUID,
        parent_run_id: Optional[uuid.UUID] = None,
        **kwargs: Any,
    ) -> Any:
        """Called when a tool finishes execution."""
        if self._current_action_id and self._action_start_time:
            duration_ms = int((time.perf_counter() - self._action_start_time) * 1000)
            self._session._complete_action(
                action_id=self._current_action_id,
                status="success",
                duration_ms=duration_ms,
                output_preview=str(output)[:500] if output else "",
            )

        self._current_action_id = None
        self._action_start_time = None
        return None

    def on_tool_error(
        self,
        error: BaseException,
        *,
        run_id: uuid.UUID,
        parent_run_id: Optional[uuid.UUID] = None,
        **kwargs: Any,
    ) -> Any:
        """Called when a tool errors."""
        if self._current_action_id and self._action_start_time:
            duration_ms = int((time.perf_counter() - self._action_start_time) * 1000)
            self._session._complete_action(
                action_id=self._current_action_id,
                status="failure",
                duration_ms=duration_ms,
                error=str(error),
            )

        self._current_action_id = None
        self._action_start_time = None
        return None

    # ── LLM Callbacks ──────────────────────────────────────────────────

    def on_llm_start(
        self,
        serialized: Dict[str, Any],
        prompts: List[str],
        *,
        run_id: uuid.UUID,
        parent_run_id: Optional[uuid.UUID] = None,
        tags: Optional[List[str]] = None,
        metadata: Optional[Dict[str, Any]] = None,
        **kwargs: Any,
    ) -> Any:
        """Called when an LLM starts generating."""
        if not self.log_llm_calls:
            return None

        model_name = serialized.get("name", serialized.get("model", "unknown"))

        # Log the LLM call
        response = self._session.llm_call(
            model=model_name,
            messages=[{"role": "user", "content": p} for p in prompts],
            metadata={"run_id": str(run_id)},
        )

        self._current_llm_action_id = response.action_id
        self._llm_start_time = time.perf_counter()

        if not response.allowed and self.block_on_violation:
            raise PermissionError(
                f"AgentShield blocked LLM call to '{model_name}': {response.reason}"
            )

        return None

    def on_chat_model_start(
        self,
        serialized: Dict[str, Any],
        messages: List[List[BaseMessage]],
        *,
        run_id: uuid.UUID,
        parent_run_id: Optional[uuid.UUID] = None,
        tags: Optional[List[str]] = None,
        metadata: Optional[Dict[str, Any]] = None,
        **kwargs: Any,
    ) -> Any:
        """Called when a chat model starts generating."""
        if not self.log_llm_calls:
            return None

        model_name = serialized.get("name", serialized.get("model", "unknown"))

        # Convert messages to dict format
        msg_list = []
        for msg_batch in messages:
            for msg in msg_batch:
                msg_list.append({
                    "role": msg.type,
                    "content": str(msg.content)[:500],
                })

        response = self._session.llm_call(
            model=model_name,
            messages=msg_list,
            metadata={"run_id": str(run_id)},
        )

        self._current_llm_action_id = response.action_id
        self._llm_start_time = time.perf_counter()

        if not response.allowed and self.block_on_violation:
            raise PermissionError(
                f"AgentShield blocked LLM call to '{model_name}': {response.reason}"
            )

        return None

    def on_llm_end(
        self,
        response: LLMResult,
        *,
        run_id: uuid.UUID,
        parent_run_id: Optional[uuid.UUID] = None,
        **kwargs: Any,
    ) -> Any:
        """Called when an LLM finishes generating."""
        if not self.log_llm_calls or not self._current_llm_action_id:
            return None

        duration_ms = int((time.perf_counter() - self._llm_start_time) * 1000) if self._llm_start_time else 0

        # Extract token usage if available
        tokens_input = 0
        tokens_output = 0
        if response.llm_output:
            token_usage = response.llm_output.get("token_usage", {})
            tokens_input = token_usage.get("prompt_tokens", 0)
            tokens_output = token_usage.get("completion_tokens", 0)

        # Extract output preview
        output_preview = ""
        if response.generations:
            first_gen = response.generations[0]
            if first_gen:
                output_preview = str(first_gen[0].text)[:500]

        self._session._complete_action(
            action_id=self._current_llm_action_id,
            status="success",
            duration_ms=duration_ms,
            output_preview=output_preview,
            tokens_input=tokens_input,
            tokens_output=tokens_output,
            # Estimate cost (rough approximation)
            cost_usd=self._estimate_cost(tokens_input, tokens_output),
        )

        self._current_llm_action_id = None
        self._llm_start_time = None
        return None

    def on_llm_error(
        self,
        error: BaseException,
        *,
        run_id: uuid.UUID,
        parent_run_id: Optional[uuid.UUID] = None,
        **kwargs: Any,
    ) -> Any:
        """Called when an LLM errors."""
        if self._current_llm_action_id and self._llm_start_time:
            duration_ms = int((time.perf_counter() - self._llm_start_time) * 1000)
            self._session._complete_action(
                action_id=self._current_llm_action_id,
                status="failure",
                duration_ms=duration_ms,
                error=str(error),
            )

        self._current_llm_action_id = None
        self._llm_start_time = None
        return None

    # ── Agent Finish ───────────────────────────────────────────────────

    def on_agent_finish(
        self,
        finish: AgentFinish,
        *,
        run_id: uuid.UUID,
        parent_run_id: Optional[uuid.UUID] = None,
        **kwargs: Any,
    ) -> Any:
        """Called when an agent finishes."""
        # Session complete - could log summary here
        return None

    # ── Helpers ────────────────────────────────────────────────────────

    def _estimate_cost(self, tokens_input: int, tokens_output: int) -> float:
        """Rough cost estimation for common models."""
        # Approximate GPT-4 pricing as default
        # Input: $0.03/1K tokens, Output: $0.06/1K tokens
        input_cost = (tokens_input / 1000) * 0.03
        output_cost = (tokens_output / 1000) * 0.06
        return input_cost + output_cost


def create_governed_agent(
    api_key: str,
    agent_id: str,
    base_url: str = "https://api.agentshield.io",
    block_on_violation: bool = True,
    **kwargs: Any,
) -> AgentShieldCallback:
    """Create an AgentShield callback for LangChain agents.

    This is a convenience function that creates a callback handler
    with sensible defaults.

    Args:
        api_key: AgentShield API key.
        agent_id: The agent ID registered in AgentShield.
        base_url: AgentShield API base URL.
        block_on_violation: Whether to block on policy violations.
        **kwargs: Additional arguments passed to AgentShieldCallback.

    Returns:
        AgentShieldCallback instance ready to use with LangChain.

    Example::

        from langchain.agents import AgentExecutor
        from agentshield.integrations import create_governed_agent

        callback = create_governed_agent(
            api_key="ask_xxx",
            agent_id="my-agent",
        )

        executor = AgentExecutor(
            agent=agent,
            tools=tools,
            callbacks=[callback],
        )
    """
    return AgentShieldCallback(
        api_key=api_key,
        agent_id=agent_id,
        base_url=base_url,
        block_on_violation=block_on_violation,
        **kwargs,
    )
