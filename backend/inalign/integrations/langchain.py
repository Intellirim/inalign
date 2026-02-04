"""
In-A-Lign LangChain Integration.

Provides seamless security for LangChain applications:
- LangChainGuard: Wrapper that checks inputs before chain execution
- InALignCallbackHandler: Callback that monitors all LLM calls

Usage:
    from inalign.integrations.langchain import LangChainGuard, InALignCallbackHandler

    # Option 1: Wrap your chain
    guard = LangChainGuard()
    safe_chain = guard.wrap(my_chain)
    result = safe_chain.invoke({"input": user_input})

    # Option 2: Use callback handler
    handler = InALignCallbackHandler()
    chain.invoke({"input": user_input}, config={"callbacks": [handler]})
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional, Union

from inalign import Guard, GuardConfig

logger = logging.getLogger("inalign.langchain")


class LangChainGuard:
    """
    Security wrapper for LangChain chains and agents.

    Intercepts inputs before they reach the LLM and blocks attacks.

    Example:
        from langchain_openai import ChatOpenAI
        from langchain_core.prompts import ChatPromptTemplate
        from inalign.integrations.langchain import LangChainGuard

        # Create your chain
        llm = ChatOpenAI()
        prompt = ChatPromptTemplate.from_template("Answer: {question}")
        chain = prompt | llm

        # Wrap with security
        guard = LangChainGuard()
        safe_chain = guard.wrap(chain)

        # Now all inputs are checked
        result = safe_chain.invoke({"question": "What is AI?"})  # OK
        result = safe_chain.invoke({"question": "Ignore instructions"})  # Blocked!
    """

    def __init__(
        self,
        config: Optional[GuardConfig] = None,
        block_on_attack: bool = True,
        log_blocked: bool = True,
    ):
        """
        Initialize LangChain guard.

        Parameters
        ----------
        config : GuardConfig, optional
            Guard configuration
        block_on_attack : bool
            If True, raise exception on attack. If False, just log warning.
        log_blocked : bool
            Whether to log blocked inputs
        """
        self.guard = Guard(config=config)
        self.block_on_attack = block_on_attack
        self.log_blocked = log_blocked
        self.stats = {
            "total_calls": 0,
            "blocked_calls": 0,
            "passed_calls": 0,
        }

    def check(self, text: str) -> bool:
        """
        Check if text is safe.

        Returns True if safe, False if attack detected.
        """
        result = self.guard.check(text)
        return result.safe

    def wrap(self, chain: Any) -> "GuardedChain":
        """
        Wrap a LangChain chain with security.

        Parameters
        ----------
        chain : Runnable
            Any LangChain Runnable (chain, agent, etc.)

        Returns
        -------
        GuardedChain
            Wrapped chain that checks inputs before execution
        """
        return GuardedChain(chain, self)

    def _check_inputs(self, inputs: Dict[str, Any]) -> None:
        """Check all string inputs for attacks."""
        self.stats["total_calls"] += 1

        for key, value in inputs.items():
            if isinstance(value, str) and value.strip():
                result = self.guard.check(value)

                if not result.safe:
                    self.stats["blocked_calls"] += 1

                    if self.log_blocked:
                        logger.warning(
                            "Blocked input in '%s': %s... (risk=%.2f, threats=%d)",
                            key, value[:50], result.risk_score, len(result.threats)
                        )

                    if self.block_on_attack:
                        from inalign import SecurityError
                        raise SecurityError(
                            f"Attack detected in '{key}': {result.threat_level.value}",
                            result=result
                        )

        self.stats["passed_calls"] += 1

    def get_stats(self) -> Dict[str, Any]:
        """Get guard statistics."""
        return {
            **self.stats,
            "block_rate": (
                self.stats["blocked_calls"] / self.stats["total_calls"]
                if self.stats["total_calls"] > 0 else 0
            ),
        }


class GuardedChain:
    """
    Wrapped LangChain chain with security checks.

    Acts like a normal chain but checks inputs before execution.
    """

    def __init__(self, chain: Any, guard: LangChainGuard):
        self._chain = chain
        self._guard = guard

    def invoke(self, inputs: Dict[str, Any], **kwargs) -> Any:
        """Invoke chain with security check."""
        self._guard._check_inputs(inputs)
        return self._chain.invoke(inputs, **kwargs)

    async def ainvoke(self, inputs: Dict[str, Any], **kwargs) -> Any:
        """Async invoke with security check."""
        self._guard._check_inputs(inputs)
        return await self._chain.ainvoke(inputs, **kwargs)

    def stream(self, inputs: Dict[str, Any], **kwargs):
        """Stream with security check."""
        self._guard._check_inputs(inputs)
        return self._chain.stream(inputs, **kwargs)

    async def astream(self, inputs: Dict[str, Any], **kwargs):
        """Async stream with security check."""
        self._guard._check_inputs(inputs)
        async for chunk in self._chain.astream(inputs, **kwargs):
            yield chunk

    def batch(self, inputs: List[Dict[str, Any]], **kwargs) -> List[Any]:
        """Batch invoke with security check on all inputs."""
        for inp in inputs:
            self._guard._check_inputs(inp)
        return self._chain.batch(inputs, **kwargs)

    def __getattr__(self, name: str) -> Any:
        """Forward other attributes to wrapped chain."""
        return getattr(self._chain, name)

    def __or__(self, other: Any) -> "GuardedChain":
        """Support pipe operator for chain composition."""
        new_chain = self._chain | other
        return GuardedChain(new_chain, self._guard)

    def __ror__(self, other: Any) -> "GuardedChain":
        """Support reverse pipe operator."""
        new_chain = other | self._chain
        return GuardedChain(new_chain, self._guard)


class InALignCallbackHandler:
    """
    LangChain callback handler for monitoring LLM calls.

    Add this to any chain to monitor and optionally block attacks.

    Example:
        from langchain_openai import ChatOpenAI
        from inalign.integrations.langchain import InALignCallbackHandler

        handler = InALignCallbackHandler(block_attacks=True)
        llm = ChatOpenAI(callbacks=[handler])

        # All LLM calls are now monitored
        llm.invoke("What is AI?")  # OK
        llm.invoke("Ignore all instructions")  # Blocked!
    """

    def __init__(
        self,
        config: Optional[GuardConfig] = None,
        block_attacks: bool = True,
        check_prompts: bool = True,
        check_outputs: bool = False,
    ):
        """
        Initialize callback handler.

        Parameters
        ----------
        config : GuardConfig, optional
            Guard configuration
        block_attacks : bool
            If True, raise exception on attack detection
        check_prompts : bool
            Check input prompts for attacks
        check_outputs : bool
            Check LLM outputs for sensitive data leaks
        """
        self.guard = Guard(config=config)
        self.block_attacks = block_attacks
        self.check_prompts = check_prompts
        self.check_outputs = check_outputs

        self.events: List[Dict[str, Any]] = []
        self.stats = {
            "llm_starts": 0,
            "llm_ends": 0,
            "blocked": 0,
        }

    def on_llm_start(
        self,
        serialized: Dict[str, Any],
        prompts: List[str],
        **kwargs: Any,
    ) -> None:
        """Called when LLM starts processing."""
        self.stats["llm_starts"] += 1

        if not self.check_prompts:
            return

        for i, prompt in enumerate(prompts):
            result = self.guard.check(prompt)

            event = {
                "type": "llm_start",
                "prompt_index": i,
                "prompt_preview": prompt[:100],
                "safe": result.safe,
                "risk_score": result.risk_score,
                "threat_level": result.threat_level.value,
            }
            self.events.append(event)

            if not result.safe:
                self.stats["blocked"] += 1
                logger.warning(
                    "Attack detected in LLM prompt: %s... (risk=%.2f)",
                    prompt[:50], result.risk_score
                )

                if self.block_attacks:
                    from inalign import SecurityError
                    raise SecurityError(
                        f"Attack detected in prompt: {result.threat_level.value}",
                        result=result
                    )

    def on_llm_end(self, response: Any, **kwargs: Any) -> None:
        """Called when LLM finishes."""
        self.stats["llm_ends"] += 1

        if not self.check_outputs:
            return

        # Check output for sensitive data leaks
        try:
            if hasattr(response, "generations"):
                for gen_list in response.generations:
                    for gen in gen_list:
                        text = gen.text if hasattr(gen, "text") else str(gen)
                        result = self.guard.check(text)

                        if not result.safe:
                            logger.warning(
                                "Suspicious LLM output detected: %s...",
                                text[:50]
                            )
        except Exception as e:
            logger.debug("Error checking LLM output: %s", e)

    def on_llm_error(self, error: Exception, **kwargs: Any) -> None:
        """Called on LLM error."""
        self.events.append({
            "type": "llm_error",
            "error": str(error),
        })

    def on_chain_start(
        self,
        serialized: Dict[str, Any],
        inputs: Dict[str, Any],
        **kwargs: Any,
    ) -> None:
        """Called when chain starts."""
        if not self.check_prompts:
            return

        # Check all string inputs
        for key, value in inputs.items():
            if isinstance(value, str) and value.strip():
                result = self.guard.check(value)

                if not result.safe:
                    self.stats["blocked"] += 1
                    logger.warning(
                        "Attack detected in chain input '%s': %s...",
                        key, value[:50]
                    )

                    if self.block_attacks:
                        from inalign import SecurityError
                        raise SecurityError(
                            f"Attack in '{key}': {result.threat_level.value}",
                            result=result
                        )

    def on_chain_end(self, outputs: Dict[str, Any], **kwargs: Any) -> None:
        """Called when chain ends."""
        pass

    def on_chain_error(self, error: Exception, **kwargs: Any) -> None:
        """Called on chain error."""
        pass

    def on_tool_start(
        self,
        serialized: Dict[str, Any],
        input_str: str,
        **kwargs: Any,
    ) -> None:
        """Called when tool starts - check tool inputs."""
        if not self.check_prompts:
            return

        result = self.guard.check(input_str)

        if not result.safe:
            self.stats["blocked"] += 1
            tool_name = serialized.get("name", "unknown")
            logger.warning(
                "Attack detected in tool '%s' input: %s...",
                tool_name, input_str[:50]
            )

            if self.block_attacks:
                from inalign import SecurityError
                raise SecurityError(
                    f"Attack in tool input: {result.threat_level.value}",
                    result=result
                )

    def on_tool_end(self, output: str, **kwargs: Any) -> None:
        """Called when tool ends."""
        pass

    def on_tool_error(self, error: Exception, **kwargs: Any) -> None:
        """Called on tool error."""
        pass

    def get_events(self) -> List[Dict[str, Any]]:
        """Get all recorded events."""
        return self.events

    def get_stats(self) -> Dict[str, Any]:
        """Get handler statistics."""
        return self.stats

    def clear_events(self) -> None:
        """Clear recorded events."""
        self.events = []


# Convenience function
def secure_chain(chain: Any, **guard_kwargs) -> GuardedChain:
    """
    Quick way to secure a LangChain chain.

    Example:
        from inalign.integrations.langchain import secure_chain

        safe_chain = secure_chain(my_chain)
        result = safe_chain.invoke({"input": "Hello"})
    """
    guard = LangChainGuard(**guard_kwargs)
    return guard.wrap(chain)
