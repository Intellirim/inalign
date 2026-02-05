"""
LLM-backed report generator for the GraphRAG pipeline.

Supports OpenAI and Anthropic as LLM providers.  Includes retry logic,
structured JSON parsing from LLM output, and token usage tracking.
"""

from __future__ import annotations

import asyncio
import json
import logging
import re
import time
from typing import Any

import httpx

logger = logging.getLogger("inalign.graphrag.report_generator")

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
_MAX_RETRIES: int = 3
_RETRY_BACKOFF_BASE: float = 1.5  # seconds
_DEFAULT_OPENAI_MODEL: str = "gpt-4o"
_DEFAULT_ANTHROPIC_MODEL: str = "claude-sonnet-4-20250514"
_DEFAULT_MAX_TOKENS: int = 4096
_DEFAULT_TEMPERATURE: float = 0.2

# Timeout for LLM HTTP calls.
_HTTP_TIMEOUT: float = 120.0


class ReportGenerator:
    """
    Generate security analysis reports by calling an LLM provider.

    Parameters
    ----------
    provider:
        ``"openai"`` or ``"anthropic"``.
    api_key:
        The API key for the chosen provider.  When ``None`` the generator
        will attempt to read from the corresponding environment variable at
        call time (via :mod:`os.environ`).
    model:
        Model identifier override.  Defaults to ``gpt-4o`` for OpenAI and
        ``claude-sonnet-4-20250514`` for Anthropic.
    max_tokens:
        Maximum tokens for the LLM response.
    temperature:
        Sampling temperature.
    """

    def __init__(
        self,
        provider: str = "openai",
        api_key: str | None = None,
        model: str | None = None,
        max_tokens: int = _DEFAULT_MAX_TOKENS,
        temperature: float = _DEFAULT_TEMPERATURE,
    ) -> None:
        self._provider: str = provider.lower().strip()
        if self._provider not in ("openai", "anthropic"):
            raise ValueError(
                f"Unsupported LLM provider: '{provider}'. "
                "Choose 'openai' or 'anthropic'."
            )

        self._api_key: str | None = api_key
        self._max_tokens: int = max_tokens
        self._temperature: float = temperature

        if model is not None:
            self._model = model
        elif self._provider == "openai":
            self._model = _DEFAULT_OPENAI_MODEL
        else:
            self._model = _DEFAULT_ANTHROPIC_MODEL

        # Cumulative token tracking across the lifetime of this instance.
        self._total_prompt_tokens: int = 0
        self._total_completion_tokens: int = 0

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def generate(
        self,
        graph_text: str,
        similar_patterns: list[dict[str, Any]],
        report_type: str = "security_analysis",
        language: str = "ko",
    ) -> dict[str, Any]:
        """
        Generate a structured report from graph text and pattern data.

        Parameters
        ----------
        graph_text:
            Textual representation of the session graph (from
            :class:`GraphToTextConverter`).
        similar_patterns:
            List of dicts describing historically similar sessions /
            matched attack signatures.
        report_type:
            Type of report to generate (currently ``"security_analysis"``).
        language:
            ``"ko"`` for Korean, ``"en"`` for English.

        Returns
        -------
        dict
            Parsed JSON report produced by the LLM.
        """
        from app.graphrag.prompts.security_report import (
            SECURITY_REPORT_PROMPT_EN,
            SECURITY_REPORT_PROMPT_KO,
        )

        prompt_template: str = (
            SECURITY_REPORT_PROMPT_KO if language == "ko" else SECURITY_REPORT_PROMPT_EN
        )

        # Format similar patterns into a readable string.
        patterns_text: str = self._format_similar_patterns(similar_patterns)

        prompt: str = prompt_template.format(
            graph_text=graph_text,
            similar_patterns=patterns_text,
        )

        logger.info(
            "Generating %s report (provider=%s, model=%s, lang=%s, prompt_len=%d)",
            report_type,
            self._provider,
            self._model,
            language,
            len(prompt),
        )

        raw_response: str = await self._call_llm(prompt)
        parsed: dict[str, Any] = self._parse_response(raw_response)

        logger.info(
            "Report generated successfully. Total tokens used so far: "
            "prompt=%d, completion=%d",
            self._total_prompt_tokens,
            self._total_completion_tokens,
        )
        return parsed

    @property
    def token_usage(self) -> dict[str, int]:
        """Return cumulative token usage."""
        return {
            "prompt_tokens": self._total_prompt_tokens,
            "completion_tokens": self._total_completion_tokens,
            "total_tokens": self._total_prompt_tokens + self._total_completion_tokens,
        }

    # ------------------------------------------------------------------
    # LLM dispatch
    # ------------------------------------------------------------------

    async def _call_llm(self, prompt: str) -> str:
        """Route to the correct provider with retry logic."""
        if self._provider == "openai":
            return await self._call_openai(prompt)
        return await self._call_anthropic(prompt)

    async def _call_openai(self, prompt: str) -> str:
        """
        Call the OpenAI Chat Completions API.

        Implements exponential backoff on transient failures.
        """
        import os

        api_key: str = self._api_key or os.environ.get("OPENAI_API_KEY", "")
        if not api_key:
            raise RuntimeError(
                "OpenAI API key is not configured. Set OPENAI_API_KEY or "
                "pass api_key to ReportGenerator."
            )

        url: str = "https://api.openai.com/v1/chat/completions"
        headers: dict[str, str] = {
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        }
        payload: dict[str, Any] = {
            "model": self._model,
            "messages": [
                {
                    "role": "system",
                    "content": (
                        "You are a security analysis AI. "
                        "Always respond with valid JSON only."
                    ),
                },
                {"role": "user", "content": prompt},
            ],
            "max_tokens": self._max_tokens,
            "temperature": self._temperature,
        }

        last_error: Exception | None = None
        for attempt in range(1, _MAX_RETRIES + 1):
            try:
                async with httpx.AsyncClient(timeout=_HTTP_TIMEOUT) as client:
                    response = await client.post(url, headers=headers, json=payload)
                    response.raise_for_status()

                data: dict[str, Any] = response.json()

                # Track token usage.
                usage: dict[str, int] = data.get("usage", {})
                self._total_prompt_tokens += usage.get("prompt_tokens", 0)
                self._total_completion_tokens += usage.get("completion_tokens", 0)

                content: str = (
                    data.get("choices", [{}])[0]
                    .get("message", {})
                    .get("content", "")
                )
                return content

            except (httpx.HTTPStatusError, httpx.RequestError, httpx.TimeoutException) as exc:
                last_error = exc
                wait: float = _RETRY_BACKOFF_BASE ** attempt
                logger.warning(
                    "OpenAI request failed (attempt %d/%d): %s. Retrying in %.1fs...",
                    attempt,
                    _MAX_RETRIES,
                    str(exc),
                    wait,
                )
                await asyncio.sleep(wait)

        raise RuntimeError(
            f"OpenAI API call failed after {_MAX_RETRIES} attempts."
        ) from last_error

    async def _call_anthropic(self, prompt: str) -> str:
        """
        Call the Anthropic Messages API.

        Implements exponential backoff on transient failures.
        """
        import os

        api_key: str = self._api_key or os.environ.get("ANTHROPIC_API_KEY", "")
        if not api_key:
            raise RuntimeError(
                "Anthropic API key is not configured. Set ANTHROPIC_API_KEY or "
                "pass api_key to ReportGenerator."
            )

        url: str = "https://api.anthropic.com/v1/messages"
        headers: dict[str, str] = {
            "x-api-key": api_key,
            "anthropic-version": "2023-06-01",
            "Content-Type": "application/json",
        }
        payload: dict[str, Any] = {
            "model": self._model,
            "max_tokens": self._max_tokens,
            "temperature": self._temperature,
            "system": (
                "You are a security analysis AI. "
                "Always respond with valid JSON only."
            ),
            "messages": [
                {"role": "user", "content": prompt},
            ],
        }

        last_error: Exception | None = None
        for attempt in range(1, _MAX_RETRIES + 1):
            try:
                async with httpx.AsyncClient(timeout=_HTTP_TIMEOUT) as client:
                    response = await client.post(url, headers=headers, json=payload)
                    response.raise_for_status()

                data: dict[str, Any] = response.json()

                # Track token usage.
                usage: dict[str, Any] = data.get("usage", {})
                self._total_prompt_tokens += int(usage.get("input_tokens", 0))
                self._total_completion_tokens += int(usage.get("output_tokens", 0))

                # Anthropic returns content as a list of blocks.
                content_blocks: list[dict[str, Any]] = data.get("content", [])
                text_parts: list[str] = [
                    block.get("text", "")
                    for block in content_blocks
                    if block.get("type") == "text"
                ]
                return "\n".join(text_parts)

            except (httpx.HTTPStatusError, httpx.RequestError, httpx.TimeoutException) as exc:
                last_error = exc
                wait: float = _RETRY_BACKOFF_BASE ** attempt
                logger.warning(
                    "Anthropic request failed (attempt %d/%d): %s. Retrying in %.1fs...",
                    attempt,
                    _MAX_RETRIES,
                    str(exc),
                    wait,
                )
                await asyncio.sleep(wait)

        raise RuntimeError(
            f"Anthropic API call failed after {_MAX_RETRIES} attempts."
        ) from last_error

    # ------------------------------------------------------------------
    # Response parsing
    # ------------------------------------------------------------------

    @staticmethod
    def _parse_response(raw: str) -> dict[str, Any]:
        """
        Extract and parse JSON from the LLM's raw text output.

        Handles cases where the model wraps JSON in markdown fences or
        includes preamble/postamble text.
        """
        if not raw or not raw.strip():
            logger.warning("LLM returned empty response.")
            return {}

        # 1. Try direct JSON parsing.
        try:
            return json.loads(raw)  # type: ignore[no-any-return]
        except json.JSONDecodeError:
            pass

        # 2. Extract from markdown code fences (```json ... ```).
        fence_pattern = re.compile(
            r"```(?:json)?\s*\n?(.*?)\n?\s*```",
            re.DOTALL,
        )
        match = fence_pattern.search(raw)
        if match:
            try:
                return json.loads(match.group(1))  # type: ignore[no-any-return]
            except json.JSONDecodeError:
                pass

        # 3. Find the first { ... } block.
        brace_start: int = raw.find("{")
        brace_end: int = raw.rfind("}")
        if brace_start != -1 and brace_end != -1 and brace_end > brace_start:
            candidate: str = raw[brace_start : brace_end + 1]
            try:
                return json.loads(candidate)  # type: ignore[no-any-return]
            except json.JSONDecodeError:
                pass

        logger.error(
            "Failed to parse JSON from LLM response (length=%d). "
            "Returning raw text in wrapper.",
            len(raw),
        )
        return {"raw_response": raw, "parse_error": True}

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _format_similar_patterns(
        patterns: list[dict[str, Any]],
    ) -> str:
        """Format a list of similar pattern dicts into readable text."""
        if not patterns:
            return "No similar patterns found in historical data."

        lines: list[str] = []
        for idx, pattern in enumerate(patterns, start=1):
            session_id: str = pattern.get("session_id", "N/A")
            score: float = float(pattern.get("score", pattern.get("similarity", 0.0)))
            name: str = pattern.get("name", "")
            lines.append(f"  {idx}. Session: {session_id} (similarity: {score:.2f})")
            if name:
                lines.append(f"     Pattern: {name}")
        return "\n".join(lines)
