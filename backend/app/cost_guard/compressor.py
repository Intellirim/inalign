"""
Prompt Compressor - Reduces token count while preserving meaning.

Techniques:
- System prompt template compression
- Redundant phrase removal
- Context summarization
- History truncation with summaries
"""
from __future__ import annotations

import re
import logging
from typing import Any, Optional
from dataclasses import dataclass

logger = logging.getLogger("inalign.cost_guard.compressor")


@dataclass
class CompressionResult:
    """Result of prompt compression."""
    original_text: str
    compressed_text: str
    original_tokens: int
    compressed_tokens: int
    tokens_saved: int
    compression_ratio: float
    techniques_applied: list[str]


class PromptCompressor:
    """
    Compresses prompts to reduce token usage while preserving meaning.

    Techniques:
    1. Remove redundant whitespace and formatting
    2. Abbreviate common phrases
    3. Compress verbose instructions
    4. Summarize long contexts
    5. Truncate conversation history with summaries
    """

    # Common verbose phrases and their shorter equivalents
    PHRASE_COMPRESSIONS: dict[str, str] = {
        # Instruction patterns
        "Please make sure to": "Ensure",
        "Please ensure that you": "Ensure",
        "It is important that you": "",
        "You must always": "Always",
        "You should never": "Never",
        "In order to": "To",
        "As a result of": "Due to",
        "For the purpose of": "For",
        "In the event that": "If",
        "With respect to": "Regarding",
        "In accordance with": "Per",
        "At this point in time": "Now",
        "Due to the fact that": "Because",
        "In spite of the fact that": "Although",
        "For the reason that": "Because",
        "In the near future": "Soon",
        "At the present time": "Currently",
        "In the process of": "Currently",
        "On a daily basis": "Daily",
        "On a regular basis": "Regularly",
        "In a timely manner": "Promptly",
        "In the majority of cases": "Usually",
        "A large number of": "Many",
        "A small number of": "Few",
        "Is able to": "Can",
        "Has the ability to": "Can",
        "Is not able to": "Cannot",
        "Does not have the ability to": "Cannot",
        "Make sure that": "Ensure",
        "Be sure to": "Ensure",
        "It is necessary that": "",
        "It is essential that": "",
        "It is important to note that": "Note:",
        "Please note that": "Note:",
        "Keep in mind that": "Note:",
        "Bear in mind that": "Note:",
        # Politeness (often unnecessary in system prompts)
        "Would you please": "",
        "Could you please": "",
        "I would like you to": "",
        "Please be so kind as to": "",
    }

    # Redundant filler patterns
    FILLER_PATTERNS: list[tuple[str, str]] = [
        (r"\s+", " "),  # Multiple spaces
        (r"\n{3,}", "\n\n"),  # Multiple newlines
        (r"^\s+|\s+$", ""),  # Leading/trailing whitespace
        (r"(?i)\b(very|really|extremely|quite|rather)\s+", ""),  # Intensifiers
        (r"(?i)\b(just|simply|basically|actually|literally)\s+", ""),  # Fillers
        (r"(?i)\b(in fact|as a matter of fact),?\s*", ""),  # Factual fillers
        (r"(?i)\b(obviously|clearly|certainly|definitely)\s+", ""),  # Certainty words
    ]

    # System prompt section markers (for intelligent compression)
    SECTION_MARKERS: list[str] = [
        "## ", "### ", "# ",
        "IMPORTANT:", "NOTE:", "WARNING:",
        "Instructions:", "Guidelines:", "Rules:",
    ]

    def __init__(
        self,
        aggressive: bool = False,
        preserve_code: bool = True,
        max_history_turns: int = 10,
        summarize_threshold_tokens: int = 2000,
    ):
        """
        Initialize the compressor.

        Parameters
        ----------
        aggressive : bool
            Apply more aggressive compression (may lose some nuance).
        preserve_code : bool
            Don't compress content within code blocks.
        max_history_turns : int
            Maximum conversation turns to keep in full.
        summarize_threshold_tokens : int
            Summarize context if exceeds this token count.
        """
        self.aggressive = aggressive
        self.preserve_code = preserve_code
        self.max_history_turns = max_history_turns
        self.summarize_threshold_tokens = summarize_threshold_tokens

        # Compile patterns
        self._filler_patterns = [
            (re.compile(p), r) for p, r in self.FILLER_PATTERNS
        ]

        logger.info(
            f"PromptCompressor initialized (aggressive={aggressive}, "
            f"preserve_code={preserve_code})"
        )

    def compress(
        self,
        text: str,
        context_type: str = "general",
    ) -> CompressionResult:
        """
        Compress the given text.

        Parameters
        ----------
        text : str
            The text to compress.
        context_type : str
            Type of content: "system_prompt", "user_message", "history", "general"
        """
        original_text = text
        original_tokens = self._estimate_tokens(text)
        techniques: list[str] = []

        if not text or len(text) < 100:
            return CompressionResult(
                original_text=original_text,
                compressed_text=text,
                original_tokens=original_tokens,
                compressed_tokens=original_tokens,
                tokens_saved=0,
                compression_ratio=0.0,
                techniques_applied=[],
            )

        # Extract and preserve code blocks
        code_blocks: list[tuple[str, str]] = []
        if self.preserve_code:
            text, code_blocks = self._extract_code_blocks(text)
            if code_blocks:
                techniques.append("code_preservation")

        # Apply phrase compressions
        text_before = text
        text = self._compress_phrases(text)
        if text != text_before:
            techniques.append("phrase_compression")

        # Remove filler patterns
        text_before = text
        text = self._remove_fillers(text)
        if text != text_before:
            techniques.append("filler_removal")

        # Context-specific compression
        if context_type == "system_prompt":
            text_before = text
            text = self._compress_system_prompt(text)
            if text != text_before:
                techniques.append("system_prompt_optimization")

        elif context_type == "history":
            text_before = text
            text = self._compress_history(text)
            if text != text_before:
                techniques.append("history_truncation")

        # Aggressive mode: additional compression
        if self.aggressive:
            text_before = text
            text = self._aggressive_compress(text)
            if text != text_before:
                techniques.append("aggressive_compression")

        # Restore code blocks
        if code_blocks:
            text = self._restore_code_blocks(text, code_blocks)

        # Final cleanup
        text = self._final_cleanup(text)

        compressed_tokens = self._estimate_tokens(text)
        tokens_saved = original_tokens - compressed_tokens

        ratio = 0.0
        if original_tokens > 0:
            ratio = 1 - (compressed_tokens / original_tokens)

        logger.debug(
            f"Compressed: {original_tokens} -> {compressed_tokens} tokens "
            f"({ratio*100:.1f}% reduction) | techniques: {techniques}"
        )

        return CompressionResult(
            original_text=original_text,
            compressed_text=text,
            original_tokens=original_tokens,
            compressed_tokens=compressed_tokens,
            tokens_saved=tokens_saved,
            compression_ratio=ratio,
            techniques_applied=techniques,
        )

    def _estimate_tokens(self, text: str) -> int:
        """Estimate token count."""
        try:
            import tiktoken
            enc = tiktoken.get_encoding("cl100k_base")
            return len(enc.encode(text))
        except ImportError:
            return len(text) // 4

    def _extract_code_blocks(self, text: str) -> tuple[str, list[tuple[str, str]]]:
        """Extract code blocks and replace with placeholders."""
        blocks: list[tuple[str, str]] = []
        pattern = re.compile(r"```[\s\S]*?```|`[^`]+`")

        def replacer(match):
            placeholder = f"__CODE_BLOCK_{len(blocks)}__"
            blocks.append((placeholder, match.group(0)))
            return placeholder

        text = pattern.sub(replacer, text)
        return text, blocks

    def _restore_code_blocks(self, text: str, blocks: list[tuple[str, str]]) -> str:
        """Restore code blocks from placeholders."""
        for placeholder, code in blocks:
            text = text.replace(placeholder, code)
        return text

    def _compress_phrases(self, text: str) -> str:
        """Replace verbose phrases with shorter equivalents."""
        for verbose, short in self.PHRASE_COMPRESSIONS.items():
            text = re.sub(re.escape(verbose), short, text, flags=re.IGNORECASE)
        return text

    def _remove_fillers(self, text: str) -> str:
        """Remove filler words and patterns."""
        for pattern, replacement in self._filler_patterns:
            text = pattern.sub(replacement, text)
        return text

    def _compress_system_prompt(self, text: str) -> str:
        """Compress system prompt specific patterns."""
        # Remove excessive bullet points formatting
        text = re.sub(r"^\s*[-*•]\s*", "- ", text, flags=re.MULTILINE)

        # Compress repeated section headers
        text = re.sub(r"(#+\s*\w+)\s*\n\s*\1", r"\1", text)

        # Remove "You are..." preambles if aggressive
        if self.aggressive:
            text = re.sub(
                r"(?i)^you are (?:an? )?(?:helpful |friendly |expert )*",
                "",
                text
            )

        return text

    def _compress_history(self, text: str) -> str:
        """Compress conversation history."""
        # Split into turns
        turns = re.split(r"(?:User|Human|Assistant|AI):\s*", text)
        turns = [t.strip() for t in turns if t.strip()]

        if len(turns) <= self.max_history_turns * 2:
            return text

        # Keep first few and last few turns, summarize middle
        keep_start = 2
        keep_end = self.max_history_turns * 2 - keep_start

        if len(turns) > keep_start + keep_end:
            middle_count = len(turns) - keep_start - keep_end
            summary = f"[... {middle_count} earlier messages summarized ...]"

            preserved = turns[:keep_start] + [summary] + turns[-keep_end:]
            return "\n".join(preserved)

        return text

    def _aggressive_compress(self, text: str) -> str:
        """Apply aggressive compression techniques."""
        # Remove all parenthetical remarks
        text = re.sub(r"\s*\([^)]{1,100}\)\s*", " ", text)

        # Remove example markers
        text = re.sub(r"(?i)\b(?:for example|e\.g\.|i\.e\.|such as)[,:]?\s*", "", text)

        # Shorten common technical terms
        abbreviations = {
            "configuration": "config",
            "information": "info",
            "application": "app",
            "documentation": "docs",
            "implementation": "impl",
            "functionality": "feature",
            "authentication": "auth",
            "authorization": "authz",
            "environment": "env",
            "development": "dev",
            "production": "prod",
        }
        for full, abbrev in abbreviations.items():
            text = re.sub(rf"\b{full}\b", abbrev, text, flags=re.IGNORECASE)

        return text

    def _final_cleanup(self, text: str) -> str:
        """Final cleanup pass."""
        # Collapse multiple spaces
        text = re.sub(r" {2,}", " ", text)

        # Collapse multiple newlines
        text = re.sub(r"\n{3,}", "\n\n", text)

        # Strip lines
        lines = [line.strip() for line in text.split("\n")]
        text = "\n".join(lines)

        return text.strip()

    def compress_messages(
        self,
        messages: list[dict[str, str]],
        max_total_tokens: Optional[int] = None,
    ) -> tuple[list[dict[str, str]], int]:
        """
        Compress a list of chat messages.

        Returns (compressed_messages, tokens_saved).
        """
        if not messages:
            return messages, 0

        total_saved = 0
        compressed = []

        for msg in messages:
            role = msg.get("role", "user")
            content = msg.get("content", "")

            # Determine context type
            if role == "system":
                context_type = "system_prompt"
            elif len(compressed) > 2:
                context_type = "history"
            else:
                context_type = "general"

            result = self.compress(content, context_type)
            total_saved += result.tokens_saved

            compressed.append({
                "role": role,
                "content": result.compressed_text,
            })

        # If max_total_tokens specified, do additional truncation
        if max_total_tokens:
            total_tokens = sum(
                self._estimate_tokens(m["content"]) for m in compressed
            )

            while total_tokens > max_total_tokens and len(compressed) > 2:
                # Remove oldest non-system message
                for i, msg in enumerate(compressed):
                    if msg["role"] != "system":
                        removed_tokens = self._estimate_tokens(msg["content"])
                        total_saved += removed_tokens
                        compressed.pop(i)
                        total_tokens -= removed_tokens
                        break
                else:
                    break

        return compressed, total_saved
