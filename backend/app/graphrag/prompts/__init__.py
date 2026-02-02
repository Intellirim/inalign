"""
Prompt templates for the GraphRAG security analysis pipeline.

All prompts are plain strings with ``{placeholder}`` markers intended for
use with :py:meth:`str.format` or f-strings at call time.
"""

from __future__ import annotations

from app.graphrag.prompts.pattern_analysis import PATTERN_ANALYSIS_PROMPT
from app.graphrag.prompts.security_report import (
    SECURITY_REPORT_PROMPT_EN,
    SECURITY_REPORT_PROMPT_KO,
)

__all__: list[str] = [
    "SECURITY_REPORT_PROMPT_KO",
    "SECURITY_REPORT_PROMPT_EN",
    "PATTERN_ANALYSIS_PROMPT",
]
