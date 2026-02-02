"""
Unified PII detector.

Combines Korean-specific and global PII pattern sets into a single
detection interface. Detected PII items can optionally be sanitized
in one step.
"""

from __future__ import annotations

import logging
import re
from typing import Any, Callable, Optional

from app.detectors.pii.korean import KOREAN_PII_PATTERNS
from app.detectors.pii.global_patterns import GLOBAL_PII_PATTERNS
from app.detectors.pii.sanitizer import PIISanitizer

logger = logging.getLogger(__name__)


class PIIDetector:
    """Detect and optionally sanitize PII in text.

    Loads pattern definitions from :mod:`korean` and :mod:`global_patterns`
    at initialisation and compiles them for efficient repeated scanning.
    """

    def __init__(self) -> None:
        self._patterns: list[dict[str, Any]] = []
        self._sanitizer = PIISanitizer()
        self._load_patterns()

    # ------------------------------------------------------------------
    # Pattern loading
    # ------------------------------------------------------------------

    def _load_patterns(self) -> None:
        """Compile all Korean and global PII patterns."""
        combined: dict[str, dict[str, Any]] = {}
        combined.update(KOREAN_PII_PATTERNS)
        combined.update(GLOBAL_PII_PATTERNS)

        loaded = 0
        for pii_type, definition in combined.items():
            raw_pattern = definition.get("pattern", "")
            try:
                compiled = re.compile(raw_pattern)
            except re.error as exc:
                logger.warning(
                    "Failed to compile PII pattern for '%s': %s",
                    pii_type,
                    exc,
                )
                continue

            self._patterns.append(
                {
                    "pii_type": pii_type,
                    "compiled": compiled,
                    "severity": definition.get("severity", "medium"),
                    "description": definition.get("description", ""),
                    "validator": definition.get("validator"),
                }
            )
            loaded += 1

        logger.info("PIIDetector loaded %d pattern(s).", loaded)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def detect(self, text: str) -> dict[str, Any]:
        """Scan *text* for PII matches.

        Returns a dict with ``pii_entities`` list and ``sanitized_text``.
        """
        if not text or not text.strip():
            return {"pii_entities": [], "sanitized_text": text}

        results: list[dict[str, Any]] = []
        seen_spans: set[tuple[int, int]] = set()

        for entry in self._patterns:
            compiled: re.Pattern[str] = entry["compiled"]
            validator: Optional[Callable[[str], bool]] = entry.get("validator")

            for match in compiled.finditer(text):
                span = match.span()

                if self._overlaps_existing(span, seen_spans):
                    continue

                matched_value = match.group()

                validated: Optional[bool] = None
                if validator is not None:
                    try:
                        validated = validator(matched_value)
                    except Exception as exc:  # noqa: BLE001
                        logger.warning(
                            "Validator for '%s' raised an exception: %s",
                            entry["pii_type"],
                            exc,
                        )
                        validated = False

                    if validated is False:
                        continue

                seen_spans.add(span)
                results.append(
                    {
                        "type": entry["pii_type"],
                        "subtype": entry["pii_type"],
                        "value": matched_value,
                        "position": [span[0], span[1]],
                        "confidence": 1.0 if validated is not False else 0.8,
                        "severity": entry["severity"],
                        "description": entry["description"],
                    }
                )

        sanitized_text = self._sanitizer.sanitize(text, results)

        logger.debug(
            "PIIDetector found %d PII item(s) in text of length %d.",
            len(results),
            len(text),
        )
        return {"pii_entities": results, "sanitized_text": sanitized_text}

    def sanitize(self, text: str, auto: bool = True) -> str:
        """Detect and replace PII in *text*.

        Parameters
        ----------
        text:
            The input text.
        auto:
            If ``True`` (default), detection is run automatically before
            sanitisation. If ``False``, an empty detection list is used
            (useful when the caller provides their own PII items).

        Returns
        -------
        str:
            The sanitized text with PII replaced by labels.
        """
        if auto:
            pii_items = self.detect(text)
        else:
            pii_items = []

        return self._sanitizer.sanitize(text, pii_items)

    def sanitize_with_items(
        self, text: str, pii_items: list[dict[str, Any]]
    ) -> str:
        """Sanitize *text* using a caller-provided PII item list.

        Parameters
        ----------
        text:
            The input text.
        pii_items:
            Pre-detected PII items.

        Returns
        -------
        str:
            The sanitized text.
        """
        return self._sanitizer.sanitize(text, pii_items)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _overlaps_existing(
        span: tuple[int, int],
        existing: set[tuple[int, int]],
    ) -> bool:
        """Check whether *span* overlaps any span in *existing*.

        Parameters
        ----------
        span:
            ``(start, end)`` of the candidate span.
        existing:
            Set of already-accepted spans.

        Returns
        -------
        bool:
            ``True`` if there is any overlap.
        """
        start, end = span
        for ex_start, ex_end in existing:
            if start < ex_end and end > ex_start:
                return True
        return False
