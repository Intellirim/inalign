"""
Rule-based prompt injection detector.

Applies regex pattern matching against input text to identify
prompt injection attempts. Patterns are loaded from the patterns
module and scored based on match quality, frequency, and text length.
"""

from __future__ import annotations

import logging
import re
from typing import Any, Optional

from app.detectors.injection.patterns import INJECTION_PATTERNS, PATTERNS_BY_ID

logger = logging.getLogger(__name__)


class RuleBasedDetector:
    """Detects prompt injection attempts using compiled regex patterns.

    This detector loads all injection patterns at initialisation,
    compiles them for performance, and provides a ``detect`` method
    that returns structured threat information for every match found
    in the input text.
    """

    def __init__(self) -> None:
        self._compiled_patterns: list[dict[str, Any]] = []
        self.load_patterns()

    # ------------------------------------------------------------------
    # Pattern loading
    # ------------------------------------------------------------------

    def load_patterns(self) -> None:
        """Load and compile all injection patterns from the pattern catalogue.

        Each pattern string is compiled into a ``re.Pattern`` object so
        that matching is performed efficiently across repeated calls.
        """
        self._compiled_patterns = []
        loaded_count = 0
        error_count = 0

        for entry in INJECTION_PATTERNS:
            compiled_entry: dict[str, Any] = {
                "id": entry["id"],
                "category": entry["category"],
                "severity": entry["severity"],
                "confidence_base": entry["confidence_base"],
                "description": entry["description"],
                "compiled": [],
            }

            for raw_pattern in entry["patterns"]:
                try:
                    compiled_entry["compiled"].append(re.compile(raw_pattern, re.DOTALL))
                    loaded_count += 1
                except re.error as exc:
                    error_count += 1
                    logger.warning(
                        "Failed to compile pattern %s in %s: %s",
                        raw_pattern,
                        entry["id"],
                        exc,
                    )

            self._compiled_patterns.append(compiled_entry)

        logger.info(
            "RuleBasedDetector loaded %d regex patterns from %d entries (%d errors).",
            loaded_count,
            len(INJECTION_PATTERNS),
            error_count,
        )

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def detect(self, text: str) -> list[dict[str, Any]]:
        """Scan *text* for prompt injection patterns.

        Parameters
        ----------
        text:
            The input text to analyse.

        Returns
        -------
        list[dict]:
            A list of threat dictionaries, each containing:
            - ``type``          -- always ``"injection"``
            - ``subtype``       -- the pattern category
            - ``pattern_id``    -- the unique pattern ID (e.g. ``"INJ-001"``)
            - ``matched_text``  -- the substring that matched
            - ``position``      -- ``(start, end)`` tuple of the match span
            - ``confidence``    -- computed confidence score ``[0, 1]``
            - ``severity``      -- ``"low"`` | ``"medium"`` | ``"high"`` | ``"critical"``
            - ``description``   -- human-readable description of the pattern
        """
        if not text or not text.strip():
            return []

        threats: list[dict[str, Any]] = []

        for entry in self._compiled_patterns:
            matches = self._check_pattern(text, entry)
            if matches:
                threats.extend(matches)

        logger.debug(
            "RuleBasedDetector found %d threat(s) in text of length %d.",
            len(threats),
            len(text),
        )
        return threats

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _check_pattern(
        self, text: str, pattern_entry: dict[str, Any]
    ) -> list[dict[str, Any]]:
        """Check a single pattern entry against *text* and return match results.

        Parameters
        ----------
        text:
            The input text to scan.
        pattern_entry:
            A compiled pattern entry dict with keys ``id``, ``category``,
            ``severity``, ``confidence_base``, ``description``, and
            ``compiled`` (list of ``re.Pattern``).

        Returns
        -------
        list[dict]:
            One threat dict per unique match found.
        """
        results: list[dict[str, Any]] = []
        seen_spans: set[tuple[int, int]] = set()
        all_matches: list[re.Match[str]] = []

        for compiled_re in pattern_entry["compiled"]:
            try:
                for match in compiled_re.finditer(text):
                    span = match.span()
                    if span not in seen_spans:
                        seen_spans.add(span)
                        all_matches.append(match)
            except Exception as exc:  # noqa: BLE001
                logger.warning(
                    "Regex execution error for pattern %s: %s",
                    pattern_entry["id"],
                    exc,
                )

        match_count = len(all_matches)
        if match_count == 0:
            return results

        confidence = self._compute_confidence(
            pattern_entry["confidence_base"],
            match_count,
            len(text),
        )

        for match in all_matches:
            results.append(
                {
                    "type": "injection",
                    "subtype": pattern_entry["category"],
                    "pattern_id": pattern_entry["id"],
                    "matched_text": match.group(),
                    "position": match.span(),
                    "confidence": round(confidence, 4),
                    "severity": pattern_entry["severity"],
                    "description": pattern_entry["description"],
                }
            )

        return results

    @staticmethod
    def _compute_confidence(
        base_confidence: float,
        match_count: int,
        text_length: int,
    ) -> float:
        """Compute an adjusted confidence score.

        The score is derived from the pattern's base confidence and
        then boosted slightly when:
        - Multiple matches are found (repetition signals intent).
        - The injection text occupies a large portion of the input
          (higher density = higher confidence).

        Parameters
        ----------
        base_confidence:
            The pattern catalogue's base confidence (0.0 -- 1.0).
        match_count:
            The number of distinct match spans found.
        text_length:
            The total length of the input text in characters.

        Returns
        -------
        float:
            The adjusted confidence, clamped to ``[0.0, 1.0]``.
        """
        if text_length <= 0:
            return base_confidence

        # Repetition bonus: each additional match adds a diminishing boost.
        repetition_bonus = min(0.05 * (match_count - 1), 0.15)

        # Density bonus: if the text is short the injection is more
        # prominent, giving a small positive signal.
        density_bonus = 0.0
        if text_length < 200:
            density_bonus = 0.05
        elif text_length < 500:
            density_bonus = 0.03

        confidence = base_confidence + repetition_bonus + density_bonus
        return max(0.0, min(confidence, 1.0))
