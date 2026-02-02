"""
Unified prompt injection detector.

Combines the rule-based and (optional) embedding-based detectors into
a single interface. Results are merged, deduplicated, and scored to
produce a final risk assessment.
"""

from __future__ import annotations

import logging
from typing import Any

from app.detectors.injection.rules import RuleBasedDetector
from app.detectors.injection.embeddings import EmbeddingDetector

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Risk-level thresholds
# ---------------------------------------------------------------------------

_RISK_THRESHOLDS: list[tuple[float, str]] = [
    (0.80, "critical"),
    (0.60, "high"),
    (0.35, "medium"),
    (0.10, "low"),
    (0.00, "negligible"),
]

# Severity weights for aggregate score computation.
_SEVERITY_WEIGHTS: dict[str, float] = {
    "critical": 1.0,
    "high": 0.75,
    "medium": 0.50,
    "low": 0.25,
}


class InjectionDetector:
    """High-level prompt injection detector.

    By default only the lightweight rule-based engine is active.
    Pass ``use_embeddings=True`` to additionally enable semantic
    similarity detection (requires ``sentence-transformers``).
    """

    def __init__(self, use_embeddings: bool = False) -> None:
        self._rule_detector = RuleBasedDetector()
        self._use_embeddings = use_embeddings
        self._embedding_detector: EmbeddingDetector | None = None

        if use_embeddings:
            self._embedding_detector = EmbeddingDetector()
            logger.info("InjectionDetector initialised with embedding support.")
        else:
            logger.info("InjectionDetector initialised (rules only).")

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def detect(self, text: str) -> list[dict[str, Any]]:
        """Detect prompt injection threats in *text*.

        Parameters
        ----------
        text:
            The input text to analyse.

        Returns
        -------
        list[dict]:
            Each dict contains:
            - ``type``          -- ``"injection"``
            - ``subtype``       -- category / detection method
            - ``pattern_id``    -- unique pattern ID
            - ``matched_text``  -- matched substring or phrase
            - ``position``      -- ``(start, end)`` character span
            - ``confidence``    -- ``[0.0, 1.0]``
            - ``severity``      -- ``"low"`` | ``"medium"`` | ``"high"`` | ``"critical"``
            - ``description``   -- human-readable description
            - ``risk_score``    -- aggregate risk score for all threats
            - ``risk_level``    -- aggregate risk level label
        """
        if not text or not text.strip():
            return []

        rule_threats = self._rule_detector.detect(text)

        embedding_threats: list[dict[str, Any]] = []
        if self._use_embeddings and self._embedding_detector is not None:
            try:
                embedding_threats = self._embedding_detector.detect(text)
            except Exception as exc:  # noqa: BLE001
                logger.error("Embedding detection failed: %s", exc)

        merged = self._merge_results(rule_threats, embedding_threats)

        # Compute aggregate risk and annotate each threat.
        risk_score = self._compute_risk_score(merged)
        risk_level = self._determine_risk_level(risk_score)

        for threat in merged:
            threat["risk_score"] = round(risk_score, 4)
            threat["risk_level"] = risk_level

        logger.info(
            "InjectionDetector: %d threat(s), risk_score=%.4f (%s) for text length %d.",
            len(merged),
            risk_score,
            risk_level,
            len(text),
        )
        return merged

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _merge_results(
        rule_threats: list[dict[str, Any]],
        embedding_threats: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        """Merge and deduplicate threats from both detectors.

        Deduplication is based on ``pattern_id``.  When a pattern ID
        appears in both lists the entry with the higher confidence is
        kept.  The final list is sorted by confidence descending.

        Parameters
        ----------
        rule_threats:
            Threats from the rule-based detector.
        embedding_threats:
            Threats from the embedding detector.

        Returns
        -------
        list[dict]:
            Merged, deduplicated list of threats.
        """
        seen: dict[str, dict[str, Any]] = {}

        for threat in rule_threats + embedding_threats:
            pid = threat.get("pattern_id", "")
            existing = seen.get(pid)
            if existing is None or threat.get("confidence", 0) > existing.get("confidence", 0):
                seen[pid] = threat

        merged = list(seen.values())
        merged.sort(key=lambda t: t.get("confidence", 0), reverse=True)
        return merged

    @staticmethod
    def _compute_risk_score(threats: list[dict[str, Any]]) -> float:
        """Compute an aggregate risk score from all detected threats.

        The score is a weighted combination of individual threat
        confidences, where the weight is determined by severity.
        The result is clamped to ``[0.0, 1.0]``.

        Parameters
        ----------
        threats:
            The list of threat dicts to aggregate.

        Returns
        -------
        float:
            The aggregate risk score.
        """
        if not threats:
            return 0.0

        weighted_sum = 0.0
        weight_total = 0.0

        for threat in threats:
            severity = threat.get("severity", "low")
            confidence = threat.get("confidence", 0.0)
            weight = _SEVERITY_WEIGHTS.get(severity, 0.25)

            weighted_sum += confidence * weight
            weight_total += weight

        if weight_total == 0.0:
            return 0.0

        # Normalise by weight total, then boost slightly when there are
        # many threats (capped).
        base_score = weighted_sum / weight_total
        count_bonus = min(0.02 * (len(threats) - 1), 0.10)
        score = base_score + count_bonus

        return max(0.0, min(score, 1.0))

    @staticmethod
    def _determine_risk_level(score: float) -> str:
        """Map a numeric risk score to a human-readable level.

        Parameters
        ----------
        score:
            The aggregate risk score (0.0 -- 1.0).

        Returns
        -------
        str:
            One of ``"critical"``, ``"high"``, ``"medium"``,
            ``"low"``, or ``"negligible"``.
        """
        for threshold, level in _RISK_THRESHOLDS:
            if score >= threshold:
                return level
        return "negligible"
