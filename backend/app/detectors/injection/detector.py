"""
Unified prompt injection detector.

Combines the rule-based, (optional) embedding-based, and (optional)
LLM-based detectors into a single interface. Results are merged,
deduplicated, and scored to produce a final risk assessment.

Detection Layers:
    1. Rule-based (fast, free, high-precision) - catches known patterns
    2. Embedding-based (optional, moderate speed) - catches semantic variants
    3. LLM Classifier (optional, slowest, paid) - catches novel/sophisticated attacks
"""

from __future__ import annotations

import logging
from typing import Any

from app.detectors.injection.rules import RuleBasedDetector
from app.detectors.injection.embeddings import EmbeddingDetector
from app.detectors.injection.llm_classifier import LLMClassifier
from app.detectors.injection.local_classifier import LocalClassifier
from app.detectors.injection.transformer_classifier import TransformerClassifier
from app.detectors.injection.graphrag_classifier import GraphRAGClassifier
from app.detectors.injection.intent_classifier import IntentClassifier

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
    Pass ``use_llm=True`` to enable LLM-based classification for
    sophisticated attacks that evade pattern matching.
    """

    def __init__(
        self,
        use_embeddings: bool = False,
        use_llm: bool = False,
        llm_always: bool = False,
        llm_confidence_threshold: float = 0.6,
        use_local_ml: bool = True,
        local_ml_confidence_threshold: float = 0.85,
        use_graphrag: bool = True,
        graphrag_confidence_threshold: float = 0.6,
        use_intent_classifier: bool = True,
        use_transformer: bool = True,
        transformer_confidence_threshold: float = 0.7,
    ) -> None:
        """
        Initialize the detector.

        Parameters
        ----------
        use_embeddings : bool
            Enable embedding-based detection.
        use_llm : bool
            Enable LLM-based classification as fallback (only when patterns miss).
        llm_always : bool
            Run LLM for ALL inputs (not just fallback). Higher accuracy but more API cost.
        llm_confidence_threshold : float
            Minimum confidence for LLM detection. Default: 0.6.
        use_local_ml : bool
            Enable local ML classifier (fast, free, offline). Default: True.
        local_ml_confidence_threshold : float
            Minimum confidence for local ML detection. Default: 0.7.
        use_graphrag : bool
            Enable GraphRAG-based classification (compares to known samples). Default: True.
        graphrag_confidence_threshold : float
            Minimum confidence for GraphRAG detection. Default: 0.6.
        use_intent_classifier : bool
            Enable intent classification to reduce false positives on educational questions. Default: True.
        """
        self._rule_detector = RuleBasedDetector()
        self._use_embeddings = use_embeddings
        self._use_llm = use_llm
        self._llm_always = llm_always
        self._use_local_ml = use_local_ml
        self._use_graphrag = use_graphrag
        self._use_intent_classifier = use_intent_classifier
        self._use_transformer = use_transformer
        self._embedding_detector: EmbeddingDetector | None = None
        self._llm_classifier: LLMClassifier | None = None
        self._local_classifier: LocalClassifier | None = None
        self._transformer_classifier: TransformerClassifier | None = None
        self._graphrag_classifier: GraphRAGClassifier | None = None
        self._intent_classifier: IntentClassifier | None = None

        # Intent classifier (fast, reduces false positives on educational questions)
        if use_intent_classifier:
            self._intent_classifier = IntentClassifier(educational_threshold=0.7)
            logger.info("InjectionDetector initialized with Intent classifier.")

        # Local ML classifier (RandomForest, fast, free)
        if use_local_ml:
            self._local_classifier = LocalClassifier(
                confidence_threshold=local_ml_confidence_threshold,
            )
            if self._local_classifier.enabled:
                logger.info("InjectionDetector initialised with local ML classifier.")
            else:
                logger.warning("Local ML classifier requested but model not found.")
                self._use_local_ml = False

        # Transformer classifier (Fine-tuned DistilBERT, most accurate)
        if use_transformer:
            self._transformer_classifier = TransformerClassifier(
                confidence_threshold=transformer_confidence_threshold,
            )
            if self._transformer_classifier.enabled:
                logger.info("InjectionDetector initialised with Transformer classifier (DistilBERT).")
            else:
                logger.warning("Transformer classifier requested but model not found.")
                self._use_transformer = False

        if use_embeddings:
            self._embedding_detector = EmbeddingDetector()
            logger.info("InjectionDetector initialised with embedding support.")

        if use_llm or llm_always:
            self._llm_classifier = LLMClassifier(
                confidence_threshold=llm_confidence_threshold,
            )
            if self._llm_classifier.enabled:
                mode = "ALWAYS" if llm_always else "fallback"
                logger.info(f"InjectionDetector initialised with LLM classifier ({mode} mode).")
                self._use_llm = True
            else:
                logger.warning("LLM classifier requested but no API key available.")
                self._use_llm = False
                self._llm_always = False

        # GraphRAG classifier (uses Neo4j graph similarity)
        if use_graphrag:
            self._graphrag_classifier = GraphRAGClassifier(
                confidence_threshold=graphrag_confidence_threshold,
            )
            if self._graphrag_classifier.enabled:
                logger.info("InjectionDetector initialised with GraphRAG classifier.")
            else:
                logger.warning("GraphRAG classifier requested but Neo4j not available.")
                self._use_graphrag = False

        if not use_embeddings and not use_llm and not llm_always and not use_local_ml and not use_graphrag:
            logger.info("InjectionDetector initialised (rules only).")

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def scan(self, text: str) -> dict[str, Any]:
        """Synchronous wrapper for detect().

        For use in sync contexts (e.g., Shield.check()).
        """
        import asyncio

        try:
            # Try to get existing loop
            loop = asyncio.get_running_loop()
        except RuntimeError:
            loop = None

        if loop is None:
            # No running loop, safe to use asyncio.run()
            return asyncio.run(self.detect(text))
        else:
            # Already in async context - run in a new thread to avoid blocking
            import concurrent.futures
            with concurrent.futures.ThreadPoolExecutor() as executor:
                future = executor.submit(asyncio.run, self.detect(text))
                return future.result()

    async def detect(self, text: str) -> dict[str, Any]:
        """Detect prompt injection threats in *text*.

        Returns a dict with ``threats`` list and ``risk_score`` float.

        Detection Flow:
            1. Rule-based detection (always runs, fast, free)
            2. Embedding detection (if enabled)
            3. LLM classification:
               - llm_always=True: runs for ALL inputs (max accuracy, higher cost)
               - llm_always=False: runs only when patterns miss (fallback mode)
        """
        if not text or not text.strip():
            return {"threats": [], "risk_score": 0.0, "risk_level": "negligible"}

        # Layer 0: Intent classification (bypass for educational questions)
        # This reduces false positives on legitimate security education questions
        if self._use_intent_classifier and self._intent_classifier is not None:
            try:
                bypass_result = self._intent_classifier.get_bypass_recommendation(text)
                if bypass_result["should_bypass"]:
                    logger.info(
                        "Intent classifier bypassed detection: %s | %s",
                        bypass_result["reason"], text[:50]
                    )
                    return {
                        "threats": [],
                        "risk_score": 0.0,
                        "risk_level": "negligible",
                        "intent_bypass": True,
                        "intent_classification": bypass_result["classification"],
                    }
            except Exception as exc:  # noqa: BLE001
                logger.warning("Intent classification failed, continuing with detection: %s", exc)

        # Layer 1: Rule-based detection (fast, free)
        rule_threats = self._rule_detector.detect(text)

        # Layer 2: Embedding detection (optional)
        embedding_threats: list[dict[str, Any]] = []
        if self._use_embeddings and self._embedding_detector is not None:
            try:
                embedding_threats = self._embedding_detector.detect(text)
            except Exception as exc:  # noqa: BLE001
                logger.error("Embedding detection failed: %s", exc)

        # Merge rule + embedding results
        merged = self._merge_results(rule_threats, embedding_threats)

        # Layer 2.5: Fine-tuned Transformer classification (most accurate, free)
        transformer_threats: list[dict[str, Any]] = []
        if self._use_transformer and self._transformer_classifier is not None:
            try:
                transformer_threats = self._transformer_classifier.classify(text)
                if transformer_threats:
                    if not merged:
                        logger.info("Transformer classifier caught attack missed by patterns.")
                    else:
                        logger.debug("Transformer classifier confirmed attack.")
            except Exception as exc:  # noqa: BLE001
                logger.error("Transformer classification failed: %s", exc)

        # Merge with transformer results
        merged = self._merge_results(merged, transformer_threats)

        # Layer 2.6: Local ML classification (RandomForest, fast, free, fallback)
        local_ml_threats: list[dict[str, Any]] = []
        if self._use_local_ml and self._local_classifier is not None and not merged:
            try:
                local_ml_threats = self._local_classifier.classify(text)
                if local_ml_threats:
                    logger.info("Local ML classifier caught attack missed by patterns.")
            except Exception as exc:  # noqa: BLE001
                logger.error("Local ML classification failed: %s", exc)

        # Merge with local ML results
        merged = self._merge_results(merged, local_ml_threats)

        # Layer 3: GraphRAG classification (compare to known attack/benign samples)
        # GraphRAG can help REDUCE false positives by comparing input similarity
        graphrag_threats: list[dict[str, Any]] = []
        graphrag_benign_sim = 0.0
        graphrag_attack_sim = 0.0
        if self._use_graphrag and self._graphrag_classifier is not None:
            try:
                graphrag_result = self._graphrag_classifier.classify(text)
                # Get similarity scores for filtering decisions
                graphrag_benign_sim = getattr(self._graphrag_classifier, 'last_benign_similarity', 0.0)
                graphrag_attack_sim = getattr(self._graphrag_classifier, 'last_attack_similarity', 0.0)

                if graphrag_result:
                    # GraphRAG detected attack
                    graphrag_threats = graphrag_result
                    if graphrag_threats and not merged:
                        logger.info("GraphRAG classifier caught attack missed by patterns.")
                else:
                    # GraphRAG says benign
                    if merged:
                        logger.debug(
                            "GraphRAG says benign (sim=%.3f), other detectors flagged - checking...",
                            graphrag_benign_sim
                        )
            except Exception as exc:  # noqa: BLE001
                logger.error("GraphRAG classification failed: %s", exc)

        # Merge with GraphRAG results
        merged = self._merge_results(merged, graphrag_threats)

        # False positive filtering based on GraphRAG benign similarity
        # IMPORTANT: Only filter when STRONGLY benign (high benign_sim AND large margin over attack)
        # This prevents filtering actual attacks that might have some benign similarity
        benign_margin = graphrag_benign_sim - graphrag_attack_sim

        # Only filter if:
        # 1. Benign similarity is significantly higher than attack similarity (margin >= 0.15)
        # 2. Benign similarity is reasonably high (>= 0.55)
        # 3. Attack similarity is not high (< 0.50) - avoid filtering real attacks
        should_filter = (
            benign_margin >= 0.15 and
            graphrag_benign_sim >= 0.55 and
            graphrag_attack_sim < 0.50 and
            merged
        )

        if should_filter:
            # Safe to filter - very strong benign signal
            filter_threshold = 0.92 if benign_margin >= 0.25 else 0.88

            filtered = []
            for threat in merged:
                conf = threat.get("confidence", 0)
                if conf >= filter_threshold:
                    filtered.append(threat)
                else:
                    logger.info(
                        "Filtered false positive (conf=%.2f < %.2f, benign_sim=%.3f, atk_sim=%.3f, margin=%.3f): %s",
                        conf, filter_threshold, graphrag_benign_sim, graphrag_attack_sim, benign_margin,
                        threat.get("pattern_id", "unknown")
                    )
            merged = filtered

        # Layer 4: LLM classification
        # - llm_always=True: run for ALL inputs (maximum accuracy)
        # - llm_always=False: run only when patterns miss (cost optimization)
        llm_threats: list[dict[str, Any]] = []
        should_run_llm = self._use_llm and self._llm_classifier is not None
        if should_run_llm:
            if self._llm_always or not merged:
                try:
                    llm_threats = await self._llm_classifier.classify(text)
                    if llm_threats and not merged:
                        logger.info("LLM classifier caught attack missed by patterns.")
                    elif llm_threats and merged:
                        logger.debug("LLM classifier confirmed pattern detection.")
                except Exception as exc:  # noqa: BLE001
                    logger.error("LLM classification failed: %s", exc)

        # Final merge
        merged = self._merge_results(merged, llm_threats)

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
        return {"threats": merged, "risk_score": risk_score, "risk_level": risk_level}

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
