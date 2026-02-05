"""
Local ML-based prompt injection classifier.

Supports two model types:
1. RandomForest + SentenceTransformer (default, fast)
2. Fine-tuned Transformer (DistilBERT/DeBERTa, more accurate)

This provides:
- Zero API cost
- Low latency (~10-50ms)
- Offline capability
- High accuracy (99%+ on test set)
"""
from __future__ import annotations

import logging
import pickle
from pathlib import Path
from typing import Any, Literal, Optional

import numpy as np

logger = logging.getLogger("inalign.local_classifier")

# Model paths
_MODEL_PATH = Path(__file__).parent / "models" / "latest_classifier.pkl"
_TRANSFORMER_MODEL_PATH = Path(__file__).parent.parent.parent / "ml" / "models" / "injection_detector" / "best"


class LocalClassifier:
    """
    Local ML-based prompt injection classifier.

    Uses pre-trained RandomForest with sentence embeddings.
    Fast, free, and works offline.

    Usage:
        classifier = LocalClassifier()
        if classifier.enabled:
            threats = classifier.classify(text)
    """

    def __init__(
        self,
        model_path: Optional[Path] = None,
        confidence_threshold: float = 0.7,
    ):
        self.model_path = model_path or _MODEL_PATH
        self.confidence_threshold = confidence_threshold

        self._model = None
        self._embedder = None
        self._classifier = None
        self._classifier_name = None
        self.enabled = False

        self._load_model()

    def _load_model(self) -> None:
        """Load the pre-trained model and embedder."""
        if not self.model_path.exists():
            logger.warning("Local model not found at %s", self.model_path)
            return

        try:
            # Load model data
            with open(self.model_path, "rb") as f:
                self._model = pickle.load(f)

            self._classifier = self._model.get("classifier")
            self._classifier_name = self._model.get("classifier_name", "Unknown")
            embedder_name = self._model.get("embedder_name", "all-MiniLM-L6-v2")

            # Load sentence transformer
            from sentence_transformers import SentenceTransformer
            self._embedder = SentenceTransformer(embedder_name)

            self.enabled = True
            logger.info(
                "LocalClassifier loaded: %s with %s embedder",
                self._classifier_name, embedder_name
            )

            # Log model metrics
            results = self._model.get("results", {})
            if self._classifier_name in results:
                metrics = results[self._classifier_name]
                logger.info(
                    "Model metrics: F1=%.3f, Precision=%.3f, Recall=%.3f",
                    metrics.get("f1", 0),
                    metrics.get("precision", 0),
                    metrics.get("recall", 0),
                )

        except Exception as e:
            logger.error("Failed to load local classifier: %s", e)
            self.enabled = False

    def classify(self, text: str) -> list[dict[str, Any]]:
        """
        Classify input text using the local model.

        Returns a list of threat dicts (empty if benign or disabled).
        """
        if not self.enabled or not text or len(text.strip()) < 5:
            return []

        try:
            # Generate embedding
            embedding = self._embedder.encode([text], convert_to_numpy=True)

            # Get prediction and probability
            prediction = self._classifier.predict(embedding)[0]
            probabilities = self._classifier.predict_proba(embedding)[0]

            # Class 1 = injection, Class 0 = benign
            is_injection = prediction == 1
            confidence = float(probabilities[1])  # Probability of injection class

            logger.debug(
                "LocalClassifier: injection=%s conf=%.2f | %s",
                is_injection, confidence, text[:60]
            )

            if is_injection and confidence >= self.confidence_threshold:
                return [{
                    "type": "injection",
                    "subtype": "local_ml_classifier",
                    "pattern_id": "LOCAL-ML-CLASSIFIER",
                    "matched_text": f"Local {self._classifier_name} classifier",
                    "position": (0, min(len(text), 50)),
                    "confidence": round(confidence, 4),
                    "severity": "high" if confidence >= 0.85 else "medium",
                    "description": (
                        f"Local ML classifier ({self._classifier_name}) detected "
                        f"potential injection (confidence={confidence:.0%})"
                    ),
                }]

            return []

        except Exception as e:
            logger.warning("LocalClassifier error: %s", e)
            return []

    def classify_batch(self, texts: list[str]) -> list[list[dict[str, Any]]]:
        """Classify multiple texts at once (more efficient)."""
        if not self.enabled or not texts:
            return [[] for _ in texts]

        try:
            # Generate embeddings in batch
            embeddings = self._embedder.encode(texts, convert_to_numpy=True)

            # Get predictions
            predictions = self._classifier.predict(embeddings)
            probabilities = self._classifier.predict_proba(embeddings)

            results = []
            for i, text in enumerate(texts):
                is_injection = predictions[i] == 1
                confidence = float(probabilities[i][1])

                if is_injection and confidence >= self.confidence_threshold:
                    results.append([{
                        "type": "injection",
                        "subtype": "local_ml_classifier",
                        "pattern_id": "LOCAL-ML-CLASSIFIER",
                        "matched_text": f"Local {self._classifier_name} classifier",
                        "position": (0, min(len(text), 50)),
                        "confidence": round(confidence, 4),
                        "severity": "high" if confidence >= 0.85 else "medium",
                        "description": (
                            f"Local ML classifier ({self._classifier_name}) detected "
                            f"potential injection (confidence={confidence:.0%})"
                        ),
                    }])
                else:
                    results.append([])

            return results

        except Exception as e:
            logger.warning("LocalClassifier batch error: %s", e)
            return [[] for _ in texts]


class TransformerClassifier:
    """
    Transformer-based prompt injection classifier.

    Uses a fine-tuned DistilBERT/DeBERTa model for higher accuracy.
    Slightly slower than RandomForest but more accurate.

    Usage:
        classifier = TransformerClassifier()
        if classifier.enabled:
            threats = classifier.classify(text)
    """

    def __init__(
        self,
        model_path: Optional[Path] = None,
        confidence_threshold: float = 0.85,
    ):
        self.model_path = model_path or _TRANSFORMER_MODEL_PATH
        self.confidence_threshold = confidence_threshold
        self._classifier = None
        self.enabled = False

        self._load_model()

    def _load_model(self) -> None:
        """Load the fine-tuned transformer model."""
        if not self.model_path.exists():
            logger.info("Transformer model not found at %s", self.model_path)
            return

        try:
            from app.ml.transformer_finetuner import InjectionClassifier
            self._classifier = InjectionClassifier(self.model_path)
            self.enabled = True
            logger.info("TransformerClassifier loaded from %s", self.model_path)

        except Exception as e:
            logger.warning("Failed to load transformer classifier: %s", e)
            self.enabled = False

    def classify(self, text: str) -> list[dict[str, Any]]:
        """Classify input text using the transformer model."""
        if not self.enabled or not text or len(text.strip()) < 5:
            return []

        try:
            result = self._classifier.predict(text)

            is_injection = result["is_injection"]
            confidence = result["confidence"]

            logger.debug(
                "TransformerClassifier: injection=%s conf=%.2f | %s",
                is_injection, confidence, text[:60]
            )

            if is_injection and confidence >= self.confidence_threshold:
                return [{
                    "type": "injection",
                    "subtype": "transformer_classifier",
                    "pattern_id": "TRANSFORMER-CLASSIFIER",
                    "matched_text": "Fine-tuned Transformer classifier",
                    "position": (0, min(len(text), 50)),
                    "confidence": round(confidence, 4),
                    "severity": "high" if confidence >= 0.92 else "medium",
                    "description": (
                        f"Transformer classifier detected potential injection "
                        f"(confidence={confidence:.0%})"
                    ),
                }]

            return []

        except Exception as e:
            logger.warning("TransformerClassifier error: %s", e)
            return []


class HybridClassifier:
    """
    Hybrid classifier combining RandomForest and Transformer.

    Strategy:
    1. First check with fast RandomForest
    2. If uncertain (0.5-0.9 confidence), verify with Transformer
    3. Use ensemble voting for final decision

    This provides best of both worlds:
    - Speed from RandomForest for clear cases
    - Accuracy from Transformer for edge cases
    """

    def __init__(
        self,
        rf_confidence_threshold: float = 0.85,
        transformer_confidence_threshold: float = 0.85,
        use_ensemble: bool = True,
    ):
        self.rf_classifier = LocalClassifier(
            confidence_threshold=rf_confidence_threshold
        )
        self.transformer_classifier = TransformerClassifier(
            confidence_threshold=transformer_confidence_threshold
        )
        self.use_ensemble = use_ensemble
        self.enabled = self.rf_classifier.enabled or self.transformer_classifier.enabled

        logger.info(
            "HybridClassifier initialized: RF=%s, Transformer=%s",
            self.rf_classifier.enabled,
            self.transformer_classifier.enabled,
        )

    def classify(self, text: str) -> list[dict[str, Any]]:
        """
        Classify using hybrid approach.

        Returns combined threats from both classifiers.
        """
        threats = []

        # Try RandomForest first (faster)
        if self.rf_classifier.enabled:
            rf_threats = self.rf_classifier.classify(text)
            if rf_threats:
                threats.extend(rf_threats)

        # Use Transformer for verification or primary detection
        if self.transformer_classifier.enabled:
            if self.use_ensemble or not threats:
                transformer_threats = self.transformer_classifier.classify(text)
                if transformer_threats:
                    # Don't duplicate if both detected
                    if not threats:
                        threats.extend(transformer_threats)
                    else:
                        # Ensemble: boost confidence if both agree
                        for threat in threats:
                            threat["confidence"] = min(
                                threat["confidence"] * 1.1, 0.99
                            )
                            threat["description"] += " (confirmed by Transformer)"

        return threats
