"""
Fine-tuned Transformer classifier for prompt injection detection.

Uses the DistilBERT model trained on our attack/benign dataset.
"""
from __future__ import annotations

import logging
from pathlib import Path
from typing import Any, Optional

# Lazy import torch to allow the module to load even without pytorch installed
torch = None

logger = logging.getLogger("inalign.transformer_classifier")


def _get_torch():
    """Lazily import torch."""
    global torch
    if torch is None:
        try:
            import torch as _torch
            torch = _torch
        except ImportError:
            logger.warning("PyTorch not installed. TransformerClassifier will be disabled.")
            return None
    return torch

# Model path
_MODEL_PATH = Path(__file__).parent.parent.parent / "ml" / "models" / "injection_detector" / "best"


class TransformerClassifier:
    """
    Fine-tuned DistilBERT classifier for prompt injection detection.

    Uses the model trained on our Neo4j attack/benign dataset.
    """

    def __init__(
        self,
        model_path: Optional[Path] = None,
        confidence_threshold: float = 0.7,
        device: Optional[str] = None,
    ):
        self.model_path = model_path or _MODEL_PATH
        self.confidence_threshold = confidence_threshold

        # Auto-detect device (lazy load torch)
        _torch = _get_torch()
        if _torch is None:
            self.device = "cpu"
            self.enabled = False
            return

        if device is None:
            self.device = "cuda" if _torch.cuda.is_available() else "cpu"
        else:
            self.device = device

        self._model = None
        self._tokenizer = None
        self.enabled = False

        # Only try to load if torch is available
        if _get_torch() is not None:
            self._load_model()

    def _load_model(self) -> None:
        """Load the fine-tuned transformer model."""
        _torch = _get_torch()
        if _torch is None:
            return

        if not self.model_path.exists():
            logger.warning("Transformer model not found at %s", self.model_path)
            return

        try:
            from transformers import AutoModelForSequenceClassification, AutoTokenizer

            logger.info("Loading transformer model from %s", self.model_path)

            self._tokenizer = AutoTokenizer.from_pretrained(str(self.model_path))
            self._model = AutoModelForSequenceClassification.from_pretrained(str(self.model_path))
            self._model.to(self.device)
            self._model.eval()

            self.enabled = True
            logger.info(
                "TransformerClassifier loaded successfully (device=%s)",
                self.device
            )

        except Exception as e:
            logger.error("Failed to load transformer classifier: %s", e)
            self.enabled = False

    def classify(self, text: str) -> list[dict[str, Any]]:
        """
        Classify input text using the fine-tuned model.

        Returns a list of threat dicts (empty if benign or disabled).
        """
        if not self.enabled or not text or len(text.strip()) < 5:
            return []

        try:
            # Tokenize
            inputs = self._tokenizer(
                text,
                return_tensors="pt",
                truncation=True,
                padding=True,
                max_length=256,
            )
            inputs = {k: v.to(self.device) for k, v in inputs.items()}

            # Inference
            with torch.no_grad():
                outputs = self._model(**inputs)
                probs = torch.softmax(outputs.logits, dim=-1)
                prediction = probs.argmax(-1).item()
                confidence = probs[0][prediction].item()

            # Class 1 = injection, Class 0 = benign
            is_injection = prediction == 1
            injection_confidence = probs[0][1].item()

            logger.debug(
                "TransformerClassifier: injection=%s conf=%.2f | %s",
                is_injection, injection_confidence, text[:60]
            )

            if is_injection and injection_confidence >= self.confidence_threshold:
                return [{
                    "type": "injection",
                    "subtype": "transformer_classifier",
                    "pattern_id": "TRANSFORMER-CLASSIFIER",
                    "matched_text": text[:50] + ("..." if len(text) > 50 else ""),
                    "position": (0, min(len(text), 50)),
                    "confidence": round(injection_confidence, 4),
                    "severity": "critical" if injection_confidence >= 0.9 else "high" if injection_confidence >= 0.8 else "medium",
                    "description": (
                        f"Fine-tuned DistilBERT detected injection "
                        f"(confidence={injection_confidence:.0%})"
                    ),
                }]

            return []

        except Exception as e:
            logger.warning("TransformerClassifier error: %s", e)
            return []

    def classify_batch(self, texts: list[str]) -> list[list[dict[str, Any]]]:
        """Classify multiple texts at once (more efficient)."""
        if not self.enabled or not texts:
            return [[] for _ in texts]

        try:
            # Tokenize batch
            inputs = self._tokenizer(
                texts,
                return_tensors="pt",
                truncation=True,
                padding=True,
                max_length=256,
            )
            inputs = {k: v.to(self.device) for k, v in inputs.items()}

            # Inference
            with torch.no_grad():
                outputs = self._model(**inputs)
                probs = torch.softmax(outputs.logits, dim=-1)

            results = []
            for i, text in enumerate(texts):
                prediction = probs[i].argmax(-1).item()
                injection_confidence = probs[i][1].item()
                is_injection = prediction == 1

                if is_injection and injection_confidence >= self.confidence_threshold:
                    results.append([{
                        "type": "injection",
                        "subtype": "transformer_classifier",
                        "pattern_id": "TRANSFORMER-CLASSIFIER",
                        "matched_text": text[:50] + ("..." if len(text) > 50 else ""),
                        "position": (0, min(len(text), 50)),
                        "confidence": round(injection_confidence, 4),
                        "severity": "critical" if injection_confidence >= 0.9 else "high" if injection_confidence >= 0.8 else "medium",
                        "description": (
                            f"Fine-tuned DistilBERT detected injection "
                            f"(confidence={injection_confidence:.0%})"
                        ),
                    }])
                else:
                    results.append([])

            return results

        except Exception as e:
            logger.warning("TransformerClassifier batch error: %s", e)
            return [[] for _ in texts]

    def get_raw_scores(self, text: str) -> dict[str, float]:
        """Get raw probability scores for both classes."""
        if not self.enabled or not text:
            return {"benign": 0.0, "injection": 0.0}

        try:
            inputs = self._tokenizer(
                text,
                return_tensors="pt",
                truncation=True,
                padding=True,
                max_length=256,
            )
            inputs = {k: v.to(self.device) for k, v in inputs.items()}

            with torch.no_grad():
                outputs = self._model(**inputs)
                probs = torch.softmax(outputs.logits, dim=-1)

            return {
                "benign": float(probs[0][0]),
                "injection": float(probs[0][1]),
            }

        except Exception as e:
            logger.warning("get_raw_scores error: %s", e)
            return {"benign": 0.0, "injection": 0.0}
