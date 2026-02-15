"""
ML-based injection scanner for MCP.

Uses fine-tuned DistilBERT model for prompt injection detection.
Falls back gracefully when PyTorch/Transformers not installed.
"""

import logging
from pathlib import Path
from typing import Any, Optional
from dataclasses import dataclass

logger = logging.getLogger("inalign-ml-scanner")

# Model paths to search
MODEL_PATHS = [
    # Relative to mcp-server
    Path(__file__).parent.parent.parent.parent / "backend" / "app" / "ml" / "models" / "injection_detector" / "best",
    # User-local model cache
    Path.home() / ".inalign" / "models" / "injection_detector",
]


@dataclass
class MLScanResult:
    """Result from ML-based scanning."""
    enabled: bool
    is_injection: bool
    confidence: float
    benign_score: float
    injection_score: float
    severity: str
    description: str


class MLScanner:
    """
    Fine-tuned DistilBERT classifier for prompt injection detection.

    Loads the model lazily and falls back gracefully if dependencies missing.
    """

    def __init__(
        self,
        model_path: Optional[Path] = None,
        confidence_threshold: float = 0.95,  # High threshold to reduce false positives
        device: Optional[str] = None,
    ):
        self.confidence_threshold = confidence_threshold
        self.device = device or "cpu"
        self.enabled = False
        self._model = None
        self._tokenizer = None
        self._torch = None

        # Find model path
        self.model_path = model_path
        if not self.model_path:
            for path in MODEL_PATHS:
                if path.exists():
                    self.model_path = path
                    break

        # Try to load
        self._init_model()

    def _init_model(self) -> None:
        """Initialize the model if dependencies available."""
        # Try import torch
        try:
            import torch
            self._torch = torch

            if self.device == "auto":
                self.device = "cuda" if torch.cuda.is_available() else "cpu"

        except ImportError:
            logger.info("PyTorch not installed. ML scanner disabled.")
            return

        # Check model path
        if not self.model_path or not self.model_path.exists():
            logger.info("ML model not found. ML scanner disabled.")
            return

        # Try load transformers
        try:
            from transformers import AutoModelForSequenceClassification, AutoTokenizer

            logger.info(f"Loading ML model from {self.model_path}")

            self._tokenizer = AutoTokenizer.from_pretrained(str(self.model_path))
            self._model = AutoModelForSequenceClassification.from_pretrained(str(self.model_path))
            self._model.to(self.device)
            self._model.eval()

            self.enabled = True
            logger.info(f"ML scanner enabled (device={self.device})")

        except Exception as e:
            logger.warning(f"Failed to load ML model: {e}")

    def scan(self, text: str) -> MLScanResult:
        """
        Scan text using the fine-tuned DistilBERT model.

        Returns ML scan result with confidence scores.
        """
        if not self.enabled or not text or len(text.strip()) < 5:
            return MLScanResult(
                enabled=self.enabled,
                is_injection=False,
                confidence=0.0,
                benign_score=1.0,
                injection_score=0.0,
                severity="none",
                description="ML scanner not enabled" if not self.enabled else "Text too short",
            )

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
            with self._torch.no_grad():
                outputs = self._model(**inputs)
                probs = self._torch.softmax(outputs.logits, dim=-1)

            benign_score = float(probs[0][0])
            injection_score = float(probs[0][1])
            is_injection = injection_score > benign_score and injection_score >= self.confidence_threshold

            # Determine severity
            if injection_score >= 0.9:
                severity = "critical"
            elif injection_score >= 0.8:
                severity = "high"
            elif injection_score >= 0.6:
                severity = "medium"
            else:
                severity = "low"

            return MLScanResult(
                enabled=True,
                is_injection=is_injection,
                confidence=injection_score,
                benign_score=benign_score,
                injection_score=injection_score,
                severity=severity if is_injection else "none",
                description=f"DistilBERT: {'injection' if is_injection else 'benign'} ({injection_score:.0%})",
            )

        except Exception as e:
            logger.error(f"ML scan error: {e}")
            return MLScanResult(
                enabled=True,
                is_injection=False,
                confidence=0.0,
                benign_score=0.0,
                injection_score=0.0,
                severity="none",
                description=f"ML scan error: {e}",
            )


# Singleton instance
_ml_scanner: Optional[MLScanner] = None


def get_ml_scanner() -> MLScanner:
    """Get or create the ML scanner singleton."""
    global _ml_scanner
    if _ml_scanner is None:
        _ml_scanner = MLScanner()
    return _ml_scanner


def ml_scan(text: str) -> MLScanResult:
    """Convenience function to scan text with ML model."""
    return get_ml_scanner().scan(text)


def get_ml_scan_summary(text: str) -> dict[str, Any]:
    """Get ML scan summary for MCP tool response."""
    result = ml_scan(text)
    return {
        "ml_enabled": result.enabled,
        "is_injection": result.is_injection,
        "ml_confidence": result.confidence,
        "benign_score": result.benign_score,
        "injection_score": result.injection_score,
        "ml_severity": result.severity,
        "ml_description": result.description,
    }
