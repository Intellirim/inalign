"""
ML-based anomaly detector (placeholder).

This module will implement an Isolation Forest-based anomaly detector
for identifying unusual session behaviour from numeric feature vectors.
The model learns a baseline of "normal" agent behaviour during training
and flags deviations at inference time.

Planned architecture
--------------------
- **Algorithm**: ``sklearn.ensemble.IsolationForest`` with configurable
  contamination factor and number of estimators.
- **Features**: The feature vector is expected to include session-level
  metrics such as actions-per-minute, unique-targets-count,
  average-record-count, failure-ratio, off-hours-ratio,
  privilege-change-rate, and entropy of action-type distribution.
- **Training**: Requires a labelled or semi-supervised dataset of
  normal session feature vectors. Anomalous samples should ideally be
  withheld so that the forest learns the "normal" manifold.
- **Inference**: Returns an anomaly score (lower = more anomalous)
  and a binary label (``-1`` for anomaly, ``1`` for normal) per sample.
- **Persistence**: Trained model will be serialised via ``joblib``
  and loaded on startup to avoid retraining.

Until implemented this class serves as a safe no-op placeholder that
returns empty results and logs appropriately.
"""

from __future__ import annotations

import logging
from typing import Any

logger = logging.getLogger(__name__)


class MLAnomalyDetector:
    """Placeholder ML-based anomaly detector.

    When fully implemented this class will wrap an Isolation Forest
    model to detect statistical outliers in session feature vectors.
    Currently all calls are no-ops that return empty results.

    Attributes
    ----------
    is_trained : bool
        Whether the underlying model has been trained on data. Always
        ``False`` in this placeholder implementation.
    """

    def __init__(self) -> None:
        self.is_trained: bool = False
        self._model: Any = None
        logger.info(
            "MLAnomalyDetector initialised (placeholder). "
            "Model is not trained -- detect() will return no results."
        )

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def detect(self, features: dict[str, Any] | list[float]) -> list[dict[str, Any]]:
        """Run anomaly detection on a feature vector.

        Parameters
        ----------
        features:
            A dict of named features or a flat list/array of numeric
            feature values for a single session snapshot.

        Returns
        -------
        list[dict]:
            In the placeholder implementation this always returns an
            empty list. When the model is trained it will return a list
            with at most one anomaly dict containing:
            - ``rule_id``     -- ``"ML-001"``
            - ``rule_name``   -- ``"isolation_forest_anomaly"``
            - ``severity``    -- determined by anomaly score
            - ``description`` -- explanation of the detected deviation
            - ``details``     -- ``{"anomaly_score": float, "label": int}``
        """
        if not self.is_trained:
            logger.debug(
                "ML detector not trained -- returning empty results."
            )
            return []

        # ---------------------------------------------------------------
        # Future implementation:
        #
        #   import numpy as np
        #   feature_array = self._prepare_features(features)
        #   score = self._model.decision_function(feature_array)[0]
        #   label = self._model.predict(feature_array)[0]
        #
        #   if label == -1:
        #       return [{
        #           "rule_id": "ML-001",
        #           "rule_name": "isolation_forest_anomaly",
        #           "severity": self._score_to_severity(score),
        #           "description": "Statistical anomaly detected via Isolation Forest.",
        #           "details": {
        #               "anomaly_score": float(score),
        #               "label": int(label),
        #           },
        #       }]
        #   return []
        # ---------------------------------------------------------------
        return []

    def train(self, training_data: list[list[float]]) -> None:
        """Train (or re-train) the anomaly detection model.

        Parameters
        ----------
        training_data:
            A list of feature vectors representing normal session
            behavior. Each inner list should have the same length.

        Notes
        -----
        This is a placeholder. When implemented it will:

        1. Validate and normalise the training data.
        2. Fit an ``IsolationForest`` with sensible defaults.
        3. Set ``self.is_trained = True``.
        4. Optionally persist the model to disk via ``joblib``.
        """
        logger.warning(
            "MLAnomalyDetector.train() called but ML training is not yet "
            "implemented. Received %d training samples -- ignoring.",
            len(training_data) if training_data else 0,
        )
        # ---------------------------------------------------------------
        # Future implementation:
        #
        #   from sklearn.ensemble import IsolationForest
        #   import numpy as np
        #
        #   X = np.array(training_data)
        #   self._model = IsolationForest(
        #       n_estimators=200,
        #       contamination=0.05,
        #       random_state=42,
        #   )
        #   self._model.fit(X)
        #   self.is_trained = True
        #   logger.info("MLAnomalyDetector trained on %d samples.", len(X))
        # ---------------------------------------------------------------

    # ------------------------------------------------------------------
    # Internal helpers (reserved for future use)
    # ------------------------------------------------------------------

    @staticmethod
    def _prepare_features(
        features: dict[str, Any] | list[float],
    ) -> Any:
        """Convert *features* to a 2-D numpy array for sklearn.

        Reserved for future implementation.
        """
        # import numpy as np
        # if isinstance(features, dict):
        #     feature_array = np.array([list(features.values())])
        # else:
        #     feature_array = np.array([features])
        # return feature_array
        return features

    @staticmethod
    def _score_to_severity(score: float) -> str:
        """Map an Isolation Forest anomaly score to a severity label.

        Lower (more negative) scores indicate stronger anomalies.

        Reserved for future implementation.
        """
        if score < -0.5:
            return "critical"
        if score < -0.3:
            return "high"
        if score < -0.1:
            return "medium"
        return "low"
