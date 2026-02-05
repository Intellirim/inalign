"""
Machine Learning Module for In-A-Lign.

Provides:
- Transformer fine-tuning for injection detection
- Training data collection and management
- Model inference and evaluation
"""

from app.ml.training_pipeline import (
    TrainingDataCollector,
    TrainingSample,
    seed_benign_data,
    collect_from_gpt_results,
)

from app.ml.transformer_finetuner import (
    InjectionClassifierTrainer,
    InjectionClassifier,
    TrainingConfig,
    DataAugmenter,
    get_classifier,
    set_classifier,
)

__all__ = [
    # Training Pipeline
    "TrainingDataCollector",
    "TrainingSample",
    "seed_benign_data",
    "collect_from_gpt_results",
    # Transformer Fine-tuning
    "InjectionClassifierTrainer",
    "InjectionClassifier",
    "TrainingConfig",
    "DataAugmenter",
    "get_classifier",
    "set_classifier",
]
