"""
Transformer Fine-tuning Module for Prompt Injection Detection.

Supports:
1. DistilBERT (faster, lighter)
2. DeBERTa-v3 (more accurate)
3. Custom training with augmentation

Usage:
    from app.ml.transformer_finetuner import InjectionClassifierTrainer

    trainer = InjectionClassifierTrainer(model_name="distilbert-base-uncased")
    trainer.prepare_data("path/to/train.jsonl")
    trainer.train(epochs=3)
    trainer.save("models/injection_detector")
"""
from __future__ import annotations

import json
import logging
import os
import random
import re
from pathlib import Path
from typing import Any, Optional
from dataclasses import dataclass, field

import torch
from torch.utils.data import Dataset, DataLoader

logger = logging.getLogger("inalign.ml.transformer_finetuner")

# Model directory
MODEL_DIR = Path(__file__).parent / "models"
MODEL_DIR.mkdir(exist_ok=True)


@dataclass
class TrainingConfig:
    """Training configuration."""
    model_name: str = "distilbert-base-uncased"
    max_length: int = 256
    batch_size: int = 16
    learning_rate: float = 2e-5
    epochs: int = 3
    warmup_ratio: float = 0.1
    weight_decay: float = 0.01
    gradient_accumulation_steps: int = 1
    fp16: bool = False  # Mixed precision
    seed: int = 42

    # Data augmentation
    augment_data: bool = True
    augment_ratio: float = 0.3


class InjectionDataset(Dataset):
    """PyTorch Dataset for injection detection."""

    def __init__(
        self,
        texts: list[str],
        labels: list[int],
        tokenizer,
        max_length: int = 256,
    ):
        self.texts = texts
        self.labels = labels
        self.tokenizer = tokenizer
        self.max_length = max_length

    def __len__(self):
        return len(self.texts)

    def __getitem__(self, idx):
        text = self.texts[idx]
        label = self.labels[idx]

        encoding = self.tokenizer(
            text,
            max_length=self.max_length,
            padding="max_length",
            truncation=True,
            return_tensors="pt",
        )

        return {
            "input_ids": encoding["input_ids"].squeeze(0),
            "attention_mask": encoding["attention_mask"].squeeze(0),
            "labels": torch.tensor(label, dtype=torch.long),
        }


class DataAugmenter:
    """
    Data augmentation for training data.

    Techniques:
    1. Synonym replacement
    2. Random character insertion
    3. Case variation
    4. Typo introduction
    """

    # Common attack keywords and their variations
    ATTACK_SYNONYMS = {
        "ignore": ["disregard", "forget", "skip", "bypass"],
        "instructions": ["rules", "guidelines", "commands", "directives"],
        "reveal": ["show", "display", "expose", "disclose"],
        "system": ["base", "core", "original", "initial"],
        "prompt": ["instructions", "commands", "directives", "context"],
        "override": ["bypass", "skip", "ignore", "circumvent"],
        "pretend": ["imagine", "suppose", "assume", "act as"],
        "jailbreak": ["unlock", "break free", "escape", "liberate"],
    }

    # Homoglyph replacements (for adversarial training)
    HOMOGLYPHS = {
        'a': ['а', 'ɑ', 'α'],  # Cyrillic, Latin small letter alpha
        'e': ['е', 'ε', 'ё'],  # Cyrillic
        'i': ['і', 'ι', '1', 'l'],
        'o': ['о', 'ο', '0'],  # Cyrillic, Greek
        'c': ['с', 'ϲ'],
        'p': ['р', 'ρ'],
        's': ['ѕ'],
    }

    def __init__(self, augment_ratio: float = 0.3):
        self.augment_ratio = augment_ratio

    def augment(self, text: str, label: int) -> list[tuple[str, int]]:
        """Generate augmented samples."""
        augmented = []

        if random.random() < self.augment_ratio:
            # Synonym replacement (only for attacks)
            if label == 1:
                aug = self._replace_synonyms(text)
                if aug != text:
                    augmented.append((aug, label))

        if random.random() < self.augment_ratio * 0.5:
            # Case variation
            aug = self._vary_case(text)
            augmented.append((aug, label))

        if random.random() < self.augment_ratio * 0.3 and label == 1:
            # Homoglyph insertion (adversarial)
            aug = self._insert_homoglyphs(text)
            if aug != text:
                augmented.append((aug, label))

        return augmented

    def _replace_synonyms(self, text: str) -> str:
        """Replace keywords with synonyms."""
        words = text.split()
        for i, word in enumerate(words):
            word_lower = word.lower()
            if word_lower in self.ATTACK_SYNONYMS:
                if random.random() < 0.5:
                    words[i] = random.choice(self.ATTACK_SYNONYMS[word_lower])
        return " ".join(words)

    def _vary_case(self, text: str) -> str:
        """Vary case randomly."""
        result = []
        for char in text:
            if random.random() < 0.1 and char.isalpha():
                char = char.upper() if char.islower() else char.lower()
            result.append(char)
        return "".join(result)

    def _insert_homoglyphs(self, text: str) -> str:
        """Insert homoglyphs for adversarial training."""
        result = []
        for char in text:
            if char.lower() in self.HOMOGLYPHS and random.random() < 0.1:
                result.append(random.choice(self.HOMOGLYPHS[char.lower()]))
            else:
                result.append(char)
        return "".join(result)


class InjectionClassifierTrainer:
    """
    Fine-tune a transformer model for prompt injection detection.

    Supports DistilBERT, BERT, DeBERTa, and other HuggingFace models.
    """

    SUPPORTED_MODELS = {
        "distilbert-base-uncased": "distilbert-base-uncased",
        "distilbert": "distilbert-base-uncased",
        "bert-base-uncased": "bert-base-uncased",
        "bert": "bert-base-uncased",
        "deberta-v3-small": "microsoft/deberta-v3-small",
        "deberta": "microsoft/deberta-v3-small",
        "deberta-v3-base": "microsoft/deberta-v3-base",
        "roberta-base": "roberta-base",
        "roberta": "roberta-base",
    }

    def __init__(
        self,
        model_name: str = "distilbert-base-uncased",
        config: Optional[TrainingConfig] = None,
    ):
        """
        Initialize the trainer.

        Parameters
        ----------
        model_name : str
            Name of the model to fine-tune.
        config : TrainingConfig, optional
            Training configuration.
        """
        self.model_name = self.SUPPORTED_MODELS.get(model_name, model_name)
        self.config = config or TrainingConfig(model_name=self.model_name)

        self.tokenizer = None
        self.model = None
        self.device = torch.device("cuda" if torch.cuda.is_available() else "cpu")

        self.train_texts: list[str] = []
        self.train_labels: list[int] = []
        self.val_texts: list[str] = []
        self.val_labels: list[int] = []

        self._augmenter = DataAugmenter(self.config.augment_ratio)

        # Set seed
        random.seed(self.config.seed)
        torch.manual_seed(self.config.seed)
        if torch.cuda.is_available():
            torch.cuda.manual_seed_all(self.config.seed)

        logger.info(f"Initialized trainer with model: {self.model_name}")
        logger.info(f"Device: {self.device}")

    def _load_model_and_tokenizer(self):
        """Load model and tokenizer."""
        from transformers import AutoTokenizer, AutoModelForSequenceClassification

        logger.info(f"Loading tokenizer and model: {self.model_name}")

        self.tokenizer = AutoTokenizer.from_pretrained(self.model_name)
        self.model = AutoModelForSequenceClassification.from_pretrained(
            self.model_name,
            num_labels=2,
            problem_type="single_label_classification",
        )
        self.model.to(self.device)

        logger.info(f"Model loaded: {sum(p.numel() for p in self.model.parameters()):,} parameters")

    def prepare_data(
        self,
        data_path: str | Path,
        val_split: float = 0.1,
    ) -> dict[str, int]:
        """
        Load and prepare training data.

        Parameters
        ----------
        data_path : str or Path
            Path to JSONL file with {"text": "...", "label": 0|1}
        val_split : float
            Fraction of data to use for validation.

        Returns
        -------
        dict
            Statistics about the loaded data.
        """
        data_path = Path(data_path)

        texts = []
        labels = []

        with open(data_path, "r", encoding="utf-8") as f:
            for line in f:
                if line.strip():
                    item = json.loads(line)
                    texts.append(item["text"])
                    labels.append(item["label"])

        logger.info(f"Loaded {len(texts)} samples from {data_path}")

        # Data augmentation
        if self.config.augment_data:
            augmented_texts = []
            augmented_labels = []

            for text, label in zip(texts, labels):
                augmented = self._augmenter.augment(text, label)
                for aug_text, aug_label in augmented:
                    augmented_texts.append(aug_text)
                    augmented_labels.append(aug_label)

            texts.extend(augmented_texts)
            labels.extend(augmented_labels)
            logger.info(f"After augmentation: {len(texts)} samples")

        # Shuffle and split
        combined = list(zip(texts, labels))
        random.shuffle(combined)

        val_size = int(len(combined) * val_split)
        val_data = combined[:val_size]
        train_data = combined[val_size:]

        self.train_texts = [t for t, l in train_data]
        self.train_labels = [l for t, l in train_data]
        self.val_texts = [t for t, l in val_data]
        self.val_labels = [l for t, l in val_data]

        # Statistics
        train_attacks = sum(self.train_labels)
        val_attacks = sum(self.val_labels)

        stats = {
            "total_samples": len(texts),
            "train_samples": len(self.train_texts),
            "val_samples": len(self.val_texts),
            "train_attacks": train_attacks,
            "train_benign": len(self.train_labels) - train_attacks,
            "val_attacks": val_attacks,
            "val_benign": len(self.val_labels) - val_attacks,
        }

        logger.info(f"Data prepared: {stats}")
        return stats

    def train(
        self,
        epochs: Optional[int] = None,
        output_dir: Optional[str | Path] = None,
    ) -> dict[str, Any]:
        """
        Train the model.

        Parameters
        ----------
        epochs : int, optional
            Number of training epochs. Defaults to config value.
        output_dir : str or Path, optional
            Directory to save the trained model.

        Returns
        -------
        dict
            Training results including loss and metrics.
        """
        if not self.train_texts:
            raise ValueError("No training data. Call prepare_data() first.")

        epochs = epochs or self.config.epochs
        output_dir = Path(output_dir) if output_dir else MODEL_DIR / "injection_detector"

        # Load model if not loaded
        if self.model is None:
            self._load_model_and_tokenizer()

        # Create datasets
        train_dataset = InjectionDataset(
            self.train_texts,
            self.train_labels,
            self.tokenizer,
            self.config.max_length,
        )

        val_dataset = InjectionDataset(
            self.val_texts,
            self.val_labels,
            self.tokenizer,
            self.config.max_length,
        ) if self.val_texts else None

        # Create dataloaders
        train_loader = DataLoader(
            train_dataset,
            batch_size=self.config.batch_size,
            shuffle=True,
        )

        val_loader = DataLoader(
            val_dataset,
            batch_size=self.config.batch_size,
        ) if val_dataset else None

        # Optimizer
        from transformers import get_linear_schedule_with_warmup

        optimizer = torch.optim.AdamW(
            self.model.parameters(),
            lr=self.config.learning_rate,
            weight_decay=self.config.weight_decay,
        )

        total_steps = len(train_loader) * epochs
        warmup_steps = int(total_steps * self.config.warmup_ratio)

        scheduler = get_linear_schedule_with_warmup(
            optimizer,
            num_warmup_steps=warmup_steps,
            num_training_steps=total_steps,
        )

        # Training loop
        logger.info(f"Starting training for {epochs} epochs...")
        logger.info(f"Total steps: {total_steps}, Warmup: {warmup_steps}")

        best_val_acc = 0.0
        results = {
            "epochs": [],
            "train_loss": [],
            "val_loss": [],
            "val_accuracy": [],
            "val_f1": [],
        }

        for epoch in range(epochs):
            # Training
            self.model.train()
            total_train_loss = 0

            for batch_idx, batch in enumerate(train_loader):
                input_ids = batch["input_ids"].to(self.device)
                attention_mask = batch["attention_mask"].to(self.device)
                labels = batch["labels"].to(self.device)

                outputs = self.model(
                    input_ids=input_ids,
                    attention_mask=attention_mask,
                    labels=labels,
                )

                loss = outputs.loss
                total_train_loss += loss.item()

                loss.backward()

                if (batch_idx + 1) % self.config.gradient_accumulation_steps == 0:
                    torch.nn.utils.clip_grad_norm_(self.model.parameters(), 1.0)
                    optimizer.step()
                    scheduler.step()
                    optimizer.zero_grad()

                if batch_idx % 50 == 0:
                    logger.info(
                        f"Epoch {epoch+1}/{epochs}, "
                        f"Batch {batch_idx}/{len(train_loader)}, "
                        f"Loss: {loss.item():.4f}"
                    )

            avg_train_loss = total_train_loss / len(train_loader)
            results["epochs"].append(epoch + 1)
            results["train_loss"].append(avg_train_loss)

            # Validation
            if val_loader:
                val_metrics = self._evaluate(val_loader)
                results["val_loss"].append(val_metrics["loss"])
                results["val_accuracy"].append(val_metrics["accuracy"])
                results["val_f1"].append(val_metrics["f1"])

                logger.info(
                    f"Epoch {epoch+1} complete - "
                    f"Train Loss: {avg_train_loss:.4f}, "
                    f"Val Loss: {val_metrics['loss']:.4f}, "
                    f"Val Acc: {val_metrics['accuracy']:.4f}, "
                    f"Val F1: {val_metrics['f1']:.4f}"
                )

                # Save best model
                if val_metrics["accuracy"] > best_val_acc:
                    best_val_acc = val_metrics["accuracy"]
                    self.save(output_dir / "best")
                    logger.info(f"New best model saved (accuracy: {best_val_acc:.4f})")
            else:
                logger.info(f"Epoch {epoch+1} complete - Train Loss: {avg_train_loss:.4f}")

        # Save final model
        self.save(output_dir / "final")
        results["best_val_accuracy"] = best_val_acc

        logger.info(f"Training complete. Best validation accuracy: {best_val_acc:.4f}")
        return results

    def _evaluate(self, dataloader: DataLoader) -> dict[str, float]:
        """Evaluate model on a dataloader."""
        self.model.eval()

        total_loss = 0
        all_preds = []
        all_labels = []

        with torch.no_grad():
            for batch in dataloader:
                input_ids = batch["input_ids"].to(self.device)
                attention_mask = batch["attention_mask"].to(self.device)
                labels = batch["labels"].to(self.device)

                outputs = self.model(
                    input_ids=input_ids,
                    attention_mask=attention_mask,
                    labels=labels,
                )

                total_loss += outputs.loss.item()

                preds = torch.argmax(outputs.logits, dim=1)
                all_preds.extend(preds.cpu().numpy())
                all_labels.extend(labels.cpu().numpy())

        # Calculate metrics
        from sklearn.metrics import accuracy_score, f1_score, precision_score, recall_score

        accuracy = accuracy_score(all_labels, all_preds)
        f1 = f1_score(all_labels, all_preds)
        precision = precision_score(all_labels, all_preds, zero_division=0)
        recall = recall_score(all_labels, all_preds, zero_division=0)

        return {
            "loss": total_loss / len(dataloader),
            "accuracy": accuracy,
            "f1": f1,
            "precision": precision,
            "recall": recall,
        }

    def save(self, path: str | Path):
        """Save model and tokenizer."""
        path = Path(path)
        path.mkdir(parents=True, exist_ok=True)

        self.model.save_pretrained(path)
        self.tokenizer.save_pretrained(path)

        # Save config
        config_path = path / "training_config.json"
        with open(config_path, "w") as f:
            json.dump({
                "model_name": self.model_name,
                "max_length": self.config.max_length,
                "batch_size": self.config.batch_size,
                "learning_rate": self.config.learning_rate,
                "epochs": self.config.epochs,
            }, f, indent=2)

        logger.info(f"Model saved to {path}")

    @classmethod
    def load(cls, path: str | Path) -> "InjectionClassifier":
        """Load a trained model."""
        return InjectionClassifier(path)


class InjectionClassifier:
    """
    Inference-time prompt injection classifier.

    Usage:
        classifier = InjectionClassifier("models/injection_detector/best")
        result = classifier.predict("Ignore all instructions")
        print(result)  # {"is_injection": True, "confidence": 0.95}
    """

    def __init__(self, model_path: str | Path):
        """Load a trained model."""
        from transformers import AutoTokenizer, AutoModelForSequenceClassification

        model_path = Path(model_path)

        self.tokenizer = AutoTokenizer.from_pretrained(model_path)
        self.model = AutoModelForSequenceClassification.from_pretrained(model_path)
        self.device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
        self.model.to(self.device)
        self.model.eval()

        # Load config
        config_path = model_path / "training_config.json"
        if config_path.exists():
            with open(config_path) as f:
                self.config = json.load(f)
        else:
            self.config = {"max_length": 256}

        logger.info(f"Loaded model from {model_path}")

    def predict(self, text: str) -> dict[str, Any]:
        """
        Predict if a text is a prompt injection.

        Parameters
        ----------
        text : str
            The text to classify.

        Returns
        -------
        dict
            {"is_injection": bool, "confidence": float, "scores": [benign, attack]}
        """
        encoding = self.tokenizer(
            text,
            max_length=self.config.get("max_length", 256),
            padding="max_length",
            truncation=True,
            return_tensors="pt",
        )

        input_ids = encoding["input_ids"].to(self.device)
        attention_mask = encoding["attention_mask"].to(self.device)

        with torch.no_grad():
            outputs = self.model(
                input_ids=input_ids,
                attention_mask=attention_mask,
            )

            probs = torch.softmax(outputs.logits, dim=1)[0]
            pred = torch.argmax(probs).item()
            confidence = probs[pred].item()

        return {
            "is_injection": bool(pred == 1),
            "confidence": confidence,
            "scores": probs.cpu().numpy().tolist(),
        }

    def predict_batch(self, texts: list[str]) -> list[dict[str, Any]]:
        """Predict on multiple texts."""
        return [self.predict(text) for text in texts]


# Singleton for global model
_global_classifier: Optional[InjectionClassifier] = None


def get_classifier(model_path: Optional[str | Path] = None) -> Optional[InjectionClassifier]:
    """Get or load the global injection classifier."""
    global _global_classifier

    if _global_classifier is None and model_path:
        model_path = Path(model_path)
        if model_path.exists():
            _global_classifier = InjectionClassifier(model_path)

    return _global_classifier


def set_classifier(classifier: InjectionClassifier) -> None:
    """Set the global classifier."""
    global _global_classifier
    _global_classifier = classifier


# ---------------------------------------------------------------------------
# CLI interface
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Train injection detection model")
    parser.add_argument("command", choices=["train", "evaluate", "predict"])
    parser.add_argument("--data", type=str, help="Path to training data JSONL")
    parser.add_argument("--model", type=str, default="distilbert", help="Model name")
    parser.add_argument("--epochs", type=int, default=3, help="Training epochs")
    parser.add_argument("--output", type=str, help="Output directory")
    parser.add_argument("--text", type=str, help="Text to predict")
    parser.add_argument("--model-path", type=str, help="Path to trained model")

    args = parser.parse_args()

    if args.command == "train":
        if not args.data:
            print("Please provide --data argument")
            exit(1)

        trainer = InjectionClassifierTrainer(model_name=args.model)
        stats = trainer.prepare_data(args.data)
        print(f"Data loaded: {stats}")

        results = trainer.train(
            epochs=args.epochs,
            output_dir=args.output,
        )
        print(f"Training complete: {results}")

    elif args.command == "predict":
        if not args.model_path or not args.text:
            print("Please provide --model-path and --text arguments")
            exit(1)

        classifier = InjectionClassifier(args.model_path)
        result = classifier.predict(args.text)
        print(f"Prediction: {result}")

    elif args.command == "evaluate":
        print("Evaluate command not yet implemented")
