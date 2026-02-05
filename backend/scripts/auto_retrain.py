"""
In-A-Lign Auto-Retraining Pipeline.

Automatically retrains the injection detection model when enough new data
is collected in Neo4j.

Pipeline:
1. Check Neo4j for new attack/benign samples since last training
2. If threshold reached, export training data
3. Train new model (local GPU or queue for Colab)
4. Evaluate against held-out test set
5. If better than current model, deploy

Usage:
    # Run once
    python scripts/auto_retrain.py

    # Run as scheduled job (cron/task scheduler)
    0 2 * * * cd /path/to/backend && python scripts/auto_retrain.py

    # Run continuously (checks every hour)
    python scripts/auto_retrain.py --continuous
"""

import argparse
import asyncio
import json
import logging
import os
import shutil
import sys
from datetime import datetime
from pathlib import Path
from typing import Optional

# Add parent to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from dotenv import load_dotenv

load_dotenv()

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
logger = logging.getLogger(__name__)

# Paths
BACKEND_DIR = Path(__file__).parent.parent
MODELS_DIR = BACKEND_DIR / "app" / "ml" / "models" / "injection_detector"
TRAINING_DATA_DIR = BACKEND_DIR / "data" / "training"
CHECKPOINT_FILE = BACKEND_DIR / "data" / "retrain_checkpoint.json"

# Thresholds
MIN_NEW_SAMPLES = 100  # Minimum new samples to trigger retraining
MIN_IMPROVEMENT = 0.02  # Minimum F1 improvement to deploy (2%)


class AutoRetrainer:
    """Automatic model retraining pipeline."""

    def __init__(self):
        self.neo4j_uri = os.getenv("NEO4J_URI")
        self.neo4j_user = os.getenv("NEO4J_USER")
        self.neo4j_password = os.getenv("NEO4J_PASSWORD")

        if not all([self.neo4j_uri, self.neo4j_user, self.neo4j_password]):
            raise ValueError("NEO4J credentials not found in environment")

        self.checkpoint = self._load_checkpoint()

    def _load_checkpoint(self) -> dict:
        """Load training checkpoint (last training timestamp, metrics)."""
        if CHECKPOINT_FILE.exists():
            with open(CHECKPOINT_FILE, "r") as f:
                return json.load(f)
        return {
            "last_training": None,
            "last_attack_count": 0,
            "last_benign_count": 0,
            "current_model_f1": 0.0,
            "training_history": [],
        }

    def _save_checkpoint(self):
        """Save training checkpoint."""
        CHECKPOINT_FILE.parent.mkdir(parents=True, exist_ok=True)
        with open(CHECKPOINT_FILE, "w") as f:
            json.dump(self.checkpoint, f, indent=2, default=str)

    async def check_new_data(self) -> dict:
        """Check Neo4j for new samples since last training."""
        from neo4j import AsyncGraphDatabase

        driver = AsyncGraphDatabase.driver(
            self.neo4j_uri,
            auth=(self.neo4j_user, self.neo4j_password)
        )

        try:
            async with driver.session() as session:
                # Count current samples
                result = await session.run("""
                    MATCH (a:AttackSample) RETURN count(a) as count
                """)
                record = await result.single()
                attack_count = record["count"]

                result = await session.run("""
                    MATCH (b:BenignSample) RETURN count(b) as count
                """)
                record = await result.single()
                benign_count = record["count"]

                # Calculate new samples
                new_attacks = attack_count - self.checkpoint.get("last_attack_count", 0)
                new_benign = benign_count - self.checkpoint.get("last_benign_count", 0)

                return {
                    "total_attacks": attack_count,
                    "total_benign": benign_count,
                    "new_attacks": new_attacks,
                    "new_benign": new_benign,
                    "new_total": new_attacks + new_benign,
                }

        finally:
            await driver.close()

    async def export_training_data(self) -> Path:
        """Export training data from Neo4j."""
        from neo4j import AsyncGraphDatabase

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_file = TRAINING_DATA_DIR / f"training_data_{timestamp}.jsonl"
        output_file.parent.mkdir(parents=True, exist_ok=True)

        driver = AsyncGraphDatabase.driver(
            self.neo4j_uri,
            auth=(self.neo4j_user, self.neo4j_password)
        )

        try:
            async with driver.session() as session:
                samples = []

                # Get attacks
                result = await session.run("""
                    MATCH (a:AttackSample)
                    WHERE a.text IS NOT NULL AND size(a.text) > 10
                    RETURN a.text as text, a.category as category
                """)
                async for record in result:
                    samples.append({
                        "text": record["text"],
                        "label": 1,
                        "category": record.get("category", "unknown"),
                    })

                # Get benign
                result = await session.run("""
                    MATCH (b:BenignSample)
                    WHERE b.text IS NOT NULL AND size(b.text) > 10
                    RETURN b.text as text, b.category as category
                """)
                async for record in result:
                    samples.append({
                        "text": record["text"],
                        "label": 0,
                        "category": record.get("category", "benign"),
                    })

                # Write to file
                with open(output_file, "w", encoding="utf-8") as f:
                    for sample in samples:
                        f.write(json.dumps(sample, ensure_ascii=False) + "\n")

                logger.info(f"Exported {len(samples)} samples to {output_file}")
                return output_file

        finally:
            await driver.close()

    def train_model(self, data_file: Path) -> dict:
        """
        Train new model locally.

        Requires: torch, transformers, scikit-learn
        """
        try:
            import torch
            from sklearn.metrics import accuracy_score, precision_recall_fscore_support
            from sklearn.model_selection import train_test_split
            from torch.utils.data import DataLoader, Dataset
            from transformers import (
                AutoModelForSequenceClassification,
                AutoTokenizer,
                Trainer,
                TrainingArguments,
            )
        except ImportError as e:
            logger.error(f"Missing training dependencies: {e}")
            logger.info("Install with: pip install torch transformers scikit-learn")
            return {"success": False, "error": str(e)}

        # Check GPU
        device = "cuda" if torch.cuda.is_available() else "cpu"
        logger.info(f"Training on: {device}")

        if device == "cpu":
            logger.warning("No GPU detected! Training will be slow.")

        # Load data
        texts, labels = [], []
        with open(data_file, "r", encoding="utf-8") as f:
            for line in f:
                if line.strip():
                    item = json.loads(line)
                    texts.append(item["text"])
                    labels.append(item["label"])

        logger.info(f"Loaded {len(texts)} samples (attacks: {sum(labels)}, benign: {len(labels) - sum(labels)})")

        # Split data
        train_texts, val_texts, train_labels, val_labels = train_test_split(
            texts, labels, test_size=0.15, random_state=42, stratify=labels
        )

        # Tokenizer and model
        model_name = "distilbert-base-uncased"
        tokenizer = AutoTokenizer.from_pretrained(model_name)

        class InjectionDataset(Dataset):
            def __init__(self, texts, labels, tokenizer, max_length=256):
                self.encodings = tokenizer(
                    texts, truncation=True, padding=True, max_length=max_length, return_tensors="pt"
                )
                self.labels = torch.tensor(labels)

            def __len__(self):
                return len(self.labels)

            def __getitem__(self, idx):
                return {
                    "input_ids": self.encodings["input_ids"][idx],
                    "attention_mask": self.encodings["attention_mask"][idx],
                    "labels": self.labels[idx],
                }

        train_dataset = InjectionDataset(train_texts, train_labels, tokenizer)
        val_dataset = InjectionDataset(val_texts, val_labels, tokenizer)

        # Model
        model = AutoModelForSequenceClassification.from_pretrained(
            model_name,
            num_labels=2,
        )

        def compute_metrics(pred):
            labels = pred.label_ids
            preds = pred.predictions.argmax(-1)
            precision, recall, f1, _ = precision_recall_fscore_support(labels, preds, average="binary")
            acc = accuracy_score(labels, preds)
            return {"accuracy": acc, "f1": f1, "precision": precision, "recall": recall}

        # Training
        output_dir = MODELS_DIR / "new_model"
        training_args = TrainingArguments(
            output_dir=str(output_dir),
            num_train_epochs=3,
            per_device_train_batch_size=16 if device == "cuda" else 8,
            per_device_eval_batch_size=32 if device == "cuda" else 16,
            warmup_steps=100,
            weight_decay=0.01,
            logging_dir=str(output_dir / "logs"),
            logging_steps=50,
            eval_strategy="epoch",
            save_strategy="epoch",
            load_best_model_at_end=True,
            metric_for_best_model="f1",
            report_to="none",  # Disable wandb etc
        )

        trainer = Trainer(
            model=model,
            args=training_args,
            train_dataset=train_dataset,
            eval_dataset=val_dataset,
            compute_metrics=compute_metrics,
        )

        logger.info("Starting training...")
        trainer.train()

        # Evaluate
        results = trainer.evaluate()
        logger.info(f"Evaluation results: {results}")

        # Save model
        final_model_dir = MODELS_DIR / "new_model" / "final"
        model.save_pretrained(final_model_dir)
        tokenizer.save_pretrained(final_model_dir)
        logger.info(f"Model saved to {final_model_dir}")

        return {
            "success": True,
            "metrics": {
                "f1": results.get("eval_f1", 0),
                "accuracy": results.get("eval_accuracy", 0),
                "precision": results.get("eval_precision", 0),
                "recall": results.get("eval_recall", 0),
            },
            "model_path": str(final_model_dir),
        }

    def deploy_model(self, model_path: Path):
        """Deploy new model by replacing the current best model."""
        best_dir = MODELS_DIR / "best"

        # Backup current best
        if best_dir.exists():
            backup_dir = MODELS_DIR / f"backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
            shutil.move(str(best_dir), str(backup_dir))
            logger.info(f"Backed up current model to {backup_dir}")

        # Copy new model to best
        shutil.copytree(str(model_path), str(best_dir))
        logger.info(f"Deployed new model to {best_dir}")

        # Clean up new_model directory
        new_model_dir = MODELS_DIR / "new_model"
        if new_model_dir.exists():
            shutil.rmtree(str(new_model_dir))

    async def run_pipeline(self, force: bool = False) -> dict:
        """Run the full retraining pipeline."""
        logger.info("=" * 60)
        logger.info("In-A-Lign Auto-Retraining Pipeline")
        logger.info("=" * 60)

        # Step 1: Check for new data
        logger.info("\n[1/5] Checking for new data in Neo4j...")
        data_status = await self.check_new_data()
        logger.info(f"  Total attacks: {data_status['total_attacks']}")
        logger.info(f"  Total benign: {data_status['total_benign']}")
        logger.info(f"  New samples since last training: {data_status['new_total']}")

        # Check if retraining is needed
        if not force and data_status["new_total"] < MIN_NEW_SAMPLES:
            logger.info(f"\nNot enough new data ({data_status['new_total']} < {MIN_NEW_SAMPLES}). Skipping.")
            return {"action": "skipped", "reason": "insufficient_new_data", "new_samples": data_status["new_total"]}

        # Step 2: Export training data
        logger.info("\n[2/5] Exporting training data...")
        data_file = await self.export_training_data()

        # Step 3: Train new model
        logger.info("\n[3/5] Training new model...")
        train_result = self.train_model(data_file)

        if not train_result["success"]:
            logger.error(f"Training failed: {train_result.get('error')}")
            return {"action": "failed", "reason": "training_error", "error": train_result.get("error")}

        new_f1 = train_result["metrics"]["f1"]
        current_f1 = self.checkpoint.get("current_model_f1", 0)

        logger.info(f"\n[4/5] Evaluating model...")
        logger.info(f"  Current model F1: {current_f1:.4f}")
        logger.info(f"  New model F1: {new_f1:.4f}")
        logger.info(f"  Improvement: {new_f1 - current_f1:.4f}")

        # Step 4: Deploy if better
        improvement = new_f1 - current_f1
        if improvement >= MIN_IMPROVEMENT or force:
            logger.info("\n[5/5] Deploying new model...")
            self.deploy_model(Path(train_result["model_path"]))

            # Update checkpoint
            self.checkpoint["last_training"] = datetime.now().isoformat()
            self.checkpoint["last_attack_count"] = data_status["total_attacks"]
            self.checkpoint["last_benign_count"] = data_status["total_benign"]
            self.checkpoint["current_model_f1"] = new_f1
            self.checkpoint["training_history"].append({
                "timestamp": datetime.now().isoformat(),
                "samples": data_status["total_attacks"] + data_status["total_benign"],
                "f1": new_f1,
                "improvement": improvement,
            })
            self._save_checkpoint()

            logger.info("\nRetraining complete! New model deployed.")
            return {
                "action": "deployed",
                "new_f1": new_f1,
                "improvement": improvement,
                "samples_trained": data_status["total_attacks"] + data_status["total_benign"],
            }
        else:
            logger.info(f"\nNew model not better enough ({improvement:.4f} < {MIN_IMPROVEMENT}). Keeping current model.")
            return {
                "action": "skipped",
                "reason": "insufficient_improvement",
                "new_f1": new_f1,
                "current_f1": current_f1,
                "improvement": improvement,
            }

    async def run_continuous(self, interval_hours: int = 1):
        """Run pipeline continuously with specified interval."""
        logger.info(f"Starting continuous retraining (checking every {interval_hours} hour(s))...")

        while True:
            try:
                result = await self.run_pipeline()
                logger.info(f"Pipeline result: {result['action']}")
            except Exception as e:
                logger.error(f"Pipeline error: {e}")

            # Wait for next check
            await asyncio.sleep(interval_hours * 3600)


async def main():
    parser = argparse.ArgumentParser(description="In-A-Lign Auto-Retraining Pipeline")
    parser.add_argument("--force", action="store_true", help="Force retraining even if threshold not met")
    parser.add_argument("--continuous", action="store_true", help="Run continuously")
    parser.add_argument("--interval", type=int, default=1, help="Check interval in hours (for continuous mode)")
    parser.add_argument("--export-only", action="store_true", help="Only export training data (for Colab)")
    parser.add_argument("--stats", action="store_true", help="Show data statistics only")
    args = parser.parse_args()

    retrainer = AutoRetrainer()

    if args.stats:
        # Just show stats
        data = await retrainer.check_new_data()
        print(f"\n{'='*50}")
        print("Neo4j Data Statistics")
        print(f"{'='*50}")
        print(f"  Total attacks: {data['total_attacks']}")
        print(f"  Total benign: {data['total_benign']}")
        print(f"  New since last training: {data['new_total']}")
        print(f"  Last training: {retrainer.checkpoint.get('last_training', 'Never')}")
        print(f"  Current model F1: {retrainer.checkpoint.get('current_model_f1', 'Unknown')}")

    elif args.export_only:
        # Export data for Colab training
        print("Exporting training data for Colab...")
        data_file = await retrainer.export_training_data()
        print(f"\nExported to: {data_file}")
        print(f"\nNext steps:")
        print(f"  1. Upload {data_file.name} to Colab")
        print(f"  2. Run train_on_colab.ipynb")
        print(f"  3. Download model and extract to backend/app/ml/models/injection_detector/best/")

    elif args.continuous:
        await retrainer.run_continuous(args.interval)

    else:
        result = await retrainer.run_pipeline(force=args.force)
        print(f"\nResult: {json.dumps(result, indent=2)}")


if __name__ == "__main__":
    asyncio.run(main())
