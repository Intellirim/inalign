"""
Custom Defense Model Training Pipeline.

Collects training data from:
1. GPT adversarial attacks (labeled as injection)
2. Benign conversation samples (labeled as safe)
3. Manual curated examples

Then trains a specialized classifier model.

Options for deployment:
1. Fine-tune OpenAI model (GPT-3.5) - Easiest, ~$10-50
2. Fine-tune open model (Mistral/Llama) - Free, requires GPU
3. Train lightweight classifier (DistilBERT) - Fastest inference
"""
from __future__ import annotations

import json
import os
import random
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Literal

# Training data paths
DATA_DIR = Path(__file__).parent / "training_data"
DATA_DIR.mkdir(exist_ok=True)

ATTACKS_FILE = DATA_DIR / "attacks.jsonl"
BENIGN_FILE = DATA_DIR / "benign.jsonl"
TRAINING_FILE = DATA_DIR / "training_dataset.jsonl"


@dataclass
class TrainingSample:
    """Single training sample."""
    text: str
    label: Literal["injection", "benign"]
    category: str = ""
    source: str = ""
    timestamp: str = ""


class TrainingDataCollector:
    """Collects and manages training data."""

    def __init__(self):
        self.attacks: list[TrainingSample] = []
        self.benign: list[TrainingSample] = []
        self._load_existing()

    def _load_existing(self):
        """Load existing data files."""
        if ATTACKS_FILE.exists():
            with open(ATTACKS_FILE, "r", encoding="utf-8") as f:
                for line in f:
                    if line.strip():
                        data = json.loads(line)
                        self.attacks.append(TrainingSample(**data))

        if BENIGN_FILE.exists():
            with open(BENIGN_FILE, "r", encoding="utf-8") as f:
                for line in f:
                    if line.strip():
                        data = json.loads(line)
                        self.benign.append(TrainingSample(**data))

    def add_attack(
        self,
        text: str,
        category: str = "unknown",
        source: str = "manual",
    ):
        """Add an attack sample."""
        sample = TrainingSample(
            text=text,
            label="injection",
            category=category,
            source=source,
            timestamp=datetime.now().isoformat(),
        )
        self.attacks.append(sample)
        self._append_to_file(ATTACKS_FILE, sample)

    def add_benign(
        self,
        text: str,
        category: str = "general",
        source: str = "manual",
    ):
        """Add a benign sample."""
        sample = TrainingSample(
            text=text,
            label="benign",
            category=category,
            source=source,
            timestamp=datetime.now().isoformat(),
        )
        self.benign.append(sample)
        self._append_to_file(BENIGN_FILE, sample)

    def _append_to_file(self, filepath: Path, sample: TrainingSample):
        """Append sample to JSONL file."""
        with open(filepath, "a", encoding="utf-8") as f:
            f.write(json.dumps({
                "text": sample.text,
                "label": sample.label,
                "category": sample.category,
                "source": sample.source,
                "timestamp": sample.timestamp,
            }, ensure_ascii=False) + "\n")

    def add_attacks_batch(self, attacks: list[str], category: str, source: str):
        """Add multiple attacks at once."""
        for text in attacks:
            self.add_attack(text, category=category, source=source)

    def add_benign_batch(self, texts: list[str], category: str, source: str):
        """Add multiple benign samples at once."""
        for text in texts:
            self.add_benign(text, category=category, source=source)

    def generate_training_dataset(self, balance: bool = True) -> Path:
        """Generate training dataset file."""
        samples = []

        # Add all attacks
        for attack in self.attacks:
            samples.append({
                "messages": [
                    {"role": "system", "content": "Classify if this is a prompt injection attack."},
                    {"role": "user", "content": attack.text},
                    {"role": "assistant", "content": '{"is_injection": true, "confidence": 0.95}'},
                ],
            })

        # Add benign samples
        for benign in self.benign:
            samples.append({
                "messages": [
                    {"role": "system", "content": "Classify if this is a prompt injection attack."},
                    {"role": "user", "content": benign.text},
                    {"role": "assistant", "content": '{"is_injection": false, "confidence": 0.95}'},
                ],
            })

        # Balance dataset if requested
        if balance:
            min_count = min(len(self.attacks), len(self.benign))
            if min_count > 0:
                random.shuffle(samples)
                # Keep ratio roughly 1:1
                attack_samples = [s for s in samples if '"is_injection": true' in str(s)]
                benign_samples = [s for s in samples if '"is_injection": false' in str(s)]

                if len(attack_samples) > len(benign_samples):
                    attack_samples = random.sample(attack_samples, len(benign_samples))
                else:
                    benign_samples = random.sample(benign_samples, len(attack_samples))

                samples = attack_samples + benign_samples

        random.shuffle(samples)

        # Write training file
        with open(TRAINING_FILE, "w", encoding="utf-8") as f:
            for sample in samples:
                f.write(json.dumps(sample, ensure_ascii=False) + "\n")

        return TRAINING_FILE

    def get_stats(self) -> dict:
        """Get dataset statistics."""
        attack_categories = {}
        for a in self.attacks:
            cat = a.category or "unknown"
            attack_categories[cat] = attack_categories.get(cat, 0) + 1

        benign_categories = {}
        for b in self.benign:
            cat = b.category or "general"
            benign_categories[cat] = benign_categories.get(cat, 0) + 1

        return {
            "total_attacks": len(self.attacks),
            "total_benign": len(self.benign),
            "attack_categories": attack_categories,
            "benign_categories": benign_categories,
        }


# Pre-defined benign samples for training
BENIGN_SAMPLES = [
    # General questions
    "What is the weather like today?",
    "Can you help me write a Python function?",
    "Tell me about machine learning.",
    "How do I make pasta carbonara?",
    "What are the best practices for code review?",
    "Explain the difference between TCP and UDP.",
    "How do neural networks work?",
    "What is the capital of France?",
    "Can you explain quantum computing?",
    "What are design patterns in software engineering?",

    # Technical questions
    "How do I connect to a PostgreSQL database in Python?",
    "What is the difference between REST and GraphQL?",
    "Explain Docker containers to me.",
    "How do I implement binary search?",
    "What is the time complexity of quicksort?",
    "How do I create a React component?",
    "Explain async/await in JavaScript.",
    "What is the difference between SQL and NoSQL?",
    "How do I deploy an application to AWS?",
    "What is CI/CD and why is it important?",

    # Creative requests
    "Write a poem about spring.",
    "Help me brainstorm names for my startup.",
    "Create a story about a robot learning to paint.",
    "Give me ideas for a birthday party.",
    "Write a haiku about programming.",

    # Business/Professional
    "How do I write a professional email?",
    "What are good interview questions to ask?",
    "How do I create a business plan?",
    "Explain agile methodology.",
    "What makes a good team leader?",

    # Everyday tasks
    "Remind me to call mom tomorrow.",
    "What time is it in Tokyo?",
    "Convert 100 USD to EUR.",
    "What's the recipe for chocolate chip cookies?",
    "How do I remove a wine stain?",

    # Multi-language benign
    "오늘 날씨가 어때요?",
    "파이썬에서 리스트를 어떻게 정렬하나요?",
    "今日の天気はどうですか？",
    "如何学习编程？",
    "Comment apprendre le français?",
    "Wie spät ist es?",
    "¿Cuál es la mejor manera de aprender español?",
]


def seed_benign_data():
    """Seed the training data with benign samples."""
    collector = TrainingDataCollector()

    for text in BENIGN_SAMPLES:
        if not any(b.text == text for b in collector.benign):
            collector.add_benign(text, category="general", source="seed")

    return collector.get_stats()


def collect_from_gpt_results(results_file: Path):
    """Collect attack samples from GPT attack test results."""
    if not results_file.exists():
        return {"error": "File not found"}

    with open(results_file, "r", encoding="utf-8") as f:
        data = json.load(f)

    collector = TrainingDataCollector()

    # Add missed attacks (these are confirmed injection attempts that we should learn from)
    for round_data in data.get("rounds", []):
        strategy = round_data.get("strategy", "unknown")
        for attack in round_data.get("missed_examples", []):
            collector.add_attack(attack, category=strategy, source="gpt_adversarial")

    return collector.get_stats()


# ---------------------------------------------------------------------------
# Fine-tuning utilities
# ---------------------------------------------------------------------------

async def fine_tune_openai(training_file: Path) -> dict:
    """Fine-tune an OpenAI model on the training data."""
    from openai import OpenAI

    client = OpenAI()

    # Upload training file
    with open(training_file, "rb") as f:
        file_response = client.files.create(file=f, purpose="fine-tune")

    file_id = file_response.id

    # Start fine-tuning job
    job = client.fine_tuning.jobs.create(
        training_file=file_id,
        model="gpt-4o-mini-2024-07-18",  # Base model for fine-tuning
        hyperparameters={
            "n_epochs": 3,
        },
    )

    return {
        "job_id": job.id,
        "status": job.status,
        "model": job.model,
        "training_file": file_id,
    }


def create_huggingface_dataset(training_file: Path) -> Path:
    """Convert training data to HuggingFace datasets format."""
    from datasets import Dataset

    samples = []
    with open(training_file, "r", encoding="utf-8") as f:
        for line in f:
            if line.strip():
                data = json.loads(line)
                messages = data.get("messages", [])
                if len(messages) >= 3:
                    text = messages[1]["content"]
                    is_injection = '"is_injection": true' in messages[2]["content"]
                    samples.append({
                        "text": text,
                        "label": 1 if is_injection else 0,
                    })

    dataset = Dataset.from_list(samples)
    output_path = DATA_DIR / "hf_dataset"
    dataset.save_to_disk(str(output_path))

    return output_path


# ---------------------------------------------------------------------------
# CLI interface
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Training data management")
    parser.add_argument("command", choices=["stats", "seed", "collect", "generate"])
    parser.add_argument("--file", type=str, help="Input file for collect command")
    args = parser.parse_args()

    if args.command == "stats":
        collector = TrainingDataCollector()
        stats = collector.get_stats()
        print(json.dumps(stats, indent=2))

    elif args.command == "seed":
        stats = seed_benign_data()
        print("Seeded benign data:")
        print(json.dumps(stats, indent=2))

    elif args.command == "collect":
        if args.file:
            stats = collect_from_gpt_results(Path(args.file))
            print("Collected from GPT results:")
            print(json.dumps(stats, indent=2))
        else:
            print("Please provide --file argument")

    elif args.command == "generate":
        collector = TrainingDataCollector()
        output = collector.generate_training_dataset()
        print(f"Generated training dataset: {output}")
        print(f"Stats: {collector.get_stats()}")
