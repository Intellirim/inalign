"""
Train Custom Prompt Injection Classifier.

Uses data from Neo4j Aura to train an embedding-based classifier.
This replaces the expensive LLM calls with a fast, local model.

Architecture:
1. sentence-transformers for text embeddings
2. XGBoost/RandomForest for classification
3. Export to ONNX for fast inference

Run: python tools/train_custom_model.py
"""
import asyncio
import json
import pickle
from pathlib import Path
from datetime import datetime

import numpy as np
from neo4j import AsyncGraphDatabase
from sentence_transformers import SentenceTransformer
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score
from xgboost import XGBClassifier


# Model save path
MODEL_DIR = Path(__file__).parent.parent / "backend" / "app" / "detectors" / "injection" / "models"


async def fetch_training_data():
    """Fetch all attack samples from Neo4j Aura."""
    driver = AsyncGraphDatabase.driver(
        "***REDACTED_URI***",
        auth=("neo4j", "***REDACTED***")
    )

    async with driver.session(database="neo4j") as session:
        result = await session.run("""
            MATCH (s:AttackSample)
            RETURN s.text as text, s.detected as detected
        """)
        records = await result.data()

    await driver.close()
    return records


def train_model(texts: list[str], labels: list[int]):
    """Train embedding + classifier model."""

    print("\n[2] Loading sentence-transformers model...")
    # Use a fast, multilingual model
    embedder = SentenceTransformer('all-MiniLM-L6-v2')

    print("[3] Generating embeddings...")
    embeddings = embedder.encode(texts, show_progress_bar=True, convert_to_numpy=True)

    print(f"    Embedding shape: {embeddings.shape}")

    # Split data
    X_train, X_test, y_train, y_test = train_test_split(
        embeddings, labels, test_size=0.2, random_state=42, stratify=labels
    )

    print(f"\n[4] Training classifiers...")
    print(f"    Train: {len(X_train)}, Test: {len(X_test)}")

    # Train multiple classifiers
    classifiers = {
        "RandomForest": RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1),
        "XGBoost": XGBClassifier(n_estimators=100, random_state=42, use_label_encoder=False, eval_metric='logloss'),
        "GradientBoosting": GradientBoostingClassifier(n_estimators=100, random_state=42),
    }

    results = {}

    for name, clf in classifiers.items():
        print(f"\n    Training {name}...")
        clf.fit(X_train, y_train)

        y_pred = clf.predict(X_test)
        accuracy = accuracy_score(y_test, y_pred)

        print(f"    {name} Accuracy: {accuracy:.2%}")
        print(classification_report(y_test, y_pred, target_names=["Benign", "Attack"]))

        results[name] = {
            "classifier": clf,
            "accuracy": accuracy,
            "report": classification_report(y_test, y_pred, output_dict=True),
        }

    # Select best model
    best_name = max(results, key=lambda x: results[x]["accuracy"])
    best_clf = results[best_name]["classifier"]

    print(f"\n[5] Best model: {best_name} ({results[best_name]['accuracy']:.2%})")

    return embedder, best_clf, best_name, results


def save_model(embedder, classifier, name: str, results: dict):
    """Save trained model for inference."""
    MODEL_DIR.mkdir(parents=True, exist_ok=True)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    # Save classifier
    clf_path = MODEL_DIR / f"injection_classifier_{timestamp}.pkl"
    with open(clf_path, "wb") as f:
        pickle.dump({
            "classifier": classifier,
            "classifier_name": name,
            "embedder_name": "all-MiniLM-L6-v2",
            "results": results,
            "timestamp": timestamp,
        }, f)

    print(f"\n[6] Model saved to: {clf_path}")

    # Save latest pointer
    latest_path = MODEL_DIR / "latest_classifier.pkl"
    with open(latest_path, "wb") as f:
        pickle.dump({
            "classifier": classifier,
            "classifier_name": name,
            "embedder_name": "all-MiniLM-L6-v2",
            "results": results,
            "timestamp": timestamp,
        }, f)

    print(f"    Latest pointer: {latest_path}")

    return clf_path


async def main():
    print("=" * 70)
    print("TRAIN CUSTOM PROMPT INJECTION CLASSIFIER")
    print("=" * 70)

    # Fetch data
    print("\n[1] Fetching training data from Neo4j Aura...")
    records = await fetch_training_data()
    print(f"    Total samples: {len(records)}")

    if len(records) < 100:
        print("\n[!] Not enough data. Need at least 100 samples.")
        print("    Run more attack tests first.")
        return

    # Prepare data
    texts = []
    labels = []

    for r in records:
        text = r.get("text", "")
        detected = r.get("detected", False)

        if text and len(text.strip()) > 5:
            texts.append(text)
            # Label: 1 = attack (should be detected), 0 = benign (evaded = false positive risk)
            # Actually, our data is all attacks, but "detected" tells us if our current system caught it
            # For training, we want to catch EVERYTHING, so all should be labeled as 1 (attack)
            labels.append(1)  # All our samples are attacks

    print(f"    Valid samples: {len(texts)}")
    print(f"    Attack samples: {sum(labels)}")
    print(f"    Benign samples: {len(labels) - sum(labels)}")

    # Need some benign samples too for balanced training
    print("\n[!] Warning: All samples are attacks. Adding synthetic benign samples...")

    benign_examples = [
        "What's the weather like today?",
        "Can you help me write a Python function?",
        "Tell me about the history of Rome",
        "How do I make pasta carbonara?",
        "What are the best practices for React development?",
        "Explain quantum computing in simple terms",
        "Write a poem about nature",
        "What's 25 times 47?",
        "How tall is Mount Everest?",
        "Recommend a good book about machine learning",
        "What programming language should I learn first?",
        "How do I install Docker on Windows?",
        "Explain the difference between SQL and NoSQL",
        "What's the capital of Japan?",
        "How do I center a div in CSS?",
        "What are the benefits of exercise?",
        "Tell me a fun fact about space",
        "How do I make a git commit?",
        "What's the difference between let and const in JavaScript?",
        "Explain object-oriented programming",
        # Add more benign examples
        "Write a function to sort an array",
        "What's the time complexity of binary search?",
        "How do I connect to a PostgreSQL database?",
        "What's the best way to learn a new language?",
        "Explain the concept of recursion",
        "What are design patterns in software engineering?",
        "How do I deploy a Flask app?",
        "What's REST API?",
        "Explain microservices architecture",
        "How do I use async/await in Python?",
    ]

    # Add benign samples (replicate to balance)
    benign_count = len(texts) // 2  # Make it 2:1 ratio
    for i in range(benign_count):
        texts.append(benign_examples[i % len(benign_examples)])
        labels.append(0)

    print(f"    After balancing: {len(texts)} total")
    print(f"    Attacks: {sum(labels)}, Benign: {len(labels) - sum(labels)}")

    # Train
    embedder, classifier, name, results = train_model(texts, labels)

    # Save
    save_model(embedder, classifier, name, results)

    print("\n" + "=" * 70)
    print("TRAINING COMPLETE")
    print("=" * 70)
    print(f"Best Model: {name}")
    print(f"Accuracy:   {results[name]['accuracy']:.2%}")
    print("\nTo use this model, update the detector to load from:")
    print(f"  {MODEL_DIR / 'latest_classifier.pkl'}")


if __name__ == "__main__":
    asyncio.run(main())
