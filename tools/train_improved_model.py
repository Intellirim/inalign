"""
Improved Prompt Injection Classifier Training.

Key improvements:
1. Balanced dataset (1:1 attack:benign ratio)
2. Diverse benign categories
3. Better evaluation metrics
4. Cross-validation
"""
import asyncio
import pickle
from pathlib import Path
from datetime import datetime

import numpy as np
from neo4j import AsyncGraphDatabase
from sentence_transformers import SentenceTransformer
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.metrics import classification_report, confusion_matrix, f1_score, precision_score, recall_score
from xgboost import XGBClassifier

MODEL_DIR = Path(__file__).parent.parent / "backend" / "app" / "detectors" / "injection" / "models"

# Diverse benign examples - covering many categories
BENIGN_EXAMPLES = {
    "weather": [
        "What's the weather like in Tokyo today?",
        "Will it rain tomorrow in London?",
        "What's the temperature in New York right now?",
        "Is it sunny in Paris today?",
        "What's the forecast for this weekend?",
        "How hot is it in Dubai?",
        "What's the humidity level in Singapore?",
        "Is there a storm coming?",
        "What's the weather like in Seoul?",
        "Will it snow in Moscow this week?",
    ],
    "math": [
        "What's 15% of 230?",
        "Calculate 25 times 47",
        "What's the square root of 144?",
        "Solve for x: 2x + 5 = 15",
        "What's 1000 divided by 8?",
        "Convert 5 miles to kilometers",
        "What's 3 to the power of 4?",
        "Calculate the area of a circle with radius 5",
        "What's 17% tip on $85?",
        "How many seconds in a day?",
    ],
    "science": [
        "Explain photosynthesis in simple terms",
        "What causes earthquakes?",
        "How do vaccines work?",
        "What is the speed of light?",
        "Explain gravity to a child",
        "What are black holes?",
        "How does DNA replication work?",
        "What causes the northern lights?",
        "Explain the water cycle",
        "What is quantum entanglement?",
    ],
    "history": [
        "When did World War 2 end?",
        "Who was the first president of the USA?",
        "When was the Great Wall of China built?",
        "What caused the French Revolution?",
        "Who invented the printing press?",
        "When did humans first land on the moon?",
        "What was the Renaissance?",
        "Who was Cleopatra?",
        "When did the Roman Empire fall?",
        "What started World War 1?",
    ],
    "geography": [
        "What's the capital of Australia?",
        "How many countries are in Europe?",
        "What's the longest river in the world?",
        "Where is Mount Everest?",
        "What's the largest ocean?",
        "How many continents are there?",
        "What's the smallest country?",
        "Where is the Amazon rainforest?",
        "What's the deepest point in the ocean?",
        "Which country has the most islands?",
    ],
    "programming": [
        "How do I center a div in CSS?",
        "What's the difference between let and const?",
        "How do I reverse a string in Python?",
        "What is a REST API?",
        "Explain object-oriented programming",
        "How do I connect to a database in Node.js?",
        "What's the difference between SQL and NoSQL?",
        "How do I sort an array in JavaScript?",
        "What is recursion?",
        "How do I handle errors in async/await?",
        "Write a function to check if a number is prime",
        "How do I parse JSON in Python?",
        "What's the time complexity of binary search?",
        "How do I create a virtual environment?",
        "Explain the difference between GET and POST",
    ],
    "cooking": [
        "How do I make spaghetti carbonara?",
        "What's the recipe for chocolate chip cookies?",
        "How long do I boil eggs?",
        "What temperature for roasting chicken?",
        "How do I make rice properly?",
        "What's a good vegetarian dinner recipe?",
        "How do I make homemade pizza dough?",
        "What's the difference between baking soda and baking powder?",
        "How do I caramelize onions?",
        "What's a simple breakfast recipe?",
    ],
    "health": [
        "How many calories are in an apple?",
        "What are the benefits of exercise?",
        "How much water should I drink daily?",
        "What foods are high in protein?",
        "How many hours of sleep do adults need?",
        "What are symptoms of dehydration?",
        "Is coffee good for you?",
        "What stretches help back pain?",
        "How do I reduce stress?",
        "What vitamins are in oranges?",
    ],
    "entertainment": [
        "What are the best movies of 2023?",
        "Who wrote Harry Potter?",
        "What TV shows are popular right now?",
        "Who directed Inception?",
        "What's a good book to read?",
        "Who won the Oscar for best picture last year?",
        "What games are trending?",
        "Who is the lead singer of Coldplay?",
        "What's the highest-grossing movie ever?",
        "Recommend a good podcast",
    ],
    "language": [
        "How do you say hello in Spanish?",
        "What does 'bon appetit' mean?",
        "Translate 'thank you' to Japanese",
        "What language is spoken in Brazil?",
        "How do you count to 10 in French?",
        "What does 'ciao' mean?",
        "How do you say goodbye in Korean?",
        "What's the most spoken language in the world?",
        "Translate 'I love you' to Italian",
        "What does 'namaste' mean?",
    ],
    "creative": [
        "Write a haiku about autumn",
        "Give me a fun fact about space",
        "Tell me a short joke",
        "Write a limerick about cats",
        "Describe a sunset poetically",
        "Write a short story opening",
        "Create a tongue twister",
        "Write a birthday message for my friend",
        "Suggest a creative team name",
        "Write a motivational quote",
    ],
    "daily_life": [
        "What time is it in London?",
        "How do I remove coffee stains?",
        "What's a good gift for a birthday?",
        "How do I tie a tie?",
        "What's the best way to organize my desk?",
        "How do I fold a fitted sheet?",
        "What should I pack for a trip?",
        "How do I get rid of hiccups?",
        "What's a good morning routine?",
        "How do I stay motivated?",
    ],
    "business": [
        "How do I write a professional email?",
        "What makes a good resume?",
        "How do I prepare for an interview?",
        "What's the difference between B2B and B2C?",
        "How do I negotiate salary?",
        "What's a good elevator pitch?",
        "How do I manage my time better?",
        "What makes a good leader?",
        "How do I give feedback to colleagues?",
        "What's the 80/20 rule?",
    ],
    "technology": [
        "What's the difference between HTTP and HTTPS?",
        "How does WiFi work?",
        "What is cloud computing?",
        "How do I speed up my computer?",
        "What's the difference between RAM and storage?",
        "How do I clear my browser cache?",
        "What is machine learning?",
        "How do I backup my phone?",
        "What's the difference between 4G and 5G?",
        "How does encryption work?",
    ],
    "sports": [
        "Who won the World Cup in 2022?",
        "What are the rules of basketball?",
        "How long is a marathon?",
        "Who has the most Grand Slam titles?",
        "What's the offside rule in soccer?",
        "How many players on a volleyball team?",
        "What's the highest score in bowling?",
        "Who invented basketball?",
        "How big is a football field?",
        "What's the fastest 100m sprint time?",
    ],
}


async def fetch_attack_data():
    """Fetch attack samples from Neo4j."""
    driver = AsyncGraphDatabase.driver(
        "***REDACTED_URI***",
        auth=("neo4j", "***REDACTED***")
    )

    async with driver.session(database="neo4j") as session:
        result = await session.run("""
            MATCH (s:AttackSample)
            RETURN s.text as text
        """)
        records = await result.data()

    await driver.close()
    return [r["text"] for r in records if r.get("text") and len(r["text"].strip()) > 5]


def prepare_balanced_dataset(attacks: list[str]):
    """Prepare balanced dataset with 1:1 ratio."""
    print(f"\n[Dataset Preparation]")
    print(f"  Attack samples from Neo4j: {len(attacks)}")

    # Collect all benign examples
    all_benign = []
    for category, examples in BENIGN_EXAMPLES.items():
        all_benign.extend(examples)
        print(f"  Benign - {category}: {len(examples)}")

    print(f"  Total benign templates: {len(all_benign)}")

    # Replicate benign to match attack count
    target_count = len(attacks)
    benign_samples = []

    # Repeat benign examples to match attack count
    while len(benign_samples) < target_count:
        benign_samples.extend(all_benign)

    benign_samples = benign_samples[:target_count]

    print(f"\n  Final dataset:")
    print(f"    Attacks: {len(attacks)}")
    print(f"    Benign:  {len(benign_samples)}")
    print(f"    Ratio:   1:1")

    # Create labels
    texts = attacks + benign_samples
    labels = [1] * len(attacks) + [0] * len(benign_samples)

    return texts, labels


def train_and_evaluate(embedder, texts, labels):
    """Train models with cross-validation."""
    print("\n[Generating Embeddings]")
    embeddings = embedder.encode(texts, show_progress_bar=True, convert_to_numpy=True)
    print(f"  Shape: {embeddings.shape}")

    # Split
    X_train, X_test, y_train, y_test = train_test_split(
        embeddings, labels, test_size=0.2, random_state=42, stratify=labels
    )

    print(f"\n[Train/Test Split]")
    print(f"  Train: {len(X_train)} (Attacks: {sum(y_train)}, Benign: {len(y_train) - sum(y_train)})")
    print(f"  Test:  {len(X_test)} (Attacks: {sum(y_test)}, Benign: {len(y_test) - sum(y_test)})")

    # Train classifiers
    classifiers = {
        "RandomForest": RandomForestClassifier(
            n_estimators=200,
            max_depth=20,
            min_samples_split=5,
            class_weight="balanced",
            random_state=42,
            n_jobs=-1
        ),
        "XGBoost": XGBClassifier(
            n_estimators=200,
            max_depth=10,
            learning_rate=0.1,
            scale_pos_weight=1,  # balanced
            random_state=42,
            eval_metric='logloss'
        ),
        "GradientBoosting": GradientBoostingClassifier(
            n_estimators=200,
            max_depth=10,
            learning_rate=0.1,
            random_state=42
        ),
    }

    results = {}

    for name, clf in classifiers.items():
        print(f"\n[Training {name}]")

        # Cross-validation
        cv_scores = cross_val_score(clf, X_train, y_train, cv=5, scoring='f1')
        print(f"  CV F1 Score: {cv_scores.mean():.4f} (+/- {cv_scores.std() * 2:.4f})")

        # Train on full training set
        clf.fit(X_train, y_train)
        y_pred = clf.predict(X_test)

        # Metrics
        accuracy = (y_pred == y_test).mean()
        precision = precision_score(y_test, y_pred)
        recall = recall_score(y_test, y_pred)
        f1 = f1_score(y_test, y_pred)

        print(f"  Test Accuracy:  {accuracy:.4f}")
        print(f"  Test Precision: {precision:.4f}")
        print(f"  Test Recall:    {recall:.4f}")
        print(f"  Test F1:        {f1:.4f}")

        print(f"\n  Confusion Matrix:")
        cm = confusion_matrix(y_test, y_pred)
        print(f"    TN={cm[0][0]:4d}  FP={cm[0][1]:4d}")
        print(f"    FN={cm[1][0]:4d}  TP={cm[1][1]:4d}")

        # False positive rate (critical!)
        fp_rate = cm[0][1] / (cm[0][0] + cm[0][1]) if (cm[0][0] + cm[0][1]) > 0 else 0
        print(f"\n  False Positive Rate: {fp_rate:.2%}")

        results[name] = {
            "classifier": clf,
            "accuracy": accuracy,
            "precision": precision,
            "recall": recall,
            "f1": f1,
            "fp_rate": fp_rate,
            "cv_f1": cv_scores.mean(),
        }

    # Select best model based on F1 score (balances precision and recall)
    best_name = max(results, key=lambda x: results[x]["f1"])

    print(f"\n{'='*60}")
    print(f"BEST MODEL: {best_name}")
    print(f"  F1 Score: {results[best_name]['f1']:.4f}")
    print(f"  FP Rate:  {results[best_name]['fp_rate']:.2%}")
    print(f"{'='*60}")

    return results[best_name]["classifier"], best_name, results


def save_model(classifier, name: str, results: dict, embedder_name: str):
    """Save trained model."""
    MODEL_DIR.mkdir(parents=True, exist_ok=True)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    # Save with timestamp
    clf_path = MODEL_DIR / f"injection_classifier_{timestamp}.pkl"
    model_data = {
        "classifier": classifier,
        "classifier_name": name,
        "embedder_name": embedder_name,
        "results": results,
        "timestamp": timestamp,
        "version": "2.0_balanced",
    }

    with open(clf_path, "wb") as f:
        pickle.dump(model_data, f)
    print(f"\nSaved: {clf_path}")

    # Save latest pointer
    latest_path = MODEL_DIR / "latest_classifier.pkl"
    with open(latest_path, "wb") as f:
        pickle.dump(model_data, f)
    print(f"Latest: {latest_path}")

    return clf_path


async def main():
    print("=" * 60)
    print("IMPROVED PROMPT INJECTION CLASSIFIER")
    print("=" * 60)

    # Fetch attack data
    print("\n[1] Fetching attack data from Neo4j...")
    attacks = await fetch_attack_data()
    print(f"    Retrieved {len(attacks)} attack samples")

    if len(attacks) < 100:
        print("\n[!] Need at least 100 attack samples!")
        return

    # Load embedder
    print("\n[2] Loading sentence-transformers...")
    embedder = SentenceTransformer('all-MiniLM-L6-v2')

    # Prepare balanced dataset
    texts, labels = prepare_balanced_dataset(attacks)

    # Train and evaluate
    classifier, name, results = train_and_evaluate(embedder, texts, labels)

    # Save
    save_model(classifier, name, results, "all-MiniLM-L6-v2")

    print("\n" + "=" * 60)
    print("TRAINING COMPLETE")
    print("=" * 60)


if __name__ == "__main__":
    asyncio.run(main())
