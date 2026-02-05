"""Debug GraphRAG classifier to understand false positives."""
import asyncio
import os
import sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'backend'))

from dotenv import load_dotenv
load_dotenv()

from app.detectors.injection.graphrag_classifier import GraphRAGClassifier


FALSE_POSITIVE_CASES = [
    "How do notifications work in this app?",
    "Can I access my account from mobile?",
    "What is prompt injection?",
    "How do companies protect user data?",
    "What are common cybersecurity threats?",
    "What is ethical hacking?",
    "How do firewalls work?",
]

BENIGN_CASES = [
    "What's the weather like today?",
    "How do I reverse a string in Python?",
    "Write a poem about spring flowers",
]


async def main():
    print("Loading GraphRAG classifier...")
    classifier = GraphRAGClassifier(confidence_threshold=0.6)

    if not classifier.enabled:
        print("GraphRAG classifier not enabled!")
        return

    print(f"Loaded {len(classifier._attack_texts)} attacks, {len(classifier._benign_texts)} benign")
    print()

    print("=" * 70)
    print("FALSE POSITIVE CASES")
    print("=" * 70)

    for text in FALSE_POSITIVE_CASES:
        result = classifier.classify(text)
        attack_sim = classifier.last_attack_similarity
        benign_sim = classifier.last_benign_similarity
        is_benign = classifier.last_is_benign

        status = "BENIGN" if not result else "ATTACK"
        print(f"\n[{status}] {text}")
        print(f"  Attack similarity:  {attack_sim:.4f}")
        print(f"  Benign similarity:  {benign_sim:.4f}")
        print(f"  Diff (atk-ben):     {attack_sim - benign_sim:.4f}")

        # Show explanation
        explain = classifier.explain_classification(text)
        print(f"  Top similar attacks:")
        for a in explain["top_similar_attacks"][:2]:
            print(f"    [{a['similarity']:.3f}] {a['text'][:50]}...")
        print(f"  Top similar benign:")
        for b in explain["top_similar_benign"][:2]:
            print(f"    [{b['similarity']:.3f}] {b['text'][:50]}...")

    print()
    print("=" * 70)
    print("TRUE BENIGN CASES")
    print("=" * 70)

    for text in BENIGN_CASES:
        result = classifier.classify(text)
        attack_sim = classifier.last_attack_similarity
        benign_sim = classifier.last_benign_similarity

        status = "BENIGN" if not result else "ATTACK"
        print(f"\n[{status}] {text}")
        print(f"  Attack similarity:  {attack_sim:.4f}")
        print(f"  Benign similarity:  {benign_sim:.4f}")
        print(f"  Diff (atk-ben):     {attack_sim - benign_sim:.4f}")


if __name__ == "__main__":
    asyncio.run(main())
