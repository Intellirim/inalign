"""
GraphRAG-based Prompt Injection Classifier.

Uses Neo4j graph data to classify inputs by comparing them to:
1. Known AttackSamples (should be blocked)
2. Known BenignSamples (should be allowed)

The classifier finds the most similar samples in the graph and makes a
decision based on which category has higher similarity scores.

This approach:
- Uses real historical data for classification
- Continuously improves as more data is added
- Can explain decisions by showing similar examples
- Zero additional API cost (runs locally)
"""
from __future__ import annotations

import logging
import os
from typing import Any, Optional

# Lazy imports - only load when actually used
np = None
SentenceTransformer = None

logger = logging.getLogger("inalign.graphrag_classifier")


def _get_dependencies():
    """Lazily import heavy dependencies."""
    global np, SentenceTransformer
    if np is None:
        try:
            import numpy as _np
            np = _np
        except ImportError:
            logger.warning("numpy not installed. GraphRAGClassifier will be disabled.")
            return False

    if SentenceTransformer is None:
        try:
            from sentence_transformers import SentenceTransformer as _ST
            SentenceTransformer = _ST
        except ImportError:
            logger.warning("sentence-transformers not installed. GraphRAGClassifier will be disabled.")
            return False

    return True


class GraphRAGClassifier:
    """
    Classifies inputs using GraphRAG similarity to known attack/benign samples.

    How it works:
    1. Encodes input text using sentence-transformers
    2. Compares to cached embeddings of AttackSamples and BenignSamples
    3. Returns classification based on which category has higher similarity

    This provides a "wisdom of the crowd" approach using historical data.
    """

    def __init__(
        self,
        embedder_name: str = "all-MiniLM-L6-v2",
        confidence_threshold: float = 0.6,
        top_k: int = 5,
    ):
        self.embedder_name = embedder_name
        self.confidence_threshold = confidence_threshold
        self.top_k = top_k

        self._embedder = None
        self._attack_embeddings = None
        self._attack_texts: list[str] = []
        self._attack_categories: list[str] = []
        self._benign_embeddings = None
        self._benign_texts: list[str] = []
        self._benign_categories: list[str] = []

        self.enabled = False

        # Only try to load if dependencies are available
        if _get_dependencies():
            self._load_data()

    def _load_data(self) -> None:
        """Load embeddings from Neo4j."""
        try:
            import asyncio
            from neo4j import AsyncGraphDatabase

            uri = os.getenv("NEO4J_URI")
            user = os.getenv("NEO4J_USER")
            password = os.getenv("NEO4J_PASSWORD")

            if not all([uri, user, password]):
                logger.warning("Neo4j credentials not found, GraphRAG classifier disabled")
                return

            # Load embedder
            logger.info("Loading sentence-transformers model: %s", self.embedder_name)
            self._embedder = SentenceTransformer(self.embedder_name)

            # Load data from Neo4j
            async def fetch_data():
                driver = AsyncGraphDatabase.driver(uri, auth=(user, password))
                try:
                    async with driver.session() as session:
                        # Get attack samples
                        result = await session.run("""
                            MATCH (a:AttackSample)
                            WHERE a.text IS NOT NULL AND size(a.text) > 5
                            RETURN a.text as text, a.category as category
                            LIMIT 1000
                        """)
                        attacks = await result.data()

                        # Get benign samples
                        result = await session.run("""
                            MATCH (b:BenignSample)
                            WHERE b.text IS NOT NULL AND size(b.text) > 5
                            RETURN b.text as text, b.category as category
                            LIMIT 1000
                        """)
                        benign = await result.data()

                    return attacks, benign
                finally:
                    await driver.close()

            # Run async fetch - handle both existing and new event loops
            try:
                loop = asyncio.get_running_loop()
                # If there's already a running loop, use nest_asyncio or run in thread
                import concurrent.futures
                with concurrent.futures.ThreadPoolExecutor() as executor:
                    future = executor.submit(asyncio.run, fetch_data())
                    attacks, benign = future.result()
            except RuntimeError:
                # No running loop, create one
                loop = asyncio.new_event_loop()
                attacks, benign = loop.run_until_complete(fetch_data())
                loop.close()

            if not attacks or not benign:
                logger.warning("Not enough data in Neo4j for GraphRAG classifier")
                return

            # Store texts and categories
            self._attack_texts = [a["text"] for a in attacks]
            self._attack_categories = [a.get("category", "unknown") for a in attacks]
            self._benign_texts = [b["text"] for b in benign]
            self._benign_categories = [b.get("category", "unknown") for b in benign]

            # Generate embeddings
            logger.info("Generating embeddings for %d attacks, %d benign...",
                       len(self._attack_texts), len(self._benign_texts))

            self._attack_embeddings = self._embedder.encode(
                self._attack_texts,
                convert_to_numpy=True,
                show_progress_bar=False,
            )
            self._benign_embeddings = self._embedder.encode(
                self._benign_texts,
                convert_to_numpy=True,
                show_progress_bar=False,
            )

            self.enabled = True
            logger.info(
                "GraphRAG classifier loaded: %d attack samples, %d benign samples",
                len(self._attack_texts), len(self._benign_texts)
            )

        except Exception as e:
            logger.error("Failed to load GraphRAG classifier: %s", e)
            self.enabled = False

    def classify(self, text: str) -> list[dict[str, Any]]:
        """
        Classify input text using GraphRAG similarity.

        Returns a list of threat dicts (empty if benign or disabled).
        """
        if not self.enabled or not text or len(text.strip()) < 5:
            return []

        # Store last classification info for external use
        self.last_benign_similarity = 0.0
        self.last_attack_similarity = 0.0
        self.last_is_benign = False

        try:
            # Encode input
            input_embedding = self._embedder.encode(
                [text],
                convert_to_numpy=True,
                show_progress_bar=False,
            )[0]

            # Calculate similarities to attacks
            attack_sims = self._cosine_similarity_batch(input_embedding, self._attack_embeddings)
            top_attack_indices = np.argsort(attack_sims)[-self.top_k:][::-1]
            top_attack_scores = attack_sims[top_attack_indices]
            avg_attack_sim = float(np.mean(top_attack_scores))
            max_attack_sim = float(np.max(attack_sims))

            # Calculate similarities to benign
            benign_sims = self._cosine_similarity_batch(input_embedding, self._benign_embeddings)
            top_benign_indices = np.argsort(benign_sims)[-self.top_k:][::-1]
            top_benign_scores = benign_sims[top_benign_indices]
            avg_benign_sim = float(np.mean(top_benign_scores))
            max_benign_sim = float(np.max(benign_sims))

            # Decision logic
            # If input is much more similar to benign than attack, it's benign
            # If input is much more similar to attack than benign, it's an attack

            attack_score = avg_attack_sim
            benign_score = avg_benign_sim

            # Calculate confidence based on the difference
            score_diff = attack_score - benign_score

            # Normalize to confidence (positive = attack, negative = benign)
            confidence = (score_diff + 1) / 2  # Map [-1, 1] to [0, 1]

            is_attack = attack_score > benign_score and confidence >= self.confidence_threshold

            # Get most similar attack for explanation
            most_similar_attack = self._attack_texts[top_attack_indices[0]][:50]
            most_similar_benign = self._benign_texts[top_benign_indices[0]][:50]
            attack_category = self._attack_categories[top_attack_indices[0]]

            # Store for external use (helps with false positive filtering)
            self.last_attack_similarity = attack_score
            self.last_benign_similarity = benign_score
            self.last_is_benign = not is_attack

            logger.debug(
                "GraphRAG: attack_sim=%.3f benign_sim=%.3f conf=%.3f is_attack=%s | %s",
                attack_score, benign_score, confidence, is_attack, text[:50]
            )

            if is_attack:
                return [{
                    "type": "injection",
                    "subtype": "graphrag_similarity",
                    "pattern_id": "GRAPHRAG-SIMILARITY",
                    "matched_text": f"Similar to: {most_similar_attack}...",
                    "position": (0, min(len(text), 50)),
                    "confidence": round(confidence, 4),
                    "severity": "high" if confidence >= 0.75 else "medium",
                    "description": (
                        f"GraphRAG classifier found input similar to known {attack_category} attacks "
                        f"(attack_sim={attack_score:.2f}, benign_sim={benign_score:.2f})"
                    ),
                    "similar_attack": most_similar_attack,
                    "similar_benign": most_similar_benign,
                    "attack_similarity": round(attack_score, 4),
                    "benign_similarity": round(benign_score, 4),
                }]

            return []

        except Exception as e:
            logger.warning("GraphRAG classify error: %s", e)
            return []

    @staticmethod
    def _cosine_similarity_batch(
        query: np.ndarray,
        corpus: np.ndarray,
    ) -> np.ndarray:
        """Calculate cosine similarity between query and all corpus vectors."""
        query_norm = query / np.linalg.norm(query)
        corpus_norm = corpus / np.linalg.norm(corpus, axis=1, keepdims=True)
        return np.dot(corpus_norm, query_norm)

    def explain_classification(self, text: str) -> dict[str, Any]:
        """
        Provide detailed explanation of classification decision.

        Useful for debugging and understanding model behavior.
        """
        if not self.enabled:
            return {"error": "GraphRAG classifier not enabled"}

        input_embedding = self._embedder.encode([text], convert_to_numpy=True)[0]

        # Get top-5 similar attacks and benign
        attack_sims = self._cosine_similarity_batch(input_embedding, self._attack_embeddings)
        benign_sims = self._cosine_similarity_batch(input_embedding, self._benign_embeddings)

        top_attack_idx = np.argsort(attack_sims)[-5:][::-1]
        top_benign_idx = np.argsort(benign_sims)[-5:][::-1]

        return {
            "input": text[:100],
            "avg_attack_similarity": float(np.mean(attack_sims[top_attack_idx])),
            "avg_benign_similarity": float(np.mean(benign_sims[top_benign_idx])),
            "max_attack_similarity": float(np.max(attack_sims)),
            "max_benign_similarity": float(np.max(benign_sims)),
            "top_similar_attacks": [
                {
                    "text": self._attack_texts[i][:80],
                    "category": self._attack_categories[i],
                    "similarity": round(float(attack_sims[i]), 4),
                }
                for i in top_attack_idx
            ],
            "top_similar_benign": [
                {
                    "text": self._benign_texts[i][:80],
                    "category": self._benign_categories[i],
                    "similarity": round(float(benign_sims[i]), 4),
                }
                for i in top_benign_idx
            ],
        }

    def refresh_data(self) -> bool:
        """
        Refresh data from Neo4j graph.

        Call this periodically to pick up new samples added to the graph.
        Returns True if refresh was successful.
        """
        logger.info("Refreshing GraphRAG classifier data from Neo4j...")
        old_attack_count = len(self._attack_texts)
        old_benign_count = len(self._benign_texts)

        try:
            self._load_data()

            new_attack_count = len(self._attack_texts)
            new_benign_count = len(self._benign_texts)

            logger.info(
                "GraphRAG data refreshed: attacks %d→%d, benign %d→%d",
                old_attack_count, new_attack_count,
                old_benign_count, new_benign_count
            )
            return self.enabled

        except Exception as e:
            logger.error("Failed to refresh GraphRAG data: %s", e)
            return False

    def get_stats(self) -> dict[str, Any]:
        """Get statistics about the classifier."""
        return {
            "enabled": self.enabled,
            "attack_samples": len(self._attack_texts),
            "benign_samples": len(self._benign_texts),
            "embedder": self.embedder_name,
            "confidence_threshold": self.confidence_threshold,
            "top_k": self.top_k,
        }
