"""
Graph Auto-Labeler - 탐지 결과를 고품질 데이터로 그래프에 저장.

테스트/탐지 결과를 자동으로:
1. AttackSample / BenignSample 노드로 저장
2. 관련 Technique, Signature와 연결
3. 유사한 기존 샘플과 SIMILAR_TO 연결
"""
from __future__ import annotations

import asyncio
import logging
import os
from datetime import datetime
from typing import Any, Optional

logger = logging.getLogger("inalign.graph_labeler")

# Technique mapping from detection patterns
PATTERN_TO_TECHNIQUE = {
    "INJ-001": "T001_instruction_override",
    "INJ-002": "T002_system_extraction",
    "INJ-003": "T002_system_extraction",
    "INJ-010": "T003_jailbreak",
    "INJ-011": "T003_jailbreak",
    "INJ-020": "T004_roleplay",
    "INJ-030": "T005_encoding",
    "INJ-040": "T006_data_exfil",
    "INJ-050": "T007_code_injection",
    "INJ-420": "T007_code_injection",
    "INJ-421": "T005_encoding",
    "INJ-422": "T004_roleplay",
    "INJ-423": "T004_roleplay",
    "INJ-424": "T005_encoding",
    "INJ-425": "T006_data_exfil",
}


class GraphLabeler:
    """
    Automatically labels and stores detection results in Neo4j graph.

    Usage:
        labeler = GraphLabeler()
        await labeler.connect()

        # After detection
        await labeler.store_attack(
            text="Ignore all instructions",
            threats=[...],
            confidence=0.95,
            category="instruction_override",
        )

        # After benign classification
        await labeler.store_benign(
            text="What's the weather?",
            confidence=0.99,
            category="general_question",
        )
    """

    def __init__(self):
        self._driver = None
        self._embedder = None

    async def connect(self) -> bool:
        """Connect to Neo4j."""
        try:
            from neo4j import AsyncGraphDatabase

            uri = os.getenv("NEO4J_URI")
            user = os.getenv("NEO4J_USER", "neo4j")
            password = os.getenv("NEO4J_PASSWORD")

            if not uri or not password:
                logger.warning("Neo4j credentials not configured")
                return False

            self._driver = AsyncGraphDatabase.driver(uri, auth=(user, password))
            await self._driver.verify_connectivity()
            logger.info("GraphLabeler connected to Neo4j")
            return True

        except Exception as e:
            logger.warning(f"Failed to connect to Neo4j: {e}")
            return False

    async def disconnect(self):
        """Disconnect from Neo4j."""
        if self._driver:
            await self._driver.close()
            self._driver = None

    def _get_embedder(self):
        """Lazy load embedder."""
        if self._embedder is None:
            try:
                from sentence_transformers import SentenceTransformer
                self._embedder = SentenceTransformer("all-MiniLM-L6-v2")
            except Exception:
                pass
        return self._embedder

    async def store_attack(
        self,
        text: str,
        threats: list[dict[str, Any]],
        confidence: float,
        category: Optional[str] = None,
        source: str = "detection",
    ) -> Optional[str]:
        """
        Store attack sample in graph.

        Parameters
        ----------
        text : str
            The attack prompt text
        threats : list
            List of detected threats from scanner
        confidence : float
            Detection confidence (0-1)
        category : str, optional
            Attack category
        source : str
            Source of this sample (detection, manual, test)

        Returns
        -------
        str or None
            Node ID if successful
        """
        if not self._driver or confidence < 0.85:
            # Only store high-confidence detections
            return None

        try:
            async with self._driver.session() as session:
                # Determine category from threats if not provided
                if not category:
                    for threat in threats:
                        pattern_id = threat.get("pattern_id", "")
                        if pattern_id.startswith("INJ-"):
                            category = self._categorize_from_pattern(pattern_id)
                            break
                    if not category:
                        category = "unknown"

                # Create attack sample node
                result = await session.run("""
                    CREATE (a:AttackSample {
                        text: $text,
                        category: $category,
                        confidence: $confidence,
                        source: $source,
                        created_at: datetime(),
                        threat_count: $threat_count
                    })
                    RETURN elementId(a) as id
                """, {
                    "text": text,
                    "category": category,
                    "confidence": confidence,
                    "source": source,
                    "threat_count": len(threats),
                })
                record = await result.single()
                node_id = record["id"] if record else None

                if not node_id:
                    return None

                # Link to signatures
                for threat in threats:
                    pattern_id = threat.get("pattern_id")
                    if pattern_id:
                        await session.run("""
                            MATCH (a:AttackSample) WHERE elementId(a) = $id
                            MERGE (s:AttackSignature {pattern_id: $pattern_id})
                            MERGE (a)-[:DETECTED_BY]->(s)
                        """, {"id": node_id, "pattern_id": pattern_id})

                        # Link to technique
                        technique = PATTERN_TO_TECHNIQUE.get(pattern_id)
                        if technique:
                            await session.run("""
                                MATCH (a:AttackSample) WHERE elementId(a) = $id
                                MERGE (t:AttackTechnique {id: $tech_id})
                                MERGE (a)-[:USES_TECHNIQUE]->(t)
                            """, {"id": node_id, "tech_id": technique})

                # Find similar samples
                await self._link_similar(session, node_id, text, is_attack=True)

                logger.debug(f"Stored attack sample: {text[:50]}...")
                return node_id

        except Exception as e:
            logger.warning(f"Failed to store attack: {e}")
            return None

    async def store_benign(
        self,
        text: str,
        confidence: float,
        category: Optional[str] = None,
        source: str = "detection",
    ) -> Optional[str]:
        """Store benign sample in graph."""
        if not self._driver or confidence < 0.9:
            # Only store very high-confidence benign
            return None

        try:
            async with self._driver.session() as session:
                if not category:
                    category = self._categorize_benign(text)

                result = await session.run("""
                    CREATE (b:BenignSample {
                        text: $text,
                        category: $category,
                        confidence: $confidence,
                        source: $source,
                        created_at: datetime()
                    })
                    RETURN elementId(b) as id
                """, {
                    "text": text,
                    "category": category,
                    "confidence": confidence,
                    "source": source,
                })
                record = await result.single()
                node_id = record["id"] if record else None

                if node_id:
                    # Link to category
                    await session.run("""
                        MATCH (b:BenignSample) WHERE elementId(b) = $id
                        MERGE (c:BenignCategory {name: $category})
                        MERGE (b)-[:BELONGS_TO]->(c)
                    """, {"id": node_id, "category": category})

                    logger.debug(f"Stored benign sample: {text[:50]}...")

                return node_id

        except Exception as e:
            logger.warning(f"Failed to store benign: {e}")
            return None

    async def _link_similar(
        self,
        session,
        node_id: str,
        text: str,
        is_attack: bool,
        threshold: float = 0.88,
    ):
        """Link to similar existing samples using embeddings."""
        embedder = self._get_embedder()
        if not embedder:
            return

        try:
            # Get embedding for new text
            new_embedding = embedder.encode([text], convert_to_numpy=True)[0]

            # Get recent samples of same type
            label = "AttackSample" if is_attack else "BenignSample"
            result = await session.run(f"""
                MATCH (s:{label})
                WHERE s.embedding IS NOT NULL AND elementId(s) <> $id
                RETURN elementId(s) as id, s.embedding as embedding
                ORDER BY s.created_at DESC
                LIMIT 50
            """, {"id": node_id})
            existing = await result.data()

            # Compare similarities
            for sample in existing:
                existing_emb = sample.get("embedding")
                if existing_emb:
                    import numpy as np
                    existing_emb = np.array(existing_emb)
                    similarity = np.dot(new_embedding, existing_emb) / (
                        np.linalg.norm(new_embedding) * np.linalg.norm(existing_emb)
                    )

                    if similarity >= threshold:
                        await session.run("""
                            MATCH (a) WHERE elementId(a) = $id1
                            MATCH (b) WHERE elementId(b) = $id2
                            MERGE (a)-[r:SIMILAR_TO]-(b)
                            SET r.similarity = $sim, r.method = 'semantic'
                        """, {
                            "id1": node_id,
                            "id2": sample["id"],
                            "sim": float(similarity),
                        })

            # Store embedding for future comparisons
            await session.run(f"""
                MATCH (s:{label}) WHERE elementId(s) = $id
                SET s.embedding = $embedding
            """, {"id": node_id, "embedding": new_embedding.tolist()})

        except Exception as e:
            logger.warning(f"Failed to link similar: {e}")

    def _categorize_from_pattern(self, pattern_id: str) -> str:
        """Categorize attack from pattern ID."""
        mapping = {
            "INJ-001": "instruction_override",
            "INJ-002": "system_extraction",
            "INJ-003": "system_extraction",
            "INJ-010": "jailbreak",
            "INJ-011": "jailbreak",
            "INJ-020": "roleplay_attack",
            "INJ-030": "encoding_evasion",
            "INJ-040": "data_extraction",
            "INJ-050": "code_injection",
        }
        return mapping.get(pattern_id, "unknown")

    def _categorize_benign(self, text: str) -> str:
        """Categorize benign prompt."""
        text_lower = text.lower()

        if any(w in text_lower for w in ["weather", "time", "date"]):
            return "general_question"
        if any(w in text_lower for w in ["code", "function", "program", "debug"]):
            return "coding_help"
        if any(w in text_lower for w in ["write", "story", "poem", "creative"]):
            return "creative_writing"
        if any(w in text_lower for w in ["explain", "how", "what is", "why"]):
            return "explanation"
        if any(w in text_lower for w in ["help", "assist", "can you"]):
            return "assistance_request"

        return "general"


# Global instance
_labeler: Optional[GraphLabeler] = None


async def get_graph_labeler() -> GraphLabeler:
    """Get or create the global graph labeler."""
    global _labeler
    if _labeler is None:
        _labeler = GraphLabeler()
        await _labeler.connect()
    return _labeler
