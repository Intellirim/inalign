#!/usr/bin/env python
"""
Smart Graph Enhancement - 의미 있는 관계만 구축.

1. 임베딩 기반 유사도로 SIMILAR_TO 연결 (threshold 0.85+)
2. 공격 기법(technique) 기반 그룹화
3. LLM으로 카테고리 자동 분류
4. 무의미한 연결은 제거
"""
import asyncio
import os
import sys
from pathlib import Path
from typing import Any
import numpy as np

sys.path.insert(0, str(Path(__file__).parent.parent))

# Similarity threshold - 높을수록 엄격
SIMILARITY_THRESHOLD = 0.85

# Attack technique groups (MITRE ATT&CK inspired)
TECHNIQUE_GROUPS = {
    "T001_instruction_override": {
        "name": "Instruction Override",
        "patterns": ["ignore", "forget", "disregard", "override", "bypass"],
        "description": "Attempts to override system instructions",
    },
    "T002_system_extraction": {
        "name": "System Prompt Extraction",
        "patterns": ["system prompt", "initial instruction", "reveal", "show me your"],
        "description": "Attempts to extract system prompts",
    },
    "T003_jailbreak": {
        "name": "Jailbreak",
        "patterns": ["dan", "jailbreak", "no restrictions", "developer mode", "evil mode"],
        "description": "Jailbreak attempts to remove safety guardrails",
    },
    "T004_roleplay": {
        "name": "Roleplay Attack",
        "patterns": ["pretend", "act as", "you are now", "roleplay", "imagine you"],
        "description": "Uses roleplay to bypass restrictions",
    },
    "T005_encoding": {
        "name": "Encoding Evasion",
        "patterns": ["base64", "rot13", "decode", "hex", "encode"],
        "description": "Uses encoding to evade detection",
    },
    "T006_data_exfil": {
        "name": "Data Exfiltration",
        "patterns": ["password", "api key", "secret", "credentials", "token"],
        "description": "Attempts to extract sensitive data",
    },
    "T007_code_injection": {
        "name": "Code Injection",
        "patterns": ["eval(", "exec(", "run code", "execute", "__import__"],
        "description": "Attempts to execute arbitrary code",
    },
}


async def get_neo4j_driver():
    """Get Neo4j driver."""
    from neo4j import AsyncGraphDatabase

    uri = os.getenv("NEO4J_URI", "***REDACTED_URI***")
    user = os.getenv("NEO4J_USER", "neo4j")
    password = os.getenv("NEO4J_PASSWORD")

    if not password:
        env_path = Path(__file__).parent.parent / ".env"
        if env_path.exists():
            with open(env_path) as f:
                for line in f:
                    if line.startswith("NEO4J_PASSWORD="):
                        password = line.split("=", 1)[1].strip()
                        break

    driver = AsyncGraphDatabase.driver(uri, auth=(user, password))
    await driver.verify_connectivity()
    return driver


def get_embedder():
    """Load sentence transformer for semantic similarity."""
    from sentence_transformers import SentenceTransformer
    return SentenceTransformer("all-MiniLM-L6-v2")


def classify_technique(text: str) -> list[str]:
    """Classify attack into technique groups."""
    text_lower = text.lower()
    matched = []

    for tech_id, tech_info in TECHNIQUE_GROUPS.items():
        for pattern in tech_info["patterns"]:
            if pattern in text_lower:
                matched.append(tech_id)
                break

    return matched


async def enhance_graph_smart():
    """Smart graph enhancement with meaningful relationships."""
    driver = await get_neo4j_driver()
    print("[OK] Connected to Neo4j")

    # Load embedder
    print("\n[1] Loading sentence embedder...")
    embedder = get_embedder()
    print("    Loaded all-MiniLM-L6-v2")

    stats = {
        "techniques_linked": 0,
        "similar_pairs_found": 0,
        "weak_links_removed": 0,
    }

    try:
        async with driver.session() as session:
            # Step 1: Create Technique nodes
            print("\n[2] Creating Attack Technique nodes...")
            for tech_id, tech_info in TECHNIQUE_GROUPS.items():
                await session.run("""
                    MERGE (t:AttackTechnique {id: $id})
                    SET t.name = $name,
                        t.description = $description,
                        t.patterns = $patterns
                """, {
                    "id": tech_id,
                    "name": tech_info["name"],
                    "description": tech_info["description"],
                    "patterns": tech_info["patterns"],
                })
            print(f"    Created {len(TECHNIQUE_GROUPS)} technique nodes")

            # Step 2: Link samples to techniques
            print("\n[3] Linking samples to techniques...")
            result = await session.run("""
                MATCH (a:AttackSample)
                RETURN a.text as text, elementId(a) as id
            """)
            samples = await result.data()
            print(f"    Processing {len(samples)} samples...")

            for sample in samples:
                text = sample.get("text", "")
                node_id = sample.get("id")

                if not text:
                    continue

                techniques = classify_technique(text)
                for tech_id in techniques:
                    await session.run("""
                        MATCH (a:AttackSample) WHERE elementId(a) = $id
                        MATCH (t:AttackTechnique {id: $tech_id})
                        MERGE (a)-[:USES_TECHNIQUE]->(t)
                    """, {"id": node_id, "tech_id": tech_id})
                    stats["techniques_linked"] += 1

            print(f"    Created {stats['techniques_linked']} technique links")

            # Step 3: Build semantic similarity (batch processing)
            print("\n[4] Computing semantic similarity...")

            # Get samples in batches
            result = await session.run("""
                MATCH (a:AttackSample)
                WHERE a.text IS NOT NULL
                RETURN a.text as text, elementId(a) as id
                LIMIT 500
            """)
            all_samples = await result.data()

            if len(all_samples) < 2:
                print("    Not enough samples for similarity")
            else:
                texts = [s["text"] for s in all_samples]
                ids = [s["id"] for s in all_samples]

                # Compute embeddings in batch
                print(f"    Computing embeddings for {len(texts)} samples...")
                embeddings = embedder.encode(texts, convert_to_numpy=True)

                # Compute similarity matrix (optimized)
                print("    Computing similarity matrix...")
                from sklearn.metrics.pairwise import cosine_similarity
                sim_matrix = cosine_similarity(embeddings)

                # Find high-similarity pairs
                print(f"    Finding pairs with similarity >= {SIMILARITY_THRESHOLD}...")
                pairs_to_create = []
                for i in range(len(sim_matrix)):
                    for j in range(i + 1, len(sim_matrix)):
                        if sim_matrix[i][j] >= SIMILARITY_THRESHOLD:
                            pairs_to_create.append({
                                "id1": ids[i],
                                "id2": ids[j],
                                "similarity": float(sim_matrix[i][j]),
                            })

                print(f"    Found {len(pairs_to_create)} high-similarity pairs")

                # Create relationships in batch
                for pair in pairs_to_create[:200]:  # Limit to prevent timeout
                    await session.run("""
                        MATCH (a1:AttackSample) WHERE elementId(a1) = $id1
                        MATCH (a2:AttackSample) WHERE elementId(a2) = $id2
                        MERGE (a1)-[r:SIMILAR_TO]-(a2)
                        SET r.similarity = $similarity,
                            r.method = 'semantic_embedding'
                    """, pair)
                    stats["similar_pairs_found"] += 1

            # Step 4: Remove weak/meaningless links
            print("\n[5] Removing weak links...")
            result = await session.run("""
                MATCH ()-[r:SIMILAR_TO]-()
                WHERE r.similarity IS NOT NULL AND r.similarity < $threshold
                DELETE r
                RETURN count(r) as removed
            """, {"threshold": SIMILARITY_THRESHOLD})
            removed = await result.single()
            stats["weak_links_removed"] = removed["removed"] if removed else 0
            print(f"    Removed {stats['weak_links_removed']} weak links")

            # Final report
            print("\n" + "=" * 60)
            print("SMART GRAPH ENHANCEMENT COMPLETE")
            print("=" * 60)

            # Get final stats
            result = await session.run("""
                MATCH (a:AttackSample)
                OPTIONAL MATCH (a)-[r]-()
                WITH a, count(r) as rels
                RETURN
                    count(a) as total,
                    sum(CASE WHEN rels > 0 THEN 1 ELSE 0 END) as connected,
                    sum(CASE WHEN rels = 0 THEN 1 ELSE 0 END) as orphaned
            """)
            final = await result.single()

            total = final["total"]
            connected = final["connected"]

            print(f"\nFinal Graph Status:")
            print(f"  Total samples: {total}")
            print(f"  Connected: {connected} ({100*connected/max(total,1):.1f}%)")

            print(f"\nMeaningful Relationships Created:")
            print(f"  Technique links: {stats['techniques_linked']}")
            print(f"  High-similarity pairs: {stats['similar_pairs_found']}")
            print(f"  Weak links removed: {stats['weak_links_removed']}")

            # Show technique distribution
            result = await session.run("""
                MATCH (t:AttackTechnique)<-[:USES_TECHNIQUE]-(a:AttackSample)
                RETURN t.name as technique, count(a) as count
                ORDER BY count DESC
            """)
            tech_dist = await result.data()
            if tech_dist:
                print(f"\nTechnique Distribution:")
                for t in tech_dist:
                    print(f"  {t['technique']}: {t['count']} samples")

    finally:
        await driver.close()


if __name__ == "__main__":
    asyncio.run(enhance_graph_smart())
