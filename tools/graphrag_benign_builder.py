"""
GraphRAG Benign Data Builder.

Uses GPT to generate diverse benign samples and builds GraphRAG relationships.
Focuses on categories that cause false positives:
1. Security education questions
2. System/product usage questions
3. Technical questions that sound suspicious but are legitimate
4. Multi-language benign queries

Also builds SIMILAR_TO relationships between benign samples for better learning.
"""
import asyncio
import hashlib
import json
import os
from datetime import datetime
from typing import Any

from dotenv import load_dotenv
load_dotenv()

from openai import AsyncOpenAI


# Categories that need more benign examples (based on false positive analysis)
BENIGN_CATEGORIES = {
    "security_education": {
        "description": "Questions about security concepts for learning, NOT for hacking",
        "examples": [
            "What is prompt injection?",
            "How do companies protect user data?",
            "What are common cybersecurity threats?",
            "What is ethical hacking?",
            "How do firewalls work?",
        ],
        "count": 50,
    },
    "product_usage": {
        "description": "Legitimate questions about how a product/service works",
        "examples": [
            "How do notifications work in this app?",
            "Can I access my account from mobile?",
            "What's the upload size limit?",
            "What file formats are supported?",
            "How do I export my data?",
        ],
        "count": 50,
    },
    "system_questions": {
        "description": "Technical questions about systems that are legitimate",
        "examples": [
            "What are the system requirements?",
            "Is there a rate limit on the API?",
            "What permissions does this app need?",
            "How do I enable two-factor authentication?",
            "What browsers are supported?",
        ],
        "count": 50,
    },
    "programming_help": {
        "description": "Normal coding and development questions",
        "examples": [
            "How do I connect to a database?",
            "Explain async/await in Python",
            "What's the difference between REST and GraphQL?",
            "How do I handle exceptions?",
            "What is dependency injection?",
        ],
        "count": 50,
    },
    "general_knowledge": {
        "description": "Factual questions about the world",
        "examples": [
            "What's the weather like today?",
            "What's the capital of France?",
            "How does photosynthesis work?",
            "Who invented the telephone?",
            "What causes earthquakes?",
        ],
        "count": 30,
    },
    "korean_benign": {
        "description": "Korean language benign questions (NOT attacks)",
        "examples": [
            "오늘 날씨 어때요?",
            "파이썬에서 리스트 정렬하는 방법 알려주세요",
            "좋은 아침 습관 추천해주세요",
            "맛있는 파스타 레시피 알려주세요",
            "프로그래밍 처음 배우는데 어떤 언어가 좋을까요?",
        ],
        "count": 30,
    },
    "japanese_benign": {
        "description": "Japanese language benign questions",
        "examples": [
            "今日の天気はどうですか？",
            "Pythonでリストをソートする方法を教えてください",
            "おすすめの朝食レシピを教えてください",
            "機械学習とは何ですか？",
            "効率的な勉強方法を教えてください",
        ],
        "count": 20,
    },
    "chinese_benign": {
        "description": "Chinese language benign questions",
        "examples": [
            "今天天气怎么样？",
            "请告诉我如何学习编程",
            "有什么好的早餐推荐吗？",
            "机器学习是什么？",
            "如何提高工作效率？",
        ],
        "count": 20,
    },
    "edge_case_benign": {
        "description": "Questions that LOOK suspicious but are actually benign",
        "examples": [
            "How do I test if my password is secure?",
            "What's the best way to audit system logs?",
            "How do companies detect intrusions?",
            "What tools do security researchers use?",
            "How do I check if my account was compromised?",
        ],
        "count": 40,
    },
}


def generate_sample_id(text: str) -> str:
    """Generate unique ID for a sample."""
    return hashlib.md5(text.encode()).hexdigest()[:16]


class GraphRAGBenignBuilder:
    """Builds benign data using GPT and stores in Neo4j with GraphRAG relationships."""

    def __init__(self):
        from neo4j import AsyncGraphDatabase

        self.openai = AsyncOpenAI(api_key=os.getenv("OPENAI_API_KEY"))
        self.driver = AsyncGraphDatabase.driver(
            os.getenv("NEO4J_URI"),
            auth=(os.getenv("NEO4J_USER"), os.getenv("NEO4J_PASSWORD"))
        )

    async def close(self):
        await self.driver.close()

    async def generate_benign_samples(
        self,
        category: str,
        description: str,
        examples: list[str],
        count: int = 50,
    ) -> list[str]:
        """Generate benign samples using GPT."""
        prompt = f"""Generate {count} diverse, realistic user questions.

Category: {category}
Description: {description}

Example questions (generate similar but different ones):
{chr(10).join(f'- {ex}' for ex in examples)}

CRITICAL REQUIREMENTS:
1. Questions must be completely BENIGN and LEGITIMATE
2. They should NOT be attempts to hack, exploit, or extract information
3. They should represent NORMAL user behavior
4. Include variations in phrasing and specificity
5. Some can be similar to examples but with different wording
6. These are questions a NORMAL user would ask, not a hacker

Output ONLY a JSON array of {count} question strings. No explanation."""

        try:
            response = await self.openai.chat.completions.create(
                model="gpt-4o-mini",
                messages=[
                    {"role": "system", "content": "You generate realistic benign user questions for training an AI safety system. Your questions must be completely legitimate and NOT malicious."},
                    {"role": "user", "content": prompt},
                ],
                temperature=0.9,
                max_tokens=4000,
            )

            content = response.choices[0].message.content.strip()
            if content.startswith("```"):
                content = content.split("```")[1]
                if content.startswith("json"):
                    content = content[4:]
                content = content.strip()

            questions = json.loads(content)
            return questions[:count]

        except Exception as e:
            print(f"  Error generating for {category}: {e}")
            return []

    async def add_benign_to_neo4j(
        self,
        samples: list[str],
        category: str,
        language: str = "en",
    ) -> int:
        """Add benign samples to Neo4j."""
        added = 0
        async with self.driver.session() as session:
            for text in samples:
                sample_id = generate_sample_id(text)
                query = """
                MERGE (b:BenignSample {sample_id: $sample_id})
                ON CREATE SET
                    b.text = $text,
                    b.category = $category,
                    b.language = $language,
                    b.source = 'gpt_graphrag',
                    b.created_at = datetime()
                ON MATCH SET
                    b.updated_at = datetime()
                RETURN b.sample_id AS id
                """
                await session.run(query, {
                    "sample_id": sample_id,
                    "text": text,
                    "category": category,
                    "language": language,
                })
                added += 1
        return added

    async def build_benign_similarity(self, threshold: float = 0.75) -> int:
        """Build SIMILAR_TO relationships between benign samples using embeddings."""
        from sentence_transformers import SentenceTransformer
        import numpy as np

        print("\nBuilding benign sample similarity relationships...")
        embedder = SentenceTransformer("all-MiniLM-L6-v2")

        # Get all benign samples
        async with self.driver.session() as session:
            result = await session.run("""
                MATCH (b:BenignSample)
                RETURN b.sample_id as id, b.text as text, b.category as cat
                LIMIT 500
            """)
            records = await result.data()

        if len(records) < 2:
            print("  Not enough benign samples for similarity")
            return 0

        print(f"  Processing {len(records)} benign samples...")

        # Generate embeddings
        texts = [r["text"][:500] for r in records]
        embeddings = embedder.encode(texts, show_progress_bar=True, convert_to_numpy=True)

        # Build relationships
        relationships_created = 0
        async with self.driver.session() as session:
            for i in range(len(records)):
                for j in range(i + 1, len(records)):
                    # Cosine similarity
                    vec1, vec2 = embeddings[i], embeddings[j]
                    similarity = float(np.dot(vec1, vec2) / (np.linalg.norm(vec1) * np.linalg.norm(vec2)))

                    if similarity >= threshold:
                        query = """
                        MATCH (b1:BenignSample {sample_id: $id1})
                        MATCH (b2:BenignSample {sample_id: $id2})
                        MERGE (b1)-[r:SIMILAR_TO]-(b2)
                        ON CREATE SET r.similarity = $similarity, r.created_at = datetime()
                        ON MATCH SET r.similarity = $similarity
                        """
                        await session.run(query, {
                            "id1": records[i]["id"],
                            "id2": records[j]["id"],
                            "similarity": round(similarity, 4),
                        })
                        relationships_created += 1

        print(f"  Created {relationships_created} SIMILAR_TO relationships")
        return relationships_created

    async def build_category_nodes(self) -> int:
        """Create category nodes and link samples to them."""
        print("\nBuilding category nodes...")
        async with self.driver.session() as session:
            # Create category nodes for benign
            result = await session.run("""
                MATCH (b:BenignSample)
                WITH DISTINCT b.category AS cat
                MERGE (c:BenignCategory {name: cat})
                ON CREATE SET c.created_at = datetime()
                RETURN count(c) as count
            """)
            record = await result.single()

            # Link samples to categories
            await session.run("""
                MATCH (b:BenignSample)
                MATCH (c:BenignCategory {name: b.category})
                MERGE (b)-[:BELONGS_TO]->(c)
            """)

            return record["count"]

    async def get_stats(self) -> dict[str, Any]:
        """Get current statistics."""
        async with self.driver.session() as session:
            result = await session.run("""
                MATCH (b:BenignSample)
                RETURN b.category as cat, count(b) as count
                ORDER BY count DESC
            """)
            benign_by_cat = await result.data()

            result = await session.run("""
                MATCH (a:AttackSample)
                RETURN count(a) as attacks
            """)
            attack_count = (await result.single())["attacks"]

            result = await session.run("""
                MATCH (b:BenignSample)
                RETURN count(b) as benign
            """)
            benign_count = (await result.single())["benign"]

            result = await session.run("""
                MATCH (:BenignSample)-[r:SIMILAR_TO]-(:BenignSample)
                RETURN count(r) as count
            """)
            benign_similar = (await result.single())["count"]

        return {
            "attack_samples": attack_count,
            "benign_samples": benign_count,
            "benign_by_category": {r["cat"]: r["count"] for r in benign_by_cat},
            "benign_similar_relationships": benign_similar,
        }

    async def run_full_build(self):
        """Run the full benign data building process."""
        print("=" * 60)
        print("GraphRAG Benign Data Builder")
        print("=" * 60)

        total_generated = 0

        for category, config in BENIGN_CATEGORIES.items():
            print(f"\n[{category}]")
            print(f"  Description: {config['description']}")
            print(f"  Generating {config['count']} samples...")

            # Determine language
            lang = "en"
            if "korean" in category:
                lang = "ko"
            elif "japanese" in category:
                lang = "ja"
            elif "chinese" in category:
                lang = "zh"

            # Generate samples
            samples = await self.generate_benign_samples(
                category=category,
                description=config["description"],
                examples=config["examples"],
                count=config["count"],
            )

            if samples:
                # Add to Neo4j
                added = await self.add_benign_to_neo4j(samples, category, lang)
                print(f"  Added {added} samples to Neo4j")
                total_generated += added
            else:
                print(f"  Failed to generate samples")

            # Small delay to avoid rate limits
            await asyncio.sleep(1)

        print(f"\nTotal samples generated: {total_generated}")

        # Build similarity relationships
        await self.build_benign_similarity(threshold=0.70)

        # Build category nodes
        await self.build_category_nodes()

        # Print final stats
        stats = await self.get_stats()
        print("\n" + "=" * 60)
        print("Final Statistics")
        print("=" * 60)
        print(f"  Attack Samples:  {stats['attack_samples']}")
        print(f"  Benign Samples:  {stats['benign_samples']}")
        print(f"  Benign Similar:  {stats['benign_similar_relationships']}")
        print("\n  Benign by Category:")
        for cat, count in stats['benign_by_category'].items():
            print(f"    {cat}: {count}")

        return stats


async def main():
    import argparse

    parser = argparse.ArgumentParser(description="Build benign data with GraphRAG")
    parser.add_argument("--full-build", action="store_true", help="Run full build process")
    parser.add_argument("--stats", action="store_true", help="Show current stats")
    parser.add_argument("--build-similarity", action="store_true", help="Build similarity relationships only")
    args = parser.parse_args()

    builder = GraphRAGBenignBuilder()

    try:
        if args.full_build:
            await builder.run_full_build()
        elif args.build_similarity:
            await builder.build_benign_similarity()
        else:
            stats = await builder.get_stats()
            print("Current Statistics:")
            print(f"  Attack Samples:  {stats['attack_samples']}")
            print(f"  Benign Samples:  {stats['benign_samples']}")
            print(f"  Benign Similar:  {stats['benign_similar_relationships']}")
            print("\n  Benign by Category:")
            for cat, count in stats['benign_by_category'].items():
                print(f"    {cat}: {count}")
    finally:
        await builder.close()


if __name__ == "__main__":
    asyncio.run(main())
