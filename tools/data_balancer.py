"""
Data Balancer for InALign.

Addresses the critical issue: 1041 attack samples, 0 benign samples.
Without benign data, the model flags EVERYTHING as an attack.

This script:
1. Generates diverse benign samples (normal user questions)
2. Adds them to Neo4j as BenignSample nodes
3. Builds SIMILAR_TO relationships between related attacks using embeddings
4. Creates a balanced training dataset

Usage:
    python tools/data_balancer.py --add-benign --build-similarity
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import os
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

# Load environment
from dotenv import load_dotenv
load_dotenv()


# ---------------------------------------------------------------------------
# Benign Sample Categories - Real user questions that should NOT be blocked
# ---------------------------------------------------------------------------

BENIGN_SAMPLES = {
    "general_knowledge": [
        "What is the capital of France?",
        "How does photosynthesis work?",
        "Who wrote Romeo and Juliet?",
        "What's the distance from Earth to the Moon?",
        "Explain the theory of relativity.",
        "What causes earthquakes?",
        "How do vaccines work?",
        "What is the largest ocean on Earth?",
        "Who invented the telephone?",
        "What is the speed of light?",
    ],
    "coding_help": [
        "How do I reverse a string in Python?",
        "What's the difference between let and const in JavaScript?",
        "How do I connect to a PostgreSQL database?",
        "Explain async/await in Python.",
        "What is a REST API?",
        "How do I use Git branches?",
        "What's the time complexity of quicksort?",
        "How do I handle exceptions in Java?",
        "What is dependency injection?",
        "How do I write unit tests?",
        "Can you help me debug this function?",
        "What's the best way to parse JSON in Python?",
        "How do I create a Docker container?",
        "Explain the MVC pattern.",
        "What's the difference between SQL and NoSQL?",
    ],
    "business_professional": [
        "How do I write a professional email?",
        "What makes a good resume?",
        "Explain agile methodology.",
        "What are OKRs?",
        "How do I prepare for an interview?",
        "What is a business plan?",
        "How do I negotiate salary?",
        "What is project management?",
        "How do I give constructive feedback?",
        "What are best practices for remote work?",
    ],
    "creative_writing": [
        "Write a poem about spring.",
        "Help me brainstorm story ideas.",
        "What makes a good opening line?",
        "How do I develop a character?",
        "Write a haiku about coding.",
        "Help me come up with a company name.",
        "What rhymes with 'technology'?",
        "How do I overcome writer's block?",
        "Write a short story about a robot.",
        "What's the structure of a sonnet?",
    ],
    "everyday_tasks": [
        "What's the recipe for chocolate chip cookies?",
        "How do I remove a wine stain?",
        "What's the weather like today?",
        "How do I tie a tie?",
        "What's 15% tip on $85?",
        "How do I change a flat tire?",
        "What's a good workout routine?",
        "How do I meditate?",
        "What are some healthy breakfast ideas?",
        "How do I organize my closet?",
    ],
    "technical_questions": [
        "What is machine learning?",
        "How does encryption work?",
        "What is cloud computing?",
        "Explain blockchain technology.",
        "What is a neural network?",
        "How does WiFi work?",
        "What is an API endpoint?",
        "How do databases store data?",
        "What is containerization?",
        "Explain microservices architecture.",
        "What's the difference between TCP and UDP?",
        "How does HTTPS encryption work?",
        "What is a load balancer?",
        "How do CDNs work?",
        "What is serverless computing?",
    ],
    "system_questions_legitimate": [
        # These look like system questions but are legitimate
        "What's the upload size limit for this service?",
        "How do I reset my password?",
        "Can I access my account from mobile?",
        "What file formats are supported?",
        "How do notifications work in this app?",
        "What are the system requirements?",
        "How do I export my data?",
        "Is there a rate limit on the API?",
        "What permissions does this app need?",
        "How do I enable two-factor authentication?",
        "Can multiple users access the same account?",
        "What happens when my subscription expires?",
        "How do I change my notification settings?",
        "Is my data backed up automatically?",
        "What browsers are supported?",
    ],
    "korean": [
        "오늘 날씨 어때요?",
        "파이썬에서 리스트 정렬하는 방법 알려주세요.",
        "이력서 작성하는 팁 알려주세요.",
        "맛있는 파스타 레시피 추천해주세요.",
        "영어 공부하는 좋은 방법이 뭐예요?",
        "기계 학습이 뭔가요?",
        "좋은 아침 습관 추천해주세요.",
        "서울에서 가볼만한 곳 알려주세요.",
        "커피 대신 마실 수 있는 음료 추천해주세요.",
        "프로그래밍 처음 배우는데 어떤 언어가 좋을까요?",
        "재택근무할 때 생산성 높이는 방법 알려주세요.",
        "건강한 점심 메뉴 추천해주세요.",
        "운동 루틴 짜는 법 알려주세요.",
        "좋은 책 추천해주세요.",
        "면접 준비 어떻게 하면 좋을까요?",
    ],
    "japanese": [
        "今日の天気はどうですか？",
        "Pythonでリストをソートする方法を教えてください。",
        "おすすめの朝食レシピを教えてください。",
        "機械学習とは何ですか？",
        "効率的な勉強方法を教えてください。",
        "東京でおすすめの観光スポットはどこですか？",
        "プログラミングを始めるにはどの言語がいいですか？",
        "健康的な生活習慣について教えてください。",
        "日本語の敬語の使い方を教えてください。",
        "おすすめの本を教えてください。",
    ],
    "chinese": [
        "今天天气怎么样？",
        "请告诉我如何学习编程。",
        "有什么好的早餐推荐吗？",
        "机器学习是什么？",
        "如何提高工作效率？",
        "北京有什么好玩的地方？",
        "请推荐一些好书。",
        "如何保持健康的生活方式？",
        "学习英语的好方法是什么？",
        "如何写一份好的简历？",
    ],
    "spanish": [
        "¿Cómo está el clima hoy?",
        "¿Cómo puedo aprender a programar?",
        "¿Qué es el aprendizaje automático?",
        "¿Puedes recomendarme un buen libro?",
        "¿Cómo puedo mejorar mi inglés?",
        "¿Cuáles son buenos hábitos matutinos?",
        "¿Cómo preparo un buen café?",
        "¿Qué ejercicios son buenos para principiantes?",
        "¿Cómo puedo ser más productivo?",
        "¿Cuáles son los mejores lugares para visitar en España?",
    ],
    "edge_cases_benign": [
        # Questions that might trigger false positives but are legitimate
        "What security features does this product have?",
        "How do I protect my account from hackers?",
        "What are common cybersecurity threats?",
        "How do I create a strong password?",
        "What is penetration testing?",
        "How do companies protect user data?",
        "What is social engineering in security context?",
        "How do firewalls work?",
        "What is encryption and why is it important?",
        "How do I report a security vulnerability?",
        "What is ethical hacking?",
        "How do bug bounty programs work?",
        "What certifications are good for cybersecurity?",
        "How do I secure my home network?",
        "What is the principle of least privilege?",
    ],
}


@dataclass
class BenignSample:
    """A benign (safe) sample."""
    sample_id: str
    text: str
    category: str
    language: str
    source: str = "seed"
    created_at: str = ""


def generate_sample_id(text: str) -> str:
    """Generate a unique ID for a sample."""
    return hashlib.md5(text.encode()).hexdigest()[:16]


class DataBalancer:
    """Balances attack and benign data in Neo4j."""

    def __init__(self):
        from neo4j import AsyncGraphDatabase

        self.uri = os.getenv("NEO4J_URI")
        self.user = os.getenv("NEO4J_USER")
        self.password = os.getenv("NEO4J_PASSWORD")
        self.driver = AsyncGraphDatabase.driver(self.uri, auth=(self.user, self.password))

        # OpenAI for embeddings
        self.openai_key = os.getenv("OPENAI_API_KEY")

    async def close(self):
        await self.driver.close()

    async def add_benign_samples(self) -> dict[str, Any]:
        """Add all benign samples to Neo4j."""
        print("Adding benign samples to Neo4j...")

        total_added = 0
        by_category = {}

        async with self.driver.session() as session:
            for category, samples in BENIGN_SAMPLES.items():
                # Determine language
                lang = "en"
                if category == "korean":
                    lang = "ko"
                elif category == "japanese":
                    lang = "ja"
                elif category == "chinese":
                    lang = "zh"
                elif category == "spanish":
                    lang = "es"

                for text in samples:
                    sample_id = generate_sample_id(text)

                    query = """
                    MERGE (b:BenignSample {sample_id: $sample_id})
                    ON CREATE SET
                        b.text = $text,
                        b.category = $category,
                        b.language = $language,
                        b.source = 'seed',
                        b.created_at = datetime()
                    RETURN b.sample_id AS id
                    """

                    await session.run(query, {
                        "sample_id": sample_id,
                        "text": text,
                        "category": category,
                        "language": lang,
                    })

                    total_added += 1
                    by_category[category] = by_category.get(category, 0) + 1

        print(f"Added {total_added} benign samples")
        print("By category:")
        for cat, count in sorted(by_category.items()):
            print(f"  {cat}: {count}")

        return {"total": total_added, "by_category": by_category}

    async def generate_more_benign_gpt(self, n_per_category: int = 20) -> int:
        """Generate more benign samples using GPT."""
        from openai import AsyncOpenAI

        client = AsyncOpenAI(api_key=self.openai_key)
        total_added = 0

        categories = [
            ("coding_help", "legitimate programming questions"),
            ("technical_questions", "IT infrastructure and technology questions"),
            ("business_professional", "workplace and career questions"),
            ("system_questions_legitimate", "legitimate product/service usage questions"),
            ("everyday_tasks", "daily life questions and tasks"),
        ]

        for category, description in categories:
            print(f"Generating {n_per_category} benign samples for {category}...")

            prompt = f"""Generate {n_per_category} diverse, realistic user questions.
Category: {description}

Requirements:
- Must be completely legitimate, helpful questions
- Should be specific and realistic (what real users actually ask)
- Include some questions that might LOOK suspicious but are legitimate
- Mix of short and detailed questions
- Some should include technical terms

Output only a JSON array of question strings."""

            try:
                response = await client.chat.completions.create(
                    model="gpt-4o-mini",
                    messages=[
                        {"role": "system", "content": "You generate realistic user questions for testing an AI assistant."},
                        {"role": "user", "content": prompt},
                    ],
                    temperature=0.9,
                    max_tokens=2000,
                )

                content = response.choices[0].message.content.strip()
                if content.startswith("```"):
                    content = content.split("```")[1]
                    if content.startswith("json"):
                        content = content[4:]
                    content = content.strip()

                questions = json.loads(content)

                async with self.driver.session() as session:
                    for text in questions:
                        sample_id = generate_sample_id(text)
                        query = """
                        MERGE (b:BenignSample {sample_id: $sample_id})
                        ON CREATE SET
                            b.text = $text,
                            b.category = $category,
                            b.language = 'en',
                            b.source = 'gpt_generated',
                            b.created_at = datetime()
                        RETURN b.sample_id AS id
                        """
                        await session.run(query, {
                            "sample_id": sample_id,
                            "text": text,
                            "category": category,
                        })
                        total_added += 1

            except Exception as e:
                print(f"Error generating for {category}: {e}")

        print(f"Generated {total_added} additional benign samples")
        return total_added

    async def build_attack_similarity(self, similarity_threshold: float = 0.85) -> int:
        """Build SIMILAR_TO relationships between attacks using embeddings."""
        from openai import AsyncOpenAI
        import numpy as np

        print("Building attack similarity relationships...")
        client = AsyncOpenAI(api_key=self.openai_key)

        # Get all attack samples
        async with self.driver.session() as session:
            result = await session.run("""
                MATCH (a:AttackSample)
                WHERE a.category <> 'unknown'
                RETURN a.sample_id as id, a.text as text, a.category as cat
                LIMIT 500
            """)
            records = await result.data()

        if not records:
            print("No attack samples found")
            return 0

        print(f"Processing {len(records)} attack samples...")

        # Get embeddings in batches
        embeddings = {}
        batch_size = 50

        for i in range(0, len(records), batch_size):
            batch = records[i:i+batch_size]
            texts = [r["text"][:500] for r in batch]  # Truncate long texts

            try:
                response = await client.embeddings.create(
                    model="text-embedding-3-small",
                    input=texts,
                )

                for j, emb in enumerate(response.data):
                    sample_id = batch[j]["id"]
                    embeddings[sample_id] = np.array(emb.embedding)

                print(f"  Processed {min(i+batch_size, len(records))}/{len(records)} embeddings")

            except Exception as e:
                print(f"  Error getting embeddings: {e}")

        # Calculate similarities and create relationships
        sample_ids = list(embeddings.keys())
        relationships_created = 0

        async with self.driver.session() as session:
            for i, id1 in enumerate(sample_ids):
                for id2 in sample_ids[i+1:]:
                    # Cosine similarity
                    vec1 = embeddings[id1]
                    vec2 = embeddings[id2]
                    similarity = float(np.dot(vec1, vec2) / (np.linalg.norm(vec1) * np.linalg.norm(vec2)))

                    if similarity >= similarity_threshold:
                        query = """
                        MATCH (s1:AttackSample {sample_id: $id1})
                        MATCH (s2:AttackSample {sample_id: $id2})
                        MERGE (s1)-[r:SIMILAR_TO]-(s2)
                        ON CREATE SET r.similarity = $similarity, r.created_at = datetime()
                        ON MATCH SET r.similarity = $similarity
                        """
                        await session.run(query, {
                            "id1": id1,
                            "id2": id2,
                            "similarity": round(similarity, 4),
                        })
                        relationships_created += 1

                if (i + 1) % 50 == 0:
                    print(f"  Compared {i+1}/{len(sample_ids)} samples, {relationships_created} relationships")

        print(f"Created {relationships_created} SIMILAR_TO relationships")
        return relationships_created

    async def get_stats(self) -> dict[str, Any]:
        """Get current data statistics."""
        async with self.driver.session() as session:
            # Count nodes
            result = await session.run("""
                MATCH (n)
                RETURN labels(n)[0] as label, count(n) as count
                ORDER BY count DESC
            """)
            nodes = await result.data()

            # Count relationships
            result = await session.run("""
                MATCH ()-[r]->()
                RETURN type(r) as type, count(r) as count
                ORDER BY count DESC
            """)
            rels = await result.data()

        return {
            "nodes": {r["label"]: r["count"] for r in nodes},
            "relationships": {r["type"]: r["count"] for r in rels},
        }

    async def create_balanced_dataset(self, output_path: Path) -> dict[str, Any]:
        """Create a balanced training dataset from Neo4j data."""
        print("Creating balanced training dataset...")

        async with self.driver.session() as session:
            # Get attacks
            result = await session.run("""
                MATCH (a:AttackSample)
                RETURN a.text as text, a.category as category, 'attack' as label
            """)
            attacks = await result.data()

            # Get benign
            result = await session.run("""
                MATCH (b:BenignSample)
                RETURN b.text as text, b.category as category, 'benign' as label
            """)
            benign = await result.data()

        # Balance the dataset
        min_count = min(len(attacks), len(benign))

        import random
        random.shuffle(attacks)
        random.shuffle(benign)

        balanced = attacks[:min_count] + benign[:min_count]
        random.shuffle(balanced)

        # Save as JSONL
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as f:
            for sample in balanced:
                f.write(json.dumps(sample, ensure_ascii=False) + "\n")

        stats = {
            "total_samples": len(balanced),
            "attacks": min_count,
            "benign": min_count,
            "output_file": str(output_path),
        }

        print(f"Created balanced dataset: {stats}")
        return stats


async def main():
    import argparse

    parser = argparse.ArgumentParser(description="Balance attack/benign data in Neo4j")
    parser.add_argument("--add-benign", action="store_true", help="Add seed benign samples")
    parser.add_argument("--generate-benign", type=int, default=0, help="Generate N more benign per category with GPT")
    parser.add_argument("--build-similarity", action="store_true", help="Build SIMILAR_TO relationships")
    parser.add_argument("--similarity-threshold", type=float, default=0.85, help="Similarity threshold (default: 0.85)")
    parser.add_argument("--create-dataset", type=str, help="Create balanced dataset at path")
    parser.add_argument("--stats", action="store_true", help="Show current stats")
    args = parser.parse_args()

    balancer = DataBalancer()

    try:
        if args.stats or not any([args.add_benign, args.generate_benign, args.build_similarity, args.create_dataset]):
            stats = await balancer.get_stats()
            print("\nCurrent Data Statistics:")
            print("-" * 40)
            print("Nodes:")
            for label, count in stats["nodes"].items():
                print(f"  {label}: {count}")
            print("\nRelationships:")
            for rel_type, count in stats["relationships"].items():
                print(f"  {rel_type}: {count}")

        if args.add_benign:
            await balancer.add_benign_samples()

        if args.generate_benign > 0:
            await balancer.generate_more_benign_gpt(args.generate_benign)

        if args.build_similarity:
            await balancer.build_attack_similarity(args.similarity_threshold)

        if args.create_dataset:
            await balancer.create_balanced_dataset(Path(args.create_dataset))

    finally:
        await balancer.close()


if __name__ == "__main__":
    asyncio.run(main())
