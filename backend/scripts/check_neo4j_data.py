#!/usr/bin/env python
"""Check Neo4j Aura data for training."""
import asyncio
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

async def check_neo4j():
    from neo4j import AsyncGraphDatabase

    uri = os.getenv("NEO4J_URI", "***REDACTED_URI***")
    user = os.getenv("NEO4J_USER", "neo4j")
    password = os.getenv("NEO4J_PASSWORD")

    if not password:
        # Try loading from .env
        env_path = Path(__file__).parent.parent / ".env"
        if env_path.exists():
            with open(env_path) as f:
                for line in f:
                    if line.startswith("NEO4J_PASSWORD="):
                        password = line.split("=", 1)[1].strip()
                        break

    print(f"Connecting to: {uri}")

    driver = AsyncGraphDatabase.driver(uri, auth=(user, password))

    try:
        await driver.verify_connectivity()
        print("[OK] Connected to Neo4j Aura!\n")

        async with driver.session() as session:
            # Count all node types
            result = await session.run("""
                CALL db.labels() YIELD label
                CALL apoc.cypher.run('MATCH (n:`' + label + '`) RETURN count(n) as count', {}) YIELD value
                RETURN label, value.count as count
            """)
            records = await result.data()

            if not records:
                # Fallback if APOC not available
                result = await session.run("MATCH (n) RETURN labels(n)[0] as label, count(*) as count GROUP BY labels(n)[0]")
                records = await result.data()

            print("=" * 50)
            print("NEO4J DATA SUMMARY")
            print("=" * 50)

            total = 0
            for record in records:
                label = record.get('label', 'Unknown')
                count = record.get('count', 0)
                total += count
                print(f"  {label}: {count:,} nodes")

            print(f"\n  TOTAL: {total:,} nodes")

            # Get attack samples specifically
            print("\n" + "-" * 50)
            print("ATTACK SAMPLES")
            print("-" * 50)

            result = await session.run("""
                MATCH (a:AttackSample)
                RETURN count(a) as total,
                       count(CASE WHEN a.is_attack = true THEN 1 END) as attacks,
                       count(CASE WHEN a.is_attack = false THEN 1 END) as benign
            """)
            data = await result.single()
            if data:
                print(f"  Total samples: {data['total']}")
                print(f"  Attacks: {data['attacks']}")
                print(f"  Benign: {data['benign']}")

            # Get sample texts
            print("\n" + "-" * 50)
            print("SAMPLE DATA (first 5)")
            print("-" * 50)

            result = await session.run("""
                MATCH (a:AttackSample)
                RETURN a.text as text, a.is_attack as is_attack, a.category as category
                LIMIT 5
            """)
            samples = await result.data()

            for i, sample in enumerate(samples, 1):
                text = sample.get('text', '')[:60]
                is_attack = sample.get('is_attack', False)
                category = sample.get('category', 'unknown')
                label = "ATTACK" if is_attack else "BENIGN"
                print(f"  {i}. [{label}] {category}: {text}...")

            # Get techniques
            print("\n" + "-" * 50)
            print("ATTACK TECHNIQUES")
            print("-" * 50)

            result = await session.run("""
                MATCH (t:AttackTechnique)
                RETURN t.name as name, t.count as count
                ORDER BY t.count DESC
                LIMIT 10
            """)
            techniques = await result.data()

            for tech in techniques:
                name = tech.get('name', 'Unknown')
                count = tech.get('count', 0)
                print(f"  - {name}: {count}")

            if not techniques:
                print("  (No techniques found)")

    except Exception as e:
        print(f"Error: {e}")
    finally:
        await driver.close()

if __name__ == "__main__":
    asyncio.run(check_neo4j())
