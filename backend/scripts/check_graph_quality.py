#!/usr/bin/env python
"""Check Neo4j graph data quality and connections."""
import asyncio
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

async def check_graph_quality():
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

    try:
        await driver.verify_connectivity()
        print("=" * 60)
        print("GRAPH DATA QUALITY CHECK")
        print("=" * 60)

        async with driver.session() as session:
            # 1. Check node counts
            print("\n[1] NODE COUNTS")
            print("-" * 40)
            result = await session.run("""
                MATCH (n)
                RETURN labels(n)[0] as label, count(*) as count
                ORDER BY count DESC
            """)
            nodes = await result.data()
            for n in nodes:
                print(f"  {n['label']}: {n['count']:,}")

            # 2. Check relationships
            print("\n[2] RELATIONSHIP TYPES")
            print("-" * 40)
            result = await session.run("""
                MATCH ()-[r]->()
                RETURN type(r) as type, count(*) as count
                ORDER BY count DESC
            """)
            rels = await result.data()
            if rels:
                for r in rels:
                    print(f"  {r['type']}: {r['count']:,}")
            else:
                print("  (No relationships found)")

            # 3. Check keyword connections
            print("\n[3] KEYWORD CONNECTIONS")
            print("-" * 40)
            result = await session.run("""
                MATCH (k:AttackKeyword)<-[:HAS_KEYWORD]-(a:AttackSample)
                RETURN k.text as keyword, count(a) as samples
                ORDER BY samples DESC
                LIMIT 10
            """)
            keywords = await result.data()
            if keywords:
                for k in keywords:
                    print(f"  '{k['keyword']}': {k['samples']} samples")
            else:
                print("  (No keyword connections)")

            # 4. Check signature matches
            print("\n[4] SIGNATURE MATCHES")
            print("-" * 40)
            result = await session.run("""
                MATCH (s:AttackSignature)<-[:MATCHED_BY]-(a:AttackSample)
                RETURN s.pattern_id as pattern, count(a) as matches
                ORDER BY matches DESC
                LIMIT 10
            """)
            sigs = await result.data()
            if sigs:
                for s in sigs:
                    print(f"  {s['pattern']}: {s['matches']} matches")
            else:
                print("  (No signature matches)")

            # 5. Check category distribution
            print("\n[5] ATTACK CATEGORIES")
            print("-" * 40)
            result = await session.run("""
                MATCH (a:AttackSample)
                RETURN a.category as category, count(*) as count
                ORDER BY count DESC
            """)
            cats = await result.data()
            for c in cats:
                cat = c['category'] or 'unknown'
                print(f"  {cat}: {c['count']}")

            # 6. Orphan nodes (not connected)
            print("\n[6] ORPHAN ANALYSIS")
            print("-" * 40)
            result = await session.run("""
                MATCH (a:AttackSample)
                WHERE NOT (a)-[]-()
                RETURN count(a) as orphan_attacks
            """)
            orphans = await result.single()
            orphan_count = orphans['orphan_attacks'] if orphans else 0

            result = await session.run("""
                MATCH (a:AttackSample)
                RETURN count(a) as total
            """)
            total = await result.single()
            total_count = total['total'] if total else 0

            connected = total_count - orphan_count
            print(f"  Total AttackSamples: {total_count}")
            print(f"  Connected: {connected} ({100*connected/max(total_count,1):.1f}%)")
            print(f"  Orphaned: {orphan_count} ({100*orphan_count/max(total_count,1):.1f}%)")

            # 7. Sample connected graph
            print("\n[7] SAMPLE GRAPH PATH")
            print("-" * 40)
            result = await session.run("""
                MATCH path = (a:AttackSample)-[*1..2]-(n)
                RETURN a.text as attack, collect(labels(n)[0]) as connected_types
                LIMIT 3
            """)
            paths = await result.data()
            if paths:
                for i, p in enumerate(paths, 1):
                    text = (p['attack'] or '')[:50]
                    types = list(set(p['connected_types']))
                    print(f"  {i}. '{text}...'")
                    print(f"     -> Connected to: {types}")
            else:
                print("  (No connected paths)")

            print("\n" + "=" * 60)

    except Exception as e:
        print(f"Error: {e}")
        import traceback
        traceback.print_exc()
    finally:
        await driver.close()

if __name__ == "__main__":
    asyncio.run(check_graph_quality())
