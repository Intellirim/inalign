"""
Migrate local Neo4j data to Neo4j Aura cloud.

Transfers all AttackSample nodes from local to cloud.
"""
import asyncio
from neo4j import AsyncGraphDatabase


async def main():
    print("=" * 60)
    print("MIGRATE LOCAL NEO4J → AURA CLOUD")
    print("=" * 60)

    # Local connection
    local_driver = AsyncGraphDatabase.driver(
        "bolt://localhost:7687",
        auth=("neo4j", "inalign_dev")
    )

    # Cloud connection
    cloud_driver = AsyncGraphDatabase.driver(
        "***REDACTED_URI***",
        auth=("neo4j", "***REDACTED***")
    )

    # Check local count
    async with local_driver.session() as session:
        result = await session.run("MATCH (s:AttackSample) RETURN count(s) as count")
        data = await result.data()
        local_count = data[0]["count"]
        print(f"\n[Local] AttackSample nodes: {local_count}")

    # Check cloud count before
    async with cloud_driver.session(database="neo4j") as session:
        result = await session.run("MATCH (s:AttackSample) RETURN count(s) as count")
        data = await result.data()
        cloud_before = data[0]["count"]
        print(f"[Cloud] AttackSample nodes (before): {cloud_before}")

    # Fetch all from local
    print(f"\n[1] Fetching {local_count} samples from local...")
    samples = []
    async with local_driver.session() as session:
        result = await session.run("""
            MATCH (s:AttackSample)
            RETURN s.sample_id as sample_id,
                   s.text as text,
                   s.detected as detected,
                   s.risk_score as risk_score,
                   s.category as category,
                   s.source as source,
                   s.created_at as created_at
        """)
        records = await result.data()
        samples = records
        print(f"    Fetched {len(samples)} samples")

    # Get existing sample_ids in cloud to avoid duplicates
    print("\n[2] Checking for duplicates...")
    existing_ids = set()
    async with cloud_driver.session(database="neo4j") as session:
        result = await session.run("MATCH (s:AttackSample) RETURN s.sample_id as id")
        records = await result.data()
        existing_ids = {r["id"] for r in records}
        print(f"    Cloud has {len(existing_ids)} existing samples")

    # Filter out duplicates
    new_samples = [s for s in samples if s["sample_id"] not in existing_ids]
    print(f"    New samples to migrate: {len(new_samples)}")

    if not new_samples:
        print("\n[!] No new samples to migrate.")
        await local_driver.close()
        await cloud_driver.close()
        return

    # Insert to cloud in batches
    print(f"\n[3] Migrating {len(new_samples)} samples to cloud...")
    batch_size = 50
    migrated = 0

    async with cloud_driver.session(database="neo4j") as session:
        for i in range(0, len(new_samples), batch_size):
            batch = new_samples[i:i+batch_size]

            for sample in batch:
                await session.run("""
                    CREATE (s:AttackSample {
                        sample_id: $sample_id,
                        text: $text,
                        detected: $detected,
                        risk_score: $risk_score,
                        category: $category,
                        source: $source,
                        created_at: $created_at,
                        migrated_from: 'local'
                    })
                """, **sample)

            migrated += len(batch)
            print(f"    Migrated: {migrated}/{len(new_samples)}")

    # Check cloud count after
    async with cloud_driver.session(database="neo4j") as session:
        result = await session.run("MATCH (s:AttackSample) RETURN count(s) as count")
        data = await result.data()
        cloud_after = data[0]["count"]

    await local_driver.close()
    await cloud_driver.close()

    print("\n" + "=" * 60)
    print("MIGRATION COMPLETE")
    print("=" * 60)
    print(f"Local samples:        {local_count}")
    print(f"Cloud before:         {cloud_before}")
    print(f"Cloud after:          {cloud_after}")
    print(f"New samples added:    {cloud_after - cloud_before}")


if __name__ == "__main__":
    asyncio.run(main())
