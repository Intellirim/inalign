"""
Pattern seeding script.

Loads injection patterns from ``data/injection_patterns.json`` and
optionally seeds Neo4j with attack signature nodes.

Usage::

    python -m scripts.seed_patterns [--neo4j]
"""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import sys
from pathlib import Path
from typing import Any

# Ensure the backend package root is on sys.path
_backend_root = Path(__file__).resolve().parent.parent
if str(_backend_root) not in sys.path:
    sys.path.insert(0, str(_backend_root))

from app.config import configure_logging, get_settings

logger = logging.getLogger("inalign.scripts.seed_patterns")


def load_injection_patterns() -> list[dict[str, Any]]:
    """Load injection patterns from the JSON data file.

    Returns
    -------
    list[dict]
        The parsed pattern entries.

    Raises
    ------
    FileNotFoundError
        If the data file does not exist.
    """
    data_file = _backend_root / "data" / "injection_patterns.json"

    if not data_file.exists():
        logger.error("Pattern file not found: %s", data_file)
        raise FileNotFoundError(f"Pattern file not found: {data_file}")

    with open(data_file, "r", encoding="utf-8") as f:
        patterns: list[dict[str, Any]] = json.load(f)

    logger.info(
        "Loaded %d injection patterns from %s",
        len(patterns),
        data_file.name,
    )

    # Print summary by category
    categories: dict[str, int] = {}
    for pattern in patterns:
        cat = pattern.get("category", "unknown")
        categories[cat] = categories.get(cat, 0) + 1

    for cat, count in sorted(categories.items()):
        logger.info("  Category '%s': %d patterns", cat, count)

    return patterns


async def seed_neo4j_signatures(patterns: list[dict[str, Any]]) -> int:
    """Seed Neo4j with attack signature nodes from pattern data.

    Parameters
    ----------
    patterns:
        List of pattern dictionaries to seed.

    Returns
    -------
    int
        Number of signatures created.
    """
    from app.graph.neo4j_client import Neo4jClient

    settings = get_settings()
    client = Neo4jClient(
        uri=settings.neo4j_uri,
        username=settings.neo4j_user,
        password=settings.neo4j_password,
        database=settings.neo4j_database,
    )

    await client.connect()
    created = 0

    try:
        for pattern in patterns:
            query = """
            MERGE (sig:AttackSignature {signature_id: $signature_id})
            ON CREATE SET
                sig.name        = $name,
                sig.pattern     = $pattern,
                sig.category    = $category,
                sig.severity    = $severity,
                sig.description = $description,
                sig.enabled     = true,
                sig.created_at  = datetime(),
                sig.updated_at  = datetime()
            ON MATCH SET
                sig.name        = $name,
                sig.pattern     = $pattern,
                sig.severity    = $severity,
                sig.description = $description,
                sig.updated_at  = datetime()
            RETURN sig.signature_id AS sid
            """

            # Combine regex patterns into a single pattern string
            combined_pattern = "|".join(pattern.get("patterns", []))

            params: dict[str, Any] = {
                "signature_id": pattern["id"],
                "name": f"{pattern['category']}:{pattern['id']}",
                "pattern": combined_pattern,
                "category": pattern.get("category", ""),
                "severity": pattern.get("severity", "medium"),
                "description": pattern.get("description", ""),
            }

            await client._execute_write(query, params)
            created += 1

        logger.info("Seeded %d attack signatures into Neo4j.", created)

    finally:
        await client.disconnect()

    return created


def main() -> None:
    """Main entry point for the seeding script."""
    parser = argparse.ArgumentParser(
        description="Load and optionally seed injection patterns."
    )
    parser.add_argument(
        "--neo4j",
        action="store_true",
        help="Also seed patterns as AttackSignature nodes in Neo4j",
    )
    args = parser.parse_args()

    settings = get_settings()
    configure_logging(settings)

    patterns = load_injection_patterns()
    print(f"\nTotal patterns loaded: {len(patterns)}")

    if args.neo4j:
        print("\nSeeding Neo4j attack signatures...")
        count = asyncio.run(seed_neo4j_signatures(patterns))
        print(f"Neo4j attack signatures seeded: {count}")
    else:
        print("\nSkipping Neo4j seeding (use --neo4j to enable).")


if __name__ == "__main__":
    main()
