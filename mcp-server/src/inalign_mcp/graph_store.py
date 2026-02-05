"""
Neo4j Graph Store for Agent Provenance

Production-grade storage layer using Neo4j graph database.
Stores provenance records as a knowledge graph for GraphRAG queries.

Graph Schema:
- (:Session) - Agent session
- (:Agent) - AI agent or user
- (:Activity) - Tool call, decision, file operation, etc.
- (:Entity) - Data used or generated
- (:SecurityEvent) - Detected threats, PII, anomalies
- (:Anchor) - On-chain anchor proof for third-party verification

Relationships:
- (Activity)-[:PART_OF]->(Session)
- (Activity)-[:PERFORMED_BY]->(Agent)
- (Activity)-[:USED]->(Entity)
- (Activity)-[:GENERATED]->(Entity)
- (Activity)-[:FOLLOWS]->(Activity)  # Chain link
- (SecurityEvent)-[:DETECTED_IN]->(Activity)
- (Anchor)-[:ANCHORS]->(Session)  # On-chain verification
"""

import os
import json
import hashlib
import logging
from typing import Any, Optional
from datetime import datetime, timezone
from dataclasses import dataclass, asdict
from contextlib import contextmanager
from pathlib import Path

# Load .env file if exists
try:
    from dotenv import load_dotenv
    env_path = Path(__file__).parent.parent.parent.parent / ".env"
    if env_path.exists():
        load_dotenv(env_path)
except ImportError:
    pass  # dotenv not installed

try:
    from neo4j import GraphDatabase, Driver, Session as Neo4jSession
    from neo4j.exceptions import ServiceUnavailable, AuthError
    NEO4J_AVAILABLE = True
except ImportError:
    NEO4J_AVAILABLE = False
    GraphDatabase = None
    Driver = None
    Neo4jSession = None

from .provenance import (
    ProvenanceRecord,
    ProvenanceChain,
    Entity,
    Agent,
    ActivityType,
)

logger = logging.getLogger("inalign-graph")


@dataclass
class Neo4jConfig:
    """Neo4j connection configuration."""
    uri: str = "bolt://localhost:7687"
    username: str = "neo4j"
    password: str = "password"
    database: str = "neo4j"
    max_connection_lifetime: int = 3600
    max_connection_pool_size: int = 50
    connection_acquisition_timeout: int = 60

    @classmethod
    def from_env(cls) -> "Neo4jConfig":
        """Load configuration from environment variables."""
        return cls(
            uri=os.getenv("NEO4J_URI", "bolt://localhost:7687"),
            username=os.getenv("NEO4J_USERNAME", "neo4j"),
            password=os.getenv("NEO4J_PASSWORD", "password"),
            database=os.getenv("NEO4J_DATABASE", "neo4j"),
        )


class ProvenanceGraphStore:
    """
    Neo4j-backed storage for provenance records.

    Features:
    - Graph-native storage of W3C PROV data
    - Efficient traversal queries
    - Real-time indexing
    - Chain integrity verification
    """

    # Cypher queries
    CREATE_CONSTRAINTS = """
    CREATE CONSTRAINT session_id IF NOT EXISTS FOR (s:Session) REQUIRE s.session_id IS UNIQUE;
    CREATE CONSTRAINT activity_id IF NOT EXISTS FOR (a:Activity) REQUIRE a.id IS UNIQUE;
    CREATE CONSTRAINT entity_id IF NOT EXISTS FOR (e:Entity) REQUIRE e.id IS UNIQUE;
    CREATE CONSTRAINT agent_id IF NOT EXISTS FOR (ag:Agent) REQUIRE ag.id IS UNIQUE;
    """

    CREATE_INDEXES = """
    CREATE INDEX activity_timestamp IF NOT EXISTS FOR (a:Activity) ON (a.timestamp);
    CREATE INDEX activity_type IF NOT EXISTS FOR (a:Activity) ON (a.activity_type);
    CREATE INDEX activity_hash IF NOT EXISTS FOR (a:Activity) ON (a.record_hash);
    CREATE INDEX entity_hash IF NOT EXISTS FOR (e:Entity) ON (e.value_hash);
    CREATE INDEX session_created IF NOT EXISTS FOR (s:Session) ON (s.created_at);
    """

    UPSERT_SESSION = """
    MERGE (s:Session {session_id: $session_id})
    ON CREATE SET
        s.created_at = datetime(),
        s.agent_name = $agent_name,
        s.record_count = 0,
        s.merkle_root = ''
    ON MATCH SET
        s.last_activity = datetime(),
        s.record_count = s.record_count + 1
    RETURN s
    """

    UPSERT_AGENT = """
    MERGE (ag:Agent {id: $id})
    ON CREATE SET
        ag.type = $type,
        ag.name = $name,
        ag.attributes = $attributes,
        ag.created_at = datetime()
    RETURN ag
    """

    CREATE_ACTIVITY = """
    MATCH (s:Session {session_id: $session_id})
    CREATE (a:Activity {
        id: $id,
        timestamp: $timestamp,
        activity_type: $activity_type,
        activity_name: $activity_name,
        activity_attributes: $activity_attributes,
        previous_hash: $previous_hash,
        sequence_number: $sequence_number,
        record_hash: $record_hash,
        signature: $signature,
        signer_id: $signer_id
    })
    CREATE (a)-[:PART_OF]->(s)
    WITH a
    OPTIONAL MATCH (ag:Agent {id: $agent_id})
    FOREACH (_ IN CASE WHEN ag IS NOT NULL THEN [1] ELSE [] END |
        CREATE (a)-[:PERFORMED_BY]->(ag)
    )
    RETURN a
    """

    LINK_ACTIVITIES = """
    MATCH (a1:Activity {record_hash: $previous_hash})
    MATCH (a2:Activity {id: $activity_id})
    MERGE (a2)-[:FOLLOWS]->(a1)
    """

    CREATE_ENTITY = """
    MERGE (e:Entity {id: $id})
    ON CREATE SET
        e.type = $type,
        e.value_hash = $value_hash,
        e.attributes = $attributes,
        e.created_at = datetime()
    RETURN e
    """

    LINK_USED_ENTITY = """
    MATCH (a:Activity {id: $activity_id})
    MATCH (e:Entity {id: $entity_id})
    MERGE (a)-[:USED]->(e)
    """

    LINK_GENERATED_ENTITY = """
    MATCH (a:Activity {id: $activity_id})
    MATCH (e:Entity {id: $entity_id})
    MERGE (a)-[:GENERATED]->(e)
    """

    CREATE_SECURITY_EVENT = """
    MATCH (a:Activity {id: $activity_id})
    CREATE (se:SecurityEvent {
        id: $event_id,
        event_type: $event_type,
        severity: $severity,
        description: $description,
        details: $details,
        detected_at: datetime()
    })
    CREATE (se)-[:DETECTED_IN]->(a)
    RETURN se
    """

    # ==========================================
    # ON-CHAIN ANCHOR TRACKING
    # ==========================================

    CREATE_ANCHOR = """
    MATCH (s:Session {session_id: $session_id})
    CREATE (an:Anchor {
        proof_id: $proof_id,
        merkle_root: $merkle_root,
        chain_type: $chain_type,
        transaction_hash: $transaction_hash,
        block_number: $block_number,
        block_hash: $block_hash,
        batch_root: $batch_root,
        merkle_proof: $merkle_proof,
        anchored_at: datetime(),
        verified: false
    })
    CREATE (an)-[:ANCHORS]->(s)
    RETURN an
    """

    GET_ANCHOR_BY_SESSION = """
    MATCH (an:Anchor)-[:ANCHORS]->(s:Session {session_id: $session_id})
    RETURN an
    ORDER BY an.anchored_at DESC
    """

    GET_ANCHOR_BY_MERKLE = """
    MATCH (an:Anchor {merkle_root: $merkle_root})
    OPTIONAL MATCH (an)-[:ANCHORS]->(s:Session)
    RETURN an, s.session_id as session_id
    """

    GET_ANCHOR_BY_TX = """
    MATCH (an:Anchor {transaction_hash: $tx_hash})
    OPTIONAL MATCH (an)-[:ANCHORS]->(s:Session)
    RETURN an, collect(s.session_id) as sessions
    """

    UPDATE_ANCHOR_VERIFIED = """
    MATCH (an:Anchor {proof_id: $proof_id})
    SET an.verified = true,
        an.verified_at = datetime(),
        an.verification_block = $verification_block
    RETURN an
    """

    # Full verification query - checks chain + anchor
    VERIFY_SESSION_FULL = """
    MATCH (s:Session {session_id: $session_id})
    OPTIONAL MATCH (an:Anchor)-[:ANCHORS]->(s)
    WITH s, an
    MATCH (a:Activity)-[:PART_OF]->(s)
    WITH s, an,
         count(a) as activity_count,
         max(a.sequence_number) as last_seq
    RETURN s.session_id as session_id,
           activity_count,
           last_seq,
           an.merkle_root as anchored_merkle_root,
           an.transaction_hash as tx_hash,
           an.block_number as block_number,
           an.chain_type as chain_type,
           an.verified as anchor_verified,
           an IS NOT NULL as is_anchored
    """

    # Find unanchored sessions
    GET_UNANCHORED_SESSIONS = """
    MATCH (s:Session)
    WHERE NOT EXISTS { MATCH (an:Anchor)-[:ANCHORS]->(s) }
    MATCH (a:Activity)-[:PART_OF]->(s)
    WITH s, count(a) as activity_count
    WHERE activity_count >= $min_activities
    RETURN s.session_id as session_id,
           s.created_at as created_at,
           activity_count
    ORDER BY s.created_at
    LIMIT $limit
    """

    # Get anchor statistics
    GET_ANCHOR_STATS = """
    MATCH (an:Anchor)
    WITH an.chain_type as chain, count(*) as total,
         sum(CASE WHEN an.verified THEN 1 ELSE 0 END) as verified
    RETURN chain, total, verified
    """

    def __init__(self, config: Optional[Neo4jConfig] = None):
        """Initialize graph store with optional configuration."""
        self.config = config or Neo4jConfig.from_env()
        self._driver: Optional[Driver] = None
        self._initialized = False

    @property
    def driver(self) -> Driver:
        """Get or create Neo4j driver."""
        if not NEO4J_AVAILABLE:
            raise RuntimeError("neo4j package not installed. Run: pip install neo4j")

        if self._driver is None:
            self._driver = GraphDatabase.driver(
                self.config.uri,
                auth=(self.config.username, self.config.password),
                max_connection_lifetime=self.config.max_connection_lifetime,
                max_connection_pool_size=self.config.max_connection_pool_size,
                connection_acquisition_timeout=self.config.connection_acquisition_timeout,
            )
        return self._driver

    @contextmanager
    def session(self):
        """Get a database session context manager."""
        session = self.driver.session(database=self.config.database)
        try:
            yield session
        finally:
            session.close()

    def initialize(self) -> bool:
        """
        Initialize database schema (constraints and indexes).
        Should be called once on startup.
        """
        if self._initialized:
            return True

        try:
            with self.session() as session:
                # Create constraints
                for constraint in self.CREATE_CONSTRAINTS.strip().split(";"):
                    constraint = constraint.strip()
                    if constraint:
                        try:
                            session.run(constraint)
                        except Exception as e:
                            # Constraint might already exist
                            logger.debug(f"Constraint creation: {e}")

                # Create indexes
                for index in self.CREATE_INDEXES.strip().split(";"):
                    index = index.strip()
                    if index:
                        try:
                            session.run(index)
                        except Exception as e:
                            logger.debug(f"Index creation: {e}")

            self._initialized = True
            logger.info("Neo4j schema initialized successfully")
            return True

        except (ServiceUnavailable, AuthError) as e:
            logger.error(f"Failed to initialize Neo4j: {e}")
            return False

    def store_record(self, record: ProvenanceRecord) -> bool:
        """
        Store a single provenance record in the graph.

        Creates:
        - Activity node with all metadata
        - Entity nodes for used/generated data
        - Relationships between nodes
        - Chain link to previous activity
        """
        try:
            with self.session() as session:
                # Upsert session
                session.run(
                    self.UPSERT_SESSION,
                    session_id=record.session_id,
                    agent_name=record.agent.name if record.agent else "unknown",
                )

                # Upsert agent if present
                if record.agent:
                    session.run(
                        self.UPSERT_AGENT,
                        id=record.agent.id,
                        type=record.agent.type,
                        name=record.agent.name,
                        attributes=json.dumps(record.agent.attributes),
                    )

                # Create activity
                session.run(
                    self.CREATE_ACTIVITY,
                    session_id=record.session_id,
                    id=record.id,
                    timestamp=record.timestamp,
                    activity_type=record.activity_type.value,
                    activity_name=record.activity_name,
                    activity_attributes=json.dumps(record.activity_attributes),
                    previous_hash=record.previous_hash,
                    sequence_number=record.sequence_number,
                    record_hash=record.record_hash,
                    signature=record.signature,
                    signer_id=record.signer_id,
                    agent_id=record.agent.id if record.agent else None,
                )

                # Link to previous activity if exists
                if record.previous_hash:
                    session.run(
                        self.LINK_ACTIVITIES,
                        previous_hash=record.previous_hash,
                        activity_id=record.id,
                    )

                # Create and link used entities
                for entity in record.used_entities:
                    session.run(
                        self.CREATE_ENTITY,
                        id=entity.id,
                        type=entity.type,
                        value_hash=entity.value_hash,
                        attributes=json.dumps(entity.attributes),
                    )
                    session.run(
                        self.LINK_USED_ENTITY,
                        activity_id=record.id,
                        entity_id=entity.id,
                    )

                # Create and link generated entities
                for entity in record.generated_entities:
                    session.run(
                        self.CREATE_ENTITY,
                        id=entity.id,
                        type=entity.type,
                        value_hash=entity.value_hash,
                        attributes=json.dumps(entity.attributes),
                    )
                    session.run(
                        self.LINK_GENERATED_ENTITY,
                        activity_id=record.id,
                        entity_id=entity.id,
                    )

            logger.debug(f"Stored record {record.id} in graph")
            return True

        except Exception as e:
            logger.error(f"Failed to store record: {e}")
            return False

    def store_chain(self, chain: ProvenanceChain) -> int:
        """
        Store an entire provenance chain.
        Returns number of records stored.
        """
        stored = 0
        for record in chain.records:
            if self.store_record(record):
                stored += 1
        return stored

    def record_security_event(
        self,
        activity_id: str,
        event_type: str,
        severity: str,
        description: str,
        details: dict[str, Any] = None,
    ) -> bool:
        """Record a security event linked to an activity."""
        import uuid
        event_id = f"sec:{uuid.uuid4().hex[:12]}"

        try:
            with self.session() as session:
                session.run(
                    self.CREATE_SECURITY_EVENT,
                    activity_id=activity_id,
                    event_id=event_id,
                    event_type=event_type,
                    severity=severity,
                    description=description,
                    details=json.dumps(details or {}),
                )
            return True
        except Exception as e:
            logger.error(f"Failed to record security event: {e}")
            return False

    def get_session_chain(self, session_id: str) -> list[dict]:
        """Get all activities in a session, ordered by sequence."""
        query = """
        MATCH (a:Activity)-[:PART_OF]->(s:Session {session_id: $session_id})
        OPTIONAL MATCH (a)-[:PERFORMED_BY]->(ag:Agent)
        OPTIONAL MATCH (a)-[:USED]->(used:Entity)
        OPTIONAL MATCH (a)-[:GENERATED]->(gen:Entity)
        RETURN a, ag, collect(DISTINCT used) as used_entities,
               collect(DISTINCT gen) as generated_entities
        ORDER BY a.sequence_number
        """
        try:
            with self.session() as session:
                result = session.run(query, session_id=session_id)
                records = []
                for row in result:
                    activity = dict(row["a"])
                    activity["agent"] = dict(row["ag"]) if row["ag"] else None
                    activity["used_entities"] = [dict(e) for e in row["used_entities"]]
                    activity["generated_entities"] = [dict(e) for e in row["generated_entities"]]
                    records.append(activity)
                return records
        except Exception as e:
            logger.error(f"Failed to get session chain: {e}")
            return []

    def verify_chain_integrity(self, session_id: str) -> tuple[bool, Optional[str]]:
        """
        Verify the integrity of a session's provenance chain.
        Checks hash links and sequence numbers.
        """
        query = """
        MATCH (a:Activity)-[:PART_OF]->(s:Session {session_id: $session_id})
        RETURN a.id as id, a.sequence_number as seq,
               a.record_hash as hash, a.previous_hash as prev_hash
        ORDER BY a.sequence_number
        """
        try:
            with self.session() as session:
                result = session.run(query, session_id=session_id)
                records = list(result)

                if not records:
                    return True, None

                # Check genesis
                if records[0]["prev_hash"] and records[0]["prev_hash"] != "":
                    return False, "Genesis record has non-empty previous_hash"

                # Check chain links
                for i in range(1, len(records)):
                    expected_prev = records[i - 1]["hash"]
                    actual_prev = records[i]["prev_hash"]
                    if actual_prev != expected_prev:
                        return False, f"Chain broken at record {i}: {records[i]['id']}"

                    # Check sequence
                    if records[i]["seq"] != i:
                        return False, f"Sequence mismatch at record {i}"

                return True, None

        except Exception as e:
            logger.error(f"Failed to verify chain: {e}")
            return False, str(e)

    def get_session_stats(self, session_id: str) -> dict[str, Any]:
        """Get statistics for a session."""
        query = """
        MATCH (s:Session {session_id: $session_id})
        OPTIONAL MATCH (a:Activity)-[:PART_OF]->(s)
        OPTIONAL MATCH (se:SecurityEvent)-[:DETECTED_IN]->(a)
        WITH s, count(DISTINCT a) as activity_count, count(DISTINCT se) as security_events
        RETURN s.session_id as session_id,
               s.created_at as created_at,
               s.agent_name as agent_name,
               activity_count,
               security_events
        """
        try:
            with self.session() as session:
                result = session.run(query, session_id=session_id)
                row = result.single()
                if row:
                    return dict(row)
                return {"exists": False}
        except Exception as e:
            logger.error(f"Failed to get session stats: {e}")
            return {"error": str(e)}

    def get_activity_by_hash(self, record_hash: str) -> Optional[dict]:
        """Get an activity by its record hash."""
        query = """
        MATCH (a:Activity {record_hash: $hash})
        OPTIONAL MATCH (a)-[:PERFORMED_BY]->(ag:Agent)
        RETURN a, ag
        """
        try:
            with self.session() as session:
                result = session.run(query, hash=record_hash)
                row = result.single()
                if row:
                    activity = dict(row["a"])
                    activity["agent"] = dict(row["ag"]) if row["ag"] else None
                    return activity
                return None
        except Exception as e:
            logger.error(f"Failed to get activity: {e}")
            return None

    # ==========================================
    # ANCHOR METHODS (Third-Party Verification)
    # ==========================================

    def store_anchor(
        self,
        session_id: str,
        proof_id: str,
        merkle_root: str,
        chain_type: str,
        transaction_hash: str,
        block_number: int,
        block_hash: str,
        batch_root: Optional[str] = None,
        merkle_proof: Optional[list[str]] = None,
    ) -> bool:
        """
        Store an on-chain anchor proof in the graph.

        Links the anchor to the session for third-party verification.
        """
        try:
            with self.session() as session:
                session.run(
                    self.CREATE_ANCHOR,
                    session_id=session_id,
                    proof_id=proof_id,
                    merkle_root=merkle_root,
                    chain_type=chain_type,
                    transaction_hash=transaction_hash,
                    block_number=block_number,
                    block_hash=block_hash,
                    batch_root=batch_root or "",
                    merkle_proof=json.dumps(merkle_proof or []),
                )
            logger.info(f"Stored anchor {proof_id} for session {session_id}")
            return True
        except Exception as e:
            logger.error(f"Failed to store anchor: {e}")
            return False

    def get_session_anchors(self, session_id: str) -> list[dict]:
        """Get all anchors for a session."""
        try:
            with self.session() as session:
                result = session.run(
                    self.GET_ANCHOR_BY_SESSION,
                    session_id=session_id,
                )
                return [dict(row["an"]) for row in result]
        except Exception as e:
            logger.error(f"Failed to get session anchors: {e}")
            return []

    def get_anchor_by_merkle(self, merkle_root: str) -> Optional[dict]:
        """Get anchor by merkle root."""
        try:
            with self.session() as session:
                result = session.run(
                    self.GET_ANCHOR_BY_MERKLE,
                    merkle_root=merkle_root,
                )
                row = result.single()
                if row:
                    anchor = dict(row["an"])
                    anchor["session_id"] = row["session_id"]
                    return anchor
                return None
        except Exception as e:
            logger.error(f"Failed to get anchor: {e}")
            return None

    def get_anchors_by_tx(self, tx_hash: str) -> Optional[dict]:
        """Get all anchors in a batch transaction."""
        try:
            with self.session() as session:
                result = session.run(
                    self.GET_ANCHOR_BY_TX,
                    tx_hash=tx_hash,
                )
                row = result.single()
                if row:
                    anchor = dict(row["an"])
                    anchor["sessions"] = row["sessions"]
                    return anchor
                return None
        except Exception as e:
            logger.error(f"Failed to get anchors by tx: {e}")
            return None

    def mark_anchor_verified(
        self,
        proof_id: str,
        verification_block: int,
    ) -> bool:
        """Mark an anchor as verified on-chain."""
        try:
            with self.session() as session:
                session.run(
                    self.UPDATE_ANCHOR_VERIFIED,
                    proof_id=proof_id,
                    verification_block=verification_block,
                )
            return True
        except Exception as e:
            logger.error(f"Failed to mark anchor verified: {e}")
            return False

    def verify_session_full(self, session_id: str) -> dict[str, Any]:
        """
        Full verification including chain integrity and on-chain anchor.

        Returns comprehensive verification status for third-party audit.
        """
        result = {
            "session_id": session_id,
            "chain_valid": False,
            "chain_error": None,
            "is_anchored": False,
            "anchor_verified": False,
            "verification_details": {},
        }

        # First verify chain integrity
        chain_valid, chain_error = self.verify_chain_integrity(session_id)
        result["chain_valid"] = chain_valid
        result["chain_error"] = chain_error

        # Then check anchor status
        try:
            with self.session() as session:
                query_result = session.run(
                    self.VERIFY_SESSION_FULL,
                    session_id=session_id,
                )
                row = query_result.single()
                if row:
                    result["is_anchored"] = row["is_anchored"]
                    result["anchor_verified"] = row["anchor_verified"] or False
                    result["verification_details"] = {
                        "activity_count": row["activity_count"],
                        "merkle_root": row["anchored_merkle_root"],
                        "tx_hash": row["tx_hash"],
                        "block_number": row["block_number"],
                        "chain_type": row["chain_type"],
                    }
        except Exception as e:
            logger.error(f"Failed full verification: {e}")
            result["error"] = str(e)

        # Overall status
        result["fully_verified"] = (
            result["chain_valid"] and
            result["is_anchored"] and
            result["anchor_verified"]
        )

        return result

    def get_unanchored_sessions(
        self,
        min_activities: int = 1,
        limit: int = 100,
    ) -> list[dict]:
        """Get sessions that haven't been anchored yet."""
        try:
            with self.session() as session:
                result = session.run(
                    self.GET_UNANCHORED_SESSIONS,
                    min_activities=min_activities,
                    limit=limit,
                )
                return [dict(row) for row in result]
        except Exception as e:
            logger.error(f"Failed to get unanchored sessions: {e}")
            return []

    def get_anchor_stats(self) -> dict[str, Any]:
        """Get global anchor statistics."""
        try:
            with self.session() as session:
                result = session.run(self.GET_ANCHOR_STATS)
                stats = {"by_chain": {}, "total": 0, "verified": 0}
                for row in result:
                    chain = row["chain"]
                    stats["by_chain"][chain] = {
                        "total": row["total"],
                        "verified": row["verified"],
                    }
                    stats["total"] += row["total"]
                    stats["verified"] += row["verified"]
                return stats
        except Exception as e:
            logger.error(f"Failed to get anchor stats: {e}")
            return {}

    def close(self):
        """Close the driver connection."""
        if self._driver:
            self._driver.close()
            self._driver = None

    def __enter__(self):
        self.initialize()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()


# Global store instance
_graph_store: Optional[ProvenanceGraphStore] = None


def get_graph_store() -> ProvenanceGraphStore:
    """Get or create the global graph store instance."""
    global _graph_store
    if _graph_store is None:
        _graph_store = ProvenanceGraphStore()
        _graph_store.initialize()
    return _graph_store


def store_provenance(record: ProvenanceRecord) -> bool:
    """Convenience function to store a provenance record."""
    return get_graph_store().store_record(record)


def store_chain(chain: ProvenanceChain) -> int:
    """Convenience function to store a provenance chain."""
    return get_graph_store().store_chain(chain)
