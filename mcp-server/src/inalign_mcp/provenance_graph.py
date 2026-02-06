"""
Provenance Graph Store - Neo4j Integration for Agent Activity Visualization.

Stores provenance records as a graph for:
- Visual audit trails
- Behavior pattern analysis
- Anomaly detection through graph algorithms
- Attack path visualization
"""

import logging
from typing import Optional, Any
from datetime import datetime, timezone
from dataclasses import dataclass

from .provenance import (
    ProvenanceRecord,
    ProvenanceChain,
    ActivityType,
    get_or_create_chain,
)

logger = logging.getLogger("inalign-provenance-graph")

# Neo4j connection (optional)
_neo4j_driver = None


def init_neo4j(uri: str = "bolt://localhost:7687", user: str = "neo4j", password: str = "password"):
    """Initialize Neo4j connection for provenance graph storage."""
    global _neo4j_driver
    try:
        from neo4j import GraphDatabase
        _neo4j_driver = GraphDatabase.driver(uri, auth=(user, password))
        # Create indexes and constraints
        with _neo4j_driver.session() as session:
            # Unique constraints
            session.run("""
                CREATE CONSTRAINT prov_record_id IF NOT EXISTS
                FOR (r:ProvenanceRecord) REQUIRE r.record_id IS UNIQUE
            """)
            session.run("""
                CREATE CONSTRAINT prov_session_id IF NOT EXISTS
                FOR (s:Session) REQUIRE s.session_id IS UNIQUE
            """)
            session.run("""
                CREATE CONSTRAINT prov_agent_id IF NOT EXISTS
                FOR (a:Agent) REQUIRE a.agent_id IS UNIQUE
            """)
            # Indexes for queries
            session.run("""
                CREATE INDEX prov_record_timestamp IF NOT EXISTS
                FOR (r:ProvenanceRecord) ON (r.timestamp)
            """)
            session.run("""
                CREATE INDEX prov_record_type IF NOT EXISTS
                FOR (r:ProvenanceRecord) ON (r.activity_type)
            """)
        logger.info("Neo4j provenance graph initialized")
        return True
    except Exception as e:
        logger.warning(f"Neo4j not available for provenance graph: {e}")
        return False


def close_neo4j():
    """Close Neo4j connection."""
    global _neo4j_driver
    if _neo4j_driver:
        _neo4j_driver.close()
        _neo4j_driver = None


def is_neo4j_available() -> bool:
    """Check if Neo4j is available."""
    return _neo4j_driver is not None


# ============================================
# Content Storage (Full Prompt/Response)
# ============================================

import zlib
import base64
import hashlib


def store_content(content: str, content_type: str = "prompt",
                  record_id: str = None, client_id: str = None) -> Optional[str]:
    """
    Store full content (prompt/response) compressed in Neo4j.

    Args:
        content: Full text content to store
        content_type: "prompt", "response", "code", etc.
        record_id: Link to ProvenanceRecord
        client_id: Client identifier for isolation

    Returns:
        content_hash if successful, None otherwise
    """
    if not _neo4j_driver or not content:
        return None

    try:
        # Compute hash of original content
        content_hash = hashlib.sha256(content.encode()).hexdigest()

        # Compress content
        compressed = zlib.compress(content.encode(), level=9)
        compressed_b64 = base64.b64encode(compressed).decode()

        with _neo4j_driver.session() as session:
            # Store content node
            session.run("""
                MERGE (c:ContentStore {content_hash: $hash})
                ON CREATE SET
                    c.compressed_content = $content,
                    c.content_type = $type,
                    c.original_size = $orig_size,
                    c.compressed_size = $comp_size,
                    c.client_id = $client_id,
                    c.created_at = datetime()
                WITH c
                MATCH (r:ProvenanceRecord {record_id: $record_id})
                MERGE (r)-[:HAS_CONTENT]->(c)
            """, hash=content_hash, content=compressed_b64, type=content_type,
                orig_size=len(content.encode()), comp_size=len(compressed_b64),
                client_id=client_id, record_id=record_id)

            logger.info(f"Stored content: {content_hash[:16]}... ({len(content)} -> {len(compressed_b64)} bytes)")
            return content_hash

    except Exception as e:
        logger.error(f"Failed to store content: {e}")
        return None


def get_content(content_hash: str) -> Optional[str]:
    """
    Retrieve and decompress content by hash.

    Args:
        content_hash: SHA256 hash of original content

    Returns:
        Original content string or None
    """
    if not _neo4j_driver:
        return None

    try:
        with _neo4j_driver.session() as session:
            result = session.run("""
                MATCH (c:ContentStore {content_hash: $hash})
                RETURN c.compressed_content as content
            """, hash=content_hash)

            row = result.single()
            if row and row['content']:
                compressed = base64.b64decode(row['content'])
                return zlib.decompress(compressed).decode()
            return None

    except Exception as e:
        logger.error(f"Failed to get content: {e}")
        return None


def get_record_content(record_id: str) -> dict:
    """
    Get all content associated with a provenance record.

    Returns:
        Dict with prompt, response, etc.
    """
    if not _neo4j_driver:
        return {}

    try:
        with _neo4j_driver.session() as session:
            result = session.run("""
                MATCH (r:ProvenanceRecord {record_id: $record_id})-[:HAS_CONTENT]->(c:ContentStore)
                RETURN c.content_type as type, c.compressed_content as content, c.content_hash as hash
            """, record_id=record_id)

            contents = {}
            for row in result:
                content_type = row['type']
                compressed = base64.b64decode(row['content'])
                contents[content_type] = {
                    'content': zlib.decompress(compressed).decode(),
                    'hash': row['hash']
                }
            return contents

    except Exception as e:
        logger.error(f"Failed to get record content: {e}")
        return {}


# ============================================
# Graph Storage Operations
# ============================================

def store_record(record: ProvenanceRecord) -> bool:
    """
    Store a provenance record in Neo4j as graph nodes and relationships.

    Creates:
    - ProvenanceRecord node
    - Session node (if not exists)
    - Agent node (if not exists)
    - Tool/Decision nodes
    - Relationships: BELONGS_TO, PERFORMED_BY, FOLLOWS, USED, GENERATED
    """
    if not _neo4j_driver:
        return False

    try:
        with _neo4j_driver.session() as session:
            # Create the main record node (including activity_attributes for full data)
            import json
            attributes_json = json.dumps(record.activity_attributes) if record.activity_attributes else "{}"

            session.run("""
                MERGE (r:ProvenanceRecord {record_id: $record_id})
                SET r.timestamp = $timestamp,
                    r.activity_type = $activity_type,
                    r.activity_name = $activity_name,
                    r.record_hash = $record_hash,
                    r.previous_hash = $previous_hash,
                    r.sequence_number = $sequence_number,
                    r.session_id = $session_id,
                    r.client_id = $client_id,
                    r.activity_attributes = $activity_attributes
            """, {
                "record_id": record.id,
                "timestamp": record.timestamp,
                "activity_type": record.activity_type.value,
                "activity_name": record.activity_name,
                "record_hash": record.record_hash,
                "previous_hash": record.previous_hash,
                "sequence_number": record.sequence_number,
                "session_id": record.session_id,
                "client_id": getattr(record, 'client_id', '') or '',
                "activity_attributes": attributes_json,
            })

            # Create/link session with client_id for data isolation
            if record.session_id:
                # Get client_id from record field or activity_attributes as fallback
                client_id = getattr(record, 'client_id', None) or (
                    record.activity_attributes.get("client_id") if record.activity_attributes else None
                )

                session.run("""
                    MERGE (s:Session {session_id: $session_id})
                    SET s.client_id = $client_id
                    WITH s
                    MATCH (r:ProvenanceRecord {record_id: $record_id})
                    SET r.client_id = $client_id
                    MERGE (r)-[:BELONGS_TO]->(s)
                """, {
                    "session_id": record.session_id,
                    "record_id": record.id,
                    "client_id": client_id,
                })

            # Create/link agent
            if record.agent:
                session.run("""
                    MERGE (a:Agent {agent_id: $agent_id})
                    SET a.name = $agent_name,
                        a.type = $agent_type
                    WITH a
                    MATCH (r:ProvenanceRecord {record_id: $record_id})
                    MERGE (r)-[:PERFORMED_BY]->(a)
                """, {
                    "agent_id": record.agent.id,
                    "agent_name": record.agent.name,
                    "agent_type": record.agent.type,
                    "record_id": record.id,
                })

            # Link to previous record (chain)
            if record.previous_hash:
                session.run("""
                    MATCH (prev:ProvenanceRecord {record_hash: $previous_hash})
                    MATCH (curr:ProvenanceRecord {record_id: $record_id})
                    MERGE (curr)-[:FOLLOWS]->(prev)
                """, {
                    "previous_hash": record.previous_hash,
                    "record_id": record.id,
                })

            # Create activity-specific nodes
            if record.activity_type == ActivityType.TOOL_CALL:
                session.run("""
                    MERGE (t:Tool {name: $tool_name})
                    WITH t
                    MATCH (r:ProvenanceRecord {record_id: $record_id})
                    MERGE (r)-[:CALLED]->(t)
                """, {
                    "tool_name": record.activity_name,
                    "record_id": record.id,
                })
            elif record.activity_type == ActivityType.DECISION:
                session.run("""
                    MERGE (d:Decision {name: $decision_name})
                    WITH d
                    MATCH (r:ProvenanceRecord {record_id: $record_id})
                    MERGE (r)-[:MADE]->(d)
                """, {
                    "decision_name": record.activity_name,
                    "record_id": record.id,
                })

            # Store used entities
            for entity in record.used_entities:
                session.run("""
                    MATCH (r:ProvenanceRecord {record_id: $record_id})
                    CREATE (e:Entity {
                        entity_id: $entity_id,
                        entity_type: $entity_type,
                        value_hash: $value_hash
                    })
                    CREATE (r)-[:USED]->(e)
                """, {
                    "record_id": record.id,
                    "entity_id": entity.id,
                    "entity_type": entity.type,
                    "value_hash": entity.value_hash,
                })

            # Store generated entities
            for entity in record.generated_entities:
                session.run("""
                    MATCH (r:ProvenanceRecord {record_id: $record_id})
                    CREATE (e:Entity {
                        entity_id: $entity_id,
                        entity_type: $entity_type,
                        value_hash: $value_hash
                    })
                    CREATE (r)-[:GENERATED]->(e)
                """, {
                    "record_id": record.id,
                    "entity_id": entity.id,
                    "entity_type": entity.type,
                    "value_hash": entity.value_hash,
                })

        return True
    except Exception as e:
        logger.error(f"Failed to store provenance record: {e}")
        return False


def store_chain(chain: ProvenanceChain) -> int:
    """Store all records from a chain. Returns count of stored records."""
    stored = 0
    for record in chain.records:
        if store_record(record):
            stored += 1
    return stored


# ============================================
# Graph Query Operations (Visualization API)
# ============================================

@dataclass
class GraphNode:
    """Node for visualization."""
    id: str
    label: str
    type: str
    properties: dict[str, Any]


@dataclass
class GraphEdge:
    """Edge for visualization."""
    source: str
    target: str
    type: str
    properties: dict[str, Any]


@dataclass
class ProvenanceGraph:
    """Graph structure for visualization."""
    nodes: list[GraphNode]
    edges: list[GraphEdge]
    metadata: dict[str, Any]

    def to_dict(self) -> dict:
        """Convert to dictionary for JSON serialization."""
        return {
            "nodes": [
                {"id": n.id, "label": n.label, "type": n.type, "properties": n.properties}
                for n in self.nodes
            ],
            "edges": [
                {"source": e.source, "target": e.target, "type": e.type, "properties": e.properties}
                for e in self.edges
            ],
            "metadata": self.metadata,
        }


def get_session_graph(session_id: str) -> Optional[ProvenanceGraph]:
    """
    Get the provenance graph for a session.
    Returns nodes and edges for visualization.
    """
    if not _neo4j_driver:
        return None

    try:
        with _neo4j_driver.session() as session:
            # Get all nodes related to session
            result = session.run("""
                MATCH (s:Session {session_id: $session_id})<-[:BELONGS_TO]-(r:ProvenanceRecord)
                OPTIONAL MATCH (r)-[:PERFORMED_BY]->(a:Agent)
                OPTIONAL MATCH (r)-[:CALLED]->(t:Tool)
                OPTIONAL MATCH (r)-[:MADE]->(d:Decision)
                OPTIONAL MATCH (r)-[:FOLLOWS]->(prev:ProvenanceRecord)
                RETURN r, a, t, d, prev
                ORDER BY r.sequence_number
            """, {"session_id": session_id})

            nodes = []
            edges = []
            seen_nodes = set()

            for record in result:
                r = record["r"]
                a = record["a"]
                t = record["t"]
                d = record["d"]
                prev = record["prev"]

                # Record node
                record_id = r["record_id"]
                if record_id not in seen_nodes:
                    nodes.append(GraphNode(
                        id=record_id,
                        label=r["activity_name"],
                        type="record",
                        properties={
                            "activity_type": r["activity_type"],
                            "timestamp": r["timestamp"],
                            "sequence": r["sequence_number"],
                        }
                    ))
                    seen_nodes.add(record_id)

                # Agent node
                if a:
                    agent_id = a["agent_id"]
                    if agent_id not in seen_nodes:
                        nodes.append(GraphNode(
                            id=agent_id,
                            label=a["name"],
                            type="agent",
                            properties={"agent_type": a.get("type", "unknown")}
                        ))
                        seen_nodes.add(agent_id)
                    edges.append(GraphEdge(
                        source=record_id,
                        target=agent_id,
                        type="PERFORMED_BY",
                        properties={}
                    ))

                # Tool node
                if t:
                    tool_id = f"tool:{t['name']}"
                    if tool_id not in seen_nodes:
                        nodes.append(GraphNode(
                            id=tool_id,
                            label=t["name"],
                            type="tool",
                            properties={}
                        ))
                        seen_nodes.add(tool_id)
                    edges.append(GraphEdge(
                        source=record_id,
                        target=tool_id,
                        type="CALLED",
                        properties={}
                    ))

                # Decision node
                if d:
                    decision_id = f"decision:{d['name']}"
                    if decision_id not in seen_nodes:
                        nodes.append(GraphNode(
                            id=decision_id,
                            label=d["name"],
                            type="decision",
                            properties={}
                        ))
                        seen_nodes.add(decision_id)
                    edges.append(GraphEdge(
                        source=record_id,
                        target=decision_id,
                        type="MADE",
                        properties={}
                    ))

                # Chain link
                if prev:
                    edges.append(GraphEdge(
                        source=record_id,
                        target=prev["record_id"],
                        type="FOLLOWS",
                        properties={}
                    ))

            return ProvenanceGraph(
                nodes=nodes,
                edges=edges,
                metadata={
                    "session_id": session_id,
                    "record_count": len([n for n in nodes if n.type == "record"]),
                    "generated_at": datetime.now(timezone.utc).isoformat(),
                }
            )
    except Exception as e:
        logger.error(f"Failed to get session graph: {e}")
        return None


def get_agent_behavior_graph(agent_id: str, limit: int = 100) -> Optional[ProvenanceGraph]:
    """
    Get behavior graph for a specific agent.
    Shows tools called, decisions made, and patterns.
    """
    if not _neo4j_driver:
        return None

    try:
        with _neo4j_driver.session() as session:
            result = session.run("""
                MATCH (a:Agent {agent_id: $agent_id})<-[:PERFORMED_BY]-(r:ProvenanceRecord)
                OPTIONAL MATCH (r)-[:CALLED]->(t:Tool)
                OPTIONAL MATCH (r)-[:MADE]->(d:Decision)
                OPTIONAL MATCH (r)-[:BELONGS_TO]->(s:Session)
                RETURN r, t, d, s
                ORDER BY r.timestamp DESC
                LIMIT $limit
            """, {"agent_id": agent_id, "limit": limit})

            nodes = []
            edges = []
            seen_nodes = set()
            tool_counts = {}
            decision_counts = {}

            # Add agent node
            nodes.append(GraphNode(
                id=agent_id,
                label=agent_id,
                type="agent",
                properties={}
            ))
            seen_nodes.add(agent_id)

            for record in result:
                r = record["r"]
                t = record["t"]
                d = record["d"]
                s = record["s"]

                record_id = r["record_id"]

                # Tool aggregation
                if t:
                    tool_name = t["name"]
                    tool_counts[tool_name] = tool_counts.get(tool_name, 0) + 1

                # Decision aggregation
                if d:
                    decision_name = d["name"]
                    decision_counts[decision_name] = decision_counts.get(decision_name, 0) + 1

            # Create aggregated tool nodes
            for tool_name, count in tool_counts.items():
                tool_id = f"tool:{tool_name}"
                nodes.append(GraphNode(
                    id=tool_id,
                    label=tool_name,
                    type="tool",
                    properties={"call_count": count}
                ))
                edges.append(GraphEdge(
                    source=agent_id,
                    target=tool_id,
                    type="USES",
                    properties={"count": count}
                ))

            # Create aggregated decision nodes
            for decision_name, count in decision_counts.items():
                decision_id = f"decision:{decision_name}"
                nodes.append(GraphNode(
                    id=decision_id,
                    label=decision_name,
                    type="decision",
                    properties={"count": count}
                ))
                edges.append(GraphEdge(
                    source=agent_id,
                    target=decision_id,
                    type="DECIDES",
                    properties={"count": count}
                ))

            return ProvenanceGraph(
                nodes=nodes,
                edges=edges,
                metadata={
                    "agent_id": agent_id,
                    "total_tools": len(tool_counts),
                    "total_decisions": len(decision_counts),
                    "generated_at": datetime.now(timezone.utc).isoformat(),
                }
            )
    except Exception as e:
        logger.error(f"Failed to get agent behavior graph: {e}")
        return None


def get_attack_path_graph(session_id: str) -> Optional[ProvenanceGraph]:
    """
    Analyze and visualize potential attack paths in a session.
    Highlights suspicious activity sequences.
    """
    if not _neo4j_driver:
        return None

    try:
        with _neo4j_driver.session() as session:
            # Find records with security-related decisions
            result = session.run("""
                MATCH (s:Session {session_id: $session_id})<-[:BELONGS_TO]-(r:ProvenanceRecord)
                WHERE r.activity_type IN ['decision', 'tool_call']
                OPTIONAL MATCH (r)-[:FOLLOWS*1..5]->(chain:ProvenanceRecord)
                OPTIONAL MATCH (r)-[:MADE]->(d:Decision)
                WHERE d.name CONTAINS 'block' OR d.name CONTAINS 'warn'
                RETURN r, collect(DISTINCT chain) as chain_records, d
                ORDER BY r.sequence_number
            """, {"session_id": session_id})

            nodes = []
            edges = []
            seen_nodes = set()

            for record in result:
                r = record["r"]
                chain_records = record["chain_records"]
                d = record["d"]

                record_id = r["record_id"]

                # Highlight blocked/warned records
                is_security_event = d is not None

                if record_id not in seen_nodes:
                    nodes.append(GraphNode(
                        id=record_id,
                        label=r["activity_name"],
                        type="security_event" if is_security_event else "record",
                        properties={
                            "activity_type": r["activity_type"],
                            "timestamp": r["timestamp"],
                            "is_blocked": is_security_event,
                        }
                    ))
                    seen_nodes.add(record_id)

                # Add chain to show attack progression
                prev_id = record_id
                for chain_rec in chain_records:
                    chain_id = chain_rec["record_id"]
                    if chain_id not in seen_nodes:
                        nodes.append(GraphNode(
                            id=chain_id,
                            label=chain_rec["activity_name"],
                            type="record",
                            properties={
                                "activity_type": chain_rec["activity_type"],
                                "timestamp": chain_rec["timestamp"],
                            }
                        ))
                        seen_nodes.add(chain_id)

                    edges.append(GraphEdge(
                        source=prev_id,
                        target=chain_id,
                        type="ATTACK_PATH",
                        properties={}
                    ))
                    prev_id = chain_id

            return ProvenanceGraph(
                nodes=nodes,
                edges=edges,
                metadata={
                    "session_id": session_id,
                    "security_events": len([n for n in nodes if n.type == "security_event"]),
                    "generated_at": datetime.now(timezone.utc).isoformat(),
                }
            )
    except Exception as e:
        logger.error(f"Failed to get attack path graph: {e}")
        return None


# ============================================
# Analytics Queries
# ============================================

def get_tool_usage_stats(days: int = 7) -> dict[str, Any]:
    """Get tool usage statistics."""
    if not _neo4j_driver:
        return {"error": "Neo4j not available"}

    try:
        with _neo4j_driver.session() as session:
            result = session.run("""
                MATCH (r:ProvenanceRecord)-[:CALLED]->(t:Tool)
                WHERE datetime(r.timestamp) > datetime() - duration({days: $days})
                RETURN t.name as tool, count(*) as count
                ORDER BY count DESC
                LIMIT 20
            """, {"days": days})

            stats = {}
            for record in result:
                stats[record["tool"]] = record["count"]

            return {
                "period_days": days,
                "tool_usage": stats,
                "total_calls": sum(stats.values()),
            }
    except Exception as e:
        logger.error(f"Failed to get tool usage stats: {e}")
        return {"error": str(e)}


def get_security_event_stats(days: int = 7) -> dict[str, Any]:
    """Get security event statistics."""
    if not _neo4j_driver:
        return {"error": "Neo4j not available"}

    try:
        with _neo4j_driver.session() as session:
            result = session.run("""
                MATCH (r:ProvenanceRecord)-[:MADE]->(d:Decision)
                WHERE datetime(r.timestamp) > datetime() - duration({days: $days})
                RETURN d.name as decision, count(*) as count
                ORDER BY count DESC
            """, {"days": days})

            stats = {}
            blocked = 0
            warned = 0
            for record in result:
                name = record["decision"]
                count = record["count"]
                stats[name] = count
                if "block" in name.lower():
                    blocked += count
                if "warn" in name.lower():
                    warned += count

            return {
                "period_days": days,
                "decision_counts": stats,
                "total_blocked": blocked,
                "total_warned": warned,
            }
    except Exception as e:
        logger.error(f"Failed to get security event stats: {e}")
        return {"error": str(e)}


def detect_anomalous_patterns() -> list[dict[str, Any]]:
    """
    Use graph algorithms to detect anomalous behavior patterns.
    """
    if not _neo4j_driver:
        return []

    try:
        with _neo4j_driver.session() as session:
            # Find agents with unusual tool usage patterns
            result = session.run("""
                MATCH (a:Agent)<-[:PERFORMED_BY]-(r:ProvenanceRecord)-[:CALLED]->(t:Tool)
                WITH a, t, count(*) as usage
                WITH a, collect({tool: t.name, count: usage}) as tool_usage, sum(usage) as total
                WHERE total > 10
                RETURN a.agent_id as agent, tool_usage, total
                ORDER BY total DESC
                LIMIT 10
            """)

            anomalies = []
            for record in result:
                agent = record["agent"]
                tool_usage = record["tool_usage"]
                total = record["total"]

                # Check for concentrated tool usage (potential automation abuse)
                max_single_tool = max(t["count"] for t in tool_usage)
                if max_single_tool / total > 0.8:  # 80%+ on single tool
                    anomalies.append({
                        "type": "concentrated_tool_usage",
                        "agent": agent,
                        "description": f"Agent uses single tool for {max_single_tool}/{total} calls",
                        "severity": "medium",
                    })

            return anomalies
    except Exception as e:
        logger.error(f"Failed to detect anomalous patterns: {e}")
        return []


# ============================================
# Convenience Functions
# ============================================

def sync_chain_to_graph(session_id: str) -> int:
    """
    Sync a provenance chain to the graph database.
    Call this after recording activities to persist to Neo4j.
    """
    chain = get_or_create_chain(session_id)
    return store_chain(chain)


def get_visualization_data(
    session_id: str = None,
    agent_id: str = None,
    view_type: str = "session"
) -> dict[str, Any]:
    """
    Get visualization data for the frontend.

    Args:
        session_id: Session to visualize
        agent_id: Agent to visualize
        view_type: "session", "agent", or "attack_path"

    Returns:
        Dict with nodes, edges, and metadata
    """
    if view_type == "session" and session_id:
        graph = get_session_graph(session_id)
    elif view_type == "agent" and agent_id:
        graph = get_agent_behavior_graph(agent_id)
    elif view_type == "attack_path" and session_id:
        graph = get_attack_path_graph(session_id)
    else:
        return {"error": "Invalid parameters"}

    if graph:
        return graph.to_dict()
    return {"error": "Failed to generate graph"}


# ============================================
# Trace & Backtrack Functions (역추적)
# ============================================

def trace_record(record_id: str) -> dict:
    """
    특정 레코드에서 연결된 모든 노드를 역추적.

    Returns:
        record 정보 + 연결된 session, agent, tool, decision,
        이전/이후 체인, 저장된 콘텐츠 전부
    """
    if not _neo4j_driver:
        return {"error": "Neo4j not available"}

    try:
        with _neo4j_driver.session() as session:
            result = session.run("""
                MATCH (r:ProvenanceRecord {record_id: $record_id})
                OPTIONAL MATCH (r)-[:BELONGS_TO]->(s:Session)
                OPTIONAL MATCH (r)-[:PERFORMED_BY]->(a:Agent)
                OPTIONAL MATCH (r)-[:CALLED]->(t:Tool)
                OPTIONAL MATCH (r)-[:MADE]->(d:Decision)
                OPTIONAL MATCH (r)-[:USED]->(ue:Entity)
                OPTIONAL MATCH (r)-[:GENERATED]->(ge:Entity)
                OPTIONAL MATCH (r)-[:FOLLOWS]->(prev:ProvenanceRecord)
                OPTIONAL MATCH (next:ProvenanceRecord)-[:FOLLOWS]->(r)
                OPTIONAL MATCH (r)-[:HAS_CONTENT]->(c:ContentStore)
                RETURN r, s, a, t, d,
                       collect(DISTINCT ue) as used_entities,
                       collect(DISTINCT ge) as generated_entities,
                       prev, next,
                       collect(DISTINCT {type: c.content_type, hash: c.content_hash, size: c.original_size}) as contents
            """, record_id=record_id)

            row = result.single()
            if not row or not row["r"]:
                return {"error": "Record not found"}

            r = row["r"]
            trace = {
                "record": {
                    "id": r["record_id"],
                    "timestamp": r["timestamp"],
                    "activity_type": r["activity_type"],
                    "activity_name": r["activity_name"],
                    "hash": r["record_hash"],
                    "previous_hash": r["previous_hash"],
                    "sequence": r["sequence_number"],
                },
                "session": None,
                "agent": None,
                "tool": None,
                "decision": None,
                "used_entities": [],
                "generated_entities": [],
                "previous_record": None,
                "next_record": None,
                "contents": [],
            }

            if row["s"]:
                trace["session"] = {
                    "id": row["s"]["session_id"],
                    "client_id": row["s"].get("client_id"),
                }
            if row["a"]:
                trace["agent"] = {
                    "id": row["a"]["agent_id"],
                    "name": row["a"]["name"],
                }
            if row["t"]:
                trace["tool"] = row["t"]["name"]
            if row["d"]:
                trace["decision"] = row["d"]["name"]
            if row["prev"]:
                trace["previous_record"] = {
                    "id": row["prev"]["record_id"],
                    "action": row["prev"]["activity_name"],
                    "timestamp": row["prev"]["timestamp"],
                }
            if row["next"]:
                trace["next_record"] = {
                    "id": row["next"]["record_id"],
                    "action": row["next"]["activity_name"],
                    "timestamp": row["next"]["timestamp"],
                }

            for e in row["used_entities"]:
                if e and e.get("entity_id"):
                    trace["used_entities"].append({
                        "id": e["entity_id"],
                        "type": e["entity_type"],
                    })
            for e in row["generated_entities"]:
                if e and e.get("entity_id"):
                    trace["generated_entities"].append({
                        "id": e["entity_id"],
                        "type": e["entity_type"],
                    })

            for c in row["contents"]:
                if c and c.get("hash"):
                    trace["contents"].append({
                        "type": c["type"],
                        "hash": c["hash"],
                        "size": c["size"],
                    })

            return trace

    except Exception as e:
        logger.error(f"Failed to trace record: {e}")
        return {"error": str(e)}


def trace_chain_path(record_id: str, direction: str = "both", depth: int = 20) -> dict:
    """
    해시 체인을 따라 이전/이후 레코드 전체 경로 추적.

    Args:
        record_id: 시작 레코드
        direction: "backward" (이전), "forward" (이후), "both"
        depth: 최대 추적 깊이
    """
    if not _neo4j_driver:
        return {"error": "Neo4j not available"}

    try:
        with _neo4j_driver.session() as session:
            chain = {"start": record_id, "backward": [], "forward": []}

            if direction in ("backward", "both"):
                result = session.run("""
                    MATCH path = (start:ProvenanceRecord {record_id: $record_id})-[:FOLLOWS*1..{depth}]->(prev:ProvenanceRecord)
                    UNWIND nodes(path) as n
                    WITH DISTINCT n
                    WHERE n.record_id <> $record_id
                    RETURN n.record_id as id, n.activity_name as action,
                           n.activity_type as type, n.timestamp as time,
                           n.record_hash as hash
                    ORDER BY n.sequence_number ASC
                """.replace("{depth}", str(depth)), record_id=record_id)

                chain["backward"] = [dict(row) for row in result]

            if direction in ("forward", "both"):
                result = session.run("""
                    MATCH path = (next:ProvenanceRecord)-[:FOLLOWS*1..{depth}]->(start:ProvenanceRecord {record_id: $record_id})
                    UNWIND nodes(path) as n
                    WITH DISTINCT n
                    WHERE n.record_id <> $record_id
                    RETURN n.record_id as id, n.activity_name as action,
                           n.activity_type as type, n.timestamp as time,
                           n.record_hash as hash
                    ORDER BY n.sequence_number ASC
                """.replace("{depth}", str(depth)), record_id=record_id)

                chain["forward"] = [dict(row) for row in result]

            chain["total_path_length"] = len(chain["backward"]) + 1 + len(chain["forward"])
            return chain

    except Exception as e:
        logger.error(f"Failed to trace chain path: {e}")
        return {"error": str(e)}


def trace_by_action(client_id: str, action_name: str = None,
                    action_type: str = None, limit: int = 50) -> dict:
    """
    특정 액션/도구/결정으로 모든 관련 기록 추적.

    Args:
        client_id: 고객 ID
        action_name: 액션 이름 (부분 매칭)
        action_type: 액션 타입 (tool_call, decision, user_input 등)
    """
    if not _neo4j_driver:
        return {"error": "Neo4j not available"}

    try:
        with _neo4j_driver.session() as session:
            conditions = ["r.client_id = $client_id"]
            params = {"client_id": client_id, "limit": limit}

            if action_name:
                conditions.append("toLower(r.activity_name) CONTAINS toLower($action_name)")
                params["action_name"] = action_name

            if action_type:
                conditions.append("r.activity_type = $action_type")
                params["action_type"] = action_type

            where = " AND ".join(conditions)

            result = session.run(f"""
                MATCH (r:ProvenanceRecord)
                WHERE {where}
                OPTIONAL MATCH (r)-[:CALLED]->(t:Tool)
                OPTIONAL MATCH (r)-[:MADE]->(d:Decision)
                OPTIONAL MATCH (r)-[:BELONGS_TO]->(s:Session)
                RETURN r.record_id as id, r.timestamp as time,
                       r.activity_type as type, r.activity_name as action,
                       r.record_hash as hash,
                       t.name as tool, d.name as decision,
                       s.session_id as session_id
                ORDER BY r.timestamp DESC
                LIMIT $limit
            """, **params)

            records = [dict(row) for row in result]

            return {
                "query": {
                    "client_id": client_id,
                    "action_name": action_name,
                    "action_type": action_type,
                },
                "count": len(records),
                "records": records,
            }

    except Exception as e:
        logger.error(f"Failed to trace by action: {e}")
        return {"error": str(e)}


def trace_full_graph(client_id: str, limit: int = 100) -> dict:
    """
    고객의 전체 프로비넌스 그래프를 추적.
    모든 노드와 관계를 반환 (시각화용).
    """
    if not _neo4j_driver:
        return {"error": "Neo4j not available"}

    try:
        with _neo4j_driver.session() as session:
            result = session.run("""
                MATCH (r:ProvenanceRecord {client_id: $client_id})
                OPTIONAL MATCH (r)-[:BELONGS_TO]->(s:Session)
                OPTIONAL MATCH (r)-[:PERFORMED_BY]->(a:Agent)
                OPTIONAL MATCH (r)-[:CALLED]->(t:Tool)
                OPTIONAL MATCH (r)-[:MADE]->(d:Decision)
                OPTIONAL MATCH (r)-[:FOLLOWS]->(prev:ProvenanceRecord)
                OPTIONAL MATCH (r)-[:HAS_CONTENT]->(c:ContentStore)
                OPTIONAL MATCH (r)-[:ANCHORED_BY]->(ba:BlockchainAnchor)
                RETURN r, s, a, t, d, prev, c, ba
                ORDER BY r.sequence_number DESC
                LIMIT $limit
            """, client_id=client_id, limit=limit)

            nodes = []
            edges = []
            seen = set()

            for row in result:
                r = row["r"]
                rid = r["record_id"]

                # Record node
                if rid not in seen:
                    nodes.append({
                        "id": rid,
                        "label": r["activity_name"],
                        "type": "record",
                        "group": r["activity_type"],
                        "time": r["timestamp"],
                        "hash": r["record_hash"],
                    })
                    seen.add(rid)

                # Session
                if row["s"]:
                    sid = row["s"]["session_id"]
                    if sid not in seen:
                        nodes.append({"id": sid, "label": sid[:12], "type": "session", "group": "session"})
                        seen.add(sid)
                    edges.append({"source": rid, "target": sid, "type": "BELONGS_TO"})

                # Agent
                if row["a"]:
                    aid = row["a"]["agent_id"]
                    if aid not in seen:
                        nodes.append({"id": aid, "label": row["a"]["name"], "type": "agent", "group": "agent"})
                        seen.add(aid)
                    edges.append({"source": rid, "target": aid, "type": "PERFORMED_BY"})

                # Tool
                if row["t"]:
                    tid = "tool:" + row["t"]["name"]
                    if tid not in seen:
                        nodes.append({"id": tid, "label": row["t"]["name"], "type": "tool", "group": "tool"})
                        seen.add(tid)
                    edges.append({"source": rid, "target": tid, "type": "CALLED"})

                # Decision
                if row["d"]:
                    did = "decision:" + row["d"]["name"]
                    if did not in seen:
                        nodes.append({"id": did, "label": row["d"]["name"], "type": "decision", "group": "decision"})
                        seen.add(did)
                    edges.append({"source": rid, "target": did, "type": "MADE"})

                # Chain
                if row["prev"]:
                    edges.append({"source": rid, "target": row["prev"]["record_id"], "type": "FOLLOWS"})

                # Content
                if row["c"]:
                    cid = "content:" + (row["c"].get("content_hash") or "")[:12]
                    if cid not in seen and row["c"].get("content_hash"):
                        nodes.append({"id": cid, "label": row["c"]["content_type"], "type": "content", "group": "content"})
                        seen.add(cid)
                    if row["c"].get("content_hash"):
                        edges.append({"source": rid, "target": cid, "type": "HAS_CONTENT"})

                # Blockchain
                if row["ba"]:
                    baid = "anchor:" + (row["ba"].get("transaction_hash") or "")[:12]
                    if baid not in seen and row["ba"].get("transaction_hash"):
                        nodes.append({"id": baid, "label": "Polygon Anchor", "type": "blockchain", "group": "blockchain"})
                        seen.add(baid)
                    if row["ba"].get("transaction_hash"):
                        edges.append({"source": rid, "target": baid, "type": "ANCHORED_BY"})

            return {
                "nodes": nodes,
                "edges": edges,
                "stats": {
                    "total_nodes": len(nodes),
                    "total_edges": len(edges),
                    "records": len([n for n in nodes if n["type"] == "record"]),
                    "tools": len([n for n in nodes if n["type"] == "tool"]),
                    "sessions": len([n for n in nodes if n["type"] == "session"]),
                },
            }

    except Exception as e:
        logger.error(f"Failed to get full trace graph: {e}")
        return {"error": str(e)}


def trace_timeline(client_id: str, limit: int = 200) -> dict:
    """
    고객의 전체 타임라인 (시간순 모든 기록).
    """
    if not _neo4j_driver:
        return {"error": "Neo4j not available"}

    try:
        with _neo4j_driver.session() as session:
            result = session.run("""
                MATCH (r:ProvenanceRecord {client_id: $client_id})
                OPTIONAL MATCH (r)-[:CALLED]->(t:Tool)
                OPTIONAL MATCH (r)-[:HAS_CONTENT]->(c:ContentStore)
                RETURN r.record_id as id,
                       r.timestamp as time,
                       r.activity_type as type,
                       r.activity_name as action,
                       r.record_hash as hash,
                       r.sequence_number as seq,
                       t.name as tool,
                       c.content_type as content_type,
                       c.original_size as content_size
                ORDER BY r.sequence_number ASC
                LIMIT $limit
            """, client_id=client_id, limit=limit)

            records = [dict(row) for row in result]

            return {
                "client_id": client_id,
                "count": len(records),
                "timeline": records,
            }

    except Exception as e:
        logger.error(f"Failed to get timeline: {e}")
        return {"error": str(e)}
