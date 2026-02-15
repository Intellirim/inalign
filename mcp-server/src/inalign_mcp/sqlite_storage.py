"""
SQLite Local Storage for InALign Provenance

Provides persistent local storage for provenance records without requiring
Neo4j or any external service. Data is stored at ~/.inalign/provenance.db.

Features:
- Zero configuration: auto-creates database on first use
- Full provenance chain persistence across sessions
- Session history browsing
- Works completely offline
- No external dependencies (uses Python stdlib sqlite3)
"""

import json
import os
import sqlite3
import logging
from pathlib import Path
from typing import Any, Optional
from datetime import datetime, timezone

from .provenance import (
    ProvenanceRecord,
    ProvenanceChain,
    ActivityType,
    Entity,
    Agent,
)

logger = logging.getLogger("inalign-mcp")

# Database location
INALIGN_DIR = Path.home() / ".inalign"
DB_PATH = INALIGN_DIR / "provenance.db"

_connection: Optional[sqlite3.Connection] = None


def _get_db() -> sqlite3.Connection:
    """Get or create SQLite connection."""
    global _connection
    if _connection is not None:
        return _connection

    # Ensure directory exists
    INALIGN_DIR.mkdir(parents=True, exist_ok=True)

    _connection = sqlite3.connect(str(DB_PATH), check_same_thread=False)
    _connection.row_factory = sqlite3.Row
    _connection.execute("PRAGMA journal_mode=WAL")
    _connection.execute("PRAGMA foreign_keys=ON")

    _init_schema(_connection)
    return _connection


def _init_schema(conn: sqlite3.Connection):
    """Create tables if they don't exist."""
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS sessions (
            session_id TEXT PRIMARY KEY,
            agent_id TEXT NOT NULL,
            agent_name TEXT NOT NULL,
            agent_type TEXT DEFAULT 'ai_agent',
            client_id TEXT DEFAULT '',
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            record_count INTEGER DEFAULT 0
        );

        CREATE TABLE IF NOT EXISTS records (
            id TEXT PRIMARY KEY,
            session_id TEXT NOT NULL,
            sequence_number INTEGER NOT NULL,
            timestamp TEXT NOT NULL,
            activity_type TEXT NOT NULL,
            activity_name TEXT NOT NULL,
            activity_attributes TEXT DEFAULT '{}',
            used_entities TEXT DEFAULT '[]',
            generated_entities TEXT DEFAULT '[]',
            agent_id TEXT,
            agent_name TEXT,
            agent_type TEXT,
            previous_hash TEXT DEFAULT '',
            record_hash TEXT NOT NULL,
            client_id TEXT DEFAULT '',
            signature TEXT,
            signer_id TEXT,
            FOREIGN KEY (session_id) REFERENCES sessions(session_id)
        );

        CREATE INDEX IF NOT EXISTS idx_records_session
            ON records(session_id, sequence_number);

        CREATE INDEX IF NOT EXISTS idx_records_timestamp
            ON records(timestamp);

        CREATE INDEX IF NOT EXISTS idx_records_client
            ON records(client_id);

        -- Agent permissions (permissions.py)
        CREATE TABLE IF NOT EXISTS agent_permissions (
            agent_id TEXT NOT NULL,
            tool_name TEXT NOT NULL,
            permission TEXT NOT NULL DEFAULT 'allow',
            reason TEXT DEFAULT '',
            set_by TEXT DEFAULT 'system',
            set_at TEXT NOT NULL,
            PRIMARY KEY (agent_id, tool_name)
        );

        CREATE TABLE IF NOT EXISTS agent_defaults (
            agent_id TEXT PRIMARY KEY,
            agent_name TEXT DEFAULT '',
            default_permission TEXT NOT NULL DEFAULT 'allow',
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );

        -- Behavior drift baselines (drift_detector.py)
        CREATE TABLE IF NOT EXISTS behavior_baselines (
            agent_id TEXT PRIMARY KEY,
            session_count INTEGER DEFAULT 0,
            total_actions INTEGER DEFAULT 0,
            tool_frequency TEXT DEFAULT '{}',
            tool_stddev TEXT DEFAULT '{}',
            avg_session_length REAL DEFAULT 0,
            avg_interval_seconds REAL DEFAULT 0,
            known_tools TEXT DEFAULT '[]',
            updated_at TEXT NOT NULL
        );

        -- Multi-agent topology (topology.py)
        CREATE TABLE IF NOT EXISTS agent_interactions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            source_agent TEXT NOT NULL,
            target_agent TEXT NOT NULL,
            interaction_type TEXT DEFAULT 'delegate',
            session_id TEXT NOT NULL,
            timestamp TEXT NOT NULL,
            metadata TEXT DEFAULT '{}'
        );

        CREATE INDEX IF NOT EXISTS idx_interactions_session
            ON agent_interactions(session_id);

        CREATE INDEX IF NOT EXISTS idx_interactions_agents
            ON agent_interactions(source_agent, target_agent);

        -- Cost tracking (topology.py)
        CREATE TABLE IF NOT EXISTS cost_tracking (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id TEXT NOT NULL,
            agent_id TEXT NOT NULL,
            model TEXT NOT NULL,
            provider TEXT DEFAULT 'unknown',
            input_tokens INTEGER DEFAULT 0,
            output_tokens INTEGER DEFAULT 0,
            cost_usd REAL DEFAULT 0.0,
            timestamp TEXT NOT NULL
        );

        CREATE INDEX IF NOT EXISTS idx_cost_session
            ON cost_tracking(session_id);

        CREATE INDEX IF NOT EXISTS idx_cost_agent
            ON cost_tracking(agent_id);
    """)
    conn.commit()


def init_sqlite() -> bool:
    """Initialize SQLite storage. Returns True if successful."""
    try:
        conn = _get_db()
        # Quick health check
        conn.execute("SELECT 1")
        logger.info(f"[SQLITE] Initialized: {DB_PATH}")
        return True
    except Exception as e:
        logger.error(f"[SQLITE] Failed to initialize: {e}")
        return False


def store_session(session_id: str, agent: Agent, client_id: str = ""):
    """Create or update a session record."""
    conn = _get_db()
    now = datetime.now(timezone.utc).isoformat()
    conn.execute(
        """INSERT INTO sessions (session_id, agent_id, agent_name, agent_type, client_id, created_at, updated_at)
           VALUES (?, ?, ?, ?, ?, ?, ?)
           ON CONFLICT(session_id) DO UPDATE SET updated_at=?, record_count=record_count""",
        (session_id, agent.id, agent.name, agent.type, client_id, now, now, now),
    )
    conn.commit()


def store_record(record: ProvenanceRecord):
    """Persist a single provenance record to SQLite."""
    conn = _get_db()

    used = json.dumps([
        {"id": e.id, "type": e.type, "value_hash": e.value_hash, "attributes": e.attributes}
        for e in record.used_entities
    ])
    generated = json.dumps([
        {"id": e.id, "type": e.type, "value_hash": e.value_hash, "attributes": e.attributes}
        for e in record.generated_entities
    ])
    attrs = json.dumps(record.activity_attributes, default=str)

    try:
        conn.execute(
            """INSERT INTO records
               (id, session_id, sequence_number, timestamp, activity_type, activity_name,
                activity_attributes, used_entities, generated_entities,
                agent_id, agent_name, agent_type, previous_hash, record_hash,
                client_id, signature, signer_id)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                record.id,
                record.session_id,
                record.sequence_number,
                record.timestamp,
                record.activity_type.value,
                record.activity_name,
                attrs,
                used,
                generated,
                record.agent.id if record.agent else None,
                record.agent.name if record.agent else None,
                record.agent.type if record.agent else None,
                record.previous_hash,
                record.record_hash,
                record.client_id,
                record.signature,
                record.signer_id,
            ),
        )
    except sqlite3.IntegrityError:
        logger.warning(f"[SQLITE] Duplicate record {record.id} — refusing to overwrite (immutable chain)")
        return

    # Update session record count
    conn.execute(
        "UPDATE sessions SET updated_at=?, record_count=record_count+1 WHERE session_id=?",
        (datetime.now(timezone.utc).isoformat(), record.session_id),
    )
    conn.commit()


def load_chain(session_id: str) -> Optional[ProvenanceChain]:
    """Load a full provenance chain from SQLite for a given session."""
    conn = _get_db()

    # Load session info
    row = conn.execute(
        "SELECT * FROM sessions WHERE session_id=?", (session_id,)
    ).fetchone()

    if not row:
        return None

    agent = Agent(
        id=row["agent_id"],
        type=row["agent_type"],
        name=row["agent_name"],
    )
    chain = ProvenanceChain(session_id, agent, row["client_id"])

    # Load records in order
    rows = conn.execute(
        "SELECT * FROM records WHERE session_id=? ORDER BY sequence_number ASC",
        (session_id,),
    ).fetchall()

    for r in rows:
        used_entities = []
        for e in json.loads(r["used_entities"]):
            used_entities.append(Entity(
                id=e["id"], type=e["type"],
                value_hash=e["value_hash"],
                attributes=e.get("attributes", {}),
            ))

        generated_entities = []
        for e in json.loads(r["generated_entities"]):
            generated_entities.append(Entity(
                id=e["id"], type=e["type"],
                value_hash=e["value_hash"],
                attributes=e.get("attributes", {}),
            ))

        record_agent = Agent(
            id=r["agent_id"] or agent.id,
            type=r["agent_type"] or agent.type,
            name=r["agent_name"] or agent.name,
        )

        record = ProvenanceRecord(
            id=r["id"],
            timestamp=r["timestamp"],
            activity_type=ActivityType(r["activity_type"]),
            activity_name=r["activity_name"],
            activity_attributes=json.loads(r["activity_attributes"]),
            used_entities=used_entities,
            generated_entities=generated_entities,
            agent=record_agent,
            previous_hash=r["previous_hash"],
            sequence_number=r["sequence_number"],
            session_id=r["session_id"],
            client_id=r["client_id"] or "",
            record_hash=r["record_hash"],
            signature=r["signature"],
            signer_id=r["signer_id"],
        )
        chain.records.append(record)

    chain._sequence = len(chain.records)
    return chain


def list_sessions(limit: int = 20, client_id: str = None) -> list[dict]:
    """List recent sessions with summary info."""
    conn = _get_db()

    if client_id:
        rows = conn.execute(
            "SELECT * FROM sessions WHERE client_id=? ORDER BY updated_at DESC LIMIT ?",
            (client_id, limit),
        ).fetchall()
    else:
        rows = conn.execute(
            "SELECT * FROM sessions ORDER BY updated_at DESC LIMIT ?",
            (limit,),
        ).fetchall()

    return [
        {
            "session_id": r["session_id"],
            "agent_name": r["agent_name"],
            "client_id": r["client_id"],
            "created_at": r["created_at"],
            "updated_at": r["updated_at"],
            "record_count": r["record_count"],
        }
        for r in rows
    ]


def get_session_count() -> int:
    """Get total number of sessions stored."""
    conn = _get_db()
    row = conn.execute("SELECT COUNT(*) as cnt FROM sessions").fetchone()
    return row["cnt"] if row else 0


def get_record_count() -> int:
    """Get total number of records stored."""
    conn = _get_db()
    row = conn.execute("SELECT COUNT(*) as cnt FROM records").fetchone()
    return row["cnt"] if row else 0


def get_db_path() -> str:
    """Get the path to the SQLite database file."""
    return str(DB_PATH)


def store_records_batch(records: list, session_id: str = ""):
    """Persist multiple provenance records in a single transaction.

    Much more efficient than calling store_record() in a loop
    (single commit instead of N commits).
    """
    if not records:
        return

    conn = _get_db()
    try:
        for record in records:
            used = json.dumps([
                {"id": e.id, "type": e.type, "value_hash": e.value_hash, "attributes": e.attributes}
                for e in record.used_entities
            ])
            generated = json.dumps([
                {"id": e.id, "type": e.type, "value_hash": e.value_hash, "attributes": e.attributes}
                for e in record.generated_entities
            ])
            attrs = json.dumps(record.activity_attributes, default=str)

            try:
                conn.execute(
                    """INSERT INTO records
                       (id, session_id, sequence_number, timestamp, activity_type, activity_name,
                        activity_attributes, used_entities, generated_entities,
                        agent_id, agent_name, agent_type, previous_hash, record_hash,
                        client_id, signature, signer_id)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (
                        record.id,
                        record.session_id,
                        record.sequence_number,
                        record.timestamp,
                        record.activity_type.value,
                        record.activity_name,
                        attrs,
                        used,
                        generated,
                        record.agent.id if record.agent else None,
                        record.agent.name if record.agent else None,
                        record.agent.type if record.agent else None,
                        record.previous_hash,
                        record.record_hash,
                        record.client_id or "",
                        record.signature,
                        record.signer_id,
                    ),
                )
            except sqlite3.IntegrityError:
                logger.debug(f"[SQLITE] Skipping duplicate record {record.id} in batch")
                continue

        # Set final record count (not incremental)
        sid = session_id or (records[0].session_id if records else "")
        if sid:
            conn.execute(
                "UPDATE sessions SET updated_at=?, record_count=? WHERE session_id=?",
                (datetime.now(timezone.utc).isoformat(), len(records), sid),
            )
        conn.commit()
    except Exception:
        conn.rollback()
        raise


def close():
    """Close the database connection."""
    global _connection
    if _connection:
        _connection.close()
        _connection = None
