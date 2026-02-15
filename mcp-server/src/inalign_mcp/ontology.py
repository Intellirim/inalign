"""
InALign Ontology Layer — W3C PROV-O + SQLite Adjacency List + Recursive CTE

Ontology (blueprint):
  "ToolCall is a subtype of Activity" — schema definition
Knowledge Graph (data):
  "At 14:32 Claude called read_file" — instance data

W3C PROV-O compatible with InALign extensions. The ontology is the schema;
the nodes/edges tables hold the knowledge graph instances.

Classes (7):
  Agent      — AI agent (Claude, GPT, Cursor)
  Session    — Work session
  ToolCall   — Tool invocation (read_file, bash, web_search)
  Entity     — Artifact (file, URL, env var, secret)
  Decision   — Agent judgment/choice
  Risk       — Detected risk pattern
  Policy     — Applied policy rule

Relations (10):
  performed    — Agent → ToolCall
  partOf       — ToolCall → Session
  used         — ToolCall → Entity
  generated    — ToolCall → Entity
  triggeredBy  — ToolCall → Decision
  detected     — ToolCall → Risk
  violates     — ToolCall → Policy
  precedes     — ToolCall → ToolCall (temporal ordering)
  derivedFrom  — Entity → Entity
  signedBy     — Session → Agent (hash chain signature)

Competency Questions (CQ):
  Q1: "Has this agent accessed .env files?"
      Agent -performed→ ToolCall -used→ Entity(.env)
  Q2: "What files were read before an external URL call?"
      Entity(file) ←used- ToolCall₁ -precedes→ ToolCall₂ -used→ Entity(URL)
  Q3: "Which policies were violated in HIGH-risk sessions?"
      Session ←partOf- ToolCall -detected→ Risk(HIGH) -violates→ Policy
  Q4: "What downstream entities are affected if a file is tampered?"
      Entity -derivedFrom→ Entity -derivedFrom→ ... (recursive)
  Q5: "What happened before/after a hash chain break?"
      ToolCall(broken) -precedes/preceded→ ToolCall chain
"""

import json
import sqlite3
import logging
import hashlib
from pathlib import Path
from typing import Any
from datetime import datetime, timezone

logger = logging.getLogger("inalign-mcp")

INALIGN_DIR = Path.home() / ".inalign"
DB_PATH = INALIGN_DIR / "provenance.db"

# Ontology schema version
ONTOLOGY_VERSION = "0.7.0"

# Valid node classes (W3C PROV + InALign)
NODE_CLASSES = {"Agent", "Session", "ToolCall", "Entity", "Decision", "Risk", "Policy"}

# Valid relation types
RELATION_TYPES = {
    "performed",     # Agent → ToolCall
    "partOf",        # ToolCall → Session
    "used",          # ToolCall → Entity
    "generated",     # ToolCall → Entity
    "triggeredBy",   # ToolCall → Decision
    "detected",      # ToolCall → Risk
    "violates",      # ToolCall → Policy
    "precedes",      # ToolCall → ToolCall (temporal)
    "derivedFrom",   # Entity → Entity
    "signedBy",      # Session → Agent
}


# ---- Schema ------------------------------------------------------------------
def init_ontology_schema(conn: sqlite3.Connection) -> None:
    """Create ontology tables if they don't exist."""
    conn.executescript("""
        -- Ontology metadata & version tracking
        CREATE TABLE IF NOT EXISTS ontology_meta (
            version TEXT PRIMARY KEY,
            created_at TEXT NOT NULL,
            classes_count INTEGER DEFAULT 0,
            relations_count INTEGER DEFAULT 0,
            migration_from TEXT DEFAULT ''
        );

        -- Knowledge graph nodes
        CREATE TABLE IF NOT EXISTS ontology_nodes (
            id TEXT PRIMARY KEY,
            node_class TEXT NOT NULL,
            label TEXT NOT NULL DEFAULT '',
            session_id TEXT NOT NULL DEFAULT '',
            timestamp TEXT NOT NULL DEFAULT '',
            attributes TEXT DEFAULT '{}',
            record_hash TEXT DEFAULT '',
            created_at TEXT NOT NULL
        );

        CREATE INDEX IF NOT EXISTS idx_onto_nodes_session
            ON ontology_nodes(session_id);
        CREATE INDEX IF NOT EXISTS idx_onto_nodes_class
            ON ontology_nodes(node_class);
        CREATE INDEX IF NOT EXISTS idx_onto_nodes_ts
            ON ontology_nodes(timestamp);

        -- Knowledge graph edges (with hash chain link)
        CREATE TABLE IF NOT EXISTS ontology_edges (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            source_id TEXT NOT NULL,
            target_id TEXT NOT NULL,
            relation TEXT NOT NULL,
            session_id TEXT NOT NULL DEFAULT '',
            timestamp TEXT NOT NULL DEFAULT '',
            confidence REAL DEFAULT 1.0,
            record_hash TEXT DEFAULT '',
            attributes TEXT DEFAULT '{}',
            FOREIGN KEY (source_id) REFERENCES ontology_nodes(id),
            FOREIGN KEY (target_id) REFERENCES ontology_nodes(id)
        );

        CREATE INDEX IF NOT EXISTS idx_onto_edges_source
            ON ontology_edges(source_id);
        CREATE INDEX IF NOT EXISTS idx_onto_edges_target
            ON ontology_edges(target_id);
        CREATE INDEX IF NOT EXISTS idx_onto_edges_relation
            ON ontology_edges(relation);
        CREATE INDEX IF NOT EXISTS idx_onto_edges_session
            ON ontology_edges(session_id);
        CREATE INDEX IF NOT EXISTS idx_onto_edges_hash
            ON ontology_edges(record_hash);
    """)
    conn.commit()


def _ensure_version(conn: sqlite3.Connection) -> None:
    """Ensure ontology version is registered."""
    row = conn.execute(
        "SELECT version FROM ontology_meta WHERE version=?", (ONTOLOGY_VERSION,)
    ).fetchone()
    if not row:
        conn.execute(
            "INSERT OR IGNORE INTO ontology_meta (version, created_at, classes_count, relations_count) VALUES (?, ?, ?, ?)",
            (ONTOLOGY_VERSION, datetime.now(timezone.utc).isoformat(),
             len(NODE_CLASSES), len(RELATION_TYPES)),
        )
        conn.commit()


def _get_db() -> sqlite3.Connection:
    """Get SQLite connection with ontology schema initialized."""
    INALIGN_DIR.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(DB_PATH), check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    init_ontology_schema(conn)
    _ensure_version(conn)
    return conn


# ---- Node & Edge Operations --------------------------------------------------
def _make_id(prefix: str, *parts: str) -> str:
    """Generate deterministic node ID from parts."""
    raw = ":".join(parts)
    return f"{prefix}:{hashlib.sha256(raw.encode()).hexdigest()[:12]}"


def _upsert_node(
    conn: sqlite3.Connection,
    node_id: str,
    node_class: str,
    label: str,
    session_id: str = "",
    timestamp: str = "",
    attributes: dict | None = None,
    record_hash: str = "",
) -> None:
    """Insert or update a knowledge graph node."""
    now = datetime.now(timezone.utc).isoformat()
    conn.execute(
        """INSERT INTO ontology_nodes
           (id, node_class, label, session_id, timestamp, attributes, record_hash, created_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?)
           ON CONFLICT(id) DO UPDATE SET
             label=excluded.label,
             attributes=excluded.attributes,
             record_hash=excluded.record_hash""",
        (node_id, node_class, label, session_id, timestamp,
         json.dumps(attributes or {}, default=str), record_hash, now),
    )


def _insert_edge(
    conn: sqlite3.Connection,
    source_id: str,
    target_id: str,
    relation: str,
    session_id: str = "",
    timestamp: str = "",
    confidence: float = 1.0,
    record_hash: str = "",
    attributes: dict | None = None,
) -> None:
    """Insert a knowledge graph edge with hash chain link."""
    conn.execute(
        """INSERT INTO ontology_edges
           (source_id, target_id, relation, session_id, timestamp, confidence, record_hash, attributes)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
        (source_id, target_id, relation, session_id, timestamp,
         confidence, record_hash, json.dumps(attributes or {}, default=str)),
    )


# ---- Auto-populate from Provenance Records -----------------------------------
def populate_from_session(session_id: str) -> dict[str, Any]:
    """Build knowledge graph from provenance records for a session.

    Maps provenance records to ontology classes:
      - Agent nodes from agent_id/agent_name
      - Session node from session_id
      - ToolCall nodes from each provenance record
      - Entity nodes from used_entities/generated_entities
      - precedes edges between consecutive ToolCalls
      - performed edges from Agent → ToolCall
      - partOf edges from ToolCall → Session
      - used/generated edges for entities
      - signedBy edge from Session → Agent

    Each edge carries the record_hash linking it to the tamper-proof chain.
    """
    conn = _get_db()
    nodes_created = 0
    edges_created = 0

    try:
        # Load provenance records
        rows = conn.execute(
            "SELECT * FROM records WHERE session_id=? ORDER BY sequence_number ASC",
            (session_id,),
        ).fetchall()

        if not rows:
            return {"nodes": 0, "edges": 0, "status": "no_records"}

        # --- Session node ---
        session_node_id = f"sess:{session_id[:12]}"
        first_ts = rows[0]["timestamp"]
        _upsert_node(conn, session_node_id, "Session", f"Session {session_id[:8]}",
                      session_id, first_ts, {"record_count": len(rows)})
        nodes_created += 1

        # --- Agent node (primary) ---
        agent_raw_id = rows[0]["agent_id"] or "unknown"
        agent_name = rows[0]["agent_name"] or "Claude Code"
        agent_node_id = _make_id("agt", agent_raw_id)
        _upsert_node(conn, agent_node_id, "Agent", agent_name,
                      session_id, first_ts,
                      {"agent_id": agent_raw_id, "agent_type": rows[0]["agent_type"] or ""})
        nodes_created += 1

        # signedBy: Session → Agent
        _insert_edge(conn, session_node_id, agent_node_id,
                      "signedBy", session_id, first_ts,
                      record_hash=rows[0]["record_hash"])
        edges_created += 1

        prev_toolcall_id = None

        for row in rows:
            ts = row["timestamp"]
            seq = row["sequence_number"]
            act_type = row["activity_type"]
            act_name = row["activity_name"]
            rec_hash = row["record_hash"]
            attrs = json.loads(row["activity_attributes"] or "{}")

            # --- ToolCall node ---
            tc_id = f"tc:{session_id[:8]}:{seq:06d}"
            _upsert_node(conn, tc_id, "ToolCall", act_name,
                          session_id, ts,
                          {"activity_type": act_type, "sequence": seq, **attrs},
                          record_hash=rec_hash)
            nodes_created += 1

            # performed: Agent → ToolCall
            _insert_edge(conn, agent_node_id, tc_id,
                          "performed", session_id, ts, record_hash=rec_hash)
            edges_created += 1

            # partOf: ToolCall → Session
            _insert_edge(conn, tc_id, session_node_id,
                          "partOf", session_id, ts, record_hash=rec_hash)
            edges_created += 1

            # precedes: prev_ToolCall → ToolCall (temporal chain)
            if prev_toolcall_id:
                _insert_edge(conn, prev_toolcall_id, tc_id,
                              "precedes", session_id, ts, record_hash=rec_hash)
                edges_created += 1
            prev_toolcall_id = tc_id

            # --- Entity nodes from used_entities ---
            for ent in json.loads(row["used_entities"] or "[]"):
                ent_raw_id = ent.get("id", "")
                ent_type = ent.get("type", "unknown")
                ent_id = _make_id("ent", session_id[:8], ent_raw_id or str(ent))
                ent_label = ent_raw_id or ent_type
                _upsert_node(conn, ent_id, "Entity", ent_label,
                              session_id, ts,
                              {"entity_type": ent_type,
                               "value_hash": ent.get("value_hash", ""),
                               **ent.get("attributes", {})})
                nodes_created += 1
                # used: ToolCall → Entity
                _insert_edge(conn, tc_id, ent_id,
                              "used", session_id, ts, record_hash=rec_hash)
                edges_created += 1

            # --- Entity nodes from generated_entities ---
            for ent in json.loads(row["generated_entities"] or "[]"):
                ent_raw_id = ent.get("id", "")
                ent_type = ent.get("type", "unknown")
                ent_id = _make_id("ent", session_id[:8], ent_raw_id or str(ent))
                ent_label = ent_raw_id or ent_type
                _upsert_node(conn, ent_id, "Entity", ent_label,
                              session_id, ts,
                              {"entity_type": ent_type,
                               "value_hash": ent.get("value_hash", ""),
                               **ent.get("attributes", {})})
                nodes_created += 1
                # generated: ToolCall → Entity
                _insert_edge(conn, tc_id, ent_id,
                              "generated", session_id, ts, record_hash=rec_hash)
                edges_created += 1

        conn.commit()
        logger.info(f"[ONTOLOGY] Populated session {session_id[:8]}: {nodes_created} nodes, {edges_created} edges")

    except Exception as e:
        conn.rollback()
        logger.error(f"[ONTOLOGY] Populate failed: {e}")
        return {"nodes": 0, "edges": 0, "error": str(e)}
    finally:
        conn.close()

    return {
        "session_id": session_id,
        "nodes": nodes_created,
        "edges": edges_created,
        "ontology_version": ONTOLOGY_VERSION,
        "status": "ok",
    }


def populate_decisions(session_id: str) -> dict[str, Any]:
    """Populate Decision nodes from session log (user prompts → agent actions).

    Extracts user messages from json.gz session log and creates:
      - Decision nodes for each user prompt
      - triggeredBy edges: subsequent ToolCall → Decision
      - used edges: Decision → Entity (if prompt references files/URLs)

    This captures WHY the agent acted (the user's intent/command).
    """
    import gzip
    conn = _get_db()
    nodes_created = 0
    edges_created = 0

    try:
        # Load session log from json.gz
        sessions_dir = INALIGN_DIR / "sessions"
        if not sessions_dir.exists():
            return {"nodes": 0, "edges": 0, "status": "no_session_dir"}

        session_log = []
        for f in sorted(sessions_dir.glob("*.json.gz"),
                        key=lambda x: x.stat().st_mtime, reverse=True):
            if session_id[:8] in f.name or not session_log:
                try:
                    with gzip.open(f, "rt", encoding="utf-8") as gz:
                        data = json.load(gz)
                        if isinstance(data, dict):
                            session_log = data.get("records", [])
                        elif isinstance(data, list):
                            session_log = data
                    if session_log:
                        break
                except Exception:
                    continue

        if not session_log:
            return {"nodes": 0, "edges": 0, "status": "no_session_log"}

        # Extract user prompts and link to subsequent tool calls
        decision_seq = 0
        pending_decision_id = None

        for idx, entry in enumerate(session_log):
            role = entry.get("role", "")
            content = entry.get("content", "")
            record_type = entry.get("type", "")
            ts = entry.get("timestamp", "")

            # User message = Decision node
            if role == "user" and content:
                # Truncate for storage (full text in PII-safe preview)
                preview = content[:200] if isinstance(content, str) else str(content)[:200]
                decision_id = f"dec:{session_id[:8]}:{decision_seq:04d}"
                _upsert_node(conn, decision_id, "Decision", preview,
                              session_id, ts,
                              {"full_length": len(str(content)),
                               "sequence_index": idx})
                nodes_created += 1
                pending_decision_id = decision_id
                decision_seq += 1

            # Tool call after a user prompt → triggeredBy
            elif pending_decision_id and record_type == "tool_call":
                tool_name = entry.get("tool_name", "")
                tc_id = f"tc:{session_id[:8]}:{idx:06d}"
                # Check if this ToolCall node already exists (from populate_from_session)
                existing = conn.execute(
                    "SELECT id FROM ontology_nodes WHERE id=?", (tc_id,)
                ).fetchone()
                if not existing:
                    # Create ToolCall node if not from provenance
                    _upsert_node(conn, tc_id, "ToolCall", tool_name,
                                  session_id, ts, {"source": "session_log"})
                    nodes_created += 1

                _insert_edge(conn, tc_id, pending_decision_id,
                              "triggeredBy", session_id, ts)
                edges_created += 1

        conn.commit()
        logger.info(f"[ONTOLOGY] Decisions for {session_id[:8]}: {nodes_created} nodes, {edges_created} edges")

    except Exception as e:
        conn.rollback()
        return {"nodes": 0, "edges": 0, "error": str(e)}
    finally:
        conn.close()

    return {"nodes": nodes_created, "edges": edges_created, "status": "ok"}


def populate_risks(session_id: str) -> dict[str, Any]:
    """Populate Risk and Policy nodes from risk analysis results.

    Adds detected → Risk and violates → Policy edges.
    """
    conn = _get_db()
    nodes_created = 0
    edges_created = 0

    try:
        from .risk_analyzer import analyze_session_risk
        risk_data = analyze_session_risk(session_id)

        for p in risk_data.get("patterns", []):
            risk_id = _make_id("risk", session_id[:8], p["id"])
            _upsert_node(conn, risk_id, "Risk", p["name"],
                          session_id, "",
                          {"risk_level": p["risk"], "confidence": p["confidence"],
                           "description": p["description"],
                           "mitre_tactic": p.get("mitre_tactic", ""),
                           "mitre_techniques": p.get("mitre_techniques", [])})
            nodes_created += 1

            # Link matched ToolCalls → detected → Risk
            for rec_idx in p.get("matched_records", []):
                if isinstance(rec_idx, str) and rec_idx.isdigit():
                    tc_id = f"tc:{session_id[:8]}:{int(rec_idx):06d}"
                    # Check if tc node exists
                    exists = conn.execute(
                        "SELECT 1 FROM ontology_nodes WHERE id=?", (tc_id,)
                    ).fetchone()
                    if exists:
                        _insert_edge(conn, tc_id, risk_id,
                                      "detected", session_id, "",
                                      confidence=p["confidence"])
                        edges_created += 1

        conn.commit()
    except Exception as e:
        conn.rollback()
        return {"nodes": 0, "edges": 0, "error": str(e)}
    finally:
        conn.close()

    return {"nodes": nodes_created, "edges": edges_created, "status": "ok"}


# ---- Data Flow Population (derivedFrom + used/generated + sensitivity) -------

# Sensitivity patterns for Entity classification
_SENSITIVITY = {
    "CRITICAL": [".env", ".pem", ".key", "credentials", "id_rsa", "id_ed25519",
                 "api_key", "secret", ".pypirc", "token", ".p12", ".pfx"],
    "HIGH": [".conf", ".yaml", ".yml", ".db", ".sqlite", "docker-compose",
             ".ssh", "config", "password", ".htpasswd", ".pgpass"],
    "MEDIUM": [".py", ".js", ".ts", ".go", ".rs", ".java", "src/", "lib/"],
}

# Tool names that read files
_READ_TOOLS = {"Read", "read_file", "view", "cat", "Glob", "Grep", "head", "tail"}
# Tool names that write/modify files
_WRITE_TOOLS = {"Write", "write_file", "Edit", "str_replace", "create_file",
                "NotebookEdit", "create"}
# Tool names that involve external/network access
_EXTERNAL_TOOLS = {"Bash", "WebFetch", "WebSearch", "web_search", "fetch", "curl"}

import re
_PATH_RE = re.compile(
    r'(?:file_path|path|file|filename|target|source)["\':\s]+["\']?'
    r'([A-Za-z]:[/\\][^\s"\'<>|]+|/[^\s"\'<>|]+|~[/\\][^\s"\'<>|]+)',
    re.IGNORECASE,
)
_URL_RE = re.compile(r'https?://[^\s"\'<>]+', re.IGNORECASE)


def _classify_sensitivity(path_or_label: str) -> str:
    """Classify an entity path into CRITICAL/HIGH/MEDIUM/LOW."""
    lower = path_or_label.lower()
    for level in ("CRITICAL", "HIGH", "MEDIUM"):
        for pattern in _SENSITIVITY[level]:
            if pattern in lower:
                return level
    return "LOW"


def _extract_paths_from_input(tool_input_str: str) -> list[str]:
    """Extract file paths from tool_input JSON string."""
    paths = []
    if not tool_input_str:
        return paths
    try:
        data = json.loads(tool_input_str) if isinstance(tool_input_str, str) else tool_input_str
        if isinstance(data, dict):
            for key in ("file_path", "path", "filename", "target", "notebook_path"):
                if key in data and isinstance(data[key], str) and len(data[key]) > 2:
                    paths.append(data[key])
            # Glob patterns
            if "pattern" in data and isinstance(data["pattern"], str):
                paths.append(data["pattern"])
            # Bash commands — extract paths
            if "command" in data and isinstance(data["command"], str):
                cmd = data["command"]
                # Extract file-like paths from commands
                for match in _PATH_RE.finditer(cmd):
                    paths.append(match.group(1))
                # Extract URLs
                for match in _URL_RE.finditer(cmd):
                    paths.append(match.group(0))
    except (json.JSONDecodeError, TypeError):
        # Try regex on raw string
        for match in _PATH_RE.finditer(str(tool_input_str)):
            paths.append(match.group(1))
        for match in _URL_RE.finditer(str(tool_input_str)):
            paths.append(match.group(0))
    return paths


def populate_data_flow(session_id: str) -> dict[str, Any]:
    """Build real data flow edges from session log tool calls.

    This is the key function that brings the ontology to life. It:
    1. Creates Entity nodes with REAL file paths (not generic ingest IDs)
    2. Creates used edges: ToolCall → Entity (for tool inputs)
    3. Creates generated edges: ToolCall → Entity (for tool outputs)
    4. Creates derivedFrom edges: Entity(written) → Entity(read) on read→write patterns
    5. Tags all Entity nodes with sensitivity (CRITICAL/HIGH/MEDIUM/LOW)

    The derivedFrom heuristic: if a file is read and later another file is written,
    the written file derivedFrom the read file. This captures data lineage.
    """
    import gzip
    conn = _get_db()
    nodes_created = 0
    edges_created = 0
    derived_from_created = 0

    try:
        # Load session log from json.gz
        sessions_dir = INALIGN_DIR / "sessions"
        if not sessions_dir.exists():
            return {"nodes": 0, "edges": 0, "derived_from": 0, "status": "no_session_dir"}

        session_log = []
        for f in sorted(sessions_dir.glob("*.json.gz"),
                        key=lambda x: x.stat().st_mtime, reverse=True):
            fname = f.name.replace(".json.gz", "")
            if session_id in fname or session_id[:8] in fname:
                try:
                    with gzip.open(f, "rt", encoding="utf-8") as gz:
                        data = json.load(gz)
                    if isinstance(data, dict):
                        session_log = data.get("records", [])
                    elif isinstance(data, list):
                        session_log = data
                    if session_log:
                        break
                except Exception:
                    continue
        # Fallback: try latest file
        if not session_log:
            gz_files = sorted(sessions_dir.glob("*.json.gz"),
                              key=lambda x: x.stat().st_mtime, reverse=True)
            for f in gz_files[:3]:
                try:
                    with gzip.open(f, "rt", encoding="utf-8") as gz:
                        data = json.load(gz)
                    if isinstance(data, dict):
                        session_log = data.get("records", [])
                    if session_log:
                        break
                except Exception:
                    continue

        if not session_log:
            return {"nodes": 0, "edges": 0, "derived_from": 0, "status": "no_session_log"}

        # Check if already populated (idempotent)
        existing_df = conn.execute(
            "SELECT COUNT(*) as cnt FROM ontology_edges WHERE session_id=? AND relation='derivedFrom'",
            (session_id,),
        ).fetchone()["cnt"]
        if existing_df > 0:
            return {"nodes": 0, "edges": 0, "derived_from": existing_df,
                    "status": "already_populated"}

        # Track read entities for derivedFrom (recent window only)
        _MAX_READ_WINDOW = 50  # Only link to most recent N reads
        read_entities: list[tuple[str, str]] = []  # [(normalized_path, entity_node_id), ...]
        read_entity_set: set[str] = set()  # For dedup
        entity_nodes: dict[str, str] = {}   # normalized_path → entity_node_id (all)

        def _normalize_path(p: str) -> str:
            """Normalize a path for matching (lowercase, forward slashes)."""
            return p.replace("\\", "/").lower().strip().rstrip("/")

        def _get_or_create_entity(path: str, ts: str) -> str:
            """Get or create Entity node for a path, return node_id."""
            nonlocal nodes_created
            norm = _normalize_path(path)
            if norm in entity_nodes:
                return entity_nodes[norm]

            sensitivity = _classify_sensitivity(path)
            # Use shortened path for label
            label = path
            if len(label) > 60:
                label = "..." + label[-57:]

            ent_id = _make_id("ent", session_id[:8], norm)
            is_url = path.startswith("http://") or path.startswith("https://")
            _upsert_node(
                conn, ent_id, "Entity", label, session_id, ts,
                attributes={
                    "full_path": path,
                    "sensitivity": sensitivity,
                    "entity_type": "url" if is_url else "file",
                    "normalized": norm,
                },
            )
            nodes_created += 1
            entity_nodes[norm] = ent_id
            return ent_id

        # Process tool calls
        for idx, entry in enumerate(session_log):
            record_type = entry.get("type", entry.get("record_type", ""))
            tool_name = entry.get("tool_name", "")
            tool_input = entry.get("tool_input", "")
            ts = entry.get("timestamp", "")

            if record_type != "tool_call" or not tool_name:
                continue

            # ToolCall node ID (must match populate_from_session)
            tc_id = f"tc:{session_id[:8]}:{idx:06d}"

            # Extract paths from tool_input
            paths = _extract_paths_from_input(tool_input)
            if not paths:
                continue

            # Determine if this is a read, write, or external tool
            is_read = tool_name in _READ_TOOLS
            is_write = tool_name in _WRITE_TOOLS
            is_external = tool_name in _EXTERNAL_TOOLS

            # For Bash, check command content for direction
            if tool_name == "Bash" and tool_input:
                try:
                    cmd_data = json.loads(tool_input) if isinstance(tool_input, str) else tool_input
                    cmd = cmd_data.get("command", "") if isinstance(cmd_data, dict) else ""
                    cmd_lower = cmd.lower()
                    if any(w in cmd_lower for w in ("curl", "wget", "fetch", "ssh", "scp", "git push")):
                        is_external = True
                    elif any(w in cmd_lower for w in ("cat ", "head ", "tail ", "less ", "more ")):
                        is_read = True
                    elif any(w in cmd_lower for w in ("echo ", "tee ", "> ", ">> ", "mv ", "cp ")):
                        is_write = True
                except Exception:
                    pass

            for path in paths:
                ent_id = _get_or_create_entity(path, ts)
                norm = _normalize_path(path)

                if is_read:
                    # Track for derivedFrom heuristic
                    if norm not in read_entity_set:
                        read_entities.append((norm, ent_id))
                        read_entity_set.add(norm)
                    # used edge: try linking to ToolCall (may not exist)
                    try:
                        _insert_edge(conn, tc_id, ent_id, "used",
                                     session_id, ts, confidence=0.9)
                        edges_created += 1
                    except sqlite3.IntegrityError:
                        pass  # ToolCall node not in ontology yet

                elif is_write:
                    # generated edge: try linking to ToolCall
                    try:
                        _insert_edge(conn, tc_id, ent_id, "generated",
                                     session_id, ts, confidence=0.9)
                        edges_created += 1
                    except sqlite3.IntegrityError:
                        pass

                    # derivedFrom: written entity → recent reads (windowed)
                    recent_reads = read_entities[-_MAX_READ_WINDOW:]
                    for i, (read_norm, read_ent_id) in enumerate(recent_reads):
                        if read_ent_id != ent_id:  # Don't self-derive
                            recency = (i + 1) / len(recent_reads)
                            conf = 0.5 + 0.4 * recency
                            _insert_edge(
                                conn, ent_id, read_ent_id, "derivedFrom",
                                session_id, ts, confidence=round(conf, 2),
                                attributes={"heuristic": "read_before_write"},
                            )
                            derived_from_created += 1
                            edges_created += 1

                elif is_external:
                    try:
                        _insert_edge(conn, tc_id, ent_id, "used",
                                     session_id, ts, confidence=0.8,
                                     attributes={"access_type": "external"})
                        edges_created += 1
                    except sqlite3.IntegrityError:
                        pass

                else:
                    try:
                        _insert_edge(conn, tc_id, ent_id, "used",
                                     session_id, ts, confidence=0.6)
                        edges_created += 1
                    except sqlite3.IntegrityError:
                        pass

        conn.commit()
        logger.info(
            f"[ONTOLOGY] Data flow for {session_id[:8]}: "
            f"{nodes_created} entities, {edges_created} edges, "
            f"{derived_from_created} derivedFrom"
        )

    except Exception as e:
        conn.rollback()
        logger.error(f"[ONTOLOGY] Data flow failed: {e}")
        return {"nodes": 0, "edges": 0, "derived_from": 0, "error": str(e)}
    finally:
        conn.close()

    return {
        "session_id": session_id,
        "entity_nodes": nodes_created,
        "edges": edges_created,
        "derived_from": derived_from_created,
        "read_entities_tracked": len(read_entities),
        "total_entities": len(entity_nodes),
        "status": "ok",
    }


# ---- Competency Question Queries (Recursive CTE) ----------------------------

def cq1_agent_accessed_entity(agent_label: str, entity_pattern: str,
                               session_id: str = "") -> dict[str, Any]:
    """CQ1: Has this agent accessed files matching a pattern?

    Path: Agent -performed→ ToolCall -used→ Entity(pattern)
    """
    conn = _get_db()
    try:
        where_session = "AND e1.session_id = ?" if session_id else ""
        params: list = [f"%{agent_label}%", f"%{entity_pattern}%"]
        if session_id:
            params.append(session_id)

        rows = conn.execute(f"""
            SELECT a.label as agent, tc.label as tool_call, tc.timestamp,
                   ent.label as entity, ent.attributes as entity_attrs,
                   e1.record_hash
            FROM ontology_nodes a
            JOIN ontology_edges e1 ON a.id = e1.source_id AND e1.relation = 'performed'
            JOIN ontology_nodes tc ON e1.target_id = tc.id AND tc.node_class = 'ToolCall'
            JOIN ontology_edges e2 ON tc.id = e2.source_id AND e2.relation = 'used'
            JOIN ontology_nodes ent ON e2.target_id = ent.id AND ent.node_class = 'Entity'
            WHERE a.node_class = 'Agent' AND a.label LIKE ?
              AND ent.label LIKE ? {where_session}
            ORDER BY tc.timestamp
        """, params).fetchall()

        results = [{
            "agent": r["agent"], "tool_call": r["tool_call"],
            "timestamp": r["timestamp"], "entity": r["entity"],
            "record_hash": r["record_hash"],
        } for r in rows]

        return {
            "question": f"Has '{agent_label}' accessed entities matching '{entity_pattern}'?",
            "answer": len(results) > 0,
            "access_count": len(results),
            "accesses": results[:50],
        }
    except Exception as e:
        return {"error": str(e)}
    finally:
        conn.close()


def cq2_files_before_external_call(session_id: str) -> dict[str, Any]:
    """CQ2: What files were read before an external URL call?

    Path: Entity(file) ←used- ToolCall₁ -precedes→ ToolCall₂ -used→ Entity(URL)
    """
    conn = _get_db()
    try:
        rows = conn.execute("""
            SELECT tc1.label as read_tool, tc1.timestamp as read_time,
                   ent1.label as file_read,
                   tc2.label as ext_tool, tc2.timestamp as ext_time,
                   ent2.label as external_target,
                   e_prec.record_hash
            FROM ontology_edges e1
            JOIN ontology_nodes tc1 ON e1.source_id = tc1.id AND tc1.node_class = 'ToolCall'
            JOIN ontology_nodes ent1 ON e1.target_id = ent1.id AND ent1.node_class = 'Entity'
            JOIN ontology_edges e_prec ON tc1.id = e_prec.source_id AND e_prec.relation = 'precedes'
            JOIN ontology_nodes tc2 ON e_prec.target_id = tc2.id AND tc2.node_class = 'ToolCall'
            JOIN ontology_edges e2 ON tc2.id = e2.source_id AND e2.relation = 'used'
            JOIN ontology_nodes ent2 ON e2.target_id = ent2.id AND ent2.node_class = 'Entity'
            WHERE e1.relation = 'used'
              AND e1.session_id = ?
              AND (tc1.label LIKE '%read%' OR tc1.label LIKE '%file_read%')
              AND (tc2.label LIKE '%curl%' OR tc2.label LIKE '%fetch%' OR tc2.label LIKE '%http%'
                   OR tc2.label LIKE '%bash%' OR tc2.label LIKE '%web%')
            ORDER BY tc1.timestamp
        """, (session_id,)).fetchall()

        results = [{
            "file_read": r["file_read"], "read_tool": r["read_tool"],
            "read_time": r["read_time"], "external_tool": r["ext_tool"],
            "external_target": r["external_target"], "ext_time": r["ext_time"],
            "record_hash": r["record_hash"],
        } for r in rows]

        return {
            "question": "What files were read before external calls?",
            "session_id": session_id,
            "exfiltration_risk": len(results) > 0,
            "patterns_found": len(results),
            "patterns": results[:50],
        }
    except Exception as e:
        return {"error": str(e)}
    finally:
        conn.close()


def cq3_policy_violations_in_risky_sessions(risk_level: str = "high",
                                              session_id: str = "") -> dict[str, Any]:
    """CQ3: Which policies were violated in HIGH-risk sessions?

    Path: Session ←partOf- ToolCall -detected→ Risk(HIGH) / -violates→ Policy
    """
    conn = _get_db()
    try:
        where_session = "AND e_part.session_id = ?" if session_id else ""
        params: list = [f"%{risk_level}%"]
        if session_id:
            params.append(session_id)

        rows = conn.execute(f"""
            SELECT s.label as session, tc.label as tool_call, tc.timestamp,
                   r.label as risk_name, r.attributes as risk_attrs
            FROM ontology_edges e_det
            JOIN ontology_nodes tc ON e_det.source_id = tc.id AND tc.node_class = 'ToolCall'
            JOIN ontology_nodes r ON e_det.target_id = r.id AND r.node_class = 'Risk'
            JOIN ontology_edges e_part ON tc.id = e_part.source_id AND e_part.relation = 'partOf'
            JOIN ontology_nodes s ON e_part.target_id = s.id AND s.node_class = 'Session'
            WHERE e_det.relation = 'detected'
              AND r.attributes LIKE ? {where_session}
            ORDER BY tc.timestamp
        """, params).fetchall()

        results = [{
            "session": r["session"], "tool_call": r["tool_call"],
            "timestamp": r["timestamp"], "risk": r["risk_name"],
            "risk_details": json.loads(r["risk_attrs"] or "{}"),
        } for r in rows]

        return {
            "question": f"Which tools triggered {risk_level.upper()} risks?",
            "violations_found": len(results),
            "violations": results[:50],
        }
    except Exception as e:
        return {"error": str(e)}
    finally:
        conn.close()


def cq4_downstream_impact(entity_id: str, max_depth: int = 5) -> dict[str, Any]:
    """CQ4: What downstream entities are affected if this entity is tampered?

    Recursive: Entity -derivedFrom→ Entity -derivedFrom→ ...
    Also follows: Entity ←generated- ToolCall -used→ Entity (indirect derivation)
    """
    conn = _get_db()
    try:
        rows = conn.execute("""
            WITH RECURSIVE impact(nid, depth, path) AS (
                -- Direct derivation
                SELECT e.target_id, 1, ? || ' -> ' || e.target_id
                FROM ontology_edges e
                WHERE e.source_id = ?
                  AND e.relation IN ('derivedFrom', 'generated', 'used')
                UNION ALL
                -- Recursive expansion
                SELECT e.target_id, i.depth + 1,
                       i.path || ' -> ' || e.target_id
                FROM ontology_edges e
                JOIN impact i ON e.source_id = i.nid
                WHERE e.relation IN ('derivedFrom', 'generated', 'used')
                  AND i.depth < ?
            )
            SELECT DISTINCT i.nid, i.depth, i.path,
                   n.label, n.node_class, n.timestamp, n.record_hash
            FROM impact i
            LEFT JOIN ontology_nodes n ON i.nid = n.id
            ORDER BY i.depth, i.nid
        """, (entity_id, entity_id, max_depth)).fetchall()

        affected = [{
            "node_id": r["nid"], "depth": r["depth"], "path": r["path"],
            "label": r["label"] or "", "class": r["node_class"] or "",
            "timestamp": r["timestamp"] or "", "record_hash": r["record_hash"] or "",
        } for r in rows]

        return {
            "question": f"What is affected if '{entity_id}' is tampered?",
            "source": entity_id,
            "affected_count": len(affected),
            "affected": affected,
        }
    except Exception as e:
        return {"error": str(e)}
    finally:
        conn.close()


def cq5_context_around_hash_break(session_id: str, broken_seq: int,
                                    window: int = 5) -> dict[str, Any]:
    """CQ5: What happened before/after a hash chain break?

    Path: ToolCall(broken) -precedes/preceded→ ToolCall chain (window)
    """
    conn = _get_db()
    try:
        # Get ToolCalls around the break point
        start_seq = max(0, broken_seq - window)
        end_seq = broken_seq + window

        rows = conn.execute("""
            SELECT n.id, n.label, n.timestamp, n.attributes, n.record_hash,
                   json_extract(n.attributes, '$.sequence') as seq
            FROM ontology_nodes n
            WHERE n.node_class = 'ToolCall'
              AND n.session_id = ?
              AND CAST(json_extract(n.attributes, '$.sequence') AS INTEGER) BETWEEN ? AND ?
            ORDER BY CAST(json_extract(n.attributes, '$.sequence') AS INTEGER) ASC
        """, (session_id, start_seq, end_seq)).fetchall()

        events = []
        for r in rows:
            seq = int(json.loads(r["attributes"] or "{}").get("sequence", -1))
            events.append({
                "node_id": r["id"], "label": r["label"],
                "timestamp": r["timestamp"], "sequence": seq,
                "record_hash": r["record_hash"],
                "is_break_point": seq == broken_seq,
                "attributes": json.loads(r["attributes"] or "{}"),
            })

        return {
            "question": f"What happened around hash break at sequence {broken_seq}?",
            "session_id": session_id,
            "break_sequence": broken_seq,
            "window": window,
            "events": events,
        }
    except Exception as e:
        return {"error": str(e)}
    finally:
        conn.close()


# ---- General Graph Queries ---------------------------------------------------
def query_neighbors(node_id: str, depth: int = 2,
                    direction: str = "both") -> dict[str, Any]:
    """Find neighboring nodes up to N hops using recursive CTE."""
    conn = _get_db()
    try:
        if direction == "outgoing":
            cte_sql = """
                WITH RECURSIVE graph(nid, relation, depth, path) AS (
                    SELECT target_id, relation, 1, ? || ' -' || relation || '-> ' || target_id
                    FROM ontology_edges WHERE source_id = ?
                    UNION ALL
                    SELECT e.target_id, e.relation, g.depth + 1,
                           g.path || ' -' || e.relation || '-> ' || e.target_id
                    FROM ontology_edges e
                    JOIN graph g ON e.source_id = g.nid
                    WHERE g.depth < ?
                )
                SELECT DISTINCT nid, relation, depth, path FROM graph ORDER BY depth
            """
        elif direction == "incoming":
            cte_sql = """
                WITH RECURSIVE graph(nid, relation, depth, path) AS (
                    SELECT source_id, relation, 1, ? || ' <-' || relation || '- ' || source_id
                    FROM ontology_edges WHERE target_id = ?
                    UNION ALL
                    SELECT e.source_id, e.relation, g.depth + 1,
                           g.path || ' <-' || e.relation || '- ' || e.source_id
                    FROM ontology_edges e
                    JOIN graph g ON e.target_id = g.nid
                    WHERE g.depth < ?
                )
                SELECT DISTINCT nid, relation, depth, path FROM graph ORDER BY depth
            """
        else:
            cte_sql = """
                WITH RECURSIVE graph(nid, relation, depth, path) AS (
                    SELECT target_id, relation, 1, ? || ' -> ' || target_id
                    FROM ontology_edges WHERE source_id = ?
                    UNION ALL
                    SELECT source_id, relation, 1, ? || ' <- ' || source_id
                    FROM ontology_edges WHERE target_id = ?
                    UNION ALL
                    SELECT CASE WHEN e.source_id = g.nid THEN e.target_id ELSE e.source_id END,
                           e.relation, g.depth + 1,
                           g.path || ' <-> ' || CASE WHEN e.source_id = g.nid THEN e.target_id ELSE e.source_id END
                    FROM ontology_edges e
                    JOIN graph g ON (e.source_id = g.nid OR e.target_id = g.nid)
                    WHERE g.depth < ?
                )
                SELECT DISTINCT nid, relation, depth, path FROM graph ORDER BY depth
            """

        if direction == "both":
            params = [node_id, node_id, node_id, node_id, depth]
        else:
            params = [node_id, node_id, depth]

        rows = conn.execute(cte_sql, params).fetchall()

        # Fetch node details
        node_ids = {node_id} | {r["nid"] for r in rows}
        nodes = {}
        for nid in node_ids:
            n = conn.execute("SELECT * FROM ontology_nodes WHERE id=?", (nid,)).fetchone()
            if n:
                nodes[nid] = {
                    "id": n["id"], "class": n["node_class"], "label": n["label"],
                    "timestamp": n["timestamp"], "record_hash": n["record_hash"],
                }

        return {
            "start_node": node_id,
            "depth": depth,
            "direction": direction,
            "results": [{"node_id": r["nid"], "relation": r["relation"],
                         "depth": r["depth"], "path": r["path"]} for r in rows],
            "nodes": nodes,
            "total_found": len(rows),
        }
    except Exception as e:
        return {"error": str(e)}
    finally:
        conn.close()


def get_ontology_stats(session_id: str = "") -> dict[str, Any]:
    """Get ontology graph statistics."""
    conn = _get_db()
    try:
        where = "WHERE session_id=?" if session_id else ""
        params = (session_id,) if session_id else ()

        node_count = conn.execute(
            f"SELECT COUNT(*) as cnt FROM ontology_nodes {where}", params
        ).fetchone()["cnt"]
        edge_count = conn.execute(
            f"SELECT COUNT(*) as cnt FROM ontology_edges {where}", params
        ).fetchone()["cnt"]

        class_dist = {}
        for row in conn.execute(
            f"SELECT node_class, COUNT(*) as cnt FROM ontology_nodes {where} GROUP BY node_class",
            params,
        ):
            class_dist[row["node_class"]] = row["cnt"]

        rel_dist = {}
        for row in conn.execute(
            f"SELECT relation, COUNT(*) as cnt FROM ontology_edges {where} GROUP BY relation",
            params,
        ):
            rel_dist[row["relation"]] = row["cnt"]

        # Version info
        versions = [dict(r) for r in conn.execute(
            "SELECT * FROM ontology_meta ORDER BY created_at DESC LIMIT 5"
        ).fetchall()]

        return {
            "total_nodes": node_count,
            "total_edges": edge_count,
            "node_classes": class_dist,
            "relation_types": rel_dist,
            "ontology_version": ONTOLOGY_VERSION,
            "schema": {"classes": sorted(NODE_CLASSES), "relations": sorted(RELATION_TYPES)},
            "versions": versions,
            "session_id": session_id or "all",
        }
    except Exception as e:
        return {"error": str(e)}
    finally:
        conn.close()
