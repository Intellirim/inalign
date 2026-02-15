"""
InALign Ontology Layer — W3C PROV-O + SQLite Adjacency List + Recursive CTE

Ontology (blueprint):
  "ToolCall is a subtype of Activity" — schema definition
Knowledge Graph (data):
  "At 14:32 Claude called read_file" — instance data

W3C PROV-O compatible with InALign extensions. The ontology is the schema;
the nodes/edges tables hold the knowledge graph instances.

Classes (8) — W3C PROV + PROV-AGENT:
  Agent              — AI agent (Claude, GPT, Cursor) [prov:Agent]
  Session            — Work session [prov:Activity]
  ToolCall           — Tool invocation [prov:Activity]
  AIModelInvocation  — LLM API call [prov:Activity, PROV-AGENT]
  Entity             — Artifact [prov:Entity]
  Decision           — Agent judgment/choice
  Risk               — Detected risk pattern
  Policy             — Applied policy rule

Relations (13) — W3C PROV + PROV-AGENT:
  performed    — Agent → ToolCall [prov:wasAssociatedWith]
  partOf       — ToolCall → Session [prov:wasInformedBy]
  used         — ToolCall → Entity [prov:used]
  generated    — ToolCall → Entity [prov:wasGeneratedBy]
  triggeredBy  — ToolCall → Decision
  detected     — ToolCall → Risk
  violates     — ToolCall → Policy
  precedes     — ToolCall → ToolCall [inalign:precedes]
  derivedFrom  — Entity → Entity [prov:wasDerivedFrom]
  signedBy     — Session → Agent
  sameAs       — Entity → Entity (cross-session identity)
  invokedModel — ToolCall → AIModelInvocation [PROV-AGENT]
  usedPrompt   — AIModelInvocation → Prompt [PROV-AGENT]

Entity subtypes (v0.9.0):
  file         — Filesystem path [inalign:File]
  url          — HTTP/HTTPS URL [inalign:URL]
  secret       — API key, credential [inalign:Secret]
  prompt       — User prompt/command [inalign:Prompt, prov:Entity]
  response     — Agent response [inalign:Response, prov:Entity]
  telemetry    — Execution metrics [inalign:TelemetryData]

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
  Q6: "Which prompts led to sensitive file access?" (v2)
      Entity(prompt) ←used- ToolCall -used→ Entity(.env)
  Q7: "Was this file accessed across multiple sessions?" (v2)
      Entity(file,sess1) -sameAs→ Entity(file,sess2)
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
ONTOLOGY_VERSION = "0.9.0"

# Valid node classes (W3C PROV + PROV-AGENT + InALign)
NODE_CLASSES = {"Agent", "Session", "ToolCall", "AIModelInvocation", "Entity", "Decision", "Risk", "Policy"}

# Valid relation types
RELATION_TYPES = {
    "performed",     # Agent → ToolCall
    "used",          # ToolCall → Entity (incl. Prompt)
    "generated",     # ToolCall → Entity (incl. Response)
    "triggeredBy",   # ToolCall → Decision
    "detected",      # ToolCall → Risk
    "violates",      # ToolCall → Policy
    "precedes",      # ToolCall → ToolCall (temporal)
    "derivedFrom",   # Entity → Entity
    "signedBy",      # Session → Agent
    "sameAs",        # Entity → Entity (cross-session identity)
    "invokedModel",  # ToolCall → AIModelInvocation (PROV-AGENT)
    "usedPrompt",    # AIModelInvocation → Prompt (PROV-AGENT)
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
        CREATE UNIQUE INDEX IF NOT EXISTS idx_onto_edges_unique
            ON ontology_edges(source_id, target_id, relation, session_id);

        -- Composite indexes for CTE/join performance
        CREATE INDEX IF NOT EXISTS idx_onto_edges_src_rel_sess
            ON ontology_edges(source_id, relation, session_id);
        CREATE INDEX IF NOT EXISTS idx_onto_edges_tgt_rel_sess
            ON ontology_edges(target_id, relation, session_id);
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
) -> bool:
    """Insert a knowledge graph edge with hash chain link.

    Returns True if inserted, False if skipped (FK or duplicate).
    Gracefully handles FOREIGN KEY failures (e.g., session log index
    doesn't match provenance sequence number for ToolCall nodes).
    """
    try:
        conn.execute(
            """INSERT OR IGNORE INTO ontology_edges
               (source_id, target_id, relation, session_id, timestamp, confidence, record_hash, attributes)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (source_id, target_id, relation, session_id, timestamp,
             confidence, record_hash, json.dumps(attributes or {}, default=str)),
        )
        return True
    except sqlite3.IntegrityError:
        # FOREIGN KEY constraint — source/target node doesn't exist
        return False


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

            # Entity nodes are created by populate_data_flow() from session log
            # (with real file paths, sensitivity, etc.) — not from hash-only
            # provenance records which lack meaningful content.

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


# ---- AIModelInvocation Population (PROV-AGENT) --------------------------------

def populate_llm_invocations(session_id: str) -> dict[str, Any]:
    """Populate AIModelInvocation nodes from session log.

    PROV-AGENT pattern: Each LLM reasoning step (thinking) is an
    AIModelInvocation Activity. Links:
      - invokedModel: preceding ToolCall → AIModelInvocation
      - usedPrompt: AIModelInvocation → Prompt Entity (user message that triggered it)
      - generated: AIModelInvocation → Response Entity (agent's output)

    This captures the LLM's internal reasoning as a first-class provenance
    activity, enabling queries like:
      "What LLM reasoning led to this file access?"
    """
    conn = _get_db()
    nodes_created = 0
    edges_created = 0

    try:
        session_log = _load_session_log_for_ontology(session_id)
        if not session_log:
            return {"nodes": 0, "edges": 0, "status": "no_session_log"}

        # Clean previous AIModelInvocation nodes
        conn.execute(
            "DELETE FROM ontology_edges WHERE session_id=? AND "
            "(source_id LIKE 'llm:%' OR target_id LIKE 'llm:%')",
            (session_id,),
        )
        conn.execute(
            "DELETE FROM ontology_nodes WHERE session_id=? AND node_class='AIModelInvocation'",
            (session_id,),
        )
        conn.commit()

        inv_seq = 0
        last_prompt_id = None
        last_tc_id = None

        for idx, entry in enumerate(session_log):
            role = entry.get("role", "")
            rtype = entry.get("type", entry.get("record_type", ""))
            ts = entry.get("timestamp", "")
            content = entry.get("content", "")
            model = entry.get("model", "")

            # Track user messages → prompt entity
            if role == "user" and content:
                prompt_count = sum(1 for e in session_log[:idx] if e.get("role") == "user")
                last_prompt_id = f"prompt:{session_id[:8]}:{prompt_count:04d}"

            # Track tool calls
            elif rtype == "tool_call":
                last_tc_id = f"tc:{session_id[:8]}:{idx:06d}"

            # thinking = AIModelInvocation
            elif rtype == "thinking" and content:
                inv_id = f"llm:{session_id[:8]}:{inv_seq:04d}"
                text = content if isinstance(content, str) else str(content)
                preview = text[:150]

                _upsert_node(conn, inv_id, "AIModelInvocation", preview,
                             session_id, ts,
                             attributes={
                                 "model": model or "claude",
                                 "reasoning_length": len(text),
                                 "sequence_index": idx,
                             })
                nodes_created += 1

                # invokedModel: last ToolCall → this LLM invocation
                if last_tc_id:
                    _insert_edge(conn, last_tc_id, inv_id, "invokedModel",
                                 session_id, ts, confidence=0.8)
                    edges_created += 1

                # usedPrompt: LLM invocation → Prompt that triggered it
                if last_prompt_id:
                    _insert_edge(conn, inv_id, last_prompt_id, "usedPrompt",
                                 session_id, ts, confidence=0.7)
                    edges_created += 1

                inv_seq += 1

        conn.commit()
        logger.info(
            f"[ONTOLOGY] LLM invocations for {session_id[:8]}: "
            f"{nodes_created} AIModelInvocation nodes, {edges_created} edges"
        )

    except Exception as e:
        conn.rollback()
        return {"nodes": 0, "edges": 0, "error": str(e)}
    finally:
        conn.close()

    return {
        "session_id": session_id,
        "invocations": inv_seq,
        "edges": edges_created,
        "status": "ok",
    }


# ---- Prompt/Response Entity Population (v2) ----------------------------------

# Injection/suspicious prompt patterns
_INJECTION_PATTERNS = [
    "ignore previous", "ignore above", "disregard", "override",
    "system prompt", "you are now", "act as", "pretend",
    "jailbreak", "dan mode", "bypass", "hack",
    "base64", "eval(", "exec(", "__import__",
    r"<script", "javascript:", "onerror=",
]


def populate_prompt_response_entities(session_id: str) -> dict[str, Any]:
    """Populate Prompt and Response Entity nodes from session log.

    v2 feature: Promotes user prompts and agent responses to Entity nodes.
    This enables tracking:
      - Which prompts led to sensitive file access
      - Prompt injection detection via content analysis
      - Full data lineage: Prompt → ToolCall → File → Response

    Creates:
      - Entity(type=prompt) for each user message
      - Entity(type=response) for each assistant message
      - used edge: first ToolCall after prompt → PromptEntity
      - generated edge: last ToolCall before response → ResponseEntity
      - derivedFrom edge: ResponseEntity → PromptEntity (causal link)
    """
    import gzip
    conn = _get_db()
    nodes_created = 0
    edges_created = 0
    injection_flags = 0

    try:
        session_log = _load_session_log_for_ontology(session_id)
        if not session_log:
            return {"nodes": 0, "edges": 0, "status": "no_session_log"}

        # Clean up previous prompt/response entities
        conn.execute(
            "DELETE FROM ontology_edges WHERE session_id=? AND "
            "(source_id LIKE 'prompt:%' OR target_id LIKE 'prompt:%' "
            "OR source_id LIKE 'resp:%' OR target_id LIKE 'resp:%')",
            (session_id,),
        )
        conn.execute(
            "DELETE FROM ontology_nodes WHERE session_id=? AND id LIKE 'prompt:%'",
            (session_id,),
        )
        conn.execute(
            "DELETE FROM ontology_nodes WHERE session_id=? AND id LIKE 'resp:%'",
            (session_id,),
        )
        conn.commit()

        prompt_seq = 0
        resp_seq = 0
        pending_prompt_id = None
        last_tc_id = None
        last_tc_idx = None

        for idx, entry in enumerate(session_log):
            role = entry.get("role", "")
            content = entry.get("content", "")
            rtype = entry.get("type", entry.get("record_type", ""))
            ts = entry.get("timestamp", "")

            if role == "user" and content:
                # === Prompt Entity ===
                text = content if isinstance(content, str) else str(content)
                preview = text[:200]
                prompt_id = f"prompt:{session_id[:8]}:{prompt_seq:04d}"

                # Check for injection patterns
                text_lower = text.lower()
                is_suspicious = any(p in text_lower for p in _INJECTION_PATTERNS)
                if is_suspicious:
                    injection_flags += 1

                # Check if prompt mentions sensitive files
                from .ontology_security import _classify_sensitivity as _cs
                prompt_sensitivity = "LOW"
                for token in text.split():
                    if "/" in token or "\\" in token:
                        level = _cs(token)
                        if level in ("CRITICAL", "HIGH"):
                            prompt_sensitivity = level
                            break

                _upsert_node(conn, prompt_id, "Entity", preview, session_id, ts,
                             attributes={
                                 "entity_type": "prompt",
                                 "full_length": len(text),
                                 "sequence_index": idx,
                                 "sensitivity": prompt_sensitivity,
                                 "injection_suspect": is_suspicious,
                             })
                nodes_created += 1

                # Link previous response → this prompt (conversation flow)
                if pending_prompt_id:
                    # derivedFrom: new prompt may reference previous context
                    pass  # Only link prompt→response, not prompt→prompt

                pending_prompt_id = prompt_id
                prompt_seq += 1

            elif role == "assistant" and content:
                # === Response Entity ===
                text = content if isinstance(content, str) else str(content)
                preview = text[:200]
                resp_id = f"resp:{session_id[:8]}:{resp_seq:04d}"

                _upsert_node(conn, resp_id, "Entity", preview, session_id, ts,
                             attributes={
                                 "entity_type": "response",
                                 "full_length": len(text),
                                 "sequence_index": idx,
                                 "sensitivity": "LOW",
                             })
                nodes_created += 1

                # generated: last ToolCall → ResponseEntity
                if last_tc_id:
                    _insert_edge(conn, last_tc_id, resp_id, "generated",
                                 session_id, ts, confidence=0.7)
                    edges_created += 1

                # derivedFrom: Response ← Prompt (causal)
                if pending_prompt_id:
                    _insert_edge(conn, resp_id, pending_prompt_id, "derivedFrom",
                                 session_id, ts, confidence=0.9,
                                 attributes={"heuristic": "prompt_response_pair"})
                    edges_created += 1

                resp_seq += 1

            elif rtype == "tool_call":
                tc_id = f"tc:{session_id[:8]}:{idx:06d}"

                # used: first ToolCall after prompt → PromptEntity
                if pending_prompt_id:
                    _insert_edge(conn, tc_id, pending_prompt_id, "used",
                                 session_id, ts, confidence=0.8,
                                 attributes={"reason": "prompt_triggered"})
                    edges_created += 1
                    pending_prompt_id = None  # Only link to first TC

                last_tc_id = tc_id
                last_tc_idx = idx

        conn.commit()
        logger.info(
            f"[ONTOLOGY] Prompt/Response for {session_id[:8]}: "
            f"{nodes_created} entities ({prompt_seq} prompts, {resp_seq} responses), "
            f"{edges_created} edges, {injection_flags} injection suspects"
        )

    except Exception as e:
        conn.rollback()
        logger.error(f"[ONTOLOGY] Prompt/Response failed: {e}")
        return {"nodes": 0, "edges": 0, "error": str(e)}
    finally:
        conn.close()

    return {
        "session_id": session_id,
        "prompt_entities": prompt_seq,
        "response_entities": resp_seq,
        "edges": edges_created,
        "injection_suspects": injection_flags,
        "status": "ok",
    }


# ---- Cross-Session Entity Linking (v2) --------------------------------------

def link_cross_session_entities(session_id: str) -> dict[str, Any]:
    """Link Entity nodes that refer to the same file across sessions.

    Creates sameAs edges between Entity nodes with matching normalized
    file paths in different sessions. Enables cross-session queries like:
      "Was this .env file accessed in other sessions?"

    Only links file-type entities (not prompts/responses/URLs).
    Uses normalized paths (lowercase, forward slashes) for matching.
    """
    conn = _get_db()
    links_created = 0

    try:
        # Get all file entities for the current session
        current_ents = conn.execute(
            "SELECT id, label, attributes FROM ontology_nodes "
            "WHERE session_id=? AND node_class='Entity' "
            "AND json_extract(attributes, '$.entity_type') = 'file'",
            (session_id,),
        ).fetchall()

        if not current_ents:
            return {"links_created": 0, "status": "no_file_entities"}

        # Build normalized path → entity_id map for current session
        def _norm(p: str) -> str:
            return p.replace("\\", "/").lower().strip().rstrip("/")

        current_map: dict[str, str] = {}
        for ent in current_ents:
            attrs = json.loads(ent["attributes"] or "{}")
            full_path = attrs.get("full_path", ent["label"])
            norm = _norm(full_path)
            current_map[norm] = ent["id"]

        if not current_map:
            return {"links_created": 0, "status": "no_paths"}

        # Find matching entities in OTHER sessions
        other_ents = conn.execute(
            "SELECT id, label, attributes, session_id FROM ontology_nodes "
            "WHERE session_id != ? AND node_class='Entity' "
            "AND json_extract(attributes, '$.entity_type') = 'file'",
            (session_id,),
        ).fetchall()

        seen_pairs: set[tuple[str, str]] = set()
        for ent in other_ents:
            attrs = json.loads(ent["attributes"] or "{}")
            full_path = attrs.get("full_path", ent["label"])
            norm = _norm(full_path)

            if norm in current_map:
                src = current_map[norm]
                tgt = ent["id"]
                pair = tuple(sorted([src, tgt]))
                if pair in seen_pairs:
                    continue
                seen_pairs.add(pair)

                _insert_edge(conn, src, tgt, "sameAs",
                             session_id, "",
                             confidence=1.0,
                             attributes={
                                 "cross_session": True,
                                 "other_session": ent["session_id"][:8],
                                 "path": norm,
                             })
                links_created += 1

        conn.commit()
        logger.info(
            f"[ONTOLOGY] Cross-session links for {session_id[:8]}: "
            f"{links_created} sameAs edges"
        )

    except Exception as e:
        conn.rollback()
        return {"links_created": 0, "error": str(e)}
    finally:
        conn.close()

    return {
        "session_id": session_id,
        "links_created": links_created,
        "current_files": len(current_map),
        "status": "ok",
    }


# ---- Data Flow Population (derivedFrom + used/generated + sensitivity) -------

# Import canonical sensitivity classification from ontology_security
# (strict matching: extension-end check, basename-only keyword match)
from .ontology_security import SENSITIVITY_PATTERNS as _SENSITIVITY
from .ontology_security import _classify_sensitivity

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


def _extract_paths_from_input(tool_input_str: str) -> list[str]:
    """Extract file paths from tool_input JSON string.

    Only extracts actual filesystem paths and URLs; ignores regex/glob
    patterns (from Grep/Glob) which are not real file paths.
    """
    paths = []
    if not tool_input_str:
        return paths
    try:
        data = json.loads(tool_input_str) if isinstance(tool_input_str, str) else tool_input_str
        if isinstance(data, dict):
            # Direct file path keys (Read, Edit, Write, etc.)
            for key in ("file_path", "path", "filename", "target", "notebook_path"):
                if key in data and isinstance(data[key], str) and len(data[key]) > 2:
                    val = data[key]
                    # Only include if it looks like a real path (has / or \)
                    if "/" in val or "\\" in val:
                        paths.append(val)
            # Bash commands — extract paths and URLs
            if "command" in data and isinstance(data["command"], str):
                cmd = data["command"]
                for match in _PATH_RE.finditer(cmd):
                    paths.append(match.group(1))
                for match in _URL_RE.finditer(cmd):
                    paths.append(match.group(0))
            # WebFetch URL
            if "url" in data and isinstance(data["url"], str):
                url = data["url"]
                if url.startswith("http://") or url.startswith("https://"):
                    paths.append(url)
    except (json.JSONDecodeError, TypeError):
        for match in _PATH_RE.finditer(str(tool_input_str)):
            paths.append(match.group(1))
        for match in _URL_RE.finditer(str(tool_input_str)):
            paths.append(match.group(0))
    return paths


def _load_session_log_for_ontology(session_id: str) -> list[dict]:
    """Load session log from json.gz for ontology population."""
    import gzip
    sessions_dir = INALIGN_DIR / "sessions"
    if not sessions_dir.exists():
        return []
    # Try exact match first
    for f in sorted(sessions_dir.glob("*.json.gz"),
                    key=lambda x: x.stat().st_mtime, reverse=True):
        fname = f.name.replace(".json.gz", "")
        if session_id in fname or session_id[:8] in fname:
            try:
                with gzip.open(f, "rt", encoding="utf-8") as gz:
                    data = json.load(gz)
                if isinstance(data, dict):
                    return data.get("records", [])
                elif isinstance(data, list):
                    return data
            except Exception:
                continue
    # Fallback: latest file
    gz_files = sorted(sessions_dir.glob("*.json.gz"),
                      key=lambda x: x.stat().st_mtime, reverse=True)
    for f in gz_files[:3]:
        try:
            with gzip.open(f, "rt", encoding="utf-8") as gz:
                data = json.load(gz)
            if isinstance(data, dict):
                records = data.get("records", [])
                if records:
                    return records
        except Exception:
            continue
    return []


def populate_data_flow(session_id: str) -> dict[str, Any]:
    """Build Entity nodes for trackable data only: files, URLs, secrets.

    W3C PROV principle: Entity = data worth tracking flow of.
    Prompts, responses, thinking → Activity attributes (NOT entities).
    Only files, URLs, and secrets become Entity nodes.

    Target: ~30-100 Entity nodes, edges < 3x node count.
    """
    import gzip
    conn = _get_db()
    # Disable FK checks during re-population (session log indices may not
    # match provenance sequence numbers for ToolCall nodes)
    conn.execute("PRAGMA foreign_keys=OFF")
    nodes_created = 0
    edges_created = 0
    derived_from_created = 0

    try:
        session_log = _load_session_log_for_ontology(session_id)
        if not session_log:
            return {"nodes": 0, "edges": 0, "derived_from": 0, "status": "no_session_log"}

        # Clean up previous file/url Entity nodes + their edges for re-population
        # Preserve prompt/response entities (created by populate_prompt_response_entities)
        conn.execute(
            "DELETE FROM ontology_edges WHERE session_id=? AND "
            "(source_id IN (SELECT id FROM ontology_nodes WHERE session_id=? AND node_class='Entity' "
            "  AND id LIKE 'ent:%') "
            "OR target_id IN (SELECT id FROM ontology_nodes WHERE session_id=? AND node_class='Entity' "
            "  AND id LIKE 'ent:%'))",
            (session_id, session_id, session_id),
        )
        conn.execute(
            "DELETE FROM ontology_nodes WHERE session_id=? AND node_class='Entity' AND id LIKE 'ent:%'",
            (session_id,),
        )
        conn.commit()

        # === File/URL entity tracking ===
        _MAX_READ_WINDOW = 10
        read_files: list[tuple[str, str]] = []
        read_file_set: set[str] = set()
        entity_map: dict[str, str] = {}  # norm_path → entity_node_id

        def _norm(p: str) -> str:
            return p.replace("\\", "/").lower().strip().rstrip("/")

        def _get_entity(path: str, ts: str) -> str:
            """Get or create Entity node for a file/URL."""
            nonlocal nodes_created
            norm = _norm(path)
            if norm in entity_map:
                return entity_map[norm]
            sensitivity = _classify_sensitivity(path)
            label = path if len(path) <= 60 else "..." + path[-57:]
            ent_id = _make_id("ent", session_id[:8], norm)
            is_url = path.startswith("http://") or path.startswith("https://")
            _upsert_node(conn, ent_id, "Entity", label, session_id, ts,
                         attributes={
                             "entity_type": "url" if is_url else "file",
                             "full_path": path,
                             "sensitivity": sensitivity,
                         })
            nodes_created += 1
            entity_map[norm] = ent_id
            return ent_id

        # Process only tool_call events — extract files/URLs
        for idx, entry in enumerate(session_log):
            rtype = entry.get("type", entry.get("record_type", ""))
            if rtype != "tool_call":
                continue
            tool_name = entry.get("tool_name", "")
            if not tool_name:
                continue
            tool_input = entry.get("tool_input", "")
            ts = entry.get("timestamp", "")
            tc_id = f"tc:{session_id[:8]}:{idx:06d}"

            paths = _extract_paths_from_input(tool_input)
            if not paths:
                continue

            # Classify tool action
            is_read = tool_name in _READ_TOOLS
            is_write = tool_name in _WRITE_TOOLS
            is_external = tool_name in _EXTERNAL_TOOLS

            if tool_name == "Bash":
                ti = tool_input
                if isinstance(ti, str):
                    try:
                        ti = json.loads(ti)
                    except (json.JSONDecodeError, ValueError):
                        pass
                if isinstance(ti, dict):
                    cmd_lower = ti.get("command", "").lower()
                    if any(w in cmd_lower for w in ("curl", "wget", "ssh", "scp", "git push")):
                        is_external = True
                    elif any(w in cmd_lower for w in ("cat ", "head ", "tail ")):
                        is_read = True
                    elif any(w in cmd_lower for w in ("echo ", "tee ", "> ", ">> ")):
                        is_write = True

            for path in paths:
                ent_id = _get_entity(path, ts)
                norm = _norm(path)

                if is_read:
                    if norm not in read_file_set:
                        read_files.append((norm, ent_id))
                        read_file_set.add(norm)
                    _insert_edge(conn, tc_id, ent_id, "used",
                                 session_id, ts, confidence=0.9)
                    edges_created += 1

                elif is_write:
                    _insert_edge(conn, tc_id, ent_id, "generated",
                                 session_id, ts, confidence=0.9)
                    edges_created += 1
                    # derivedFrom: written → recently read (data lineage)
                    for i, (rn, re_id) in enumerate(read_files[-_MAX_READ_WINDOW:]):
                        if re_id != ent_id:
                            recency = (i + 1) / min(len(read_files), _MAX_READ_WINDOW)
                            _insert_edge(conn, ent_id, re_id, "derivedFrom",
                                         session_id, ts,
                                         confidence=round(0.5 + 0.4 * recency, 2),
                                         attributes={"heuristic": "read_before_write"})
                            derived_from_created += 1
                            edges_created += 1

                elif is_external:
                    _insert_edge(conn, tc_id, ent_id, "used",
                                 session_id, ts, confidence=0.8,
                                 attributes={"access_type": "external"})
                    edges_created += 1
                else:
                    _insert_edge(conn, tc_id, ent_id, "used",
                                 session_id, ts, confidence=0.6)
                    edges_created += 1

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
        conn.execute("PRAGMA foreign_keys=ON")
        conn.close()

    return {
        "session_id": session_id,
        "entity_nodes": nodes_created,
        "edges": edges_created,
        "derived_from": derived_from_created,
        "total_unique_files": len(entity_map),
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
