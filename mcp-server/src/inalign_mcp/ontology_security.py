"""
InALign Ontology Security Engine — Graph-powered threat detection

Uses the W3C PROV ontology knowledge graph for security analysis that
flat pattern matching cannot achieve:

1. Entity Sensitivity Classification — Auto-classify files/URLs/secrets
2. Data Flow Tracking — Trace sensitive data → external target paths
3. Cross-Session Threat Detection — Gradual escalation across sessions
4. Graph-Based Policy Engine — Pattern-based security policies
5. Impact Analysis — Downstream blast radius of entity compromise

Each analysis returns structured findings with MITRE ATT&CK mappings
and a risk_boost score that augments the base risk_analyzer score.
"""

import json
import gzip
import sqlite3
import logging
from pathlib import Path
from typing import Any
from datetime import datetime, timezone

logger = logging.getLogger("inalign-mcp")

INALIGN_DIR = Path.home() / ".inalign"
DB_PATH = INALIGN_DIR / "provenance.db"

# === Sensitivity Patterns (strict — only truly sensitive files) ===
SENSITIVITY_PATTERNS = {
    "CRITICAL": [
        ".env", ".pem", ".key", "id_rsa", "id_ed25519",
        "credentials", "password", "passwd", "shadow",
        "private_key", ".p12", ".pfx", ".keystore",
        "master.key", "encryption_key",
        ".aws/credentials", ".npmrc", ".pypirc",
        "secret", "apikey", "api_key",
    ],
    "HIGH": [
        ".ssh/config", ".gitconfig", "authorized_keys", "known_hosts",
        "docker-compose", "Dockerfile",
        "connection_string", "dsn",
    ],
}

# External communication patterns — must be actual network calls
EXTERNAL_CMD_PATTERNS = [
    "curl ", "wget ", "scp ", "rsync ", "ssh ",
    "nc ", "ncat ", "netcat ",
    "twine upload", "pip upload", "npm publish",
    "git push",
]

EXTERNAL_URL_PATTERNS = [
    "http://", "https://", "ftp://", "ssh://",
]

# Truly suspicious shell operations (not just "Bash" tool)
DANGEROUS_SHELL_PATTERNS = [
    "chmod 777", "chmod +x", "chown", "sudo ",
    "rm -rf", "mkfifo", "nc -l", "ncat -l",
    "/etc/passwd", "/etc/shadow",
    "base64 -d", "eval ", "exec(",
]


def _get_db() -> sqlite3.Connection:
    conn = sqlite3.connect(str(DB_PATH), check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    return conn


def _classify_sensitivity(label: str, attrs: dict = None) -> str:
    """Classify entity sensitivity based on file path or label.

    Uses strict matching: file extension patterns (e.g. '.key') only
    match at end of a path component, not as substrings of code.
    """
    label_lower = (label or "").lower()
    # Only match against the basename for file paths
    basename = label_lower.rsplit("/", 1)[-1].rsplit("\\", 1)[-1]

    for level, patterns in SENSITIVITY_PATTERNS.items():
        for p in patterns:
            if "/" in p:
                # Directory pattern — match as path substring
                if p in label_lower:
                    return level
            elif p.startswith("."):
                # File extension — must end the basename or be followed by non-alpha
                idx = basename.find(p)
                while idx >= 0:
                    end = idx + len(p)
                    # Valid if at end, or next char is non-alphanumeric
                    if end >= len(basename) or not basename[end].isalpha():
                        return level
                    idx = basename.find(p, end)
            else:
                # Keyword pattern — match as whole word in basename
                if p in basename:
                    return level
    return "LOW"


def _is_external_cmd(cmd: str) -> bool:
    """Check if a command performs actual network communication."""
    cmd_lower = (cmd or "").lower()
    return any(p in cmd_lower for p in EXTERNAL_CMD_PATTERNS)


def _has_external_url(text: str) -> bool:
    """Check if text contains actual URLs."""
    text_lower = (text or "").lower()
    return any(p in text_lower for p in EXTERNAL_URL_PATTERNS)


def _is_dangerous_shell(cmd: str) -> bool:
    """Check if a command is genuinely dangerous (not just 'Bash')."""
    cmd_lower = (cmd or "").lower()
    return any(p in cmd_lower for p in DANGEROUS_SHELL_PATTERNS)


def _match_reason(label: str) -> str:
    label_lower = (label or "").lower()
    for level, patterns in SENSITIVITY_PATTERNS.items():
        for p in patterns:
            if p in label_lower:
                return f"matches '{p}'"
    return "attribute"


# In-memory caches for the current analysis run (cleared each run)
_session_log_cache: dict[str, list[dict]] = {}
_tool_ctx_cache: dict[str, list[dict]] = {}


def _load_session_log(session_id: str = "") -> list[dict]:
    """Load the latest session log from json.gz (cached per session_id)."""
    if session_id in _session_log_cache:
        return _session_log_cache[session_id]
    sessions_dir = INALIGN_DIR / "sessions"
    if not sessions_dir.exists():
        return []
    for f in sorted(sessions_dir.glob("*.json.gz"),
                    key=lambda x: x.stat().st_mtime, reverse=True):
        try:
            with gzip.open(f, "rt", encoding="utf-8") as gz:
                data = json.load(gz)
                if isinstance(data, dict):
                    if session_id and data.get("session_id", "")[:8] != session_id[:8]:
                        continue
                    result = data.get("records", [])
                    _session_log_cache[session_id] = result
                    return result
                result = data if isinstance(data, list) else []
                _session_log_cache[session_id] = result
                return result
        except Exception:
            continue
    return []


def _get_tool_context(session_id: str) -> list[dict]:
    """Get tool context for session (cached)."""
    if session_id in _tool_ctx_cache:
        return _tool_ctx_cache[session_id]
    log = _load_session_log(session_id)
    ctx = _extract_tool_context(log)
    _tool_ctx_cache[session_id] = ctx
    return ctx


def _extract_tool_context(session_log: list[dict]) -> list[dict]:
    """Extract file paths, commands, and URLs from session log tool calls.

    Returns list of {index, tool_name, files, commands, urls, is_external}.
    """
    entries = []
    for i, entry in enumerate(session_log):
        rtype = entry.get("type", entry.get("record_type", ""))
        if rtype != "tool_call":
            continue
        tool_name = entry.get("tool_name", "")
        tool_input = entry.get("tool_input", "")
        # tool_input may be a JSON string — parse it
        if isinstance(tool_input, str):
            try:
                tool_input = json.loads(tool_input)
            except (json.JSONDecodeError, ValueError):
                pass
        ti_str = json.dumps(tool_input) if isinstance(tool_input, dict) else str(tool_input)

        files = []
        commands = []
        urls = []

        if isinstance(tool_input, dict):
            # Read/Edit/Write → file_path
            fp = tool_input.get("file_path", "")
            if fp:
                files.append(fp)
            # Bash → command
            cmd = tool_input.get("command", "")
            if cmd:
                commands.append(cmd)
            # Grep/Glob → path, pattern
            p = tool_input.get("path", "")
            if p:
                files.append(p)
            # WebFetch → url
            url = tool_input.get("url", "")
            if url:
                urls.append(url)

        is_ext = bool(urls) or any(_is_external_cmd(c) for c in commands)
        is_sh = any(_is_dangerous_shell(c) for c in commands)

        entries.append({
            "index": i, "tool_name": tool_name,
            "files": files, "commands": commands, "urls": urls,
            "text": ti_str[:500],
            "is_external": is_ext, "is_shell": is_sh,
        })
    return entries


# =========================================================================
# 1. Entity Sensitivity Classification
# =========================================================================
def classify_entities(session_id: str) -> dict[str, Any]:
    """Classify all accessed files/resources by sensitivity level.

    Scans session log tool_input for file paths, commands, and URLs,
    then classifies each against known sensitivity patterns.
    Also checks ontology Entity nodes as a secondary source.
    """
    tool_ctx = _get_tool_context(session_id)

    classified: dict[str, list] = {"CRITICAL": [], "HIGH": [], "MEDIUM": [], "LOW": []}
    seen: set[str] = set()

    # Primary: classify from session log tool calls (has actual file paths)
    for tc in tool_ctx:
        for fp in tc["files"]:
            if fp in seen:
                continue
            seen.add(fp)
            level = _classify_sensitivity(fp)
            entry = {"file": fp, "tool": tc["tool_name"], "sensitivity": level}
            if level != "LOW":
                entry["reason"] = _match_reason(fp)
            classified[level].append(entry)

        for cmd in tc["commands"]:
            # Extract file paths from commands
            for token in cmd.split():
                if ("/" in token or "\\" in token) and token not in seen:
                    seen.add(token)
                    level = _classify_sensitivity(token)
                    if level in ("CRITICAL", "HIGH"):
                        classified[level].append({
                            "file": token, "tool": "Bash",
                            "sensitivity": level, "reason": _match_reason(token),
                        })

        for url in tc["urls"]:
            if url not in seen:
                seen.add(url)
                classified["MEDIUM"].append({
                    "file": url, "tool": tc["tool_name"],
                    "sensitivity": "MEDIUM", "reason": "external URL",
                })

    # Secondary: check ontology Entity nodes
    conn = _get_db()
    try:
        rows = conn.execute(
            "SELECT id, label, attributes FROM ontology_nodes "
            "WHERE session_id=? AND node_class='Entity'",
            (session_id,),
        ).fetchall()
        for r in rows:
            attrs = json.loads(r["attributes"] or "{}")
            level = _classify_sensitivity(r["label"], attrs)
            if level in ("CRITICAL", "HIGH") and r["label"] not in seen:
                seen.add(r["label"])
                classified[level].append({
                    "file": r["label"], "tool": "ontology",
                    "sensitivity": level, "reason": _match_reason(r["label"]),
                })
    except Exception:
        pass
    finally:
        conn.close()

    total = sum(len(v) for v in classified.values())
    return {
        "total_entities": total,
        "critical": classified["CRITICAL"],
        "high": classified["HIGH"],
        "medium_count": len(classified["MEDIUM"]),
        "low_count": len(classified["LOW"]),
        "sensitive_count": len(classified["CRITICAL"]) + len(classified["HIGH"]),
    }


# =========================================================================
# 2. Data Flow Tracking
# =========================================================================
def track_data_flows(session_id: str) -> dict[str, Any]:
    """Track sensitive data flowing toward external targets using graph CTE.

    Two-phase approach:
      Phase 1 (Graph CTE): Recursive traversal of ontology graph
        sensitive Entity → used/generated → ToolCall → precedes → ToolCall → used/generated → external Entity
        depth ≤ 10, LIMIT 500
      Phase 2 (Session log fallback): If graph has no Entity nodes yet,
        falls back to chronological session log scan.

    Returns flow paths with source/target entity, path, and severity.
    """
    conn = _get_db()
    graph_flows: list[dict] = []
    fallback_used = False

    try:
        # --- Phase 1: Graph sequence-based flow detection ---
        # Uses ToolCall node IDs which encode sequence numbers (tc:sid:NNNNNN).
        # Instead of expensive recursive CTE through precedes chains, computes
        # distance = seq(external_tc) - seq(sensitive_tc) directly.
        # O(sensitive_count × external_count) join — sub-second even on 27K+ nodes.
        ent_count = conn.execute(
            "SELECT COUNT(*) as cnt FROM ontology_nodes "
            "WHERE session_id=? AND node_class='Entity' "
            "AND json_extract(attributes, '$.sensitivity') IN ('CRITICAL', 'HIGH')",
            (session_id,),
        ).fetchone()["cnt"]

        if ent_count > 0:
            rows = conn.execute("""
                WITH
                sensitive_tcs AS (
                    SELECT DISTINCT e.source_id as tc_id, n.label as entity_label,
                           json_extract(n.attributes, '$.sensitivity') as sensitivity,
                           CAST(SUBSTR(e.source_id, -6) AS INTEGER) as seq
                    FROM ontology_edges e
                    JOIN ontology_nodes n ON e.target_id = n.id
                    WHERE e.session_id = ?
                      AND e.relation = 'used'
                      AND n.node_class = 'Entity'
                      AND json_extract(n.attributes, '$.sensitivity') IN ('CRITICAL', 'HIGH')
                ),
                external_tcs AS (
                    SELECT DISTINCT e.source_id as tc_id, n.label as ext_label,
                           CAST(SUBSTR(e.source_id, -6) AS INTEGER) as seq
                    FROM ontology_edges e
                    JOIN ontology_nodes n ON e.target_id = n.id
                    WHERE e.session_id = ?
                      AND e.relation = 'used'
                      AND n.node_class = 'Entity'
                      AND (
                        json_extract(n.attributes, '$.entity_type') = 'url'
                        OR json_extract(n.attributes, '$.access_type') = 'external'
                        OR n.label LIKE 'http%%'
                      )
                )
                SELECT
                    s.entity_label as source_label,
                    s.sensitivity as source_sensitivity,
                    ext.ext_label as target_label,
                    (ext.seq - s.seq) as distance
                FROM sensitive_tcs s
                JOIN external_tcs ext ON ext.seq > s.seq AND (ext.seq - s.seq) <= 10
                ORDER BY distance ASC
                LIMIT 500
            """, (session_id, session_id)).fetchall()

            for r in rows:
                src_sensitivity = r["source_sensitivity"] or "HIGH"
                graph_flows.append({
                    "source_file": r["source_label"],
                    "source_sensitivity": src_sensitivity,
                    "source_tool": "graph",
                    "target_tool": "graph",
                    "target_detail": r["target_label"][:80],
                    "distance": r["distance"],
                    "severity": "CRITICAL" if src_sensitivity == "CRITICAL" else "HIGH",
                    "method": "graph_cte",
                })
    except Exception as e:
        logger.warning(f"[ONTO-SEC] Graph CTE flow tracking failed: {e}")
    finally:
        conn.close()

    # --- Phase 2: Session log fallback (if graph had no results) ---
    session_flows: list[dict] = []
    if not graph_flows:
        fallback_used = True
        tool_ctx = _get_tool_context(session_id)

        sensitive_reads = []
        external_actions = []
        seen_sr: set[int] = set()
        for tc in tool_ctx:
            found = False
            for fp in tc["files"]:
                level = _classify_sensitivity(fp)
                if level in ("CRITICAL", "HIGH") and tc["index"] not in seen_sr:
                    sensitive_reads.append({
                        "index": tc["index"], "tool": tc["tool_name"],
                        "file": fp, "sensitivity": level,
                    })
                    seen_sr.add(tc["index"])
                    found = True
                    break
            if not found:
                for cmd in tc["commands"]:
                    for token in cmd.split():
                        if "/" not in token and "\\" not in token:
                            continue
                        level = _classify_sensitivity(token)
                        if level in ("CRITICAL", "HIGH") and tc["index"] not in seen_sr:
                            sensitive_reads.append({
                                "index": tc["index"], "tool": tc["tool_name"],
                                "file": token, "sensitivity": level,
                            })
                            seen_sr.add(tc["index"])
                            found = True
                            break
                    if found:
                        break
            if tc["is_external"] or tc["is_shell"]:
                external_actions.append({
                    "index": tc["index"], "tool": tc["tool_name"],
                    "urls": tc["urls"], "commands": tc["commands"],
                })

        MAX_DISTANCE = 15
        seen: set[tuple] = set()
        for sr in sensitive_reads:
            for ea in external_actions:
                if ea["index"] > sr["index"]:
                    distance = ea["index"] - sr["index"]
                    if distance <= MAX_DISTANCE:
                        key = (sr["file"], ea["index"])
                        if key in seen:
                            continue
                        seen.add(key)
                        session_flows.append({
                            "source_file": sr["file"],
                            "source_sensitivity": sr["sensitivity"],
                            "source_tool": sr["tool"],
                            "target_tool": ea["tool"],
                            "target_detail": (ea["urls"] or ea["commands"] or [""])[0][:80],
                            "distance": distance,
                            "severity": "CRITICAL" if sr["sensitivity"] == "CRITICAL" else "HIGH",
                            "method": "session_log",
                        })

    all_flows = graph_flows or session_flows
    return {
        "sensitive_reads": len(graph_flows) if graph_flows else len(session_flows),
        "external_actions": 0,  # not tracked in graph mode
        "suspicious_flows": all_flows[:50],
        "flow_count": len(all_flows),
        "risk_boost": min(30, len(all_flows) * 5),
        "method": "graph_cte" if not fallback_used else "session_log_fallback",
    }


# =========================================================================
# 3. Cross-Session Threat Detection
# =========================================================================
def detect_cross_session_threats(session_id: str) -> dict[str, Any]:
    """Detect escalation patterns across multiple sessions.

    Compares the current session's entity access and tool usage against
    historical sessions for the same agent. Flags:
    - New sensitive resources never seen before
    - New suspicious tools (bash, curl, etc.)
    - Risk count escalation beyond historical average
    """
    conn = _get_db()
    try:
        sessions = conn.execute("""
            SELECT DISTINCT session_id, MIN(timestamp) as timestamp
            FROM ontology_nodes WHERE node_class = 'Session'
            GROUP BY session_id ORDER BY timestamp DESC LIMIT 20
        """).fetchall()

        if len(sessions) < 2:
            return {
                "sessions_analyzed": len(sessions),
                "escalation_detected": False,
                "message": "Need 2+ sessions for cross-session analysis",
                "patterns": [], "risk_boost": 0,
            }

        # Build per-session profiles
        profiles: dict[str, dict] = {}
        for s in sessions:
            sid = s["session_id"]
            ents = conn.execute("""
                SELECT ent.label, ent.attributes
                FROM ontology_edges e
                JOIN ontology_nodes ent ON e.target_id = ent.id AND ent.node_class = 'Entity'
                WHERE e.relation = 'used' AND e.session_id = ?
            """, (sid,)).fetchall()

            sensitive = set()
            for ent in ents:
                attrs = json.loads(ent["attributes"] or "{}")
                if _classify_sensitivity(ent["label"], attrs) in ("CRITICAL", "HIGH"):
                    sensitive.add(ent["label"])

            tools = set(
                t["label"] for t in conn.execute(
                    "SELECT DISTINCT label FROM ontology_nodes "
                    "WHERE session_id=? AND node_class='ToolCall'", (sid,),
                ).fetchall()
            )

            risk_cnt = conn.execute(
                "SELECT COUNT(*) as cnt FROM ontology_nodes "
                "WHERE session_id=? AND node_class='Risk'", (sid,),
            ).fetchone()["cnt"]

            profiles[sid] = {
                "sensitive": sensitive, "tools": tools,
                "risk_count": risk_cnt, "ts": s["timestamp"],
            }

        current_sid = session_id if session_id in profiles else sessions[0]["session_id"]
        current = profiles.get(current_sid)
        if not current:
            return {"sessions_analyzed": len(sessions), "escalation_detected": False,
                    "patterns": [], "risk_boost": 0}

        hist_sensitive: set[str] = set()
        hist_tools: set[str] = set()
        hist_risks: list[int] = []
        for sid, p in profiles.items():
            if sid != current_sid:
                hist_sensitive |= p["sensitive"]
                hist_tools |= p["tools"]
                hist_risks.append(p["risk_count"])

        patterns = []

        new_sensitive = current["sensitive"] - hist_sensitive
        if new_sensitive:
            patterns.append({
                "type": "NEW_SENSITIVE_ACCESS",
                "severity": "HIGH",
                "description": f"Agent accessed {len(new_sensitive)} sensitive entities not seen in previous sessions",
                "entities": sorted(new_sensitive)[:20],
                "mitre": "TA0009 Collection",
            })

        _SUS_NAMES = {"bash", "shell", "terminal", "exec", "subprocess", "curl", "wget", "ssh", "scp"}
        new_sus_tools = [t for t in (current["tools"] - hist_tools) if t.lower() in _SUS_NAMES]
        if new_sus_tools:
            patterns.append({
                "type": "NEW_SUSPICIOUS_TOOLS",
                "severity": "HIGH",
                "description": f"Agent using {len(new_sus_tools)} new suspicious tools not seen historically",
                "tools": new_sus_tools[:10],
                "mitre": "TA0004 Privilege Escalation",
            })

        avg_risk = sum(hist_risks) / len(hist_risks) if hist_risks else 0
        if current["risk_count"] > avg_risk * 2 and current["risk_count"] > 3:
            patterns.append({
                "type": "RISK_ESCALATION",
                "severity": "MEDIUM",
                "description": (
                    f"Current session risks ({current['risk_count']}) is "
                    f"{current['risk_count'] / max(avg_risk, 1):.1f}x historical avg ({avg_risk:.1f})"
                ),
                "mitre": "TA0004 Privilege Escalation",
            })

        return {
            "sessions_analyzed": len(sessions),
            "current_session": current_sid,
            "escalation_detected": len(patterns) > 0,
            "patterns": patterns,
            "risk_boost": min(20, len(patterns) * 7),
        }
    except Exception as e:
        return {"error": str(e)}
    finally:
        conn.close()


# =========================================================================
# 4. Graph-Based Policy Engine
# =========================================================================
POLICIES = [
    {"id": "POL-DFT-001", "name": "Sensitive Data to External Call",
     "severity": "CRITICAL", "mitre": "TA0010 Exfiltration, T1048",
     "max_depth": 10},
    {"id": "POL-DFT-002", "name": "Credentials to Shell Execution",
     "severity": "HIGH", "mitre": "TA0002 Execution, T1059",
     "max_depth": 5},
    {"id": "POL-ENT-001", "name": "Excessive Sensitive Entity Access",
     "severity": "HIGH", "mitre": "TA0009 Collection, T1119", "threshold": 10},
    {"id": "POL-ENT-002", "name": "Sensitive File Write",
     "severity": "CRITICAL", "mitre": "TA0003 Persistence, T1546"},
]


def check_graph_policies(session_id: str) -> dict[str, Any]:
    """Check security policies using session log + ontology graph.

    POL-DFT-001: Sensitive file read → external call within max_depth=10 steps
    POL-DFT-002: Credential access → shell execution within max_depth=5 steps
    POL-ENT-001: >10 sensitive files accessed in one session
    POL-ENT-002: Write to sensitive/system file paths

    All distance checks use explicit depth limits from policy definitions.
    """
    tool_ctx = _get_tool_context(session_id)
    violations = []

    # Build indexed lists
    sensitive_accesses = []  # (index, file, level)
    external_indices = []    # indices of external/shell calls
    write_ops = []           # (index, tool, file)

    for tc in tool_ctx:
        for fp in tc["files"]:
            level = _classify_sensitivity(fp)
            if level in ("CRITICAL", "HIGH"):
                sensitive_accesses.append((tc["index"], fp, level))
        for cmd in tc["commands"]:
            for token in cmd.split():
                if "/" not in token and "\\" not in token:
                    continue
                level = _classify_sensitivity(token)
                if level in ("CRITICAL", "HIGH"):
                    sensitive_accesses.append((tc["index"], token, level))
        if tc["is_external"]:
            external_indices.append(tc["index"])
        if tc["is_shell"]:
            external_indices.append(tc["index"])

        # Detect writes to sensitive paths
        if tc["tool_name"] in ("Write", "Edit"):
            for fp in tc["files"]:
                if _classify_sensitivity(fp) in ("CRITICAL", "HIGH"):
                    write_ops.append((tc["index"], tc["tool_name"], fp))

    # --- POL-DFT-001: Sensitive → External within max_depth steps ---
    dft001_depth = POLICIES[0]["max_depth"]
    dft001_hits = []
    for idx, fp, level in sensitive_accesses:
        for ext_idx in external_indices:
            distance = ext_idx - idx
            if 0 < distance <= dft001_depth:
                dft001_hits.append({
                    "file": fp, "sensitivity": level,
                    "distance": distance, "max_depth": dft001_depth,
                })
                break
    if dft001_hits:
        violations.append({
            **POLICIES[0], "count": len(dft001_hits),
            "details": dft001_hits[:10],
        })

    # --- POL-DFT-002: Credential → Shell within max_depth steps ---
    dft002_depth = POLICIES[1]["max_depth"]
    cred_patterns = [".pem", "id_rsa", "credential", ".p12", ".pfx", ".key"]
    cred_accesses = [
        (idx, fp) for idx, fp, _ in sensitive_accesses
        if any(p in fp.lower() for p in cred_patterns)
    ]
    shell_indices = [tc["index"] for tc in tool_ctx if tc["is_shell"]]
    dft002_hits = []
    for idx, fp in cred_accesses:
        for sh_idx in shell_indices:
            distance = sh_idx - idx
            if 0 < distance <= dft002_depth:
                dft002_hits.append({
                    "file": fp, "distance": distance, "max_depth": dft002_depth,
                })
                break
    if dft002_hits:
        violations.append({
            **POLICIES[1], "count": len(dft002_hits),
            "details": dft002_hits[:10],
        })

    # --- POL-ENT-001: Excessive Sensitive Access ---
    unique_sensitive = set(fp for _, fp, _ in sensitive_accesses)
    if len(unique_sensitive) > POLICIES[2]["threshold"]:
        violations.append({
            **POLICIES[2], "count": len(unique_sensitive),
            "sample_files": sorted(unique_sensitive)[:10],
        })

    # --- POL-ENT-002: Sensitive File Write ---
    if write_ops:
        violations.append({
            **POLICIES[3], "count": len(write_ops),
            "files": [{"tool": t, "file": f} for _, t, f in write_ops[:10]],
        })

    risk_boost = sum(10 if v["severity"] == "CRITICAL" else 5 for v in violations)

    return {
        "policies_checked": len(POLICIES),
        "violations": violations,
        "violation_count": len(violations),
        "risk_boost": min(25, risk_boost),
    }


# =========================================================================
# 5. Impact Analysis
# =========================================================================
def analyze_impact(session_id: str, top_n: int = 10) -> dict[str, Any]:
    """Compute blast radius for sensitive entities.

    Only analyzes CRITICAL/HIGH sensitivity entities.
    Hybrid approach:
      - If total derivedFrom edges < 2000: use recursive CTE (depth ≤ 5)
      - Otherwise: use fast 1-hop edge count heuristic
    """
    conn = _get_db()
    try:
        entities = conn.execute(
            "SELECT id, label, attributes FROM ontology_nodes "
            "WHERE session_id=? AND node_class='Entity'",
            (session_id,),
        ).fetchall()

        # Pre-filter: only analyze CRITICAL/HIGH entities
        sensitive_ents = []
        for ent in entities:
            attrs = json.loads(ent["attributes"] or "{}")
            level = _classify_sensitivity(ent["label"], attrs)
            if level in ("CRITICAL", "HIGH"):
                sensitive_ents.append((ent, level))

        if not sensitive_ents:
            return {
                "total_entities": len(entities),
                "entities_with_impact": 0,
                "high_impact_entities": [],
                "top_impact": [],
                "max_blast_radius": 0,
            }

        # Decide strategy based on derivedFrom edge count
        df_count = conn.execute(
            "SELECT COUNT(*) as cnt FROM ontology_edges "
            "WHERE session_id=? AND relation='derivedFrom'",
            (session_id,),
        ).fetchone()["cnt"]
        use_cte = df_count < 2000

        scores = []
        for ent, sensitivity in sensitive_ents:
            downstream_count = 0
            max_depth = 0

            if use_cte:
                # Recursive CTE: follow derivedFrom chain (depth ≤ 5)
                try:
                    impact_rows = conn.execute("""
                        WITH RECURSIVE impact(entity_id, depth) AS (
                            SELECT id, 0 FROM ontology_nodes
                            WHERE id = ? AND node_class = 'Entity'
                            UNION ALL
                            SELECT e.source_id, i.depth + 1
                            FROM impact i
                            JOIN ontology_edges e ON e.target_id = i.entity_id
                              AND e.relation = 'derivedFrom'
                              AND e.session_id = ?
                            WHERE i.depth < 5
                        )
                        SELECT DISTINCT entity_id, MIN(depth) as min_depth
                        FROM impact WHERE depth > 0
                        GROUP BY entity_id
                        LIMIT 500
                    """, (ent["id"], session_id)).fetchall()
                    downstream_count = len(impact_rows)
                    max_depth = max((r["min_depth"] for r in impact_rows), default=0)
                except Exception:
                    use_cte = False  # Fall through to heuristic

            if not use_cte or downstream_count == 0:
                # Fast: 1-hop edge count (derivedFrom + used + generated)
                downstream_count = conn.execute(
                    "SELECT COUNT(*) as cnt FROM ontology_edges "
                    "WHERE (source_id=? OR target_id=?) AND session_id=? "
                    "AND relation IN ('derivedFrom','generated','used')",
                    (ent["id"], ent["id"], session_id),
                ).fetchone()["cnt"]
                max_depth = 1 if downstream_count > 0 else 0

            if downstream_count == 0:
                continue

            weight = {"CRITICAL": 4, "HIGH": 3}[sensitivity]
            depth_bonus = min(max_depth, 5)
            scores.append({
                "entity_id": ent["id"],
                "entity_label": ent["label"],
                "sensitivity": sensitivity,
                "downstream_count": downstream_count,
                "max_depth": max_depth,
                "impact_score": downstream_count * weight + depth_bonus * 2,
                "method": "cte" if use_cte and max_depth > 1 else "heuristic",
            })

        scores.sort(key=lambda x: -x["impact_score"])
        high_impact = [e for e in scores if e["impact_score"] >= 5]

        return {
            "total_entities": len(entities),
            "entities_with_impact": len(scores),
            "high_impact_entities": high_impact[:top_n],
            "top_impact": scores[:top_n],
            "max_blast_radius": scores[0]["downstream_count"] if scores else 0,
            "method": "cte" if use_cte else "heuristic",
            "derivedFrom_count": df_count,
        }
    except Exception as e:
        return {"error": str(e)}
    finally:
        conn.close()


# =========================================================================
# 6. Prompt Injection Flow Tracking (v2)
# =========================================================================
# Patterns that indicate potential prompt injection
_PROMPT_INJECTION_PATTERNS = [
    ("ignore_instruction", ["ignore previous", "ignore above", "disregard",
                            "forget your instructions", "override your"]),
    ("role_hijack", ["you are now", "act as", "pretend to be",
                     "new persona", "dan mode", "jailbreak"]),
    ("code_injection", ["eval(", "exec(", "__import__", "subprocess",
                        "os.system", "base64.b64decode"]),
    ("xss_attempt", ["<script", "javascript:", "onerror=",
                     "onload=", "document.cookie"]),
    ("data_exfil_request", ["send to", "upload to", "post to",
                            "curl ", "wget ", "exfiltrate"]),
    ("system_probe", ["/etc/passwd", "/etc/shadow", "whoami",
                      "uname -a", "cat /proc", "env | grep"]),
]


def track_prompt_injection_flows(session_id: str) -> dict[str, Any]:
    """Track prompt injection attempts and their downstream effects.

    Uses ontology graph to trace:
      1. Find Prompt entities with injection_suspect=true
      2. Follow: Prompt ←used- ToolCall -precedes→ ToolCall chain
      3. Check if any downstream ToolCall accessed sensitive files or ran shell

    Also scans session log for injection patterns not yet in the graph.

    Returns findings with causal chains and MITRE ATT&CK mappings.
    """
    conn = _get_db()
    injection_flows: list[dict] = []
    pattern_matches: list[dict] = []

    try:
        # === Phase 1: Check ontology Prompt entities ===
        suspect_prompts = conn.execute(
            "SELECT id, label, attributes FROM ontology_nodes "
            "WHERE session_id=? AND node_class='Entity' "
            "AND json_extract(attributes, '$.entity_type') = 'prompt' "
            "AND json_extract(attributes, '$.injection_suspect') = 1",
            (session_id,),
        ).fetchall()

        for prompt in suspect_prompts:
            attrs = json.loads(prompt["attributes"] or "{}")
            prompt_seq = CAST_INT(prompt["id"].rsplit(":", 1)[-1]) if ":" in prompt["id"] else 0

            # Find ToolCalls that used this prompt
            tc_rows = conn.execute(
                "SELECT e.source_id as tc_id, "
                "       CAST(SUBSTR(e.source_id, -6) AS INTEGER) as seq "
                "FROM ontology_edges e "
                "WHERE e.target_id = ? AND e.relation = 'used' AND e.session_id = ?",
                (prompt["id"], session_id),
            ).fetchall()

            for tc in tc_rows:
                # Check if any subsequent ToolCall within 10 steps accessed sensitive data
                nearby_sensitive = conn.execute("""
                    SELECT n.label as entity_label,
                           json_extract(n.attributes, '$.sensitivity') as sens,
                           CAST(SUBSTR(e.source_id, -6) AS INTEGER) as tc_seq
                    FROM ontology_edges e
                    JOIN ontology_nodes n ON e.target_id = n.id
                    WHERE e.session_id = ?
                      AND e.relation = 'used'
                      AND n.node_class = 'Entity'
                      AND json_extract(n.attributes, '$.entity_type') = 'file'
                      AND json_extract(n.attributes, '$.sensitivity') IN ('CRITICAL', 'HIGH')
                      AND CAST(SUBSTR(e.source_id, -6) AS INTEGER) BETWEEN ? AND ?
                    LIMIT 20
                """, (session_id, tc["seq"], tc["seq"] + 10)).fetchall()

                for sens_hit in nearby_sensitive:
                    injection_flows.append({
                        "prompt_preview": prompt["label"][:80],
                        "prompt_id": prompt["id"],
                        "sensitive_file": sens_hit["entity_label"],
                        "sensitivity": sens_hit["sens"],
                        "distance": sens_hit["tc_seq"] - tc["seq"],
                        "severity": "CRITICAL",
                        "mitre": "ATLAS AML.T0051 Prompt Injection → TA0009 Collection",
                    })

                # Check if any subsequent ToolCall is external/shell
                nearby_external = conn.execute("""
                    SELECT n.label as entity_label,
                           json_extract(n.attributes, '$.entity_type') as etype,
                           CAST(SUBSTR(e.source_id, -6) AS INTEGER) as tc_seq
                    FROM ontology_edges e
                    JOIN ontology_nodes n ON e.target_id = n.id
                    WHERE e.session_id = ?
                      AND e.relation = 'used'
                      AND n.node_class = 'Entity'
                      AND (json_extract(n.attributes, '$.entity_type') = 'url'
                           OR json_extract(n.attributes, '$.access_type') = 'external')
                      AND CAST(SUBSTR(e.source_id, -6) AS INTEGER) BETWEEN ? AND ?
                    LIMIT 20
                """, (session_id, tc["seq"], tc["seq"] + 10)).fetchall()

                for ext_hit in nearby_external:
                    injection_flows.append({
                        "prompt_preview": prompt["label"][:80],
                        "prompt_id": prompt["id"],
                        "external_target": ext_hit["entity_label"][:60],
                        "distance": ext_hit["tc_seq"] - tc["seq"],
                        "severity": "CRITICAL",
                        "mitre": "ATLAS AML.T0051 Prompt Injection → TA0010 Exfiltration",
                    })

    except Exception as e:
        logger.warning(f"[ONTO-SEC] Prompt injection graph analysis failed: {e}")
    finally:
        conn.close()

    # === Phase 2: Session log pattern scan (covers sessions without prompt entities) ===
    tool_ctx = _get_tool_context(session_id)
    log = _load_session_log(session_id)

    for i, entry in enumerate(log):
        if entry.get("role") != "user":
            continue
        content = entry.get("content", "")
        if not isinstance(content, str):
            content = str(content)
        content_lower = content.lower()

        for cat, patterns in _PROMPT_INJECTION_PATTERNS:
            for p in patterns:
                if p in content_lower:
                    # Find what happened after this prompt
                    downstream_actions = []
                    for tc in tool_ctx:
                        if tc["index"] > i and tc["index"] - i <= 15:
                            if tc["is_external"] or tc["is_shell"]:
                                downstream_actions.append({
                                    "tool": tc["tool_name"],
                                    "is_external": tc["is_external"],
                                    "is_shell": tc["is_shell"],
                                })
                            for fp in tc["files"]:
                                level = _classify_sensitivity(fp)
                                if level in ("CRITICAL", "HIGH"):
                                    downstream_actions.append({
                                        "tool": tc["tool_name"],
                                        "file": fp,
                                        "sensitivity": level,
                                    })

                    pattern_matches.append({
                        "category": cat,
                        "matched_pattern": p,
                        "prompt_preview": content[:100],
                        "index": i,
                        "downstream_actions": downstream_actions[:10],
                        "severity": "CRITICAL" if downstream_actions else "MEDIUM",
                        "mitre": "ATLAS AML.T0051",
                    })
                    break  # One match per category per prompt
            # Don't break outer loop — check all categories

    risk_boost = min(20, len(injection_flows) * 5 + len(pattern_matches) * 3)

    return {
        "graph_injection_flows": injection_flows[:50],
        "pattern_matches": pattern_matches[:50],
        "total_injection_suspects": len(injection_flows) + len(pattern_matches),
        "risk_boost": risk_boost,
    }


def CAST_INT(s: str) -> int:
    """Safe integer cast for sequence extraction."""
    try:
        return int(s)
    except (ValueError, TypeError):
        return 0


# =========================================================================
# Combined Analysis
# =========================================================================
def run_ontology_security_analysis(session_id: str) -> dict[str, Any]:
    """Run all ontology-based security analyses and combine results.

    Returns unified report with findings, MITRE mappings, and risk_boost.
    """
    # Clear per-run caches
    _session_log_cache.clear()
    _tool_ctx_cache.clear()

    results: dict[str, Any] = {
        "session_id": session_id,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }

    for key, fn in [
        ("entity_sensitivity", lambda: classify_entities(session_id)),
        ("data_flows", lambda: track_data_flows(session_id)),
        ("cross_session", lambda: detect_cross_session_threats(session_id)),
        ("policy_violations", lambda: check_graph_policies(session_id)),
        ("impact_analysis", lambda: analyze_impact(session_id)),
        ("prompt_injection", lambda: track_prompt_injection_flows(session_id)),
    ]:
        try:
            results[key] = fn()
        except Exception as e:
            results[key] = {"error": str(e)}

    # Combined risk boost (capped at 50)
    total_boost = 0
    for key in ("data_flows", "cross_session", "policy_violations", "prompt_injection"):
        if isinstance(results.get(key), dict):
            total_boost += results[key].get("risk_boost", 0)
    results["combined_risk_boost"] = min(50, total_boost)

    # Generate structured findings
    findings = []

    es = results.get("entity_sensitivity", {})
    if es.get("sensitive_count", 0) > 0:
        findings.append({
            "severity": "HIGH" if es.get("critical") else "MEDIUM",
            "title": f"{es['sensitive_count']} Sensitive Entities Detected",
            "description": (
                f"{len(es.get('critical', []))} CRITICAL, "
                f"{len(es.get('high', []))} HIGH sensitivity entities accessed."
            ),
            "mitre": "TA0009 Collection",
        })

    df = results.get("data_flows", {})
    if df.get("flow_count", 0) > 0:
        findings.append({
            "severity": "CRITICAL",
            "title": f"{df['flow_count']} Suspicious Data Flows",
            "description": "Sensitive data read followed by external/shell calls.",
            "mitre": "TA0010 Exfiltration, T1048",
        })

    cs = results.get("cross_session", {})
    for p in cs.get("patterns", []):
        findings.append({
            "severity": p["severity"],
            "title": p["type"].replace("_", " ").title(),
            "description": p["description"],
            "mitre": p.get("mitre", ""),
        })

    pv = results.get("policy_violations", {})
    for v in pv.get("violations", []):
        findings.append({
            "severity": v["severity"],
            "title": f"Policy {v['id']}: {v['name']}",
            "description": f"{v['count']} violation(s). {v.get('mitre', '')}",
            "mitre": v.get("mitre", ""),
        })

    ia = results.get("impact_analysis", {})
    if ia.get("high_impact_entities"):
        top = ia["high_impact_entities"][0]
        findings.append({
            "severity": "MEDIUM",
            "title": f"High-Impact Entity: {top['entity_label'][:40]}",
            "description": (
                f"Blast radius: {top['downstream_count']} downstream nodes, "
                f"sensitivity: {top['sensitivity']}"
            ),
            "mitre": "",
        })

    # Prompt injection findings (v2)
    pi = results.get("prompt_injection", {})
    if pi.get("total_injection_suspects", 0) > 0:
        graph_flows = pi.get("graph_injection_flows", [])
        pat_matches = pi.get("pattern_matches", [])
        if graph_flows:
            findings.append({
                "severity": "CRITICAL",
                "title": f"{len(graph_flows)} Prompt Injection → Action Flows",
                "description": (
                    f"Suspicious prompts led to {len(graph_flows)} sensitive/external actions. "
                    f"First: {graph_flows[0].get('prompt_preview', '')[:50]}..."
                ),
                "mitre": "ATLAS AML.T0051 Prompt Injection",
            })
        if pat_matches:
            cats = set(m["category"] for m in pat_matches)
            findings.append({
                "severity": "HIGH" if any(m.get("downstream_actions") for m in pat_matches) else "MEDIUM",
                "title": f"{len(pat_matches)} Prompt Injection Patterns Detected",
                "description": (
                    f"Categories: {', '.join(cats)}. "
                    f"{sum(1 for m in pat_matches if m.get('downstream_actions'))} with downstream impact."
                ),
                "mitre": "ATLAS AML.T0051",
            })

    results["findings"] = findings
    results["findings_count"] = len(findings)

    logger.info(
        f"[ONTO-SEC] Session {session_id[:8]}: "
        f"{len(findings)} findings, risk_boost={results['combined_risk_boost']}"
    )
    return results
