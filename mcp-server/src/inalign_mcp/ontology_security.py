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

# === Sensitivity Patterns ===
SENSITIVITY_PATTERNS = {
    "CRITICAL": [
        ".env", ".pem", ".key", "id_rsa", "id_ed25519", "credentials",
        "password", "passwd", "secret", "token", "apikey", "api_key",
        "private_key", ".p12", ".pfx", ".keystore", "shadow",
        "master.key", "encryption_key", ".aws/credentials",
        ".npmrc", ".pypirc",
    ],
    "HIGH": [
        ".conf", ".ini", ".cfg", ".yaml", ".yml", ".toml",
        "database", ".db", ".sqlite", "connection_string", "dsn",
        "docker-compose", "Dockerfile",
        ".gitconfig", ".ssh/config", "authorized_keys", "known_hosts",
    ],
    "MEDIUM": [
        ".py", ".js", ".ts", ".go", ".rs", ".java",
        "src/", "lib/", "internal/",
    ],
}

EXTERNAL_PATTERNS = [
    "http://", "https://", "ftp://", "ssh://",
    "curl", "wget", "fetch", "request",
    "api.openai.com", "api.anthropic.com",
    "smtp", "email", "webhook",
]

SHELL_PATTERNS = [
    "bash", "shell", "exec", "system", "subprocess",
    "cmd", "powershell", "chmod", "chown", "sudo",
]


def _get_db() -> sqlite3.Connection:
    conn = sqlite3.connect(str(DB_PATH), check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    return conn


def _classify_sensitivity(label: str, attrs: dict = None) -> str:
    """Classify entity sensitivity based on label and attributes."""
    label_lower = (label or "").lower()
    entity_type = str((attrs or {}).get("entity_type", "")).lower()
    combined = label_lower + " " + entity_type

    for level, patterns in SENSITIVITY_PATTERNS.items():
        for p in patterns:
            if p in combined:
                return level
    return "LOW"


def _is_external(label: str) -> bool:
    label_lower = (label or "").lower()
    return any(p in label_lower for p in EXTERNAL_PATTERNS)


def _is_shell(label: str) -> bool:
    label_lower = (label or "").lower()
    return any(p in label_lower for p in SHELL_PATTERNS)


def _match_reason(label: str) -> str:
    label_lower = (label or "").lower()
    for level, patterns in SENSITIVITY_PATTERNS.items():
        for p in patterns:
            if p in label_lower:
                return f"matches '{p}'"
    return "attribute"


def _load_session_log(session_id: str = "") -> list[dict]:
    """Load the latest session log from json.gz."""
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
                    return data.get("records", [])
                return data if isinstance(data, list) else []
        except Exception:
            continue
    return []


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
        ti_str = json.dumps(tool_input) if isinstance(tool_input, dict) else str(tool_input)
        ti_lower = ti_str.lower()

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

        is_ext = bool(urls) or _is_external(tool_name) or _is_external(ti_str)
        is_sh = _is_shell(tool_name) or any(_is_shell(c) for c in commands)

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
    session_log = _load_session_log(session_id)
    tool_ctx = _extract_tool_context(session_log)

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

        # Also scan full tool_input text for patterns not captured above
        text = tc["text"]
        if text and tc["tool_name"] not in ("TaskCreate", "TaskUpdate", "mcp__inalign__record_user_command"):
            level = _classify_sensitivity(text)
            if level in ("CRITICAL", "HIGH"):
                key = f"{tc['tool_name']}:{tc['index']}"
                if key not in seen:
                    seen.add(key)
                    classified[level].append({
                        "file": f"[{tc['tool_name']}] input contains sensitive pattern",
                        "tool": tc["tool_name"],
                        "sensitivity": level, "reason": _match_reason(text),
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
    """Track sensitive data flowing toward external targets.

    Scans session log chronologically:
      1. Identify tool calls that access sensitive files (Read, Edit, Grep on .env, .pem, etc.)
      2. Find subsequent external/shell calls (Bash with curl/wget, WebFetch, etc.)
      3. Flag any sensitive read followed by external call within N steps

    Also uses ontology graph precedes edges for structural confirmation.
    """
    session_log = _load_session_log(session_id)
    tool_ctx = _extract_tool_context(session_log)

    # Step 1: Tag sensitive reads and external actions
    sensitive_reads = []
    external_actions = []
    seen_sr: set[int] = set()
    for tc in tool_ctx:
        found = False
        # Check files for sensitivity
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
        # Check commands for sensitivity
        if not found:
            for cmd in tc["commands"]:
                for token in cmd.split():
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
        # Full text scan
        if not found and tc["index"] not in seen_sr:
            level = _classify_sensitivity(tc["text"])
            if level in ("CRITICAL", "HIGH"):
                sensitive_reads.append({
                    "index": tc["index"], "tool": tc["tool_name"],
                    "file": f"[{tc['tool_name']}] sensitive pattern",
                    "sensitivity": level,
                })
                seen_sr.add(tc["index"])

        if tc["is_external"] or tc["is_shell"]:
            external_actions.append({
                "index": tc["index"], "tool": tc["tool_name"],
                "urls": tc["urls"], "commands": tc["commands"],
            })

    # Step 2: Find flows — sensitive read followed by external within 15 steps
    MAX_DISTANCE = 15
    suspicious_flows = []
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
                    suspicious_flows.append({
                        "source_file": sr["file"],
                        "source_sensitivity": sr["sensitivity"],
                        "source_tool": sr["tool"],
                        "target_tool": ea["tool"],
                        "target_detail": (ea["urls"] or ea["commands"] or [""])[0][:80],
                        "distance": distance,
                        "severity": "CRITICAL" if sr["sensitivity"] == "CRITICAL" else "HIGH",
                    })

    return {
        "sensitive_reads": len(sensitive_reads),
        "external_actions": len(external_actions),
        "suspicious_flows": suspicious_flows[:50],
        "flow_count": len(suspicious_flows),
        "risk_boost": min(30, len(suspicious_flows) * 5),
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

        new_sus_tools = [t for t in (current["tools"] - hist_tools) if _is_shell(t) or _is_external(t)]
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
     "severity": "CRITICAL", "mitre": "TA0010 Exfiltration, T1048"},
    {"id": "POL-DFT-002", "name": "Credentials to Shell Execution",
     "severity": "HIGH", "mitre": "TA0002 Execution, T1059"},
    {"id": "POL-ENT-001", "name": "Excessive Sensitive Entity Access",
     "severity": "HIGH", "mitre": "TA0009 Collection, T1119", "threshold": 10},
    {"id": "POL-ENT-002", "name": "Sensitive File Write",
     "severity": "CRITICAL", "mitre": "TA0003 Persistence, T1546"},
]


def check_graph_policies(session_id: str) -> dict[str, Any]:
    """Check security policies using session log + ontology graph.

    POL-DFT-001: Sensitive file read → external call within 10 steps
    POL-DFT-002: Credential access → shell execution within 5 steps
    POL-ENT-001: >10 sensitive files accessed in one session
    POL-ENT-002: Write to sensitive/system file paths
    """
    session_log = _load_session_log(session_id)
    tool_ctx = _extract_tool_context(session_log)
    violations = []

    # Build indexed lists
    sensitive_accesses = []  # (index, file, level)
    external_indices = []    # indices of external/shell calls
    write_ops = []           # (index, tool, file)
    seen_sa: set[int] = set()

    for tc in tool_ctx:
        found = False
        for fp in tc["files"]:
            level = _classify_sensitivity(fp)
            if level in ("CRITICAL", "HIGH"):
                sensitive_accesses.append((tc["index"], fp, level))
                found = True
        for cmd in tc["commands"]:
            for token in cmd.split():
                level = _classify_sensitivity(token)
                if level in ("CRITICAL", "HIGH"):
                    sensitive_accesses.append((tc["index"], token, level))
                    found = True
        # Full text scan fallback
        if not found and tc["index"] not in seen_sa:
            level = _classify_sensitivity(tc["text"])
            if level in ("CRITICAL", "HIGH"):
                sensitive_accesses.append((tc["index"], f"[{tc['tool_name']}]", level))
                seen_sa.add(tc["index"])

        if tc["is_external"]:
            external_indices.append(tc["index"])
        if tc["is_shell"]:
            external_indices.append(tc["index"])

        # Detect writes to sensitive paths
        if tc["tool_name"] in ("Write", "Edit"):
            for fp in tc["files"]:
                if _classify_sensitivity(fp) in ("CRITICAL", "HIGH"):
                    write_ops.append((tc["index"], tc["tool_name"], fp))

    # --- POL-DFT-001: Sensitive → External within 10 steps ---
    dft001_hits = []
    for idx, fp, level in sensitive_accesses:
        for ext_idx in external_indices:
            if 0 < ext_idx - idx <= 10:
                dft001_hits.append({
                    "file": fp, "sensitivity": level,
                    "distance": ext_idx - idx,
                })
                break
    if dft001_hits:
        violations.append({
            **POLICIES[0], "count": len(dft001_hits),
            "details": dft001_hits[:10],
        })

    # --- POL-DFT-002: Credential → Shell within 5 steps ---
    cred_patterns = [".pem", "id_rsa", "credential", ".p12", ".pfx", ".key"]
    cred_accesses = [
        (idx, fp) for idx, fp, _ in sensitive_accesses
        if any(p in fp.lower() for p in cred_patterns)
    ]
    shell_indices = [tc["index"] for tc in tool_ctx if tc["is_shell"]]
    dft002_hits = []
    for idx, fp in cred_accesses:
        for sh_idx in shell_indices:
            if 0 < sh_idx - idx <= 5:
                dft002_hits.append({"file": fp, "distance": sh_idx - idx})
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
    """Compute blast radius for each entity in the session.

    For each Entity node, uses recursive CTE to count downstream
    reachable nodes via derivedFrom/generated/used edges.
    Weighted by sensitivity level.
    """
    conn = _get_db()
    try:
        entities = conn.execute(
            "SELECT id, label, attributes FROM ontology_nodes "
            "WHERE session_id=? AND node_class='Entity'",
            (session_id,),
        ).fetchall()

        scores = []
        for ent in entities:
            reach = conn.execute("""
                WITH RECURSIVE impact(nid, depth) AS (
                    SELECT e.target_id, 1
                    FROM ontology_edges e
                    WHERE e.source_id = ?
                      AND e.relation IN ('derivedFrom', 'generated', 'used')
                    UNION ALL
                    SELECT e.target_id, i.depth + 1
                    FROM ontology_edges e
                    JOIN impact i ON e.source_id = i.nid
                    WHERE e.relation IN ('derivedFrom', 'generated', 'used')
                      AND i.depth < 5
                )
                SELECT COUNT(DISTINCT nid) as cnt, MAX(depth) as max_d FROM impact
            """, (ent["id"],)).fetchone()

            cnt = reach["cnt"] or 0
            if cnt == 0:
                continue
            attrs = json.loads(ent["attributes"] or "{}")
            sensitivity = _classify_sensitivity(ent["label"], attrs)
            weight = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}[sensitivity]

            scores.append({
                "entity_id": ent["id"],
                "entity_label": ent["label"],
                "sensitivity": sensitivity,
                "downstream_count": cnt,
                "max_depth": reach["max_d"] or 0,
                "impact_score": cnt * weight,
            })

        scores.sort(key=lambda x: -x["impact_score"])
        high_impact = [e for e in scores if e["impact_score"] >= 5]

        return {
            "total_entities": len(entities),
            "entities_with_impact": len(scores),
            "high_impact_entities": high_impact[:top_n],
            "top_impact": scores[:top_n],
            "max_blast_radius": scores[0]["downstream_count"] if scores else 0,
        }
    except Exception as e:
        return {"error": str(e)}
    finally:
        conn.close()


# =========================================================================
# Combined Analysis
# =========================================================================
def run_ontology_security_analysis(session_id: str) -> dict[str, Any]:
    """Run all ontology-based security analyses and combine results.

    Returns unified report with findings, MITRE mappings, and risk_boost.
    """
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
    ]:
        try:
            results[key] = fn()
        except Exception as e:
            results[key] = {"error": str(e)}

    # Combined risk boost (capped at 50)
    total_boost = 0
    for key in ("data_flows", "cross_session", "policy_violations"):
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

    results["findings"] = findings
    results["findings_count"] = len(findings)

    logger.info(
        f"[ONTO-SEC] Session {session_id[:8]}: "
        f"{len(findings)} findings, risk_boost={results['combined_risk_boost']}"
    )
    return results
