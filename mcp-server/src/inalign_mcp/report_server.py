"""
InALign Report Server

Local HTTP server that serves the React dashboard and REST API.
All data stays local — zero-trust, zero telemetry.

Usage:
    inalign-report                  # Serve dashboard + API
    inalign-report --port 8275      # Custom port
    inalign-report --legacy         # Serve old single-HTML report
"""

import json
import gzip
import mimetypes
import argparse
import webbrowser
import logging
from http.server import HTTPServer, BaseHTTPRequestHandler
from socketserver import ThreadingMixIn
from pathlib import Path
from urllib.request import Request, urlopen
from urllib.error import HTTPError, URLError

import re

logger = logging.getLogger("inalign.report_server")

DEFAULT_PORT = 8275

_UUID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.I
)


def _is_uuid(s: str) -> bool:
    return bool(_UUID_RE.match(s))


# ─── Dashboard static files ─────────────────────────────────────────
_DASHBOARD_DIR = Path(__file__).parent / "dashboard_dist"

# MIME types for static assets
mimetypes.add_type("application/javascript", ".js")
mimetypes.add_type("text/css", ".css")
mimetypes.add_type("image/svg+xml", ".svg")


# ─── Session data cache ─────────────────────────────────────────────
_session_cache = {}  # session_id -> (data_dict, timestamp)
_CACHE_TTL = 600  # seconds (10 min — data doesn't change until refresh)


def _cache_get(session_id: str):
    import time
    if session_id in _session_cache:
        data, ts = _session_cache[session_id]
        if time.time() - ts < _CACHE_TTL:
            return data
    return None


def _cache_set(session_id: str, data: dict):
    import time
    _session_cache[session_id] = (data, time.time())


# ─── Legacy report ──────────────────────────────────────────────────
_report_html = ""
_report_source_mtime = 0.0


# ─── Auto-ingest ────────────────────────────────────────────────────
def auto_ingest_new_sessions() -> tuple[int, str | None]:
    """Auto-discover and ingest new Claude Code sessions."""
    from .session_ingest import SessionIngestor

    sessions_dir = Path.home() / ".inalign" / "sessions"
    sessions_dir.mkdir(parents=True, exist_ok=True)

    existing_gz = {}
    for gz in sessions_dir.glob("*.json.gz"):
        key = gz.name.replace(".json.gz", "")
        existing_gz[key] = gz.stat().st_mtime

    claude_base = Path.home() / ".claude" / "projects"
    if not claude_base.exists():
        return 0, None

    ingested = 0
    latest_mtime = 0.0
    latest_id = None

    for jsonl in claude_base.rglob("*.jsonl"):
        full_path_lower = str(jsonl).lower()
        if "subagent" in full_path_lower or "compact" in full_path_lower:
            continue
        if not _is_uuid(jsonl.stem):
            continue

        stem = jsonl.stem
        jsonl_mtime = jsonl.stat().st_mtime

        if jsonl_mtime > latest_mtime:
            latest_mtime = jsonl_mtime
            latest_id = stem

        if stem in existing_gz and jsonl_mtime <= existing_gz[stem] + 2:
            continue

        try:
            ingestor = SessionIngestor()
            ingestor.ingest_file(str(jsonl))
            if ingestor.session_id != stem:
                ingestor.session_id = stem
            ingestor.save_compressed(str(sessions_dir))
            ingested += 1
        except Exception:
            continue

    return ingested, latest_id


# ─── SQLite Session Index ──────────────────────────────────────────
import sqlite3
from datetime import datetime, timezone

_INDEX_DB = Path.home() / ".inalign" / "provenance.db"


def _init_session_index():
    """Create session_index table if not exists."""
    _INDEX_DB.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(_INDEX_DB))
    conn.execute("""
        CREATE TABLE IF NOT EXISTS session_index (
            session_id TEXT PRIMARY KEY,
            timestamp TEXT,
            record_count INTEGER DEFAULT 0,
            file_size_kb REAL DEFAULT 0,
            risk_score INTEGER DEFAULT -1,
            risk_level TEXT DEFAULT '',
            chain_valid INTEGER DEFAULT -1,
            patterns_count INTEGER DEFAULT 0,
            findings_count INTEGER DEFAULT 0,
            events_count INTEGER DEFAULT 0,
            last_indexed REAL DEFAULT 0
        )
    """)
    conn.commit()
    conn.close()


def _index_sessions_to_sqlite():
    """Scan session gzip files and index metadata into SQLite.

    Only re-indexes files that have changed since last indexing.
    """
    sessions_dir = Path.home() / ".inalign" / "sessions"
    if not sessions_dir.exists():
        return 0

    _init_session_index()
    conn = sqlite3.connect(str(_INDEX_DB))
    conn.row_factory = sqlite3.Row

    # Get existing index
    existing = {}
    for row in conn.execute("SELECT session_id, last_indexed FROM session_index"):
        existing[row["session_id"]] = row["last_indexed"]

    indexed = 0
    for gz in sessions_dir.glob("*.json.gz"):
        sid = gz.name.replace(".json.gz", "")
        try:
            stat = gz.stat()
            file_mtime = stat.st_mtime

            # Skip if already indexed and file hasn't changed
            if sid in existing and existing[sid] >= file_mtime:
                continue

            record_count = 0
            events_count = 0
            try:
                with gzip.open(gz, "rt", encoding="utf-8") as f:
                    sdata = json.load(f)
                records = sdata.get("records", sdata) if isinstance(sdata, dict) else sdata
                if isinstance(records, list):
                    record_count = len(records)
                    events_count = len(records)
            except Exception:
                pass

            ts = datetime.fromtimestamp(file_mtime, tz=timezone.utc).isoformat()

            conn.execute("""
                INSERT OR REPLACE INTO session_index
                (session_id, timestamp, record_count, file_size_kb, events_count, last_indexed)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (sid, ts, record_count, round(stat.st_size / 1024, 1), events_count, file_mtime))
            indexed += 1

        except Exception:
            continue

    conn.commit()
    conn.close()
    return indexed


def _update_session_risk_index(session_id: str, risk_data: dict, verification: dict, ontology_data: dict):
    """Update session index with risk/analysis data after full analysis."""
    try:
        _init_session_index()
        conn = sqlite3.connect(str(_INDEX_DB))
        risk_score = risk_data.get("risk_score", -1)
        risk_level = risk_data.get("overall_risk", risk_data.get("risk_level", ""))
        chain_valid = 1 if verification.get("valid") else 0
        patterns_count = len(risk_data.get("patterns", []))
        findings_count = len(ontology_data.get("security", {}).get("findings", []))

        conn.execute("""
            UPDATE session_index SET
                risk_score=?, risk_level=?, chain_valid=?,
                patterns_count=?, findings_count=?
            WHERE session_id=?
        """, (risk_score, risk_level, chain_valid, patterns_count, findings_count, session_id))
        conn.commit()
        conn.close()
    except Exception:
        pass


# ─── Session listing ────────────────────────────────────────────────
def list_all_sessions(include_empty: bool = True) -> list[dict]:
    """List all ingested sessions from SQLite index.

    Falls back to filesystem scan if index is empty.
    """
    _init_session_index()

    # Ensure index is populated
    _index_sessions_to_sqlite()

    conn = sqlite3.connect(str(_INDEX_DB))
    conn.row_factory = sqlite3.Row

    query = "SELECT * FROM session_index"
    if not include_empty:
        query += " WHERE record_count > 0 AND file_size_kb > 1"
    query += " ORDER BY timestamp DESC"

    results = []
    for row in conn.execute(query):
        results.append({
            "session_id": row["session_id"],
            "timestamp": row["timestamp"],
            "record_count": row["record_count"],
            "file_size_kb": row["file_size_kb"],
            "risk_score": row["risk_score"] if row["risk_score"] >= 0 else None,
            "risk_level": row["risk_level"] or None,
            "chain_valid": True if row["chain_valid"] == 1 else (False if row["chain_valid"] == 0 else None),
            "patterns_count": row["patterns_count"],
            "findings_count": row["findings_count"],
            "events_count": row["events_count"],
        })

    conn.close()
    return results


# ─── Session data loading ───────────────────────────────────────────
def _load_session_log(session_id: str) -> list:
    """Load session log from .json.gz file."""
    sessions_dir = Path.home() / ".inalign" / "sessions"
    target_gz = sessions_dir / f"{session_id}.json.gz"
    if not target_gz.exists() or target_gz.stat().st_size < 100:
        return []
    try:
        with gzip.open(target_gz, "rt", encoding="utf-8") as gf:
            sdata = json.load(gf)
        records = sdata.get("records", sdata) if isinstance(sdata, dict) else sdata
        return records if isinstance(records, list) else []
    except Exception:
        return []


def generate_session_data(session_id: str, skip_ontology: bool = False) -> dict:
    """Generate full report data for a specific session.

    Returns a dict with all data needed by the React dashboard.
    """
    cached = _cache_get(session_id)
    if cached:
        return cached

    from .provenance import get_or_create_chain
    from .sqlite_storage import init_sqlite, load_chain
    from .session_ingest import convert_session_log_to_chain

    init_sqlite()

    # Load session log
    session_log = _load_session_log(session_id)

    # Build provenance chain
    chain = None
    if session_log:
        try:
            chain = convert_session_log_to_chain(session_log, session_id)
        except Exception:
            pass

    if chain is None:
        chain = load_chain(session_id)
        if chain is None:
            chain = get_or_create_chain(session_id, "Claude Code")

    # Build records data
    records_data = [
        {
            "sequence": r.sequence_number,
            "type": r.activity_type.value,
            "name": r.activity_name,
            "hash": r.record_hash,
            "previous_hash": r.previous_hash,
            "timestamp": r.timestamp,
            "attributes": r.activity_attributes or {},
        }
        for r in chain.records
    ]

    is_valid, error = chain.verify_chain()
    verification = {
        "valid": is_valid,
        "error": error,
        "merkle_root": chain.get_merkle_root(),
    }

    stats = {
        "provenance_records": len(chain.records),
        "policy_checks": 0,
        "sessions_tracked": 1,
    }

    # Load feature data
    compliance_data = {}
    owasp_data = {}
    drift_data = {}
    permissions_data = {}
    cost_data = {}
    topology_data = {}
    risk_data = {}
    ontology_data = {}

    try:
        from .compliance import generate_compliance_report, compliance_report_to_dict
        compliance_data = compliance_report_to_dict(generate_compliance_report(session_id))
    except Exception:
        pass

    try:
        from .owasp import check_owasp_compliance, owasp_report_to_dict
        owasp_data = owasp_report_to_dict(check_owasp_compliance(session_id))
    except Exception:
        pass

    try:
        from .drift_detector import detect_drift, drift_report_to_dict
        drift_data = drift_report_to_dict(detect_drift(session_id))
    except Exception:
        pass

    try:
        from .permissions import get_permission_matrix
        permissions_data = get_permission_matrix()
    except Exception:
        pass

    try:
        from .topology import get_cost_report, get_agent_topology
        cost_data = get_cost_report(session_id=session_id)
        topology_data = get_agent_topology(session_id=session_id)
    except Exception:
        pass

    try:
        from .risk_analyzer import analyze_session_risk
        risk_data = analyze_session_risk(session_id)
    except Exception:
        pass

    if not skip_ontology:
        try:
            from .ontology import (
                populate_from_session, populate_decisions, populate_risks,
                populate_data_flow, populate_llm_invocations,
                populate_prompt_response_entities, link_cross_session_entities,
                get_ontology_stats,
                cq2_files_before_external_call, cq3_policy_violations_in_risky_sessions,
            )
            populate_from_session(session_id)
            populate_decisions(session_id)
            populate_risks(session_id)
            df_result = populate_data_flow(session_id)
            llm_result = populate_llm_invocations(session_id)
            pr_result = populate_prompt_response_entities(session_id)
            xs_result = link_cross_session_entities(session_id)
            ontology_data = get_ontology_stats(session_id)
            ontology_data["data_flow"] = df_result
            ontology_data["llm_invocations"] = llm_result
            ontology_data["prompt_response"] = pr_result
            ontology_data["cross_session_links"] = xs_result

            try:
                ontology_data["cq2"] = cq2_files_before_external_call(session_id)
            except Exception:
                ontology_data["cq2"] = {}
            try:
                ontology_data["cq3"] = cq3_policy_violations_in_risky_sessions(
                    risk_level="high", session_id=session_id
                )
            except Exception:
                ontology_data["cq3"] = {}

            # Ontology Security Engine
            try:
                from .ontology_security import run_ontology_security_analysis
                onto_sec = run_ontology_security_analysis(session_id)
                ontology_data["security"] = onto_sec

                boost = onto_sec.get("combined_risk_boost", 0)
                if boost > 0 and risk_data:
                    risk_data["risk_score"] = min(
                        100, risk_data.get("risk_score", 0) + boost
                    )
                    for f in onto_sec.get("findings", []):
                        risk_data.setdefault("patterns", []).append({
                            "id": "ONTO-" + f["title"][:20].upper().replace(" ", "-").replace(":", ""),
                            "name": f["title"],
                            "risk": f["severity"].lower(),
                            "confidence": 0.85,
                            "description": f["description"],
                            "source": "ontology_security",
                            "mitre_tactic": f.get("mitre", ""),
                        })
            except Exception as e:
                logger.warning("ontology_security failed: %s", e)

            # Graph visualization data
            try:
                from .ontology import _get_db
                conn = _get_db()
                try:
                    MAX_NODES, MAX_EDGES = 150, 300
                    hub_classes = ("Agent", "Session", "Decision", "Risk", "Policy", "AIModelInvocation")
                    node_map = {}
                    for row in conn.execute(
                        "SELECT id, node_class, label, timestamp, attributes FROM ontology_nodes "
                        "WHERE session_id=? AND node_class IN (" + ",".join("?" * len(hub_classes)) + ")",
                        (session_id, *hub_classes),
                    ).fetchall():
                        node_map[row["id"]] = {
                            "id": row["id"], "class": row["node_class"],
                            "label": (row["label"] or "")[:30],
                            "ts": (row["timestamp"] or "")[:19],
                            "attrs": json.loads(row["attributes"] or "{}"),
                        }

                    remaining = MAX_NODES - len(node_map)
                    if remaining > 0:
                        hub_ids = list(node_map.keys())
                        if hub_ids:
                            ph = ",".join("?" * len(hub_ids))
                            for row in conn.execute(
                                f"SELECT DISTINCT n.id, n.node_class, n.label, n.timestamp, n.attributes "
                                f"FROM ontology_edges e "
                                f"JOIN ontology_nodes n ON n.id=e.target_id AND n.session_id=e.session_id "
                                f"WHERE e.session_id=? AND e.source_id IN ({ph}) "
                                f"AND n.node_class IN ('ToolCall','Entity') ORDER BY RANDOM() LIMIT ?",
                                (session_id, *hub_ids, remaining),
                            ).fetchall():
                                node_map[row["id"]] = {
                                    "id": row["id"], "class": row["node_class"],
                                    "label": (row["label"] or "")[:30],
                                    "ts": (row["timestamp"] or "")[:19],
                                    "attrs": json.loads(row["attributes"] or "{}"),
                                }

                    node_ids = set(node_map.keys())
                    vis_edges = []
                    for row in conn.execute(
                        "SELECT source_id, target_id, relation FROM ontology_edges WHERE session_id=?",
                        (session_id,),
                    ).fetchall():
                        if row["source_id"] in node_ids and row["target_id"] in node_ids:
                            vis_edges.append({
                                "s": row["source_id"], "t": row["target_id"],
                                "r": row["relation"],
                            })
                            if len(vis_edges) >= MAX_EDGES:
                                break

                    ontology_data["vis_nodes"] = list(node_map.values())
                    ontology_data["vis_edges"] = vis_edges
                except Exception:
                    pass
                finally:
                    conn.close()
            except Exception:
                pass
        except Exception:
            pass

    # Truncate session log for API response — limit to 300 entries, trim content
    capped_log = session_log[:300] if len(session_log) > 300 else session_log
    trimmed_log = []
    for evt in capped_log:
        e = dict(evt) if isinstance(evt, dict) else evt
        if isinstance(e, dict):
            for field in ("content", "result", "tool_input"):
                val = e.get(field)
                if isinstance(val, str) and len(val) > 300:
                    e[field] = val[:300] + f"... [{len(val)} chars]"
                elif isinstance(val, dict):
                    s = json.dumps(val, default=str)
                    if len(s) > 300:
                        e[field] = s[:300] + f"... [{len(s)} chars]"
        trimmed_log.append(e)

    result = {
        "session_id": session_id,
        "records": records_data,
        "verification": verification,
        "stats": stats,
        "session_log": trimmed_log,
        "compliance": compliance_data,
        "owasp": owasp_data,
        "drift": drift_data,
        "permissions": permissions_data,
        "cost": cost_data,
        "topology": topology_data,
        "risk": risk_data,
        "ontology": ontology_data,
    }

    # Update SQLite index with analysis results
    _update_session_risk_index(session_id, risk_data, verification, ontology_data)

    _cache_set(session_id, result)
    return result


# ─── Legacy report support ──────────────────────────────────────────
def generate_report_data(skip_ingest: bool = False):
    """Legacy: Generate report data tuple for old HTML report."""
    latest_session_hint = None
    if not skip_ingest:
        try:
            n_ingested, latest_session_hint = auto_ingest_new_sessions()
            if n_ingested > 0:
                print(f"  Auto-ingested {n_ingested} new session(s)")
        except Exception:
            pass

    # Find latest session
    session_id = latest_session_hint
    if not session_id:
        sessions = list_all_sessions()
        if sessions:
            session_id = sessions[0]["session_id"]
        else:
            session_id = "no-session"

    data = generate_session_data(session_id)

    return (
        data["session_id"],
        data["records"],
        data["verification"],
        data["stats"],
        data["session_log"],
        data["compliance"],
        data["owasp"],
        data["drift"],
        data["permissions"],
        data["cost"],
        data["topology"],
        data["risk"],
        data["ontology"],
    )


def _get_gz_mtime() -> float:
    try:
        sessions_dir = Path.home() / ".inalign" / "sessions"
        if not sessions_dir.exists():
            return 0.0
        best = 0.0
        for gz in sessions_dir.glob("*.json.gz"):
            mt = gz.stat().st_mtime
            if mt > best:
                best = mt
        return best
    except Exception:
        return 0.0


def _regenerate_report(skip_ingest: bool = True) -> str:
    global _report_html, _report_source_mtime
    try:
        from .report import generate_html_report
        (
            session_id, records, verification, stats, session_log,
            compliance_data, owasp_data, drift_data,
            permissions_data, cost_data, topology_data, risk_data,
            ontology_data,
        ) = generate_report_data(skip_ingest=skip_ingest)
        _report_html = generate_html_report(
            session_id, records, verification, stats,
            session_log=session_log,
            compliance_data=compliance_data,
            owasp_data=owasp_data,
            drift_data=drift_data,
            permissions_data=permissions_data,
            cost_data=cost_data,
            topology_data=topology_data,
            risk_data=risk_data,
            ontology_data=ontology_data,
        )
        _report_source_mtime = _get_gz_mtime()
        print(f"  [Refresh] Session: {session_id} | {len(records)} records | {len(session_log)} log events")
    except Exception as e:
        if not _report_html:
            _report_html = f"<html><body><h1>Error: {e}</h1></body></html>"
    return _report_html


# ─── HTTP Handler ───────────────────────────────────────────────────
class ReportHandler(BaseHTTPRequestHandler):
    """HTTP handler for React dashboard + REST API."""

    def log_message(self, format, *args):
        pass

    def _send_cors(self):
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")

    def _send_json(self, code, data):
        try:
            body = json.dumps(data, default=str).encode("utf-8")
            self.send_response(code)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self._send_cors()
            self.end_headers()
            self.wfile.write(body)
        except (ConnectionAbortedError, ConnectionResetError, BrokenPipeError):
            pass  # Client disconnected, ignore

    def _serve_file(self, file_path: Path):
        """Serve a static file."""
        try:
            if not file_path.exists() or not file_path.is_file():
                self.send_response(404)
                self.end_headers()
                return
            content_type, _ = mimetypes.guess_type(str(file_path))
            content_type = content_type or "application/octet-stream"
            data = file_path.read_bytes()
            self.send_response(200)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(data)))
            # Assets have content-hash in filename, safe to cache long
            # index.html must not be cached to pick up new builds
            if file_path.name == "index.html":
                self.send_header("Cache-Control", "no-cache, no-store, must-revalidate")
            else:
                self.send_header("Cache-Control", "public, max-age=86400")
            self._send_cors()
            self.end_headers()
            self.wfile.write(data)
        except (ConnectionAbortedError, ConnectionResetError, BrokenPipeError):
            pass  # Client disconnected, ignore

    def do_OPTIONS(self):
        self.send_response(200)
        self._send_cors()
        self.end_headers()

    def do_GET(self):
        path = self.path.split("?")[0]  # strip query string

        # ── REST API ──
        if path == "/api/sessions":
            # Support ?include_empty=true query param
            include_empty = "include_empty=true" in self.path
            self._handle_list_sessions(include_empty=include_empty)
        elif path == "/api/sessions/latest":
            self._handle_latest_session()
        elif path.startswith("/api/sessions/") and path.endswith("/ontology"):
            session_id = path[len("/api/sessions/"):-len("/ontology")]
            self._handle_ontology_export(session_id)
        elif path.startswith("/api/sessions/"):
            session_id = path[len("/api/sessions/"):]
            self._handle_session_data(session_id)
        elif path == "/api/ontology/export":
            self._handle_ontology_export_all()
        elif path == "/api/health":
            self._send_json(200, {"status": "ok", "version": "0.9.0"})

        # ── Legacy HTML report ──
        elif path == "/legacy":
            html = _report_html or "<html><body><h1>Use /api/ endpoints or React dashboard</h1></body></html>"
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self._send_cors()
            self.end_headers()
            self.wfile.write(html.encode("utf-8"))

        # ── React SPA static files ──
        elif path.startswith("/assets/") or path.endswith((".js", ".css", ".svg", ".png", ".ico", ".woff", ".woff2")):
            # Serve from dashboard_dist
            rel = path.lstrip("/")
            self._serve_file(_DASHBOARD_DIR / rel)

        # ── React SPA catch-all (index.html) ──
        else:
            index = _DASHBOARD_DIR / "index.html"
            if index.exists():
                self._serve_file(index)
            else:
                # Fallback: show error with setup instructions
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.end_headers()
                self.wfile.write(
                    b"<html><body style='font-family:system-ui;max-width:600px;margin:80px auto;text-align:center'>"
                    b"<h2>InALign Dashboard</h2>"
                    b"<p>React dashboard not built yet.</p>"
                    b"<p>Run <code>cd dashboard && npm install && npm run build</code></p>"
                    b"<p>Or use the <a href='/api/sessions'>REST API</a> directly.</p>"
                    b"</body></html>"
                )

    def do_POST(self):
        path = self.path.split("?")[0]
        if path == "/api/analyze":
            self._handle_analyze()
        elif path == "/api/refresh":
            self._handle_refresh()
        else:
            self.send_response(404)
            self.end_headers()

    # ── API Handlers ──

    def _handle_list_sessions(self, include_empty: bool = False):
        try:
            sessions = list_all_sessions(include_empty=include_empty)
            self._send_json(200, {"sessions": sessions, "total": len(sessions)})
        except (ConnectionAbortedError, ConnectionResetError, BrokenPipeError):
            pass
        except Exception as e:
            self._send_json(500, {"error": str(e)})

    def _handle_latest_session(self):
        try:
            sessions = list_all_sessions()
            if not sessions:
                self._send_json(404, {"error": "No sessions found"})
                return
            session_id = sessions[0]["session_id"]
            data = generate_session_data(session_id)
            self._send_json(200, data)
        except (ConnectionAbortedError, ConnectionResetError, BrokenPipeError):
            pass
        except Exception as e:
            self._send_json(500, {"error": str(e)})

    def _handle_ontology_export(self, session_id: str):
        """Export ontology nodes + edges for a session as JSON-LD."""
        try:
            if not _is_uuid(session_id):
                self._send_json(400, {"error": "Invalid session ID"})
                return
            db_path = Path.home() / ".inalign" / "provenance.db"
            if not db_path.exists():
                self._send_json(404, {"error": "No ontology data"})
                return
            import sqlite3
            conn = sqlite3.connect(str(db_path))
            conn.row_factory = sqlite3.Row
            nodes = [dict(r) for r in conn.execute(
                "SELECT id, node_class, label, session_id, created_at, attributes FROM ontology_nodes WHERE session_id=?",
                (session_id,),
            ).fetchall()]
            edges = [dict(r) for r in conn.execute(
                "SELECT source_id, target_id, relation, session_id, timestamp, confidence FROM ontology_edges WHERE session_id=?",
                (session_id,),
            ).fetchall()]
            conn.close()
            # Parse attributes JSON
            for n in nodes:
                try:
                    n["attributes"] = json.loads(n["attributes"]) if n.get("attributes") else {}
                except (json.JSONDecodeError, TypeError):
                    n["attributes"] = {}
            export = {
                "@context": {
                    "prov": "http://www.w3.org/ns/prov#",
                    "inalign": "https://inalign.dev/ontology#",
                },
                "@type": "inalign:OntologyExport",
                "session_id": session_id,
                "export_version": "0.9.0",
                "total_nodes": len(nodes),
                "total_edges": len(edges),
                "nodes": nodes,
                "edges": edges,
            }
            self._send_json(200, export)
        except Exception as e:
            self._send_json(500, {"error": str(e)})

    def _handle_ontology_export_all(self):
        """Export all ontology data across all sessions."""
        try:
            db_path = Path.home() / ".inalign" / "provenance.db"
            if not db_path.exists():
                self._send_json(404, {"error": "No ontology data"})
                return
            import sqlite3
            conn = sqlite3.connect(str(db_path))
            conn.row_factory = sqlite3.Row
            node_count = conn.execute("SELECT COUNT(*) FROM ontology_nodes").fetchone()[0]
            edge_count = conn.execute("SELECT COUNT(*) FROM ontology_edges").fetchone()[0]
            sessions = [r[0] for r in conn.execute(
                "SELECT DISTINCT session_id FROM ontology_nodes ORDER BY session_id"
            ).fetchall()]
            class_counts = {r[0]: r[1] for r in conn.execute(
                "SELECT node_class, COUNT(*) FROM ontology_nodes GROUP BY node_class"
            ).fetchall()}
            relation_counts = {r[0]: r[1] for r in conn.execute(
                "SELECT relation, COUNT(*) FROM ontology_edges GROUP BY relation"
            ).fetchall()}
            conn.close()
            self._send_json(200, {
                "total_nodes": node_count,
                "total_edges": edge_count,
                "sessions": len(sessions),
                "session_ids": sessions,
                "node_classes": class_counts,
                "relation_types": relation_counts,
                "download_per_session": "/api/sessions/{session_id}/ontology",
            })
        except Exception as e:
            self._send_json(500, {"error": str(e)})

    def _handle_session_data(self, session_id: str):
        try:
            if not _is_uuid(session_id):
                self._send_json(400, {"error": "Invalid session ID format"})
                return
            gz = Path.home() / ".inalign" / "sessions" / f"{session_id}.json.gz"
            if not gz.exists():
                self._send_json(404, {"error": f"Session {session_id} not found"})
                return
            # Default: skip ontology for fast load. Use ?full=true for full data.
            full = "full=true" in self.path
            data = generate_session_data(session_id, skip_ontology=not full)
            self._send_json(200, data)
        except (ConnectionAbortedError, ConnectionResetError, BrokenPipeError):
            pass
        except Exception as e:
            self._send_json(500, {"error": str(e)})

    def _handle_refresh(self):
        try:
            n, latest = auto_ingest_new_sessions()
            # Clear cache
            _session_cache.clear()
            self._send_json(200, {
                "ingested": n,
                "latest_session": latest,
            })
        except Exception as e:
            self._send_json(500, {"error": str(e)})

    def _handle_analyze(self):
        """Proxy AI analysis calls to OpenAI/Anthropic/Ollama."""
        try:
            content_length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(content_length)
            req_data = json.loads(body)

            provider = req_data.get("provider", "openai")
            api_key = req_data.get("api_key", "")
            session_text = req_data.get("session_data", "")
            model = req_data.get("model", "")

            if provider != "local" and not api_key:
                self._send_json(400, {"error": "API key required for cloud providers"})
                return

            # Enrich with ontology data from server-side
            session_id = req_data.get("session_id", "")
            ontology_section = ""
            if session_id:
                try:
                    from .ai_analyzer import _load_ontology_for_session, _load_risk_analysis, mask_pii
                    ont = _load_ontology_for_session(session_id)
                    risk = _load_risk_analysis(session_id)
                    if ont or risk:
                        enrichment = {}
                        if ont:
                            enrichment["ontology_graph"] = ont
                        if risk:
                            enrichment["pre_computed_risk"] = risk
                        enr_text, _ = mask_pii(json.dumps(enrichment, ensure_ascii=False))
                        ontology_section = f"\n\nOntology Graph & Risk Analysis:\n{enr_text[:8000]}"
                except Exception:
                    pass

            from .ai_analyzer import _build_prompt, mask_pii as _mask

            # ── Local (Ollama) — short prompt for small models ──
            if provider == "local":
                ollama_model = model or "llama3.2"
                masked_data, _ = _mask(session_text[:2000])
                ont_short = ontology_section[:1500] if ontology_section else ""
                local_prompt = (
                    "You are a security analyst. Analyze this AI agent session data.\n"
                    "Return ONLY valid JSON with these fields:\n"
                    '{"risk_score": 0-100, "risk_level": "LOW|MEDIUM|HIGH|CRITICAL", '
                    '"summary": "2-3 sentences", '
                    '"findings": [{"severity": "HIGH", "title": "...", "description": "..."}], '
                    '"recommendations": ["..."], '
                    '"behavioral_summary": {"total_actions": 0, "tools_used": {}}}\n\n'
                    "Data:\n" + masked_data + ont_short
                )
                ollama_url = "http://localhost:11434/api/generate"
                payload = json.dumps({
                    "model": ollama_model,
                    "prompt": local_prompt,
                    "stream": False,
                    "options": {"num_predict": 2048, "num_ctx": 8192},
                }).encode()
                req = Request(ollama_url, data=payload, method="POST")
                req.add_header("Content-Type", "application/json")
                with urlopen(req, timeout=180) as resp:
                    api_response = json.loads(resp.read().decode())
                text = api_response.get("response", "")
                self._send_json(200, {"result": text, "provider": "local", "model": ollama_model})
                return

            # ── Cloud (Anthropic/OpenAI) — full prompt ──
            system_prompt = _build_prompt()
            masked_session, _ = _mask(session_text[:12000])
            if ontology_section:
                ontology_section = ontology_section[:8000]
            prompt = system_prompt + "\n\n--- SESSION DATA ---\n" + masked_session + ontology_section

            # ── OpenAI ──
            if provider == "openai":
                url = "https://api.openai.com/v1/chat/completions"
                headers = {
                    "Content-Type": "application/json",
                    "Authorization": f"Bearer {api_key}",
                }
                payload = json.dumps({
                    "model": "gpt-4o-mini",
                    "messages": [{"role": "user", "content": prompt}],
                    "max_completion_tokens": 2000,
                }).encode()
            # ── Anthropic ──
            else:
                url = "https://api.anthropic.com/v1/messages"
                headers = {
                    "Content-Type": "application/json",
                    "x-api-key": api_key,
                    "anthropic-version": "2023-06-01",
                }
                payload = json.dumps({
                    "model": "claude-sonnet-4-5-20250929",
                    "max_tokens": 2000,
                    "messages": [{"role": "user", "content": prompt}],
                }).encode()

            req = Request(url, data=payload, method="POST")
            for k, v in headers.items():
                req.add_header(k, v)

            with urlopen(req, timeout=120) as resp:
                api_response = json.loads(resp.read().decode())

            if provider == "openai":
                text = (
                    api_response.get("choices", [{}])[0]
                    .get("message", {})
                    .get("content", json.dumps(api_response))
                )
            else:
                content_list = api_response.get("content", [])
                text = content_list[0].get("text", json.dumps(api_response)) if content_list else json.dumps(api_response)

            self._send_json(200, {"result": text, "provider": provider})

        except HTTPError as e:
            error_body = e.read().decode() if e.fp else str(e)
            self._send_json(e.code, {"error": error_body})
        except URLError as e:
            self._send_json(502, {"error": f"Connection failed: {e.reason}"})
        except Exception as e:
            self._send_json(500, {"error": str(e)})


# ─── Main ───────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(
        description="InALign Dashboard — Local zero-trust audit dashboard",
    )
    parser.add_argument("--port", type=int, default=DEFAULT_PORT, help=f"Port (default: {DEFAULT_PORT})")
    parser.add_argument("--no-open", action="store_true", help="Don't open browser")
    parser.add_argument("--legacy", action="store_true", help="Serve legacy single-HTML report")
    args = parser.parse_args()

    print("\n  InALign Dashboard Server")
    print("  " + "=" * 40)

    # Auto-ingest on startup
    print("  Ingesting sessions...")
    try:
        n, latest = auto_ingest_new_sessions()
        if n > 0:
            print(f"  Auto-ingested {n} new session(s)")
        sessions = list_all_sessions()
        print(f"  {len(sessions)} session(s) available")
    except Exception as e:
        print(f"  Ingest warning: {e}")

    # Legacy mode
    if args.legacy:
        print("  Mode: Legacy HTML report")
        _regenerate_report(skip_ingest=True)

    # Check dashboard build
    dashboard_index = _DASHBOARD_DIR / "index.html"
    if dashboard_index.exists():
        print(f"  Mode: React Dashboard")
    else:
        print(f"  Warning: React dashboard not built")
        print(f"  Run: cd dashboard && npm install && npm run build")

    class ThreadedServer(ThreadingMixIn, HTTPServer):
        daemon_threads = True

    server = ThreadedServer(("127.0.0.1", args.port), ReportHandler)
    url = f"http://127.0.0.1:{args.port}"
    print(f"\n  Dashboard:  {url}")
    print(f"  REST API:   {url}/api/sessions")
    print(f"  Health:     {url}/api/health")
    print(f"\n  Press Ctrl+C to stop.\n")

    if not args.no_open:
        webbrowser.open(url)

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n  Server stopped.")
        server.server_close()


if __name__ == "__main__":
    main()
