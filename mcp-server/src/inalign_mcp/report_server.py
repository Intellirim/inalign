"""
InALign Report Server

Local HTTP server that serves the HTML report and proxies API calls
to OpenAI/Anthropic, bypassing browser CORS restrictions.

Usage:
    inalign-report                  # Generate + serve latest report
    inalign-report --port 8275      # Custom port
"""

import json
import gzip
import argparse
import webbrowser
import sys
import hashlib
import uuid
from http.server import HTTPServer, BaseHTTPRequestHandler
from pathlib import Path
from datetime import datetime, timezone
from urllib.request import Request, urlopen
from urllib.error import HTTPError, URLError

# Default port
DEFAULT_PORT = 8275

# Store report HTML in memory
_report_html = ""


def generate_report_data():
    """Generate report data from local storage.

    Auto-converts session log events into SHA-256 hash-chained provenance
    records if not already converted. This ensures the Provenance Chain tab
    shows a full tamper-proof audit trail (not just MCP tool calls).
    """
    from .provenance import get_or_create_chain, ActivityType
    from .sqlite_storage import init_sqlite, list_sessions, load_chain

    # Init storage
    init_sqlite()

    # --- Load session log first (needed for auto-conversion) ---
    session_log = []
    log_session_id = None
    try:
        sessions_dir = Path.home() / ".inalign" / "sessions"
        if sessions_dir.exists():
            gz_files = sorted(
                sessions_dir.glob("*.json.gz"),
                key=lambda f: f.stat().st_mtime,
                reverse=True,
            )
            if gz_files:
                with gzip.open(gz_files[0], "rt", encoding="utf-8") as gf:
                    sdata = json.load(gf)
                session_log = (
                    sdata.get("records", sdata)
                    if isinstance(sdata, dict)
                    else sdata
                )
                if isinstance(sdata, dict):
                    log_session_id = sdata.get("session_id")
    except Exception:
        pass

    # --- Auto-convert session log → provenance chain ---
    chain = None
    session_id = None

    if session_log and log_session_id:
        try:
            from .session_ingest import convert_session_log_to_chain
            chain = convert_session_log_to_chain(session_log, log_session_id)
            if chain:
                session_id = log_session_id
        except Exception:
            pass

    # Fallback: load MCP session chain from SQLite
    if chain is None:
        sessions = list_sessions(limit=1)
        if sessions:
            session_id = sessions[0].get("session_id", "unknown")
        else:
            session_id = "no-session"
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

    # Load v0.5.0 feature data (all local, zero external calls)
    compliance_data = {}
    owasp_data = {}
    drift_data = {}
    permissions_data = {}
    cost_data = {}
    topology_data = {}

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

    risk_data = {}
    try:
        from .risk_analyzer import analyze_session_risk
        risk_data = analyze_session_risk(session_id)
    except Exception:
        pass

    ontology_data = {}
    try:
        from .ontology import (
            populate_from_session, populate_decisions, populate_risks,
            get_ontology_stats,
            cq2_files_before_external_call, cq3_policy_violations_in_risky_sessions,
        )
        # Auto-populate ontology from this session's data
        populate_from_session(session_id)
        populate_decisions(session_id)
        populate_risks(session_id)
        ontology_data = get_ontology_stats(session_id)

        # Auto-run competency queries
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

        # Ontology Security Engine — graph-powered threat detection
        try:
            from .ontology_security import run_ontology_security_analysis
            onto_sec = run_ontology_security_analysis(session_id)
            ontology_data["security"] = onto_sec

            # Feed findings back into risk_data
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
        except Exception:
            pass

        # Add graph data for visualization (connectivity-preserving sampling)
        from .ontology import _get_db
        conn = _get_db()
        try:
            MAX_NODES = 150
            MAX_EDGES = 300

            # Step 1: Always include hub nodes (Agent, Session, Decision, Risk)
            hub_classes = ("Agent", "Session", "Decision", "Risk", "Policy")
            node_map = {}  # id -> {id, class, label, ...}
            for row in conn.execute(
                "SELECT id, node_class, label, timestamp, attributes FROM ontology_nodes WHERE session_id=? AND node_class IN (?,?,?,?,?)",
                (session_id, *hub_classes),
            ).fetchall():
                node_map[row["id"]] = {
                    "id": row["id"], "class": row["node_class"],
                    "label": (row["label"] or "")[:30],
                    "ts": (row["timestamp"] or "")[:19],
                    "attrs": json.loads(row["attributes"] or "{}"),
                }

            # Step 2: Get edges connected to hub nodes, include their ToolCall/Entity endpoints
            remaining = MAX_NODES - len(node_map)
            if remaining > 0:
                hub_ids = list(node_map.keys())
                if hub_ids:
                    placeholders = ",".join("?" * len(hub_ids))
                    # Get ToolCall/Entity nodes connected to hubs
                    neighbor_rows = conn.execute(
                        f"""SELECT DISTINCT n.id, n.node_class, n.label, n.timestamp, n.attributes
                            FROM ontology_edges e
                            JOIN ontology_nodes n ON n.id = e.target_id AND n.session_id = e.session_id
                            WHERE e.session_id=? AND e.source_id IN ({placeholders})
                            AND n.node_class IN ('ToolCall','Entity')
                            ORDER BY RANDOM() LIMIT ?""",
                        (session_id, *hub_ids, remaining),
                    ).fetchall()
                    for row in neighbor_rows:
                        node_map[row["id"]] = {
                            "id": row["id"], "class": row["node_class"],
                            "label": (row["label"] or "")[:30],
                            "ts": (row["timestamp"] or "")[:19],
                            "attrs": json.loads(row["attributes"] or "{}"),
                        }

            # Step 3: Collect all edges between selected nodes
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

    return (
        session_id, records_data, verification, stats, session_log,
        compliance_data, owasp_data, drift_data,
        permissions_data, cost_data, topology_data, risk_data,
        ontology_data,
    )


class ReportHandler(BaseHTTPRequestHandler):
    """HTTP handler for report serving and API proxying."""

    def log_message(self, format, *args):
        """Suppress default logging."""
        pass

    def _send_cors_headers(self):
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")

    def do_OPTIONS(self):
        self.send_response(200)
        self._send_cors_headers()
        self.end_headers()

    def do_GET(self):
        if self.path == "/" or self.path == "/report":
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self._send_cors_headers()
            self.end_headers()
            self.wfile.write(_report_html.encode("utf-8"))
        elif self.path == "/health":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self._send_cors_headers()
            self.end_headers()
            self.wfile.write(json.dumps({"status": "ok"}).encode())
        else:
            self.send_response(404)
            self.end_headers()

    def do_POST(self):
        if self.path == "/api/analyze":
            self._handle_analyze()
        else:
            self.send_response(404)
            self.end_headers()

    def _handle_analyze(self):
        """Proxy API calls to OpenAI/Anthropic."""
        try:
            content_length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(content_length)
            req_data = json.loads(body)

            provider = req_data.get("provider", "openai")
            api_key = req_data.get("api_key", "")
            session_text = req_data.get("session_data", "")

            if not api_key:
                self._send_json(400, {"error": "API key required"})
                return

            prompt = (
                "Analyze this AI agent session for security risks. "
                "Return JSON with: risk_score (0-100), risk_level (LOW/MEDIUM/HIGH/CRITICAL), "
                "summary (string), findings (array of {severity,title,description}), "
                "recommendations (array of strings).\n\n"
                "Session data:\n" + session_text[:15000]
            )

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
            else:  # anthropic
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

            # Make the API call (server-side, no CORS issues)
            req = Request(url, data=payload, method="POST")
            for k, v in headers.items():
                req.add_header(k, v)

            with urlopen(req, timeout=120) as resp:
                api_response = json.loads(resp.read().decode())

            # Extract text from response
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

    def _send_json(self, code, data):
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self._send_cors_headers()
        self.end_headers()
        self.wfile.write(json.dumps(data).encode())


def main():
    global _report_html

    parser = argparse.ArgumentParser(
        description="InALign Report Server — Serve audit dashboard with AI analysis proxy",
    )
    parser.add_argument("--port", type=int, default=DEFAULT_PORT, help=f"Port (default: {DEFAULT_PORT})")
    parser.add_argument("--no-open", action="store_true", help="Don't open browser automatically")
    args = parser.parse_args()

    # Generate report
    print("\n  InALign Report Server")
    print("  " + "=" * 40)
    print(f"\n  Generating report...")

    try:
        from .report import generate_html_report
        (
            session_id, records, verification, stats, session_log,
            compliance_data, owasp_data, drift_data,
            permissions_data, cost_data, topology_data, risk_data,
            ontology_data,
        ) = generate_report_data()
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
        print(f"  Session: {session_id}")
        print(f"  Records: {len(records)} provenance, {len(session_log)} session log")
    except Exception as e:
        print(f"  Error generating report: {e}")
        print(f"  Starting with empty report...")
        _report_html = f"<html><body><h1>Error: {e}</h1></body></html>"

    # Start server
    server = HTTPServer(("127.0.0.1", args.port), ReportHandler)
    url = f"http://127.0.0.1:{args.port}"
    print(f"\n  Server running: {url}")
    print(f"  API proxy:      {url}/api/analyze")
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
