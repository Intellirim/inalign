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
    """Generate report data from local storage."""
    from .provenance import get_or_create_chain, ActivityType
    from .sqlite_storage import init_sqlite, list_sessions

    # Init storage
    init_sqlite()

    # Get latest session from SQLite
    sessions = list_sessions(limit=1)
    if sessions:
        session_id = sessions[0].get("session_id", "unknown")
    else:
        session_id = "no-session"

    # Try to load chain from memory or create
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

    # Load session log
    session_log = []
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
    except Exception:
        pass

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

    return (
        session_id, records_data, verification, stats, session_log,
        compliance_data, owasp_data, drift_data,
        permissions_data, cost_data, topology_data,
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
            permissions_data, cost_data, topology_data,
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
