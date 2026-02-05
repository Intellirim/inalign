"""
InALign Dashboard - AI Agent Governance Platform

Features:
- Login with company API key
- Real-time provenance monitoring
- Incident search & trace
- Audit log export with certificates
- Policy management
"""

import os
import json
from datetime import datetime
from typing import Optional
from fastapi import FastAPI, Request, Form, HTTPException, Depends
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from starlette.middleware.sessions import SessionMiddleware
import uvicorn

from .client_manager import get_client_manager, Client
from .trace_finder import init_trace_db, trace_agent, trace_decision, trace_session, quick_search
from .audit_export import export_session_json, export_session_summary
from .auto_anchor import generate_certificate

app = FastAPI(title="InALign Dashboard")
app.add_middleware(SessionMiddleware, secret_key=os.getenv("SESSION_SECRET", "inalign-secret-key-change-me"))

# Initialize
manager = get_client_manager()


# ============================================
# HTML Templates
# ============================================

LOGIN_HTML = """
<!DOCTYPE html>
<html>
<head>
    <title>InALign - Login</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{
            font-family: 'Segoe UI', sans-serif;
            background: linear-gradient(135deg, #1e3a5f 0%, #0d1b2a 100%);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
        }}
        .login-box {{
            background: white;
            padding: 40px;
            border-radius: 16px;
            box-shadow: 0 20px 60px rgba(0,0,0,0.3);
            width: 400px;
        }}
        .logo {{
            font-size: 32px;
            font-weight: bold;
            color: #2563eb;
            text-align: center;
            margin-bottom: 8px;
        }}
        .subtitle {{
            text-align: center;
            color: #666;
            margin-bottom: 30px;
        }}
        .form-group {{ margin-bottom: 20px; }}
        label {{ display: block; margin-bottom: 8px; color: #333; font-weight: 500; }}
        input {{
            width: 100%;
            padding: 12px 16px;
            border: 2px solid #e5e7eb;
            border-radius: 8px;
            font-size: 16px;
            transition: border-color 0.2s;
        }}
        input:focus {{ outline: none; border-color: #2563eb; }}
        button {{
            width: 100%;
            padding: 14px;
            background: #2563eb;
            color: white;
            border: none;
            border-radius: 8px;
            font-size: 16px;
            font-weight: 600;
            cursor: pointer;
            transition: background 0.2s;
        }}
        button:hover {{ background: #1d4ed8; }}
        .error {{
            background: #fef2f2;
            color: #dc2626;
            padding: 12px;
            border-radius: 8px;
            margin-bottom: 20px;
            text-align: center;
        }}
    </style>
</head>
<body>
    <div class="login-box">
        <div class="logo">InALign</div>
        <div class="subtitle">AI Agent Governance Platform</div>
        {error}
        <form method="post" action="/login">
            <div class="form-group">
                <label>API Key</label>
                <input type="text" name="api_key" placeholder="ial_xxxxxxxxxxxx" required>
            </div>
            <button type="submit">Login</button>
        </form>
    </div>
</body>
</html>
"""

DASHBOARD_HTML = """
<!DOCTYPE html>
<html>
<head>
    <title>InALign Dashboard - {company}</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ font-family: 'Segoe UI', sans-serif; background: #f3f4f6; }}
        .header {{
            background: linear-gradient(135deg, #1e3a5f 0%, #0d1b2a 100%);
            color: white;
            padding: 20px 40px;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }}
        .logo {{ font-size: 24px; font-weight: bold; }}
        .company {{ color: #93c5fd; }}
        .logout {{ color: white; text-decoration: none; opacity: 0.8; }}
        .logout:hover {{ opacity: 1; }}
        .container {{ max-width: 1400px; margin: 0 auto; padding: 30px; }}
        .stats {{
            display: grid;
            grid-template-columns: repeat(4, 1fr);
            gap: 20px;
            margin-bottom: 30px;
        }}
        .stat-card {{
            background: white;
            padding: 24px;
            border-radius: 12px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.08);
        }}
        .stat-value {{ font-size: 36px; font-weight: bold; color: #1e3a5f; }}
        .stat-label {{ color: #666; margin-top: 4px; }}
        .card {{
            background: white;
            border-radius: 12px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.08);
            margin-bottom: 20px;
        }}
        .card-header {{
            padding: 20px 24px;
            border-bottom: 1px solid #e5e7eb;
            font-weight: 600;
            font-size: 18px;
        }}
        .card-body {{ padding: 24px; }}
        .search-box {{
            display: flex;
            gap: 12px;
            margin-bottom: 20px;
        }}
        .search-box input {{
            flex: 1;
            padding: 12px 16px;
            border: 2px solid #e5e7eb;
            border-radius: 8px;
            font-size: 16px;
        }}
        .search-box button {{
            padding: 12px 24px;
            background: #2563eb;
            color: white;
            border: none;
            border-radius: 8px;
            cursor: pointer;
            font-weight: 600;
        }}
        .activity-list {{ list-style: none; }}
        .activity-item {{
            display: flex;
            align-items: center;
            padding: 16px 0;
            border-bottom: 1px solid #f3f4f6;
        }}
        .activity-item:last-child {{ border-bottom: none; }}
        .activity-icon {{
            width: 40px;
            height: 40px;
            border-radius: 8px;
            display: flex;
            align-items: center;
            justify-content: center;
            margin-right: 16px;
            font-size: 18px;
        }}
        .icon-tool {{ background: #dbeafe; color: #2563eb; }}
        .icon-decision {{ background: #dcfce7; color: #16a34a; }}
        .icon-error {{ background: #fef2f2; color: #dc2626; }}
        .activity-info {{ flex: 1; }}
        .activity-name {{ font-weight: 500; }}
        .activity-time {{ color: #666; font-size: 14px; }}
        .activity-hash {{ font-family: monospace; font-size: 12px; color: #999; }}
        .btn {{
            padding: 10px 20px;
            border-radius: 8px;
            border: none;
            cursor: pointer;
            font-weight: 500;
            text-decoration: none;
            display: inline-block;
        }}
        .btn-primary {{ background: #2563eb; color: white; }}
        .btn-secondary {{ background: #e5e7eb; color: #333; }}
        .grid-2 {{ display: grid; grid-template-columns: 2fr 1fr; gap: 20px; }}
        .quick-actions {{ display: flex; gap: 10px; flex-wrap: wrap; }}
        .quick-actions button {{
            padding: 8px 16px;
            background: #f3f4f6;
            border: 1px solid #e5e7eb;
            border-radius: 6px;
            cursor: pointer;
        }}
        .quick-actions button:hover {{ background: #e5e7eb; }}
        #results {{ margin-top: 20px; }}
        .result-item {{
            padding: 12px;
            background: #f9fafb;
            border-radius: 8px;
            margin-bottom: 8px;
            font-family: monospace;
            font-size: 14px;
        }}
    </style>
</head>
<body>
    <div class="header">
        <div class="logo">InALign <span class="company">| {company}</span></div>
        <a href="/logout" class="logout">Logout</a>
    </div>

    <div class="container">
        <div class="stats">
            <div class="stat-card">
                <div class="stat-value">{total_actions}</div>
                <div class="stat-label">Actions Recorded</div>
            </div>
            <div class="stat-card">
                <div class="stat-value">{user_commands}</div>
                <div class="stat-label">User Commands</div>
            </div>
            <div class="stat-card">
                <div class="stat-value">{sessions}</div>
                <div class="stat-label">Active Sessions</div>
            </div>
            <div class="stat-card">
                <div class="stat-value">{agents}</div>
                <div class="stat-label">Agents Tracked</div>
            </div>
        </div>

        <div class="grid-2">
            <div>
                <div class="card">
                    <div class="card-header">Search & Trace</div>
                    <div class="card-body">
                        <div class="search-box">
                            <input type="text" id="searchQuery" placeholder="What did the agent do? / Who made this change?">
                            <button onclick="search()">Search</button>
                        </div>
                        <div class="quick-actions">
                            <button onclick="quickSearch('agent')">Agent Activity</button>
                            <button onclick="quickSearch('decisions')">All Decisions</button>
                            <button onclick="quickSearch('files')">File Access</button>
                            <button onclick="quickSearch('errors')">Errors</button>
                        </div>
                        <div id="results"></div>
                    </div>
                </div>

                <div class="card">
                    <div class="card-header">Recent Activity</div>
                    <div class="card-body">
                        <ul class="activity-list">
                            {activity_list}
                        </ul>
                    </div>
                </div>
            </div>

            <div>
                <div class="card">
                    <div class="card-header">Quick Actions</div>
                    <div class="card-body">
                        <a href="/export/json" class="btn btn-primary" style="width:100%; margin-bottom:10px; text-align:center;">
                            Download Audit Log (JSON)
                        </a>
                        <a href="/export/certificate" class="btn btn-secondary" style="width:100%; margin-bottom:10px; text-align:center;">
                            Download Certificate
                        </a>
                        <a href="/export/csv" class="btn btn-secondary" style="width:100%; text-align:center;">
                            Export to CSV
                        </a>
                    </div>
                </div>

                <div class="card">
                    <div class="card-header">Plan: {plan}</div>
                    <div class="card-body">
                        <p><strong>Scans used:</strong> {scans_used} / {scan_limit}</p>
                        <div style="background:#e5e7eb; height:8px; border-radius:4px; margin-top:12px;">
                            <div style="background:#2563eb; height:100%; border-radius:4px; width:{usage_percent}%;"></div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <script>
        async function search() {{
            const query = document.getElementById('searchQuery').value;
            const res = await fetch('/api/search?q=' + encodeURIComponent(query));
            const data = await res.json();
            showResults(data);
        }}

        async function quickSearch(type) {{
            const res = await fetch('/api/search?type=' + type);
            const data = await res.json();
            showResults(data);
        }}

        function showResults(data) {{
            const div = document.getElementById('results');
            if (!data.records || data.records.length === 0) {{
                div.innerHTML = '<div class="result-item">No results found</div>';
                return;
            }}
            div.innerHTML = data.records.map(r =>
                '<div class="result-item">' +
                (r.time ? r.time.substring(0,19) + ' | ' : '') +
                (r.type || r.action || 'record') + ' | ' +
                (r.action || r.decision || '-') +
                '</div>'
            ).join('');
        }}
    </script>
</body>
</html>
"""


# ============================================
# Auth Helpers
# ============================================

def get_current_client(request: Request) -> Optional[Client]:
    """Get client from session."""
    client_id = request.session.get("client_id")
    if not client_id:
        return None
    return manager.get_client(client_id)


# ============================================
# Routes
# ============================================

@app.get("/", response_class=HTMLResponse)
async def home(request: Request):
    client = get_current_client(request)
    if client:
        return RedirectResponse("/dashboard")
    return RedirectResponse("/login")


@app.get("/login", response_class=HTMLResponse)
async def login_page(error: str = ""):
    error_html = f'<div class="error">{error}</div>' if error else ""
    return LOGIN_HTML.format(error=error_html)


@app.post("/login")
async def login(request: Request, api_key: str = Form(...)):
    valid, client, error = manager.validate_api_key(api_key)
    if not valid or not client:
        return RedirectResponse(f"/login?error={error or 'Invalid API key'}", status_code=303)

    request.session["client_id"] = client.client_id
    request.session["api_key"] = api_key
    return RedirectResponse("/dashboard", status_code=303)


@app.get("/logout")
async def logout(request: Request):
    request.session.clear()
    return RedirectResponse("/login")


@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard(request: Request):
    client = get_current_client(request)
    if not client:
        return RedirectResponse("/login")

    # Get stats
    stats = manager.get_usage_stats(client.client_id)
    sessions = manager.get_client_sessions(client.client_id)

    # Build activity list
    activity_html = ""
    for session in sessions[:10]:
        icon_class = "icon-tool"
        activity_html += f"""
        <li class="activity-item">
            <div class="activity-icon {icon_class}">A</div>
            <div class="activity-info">
                <div class="activity-name">{session.agent_name}</div>
                <div class="activity-time">{session.record_count} records</div>
            </div>
        </li>
        """

    if not activity_html:
        activity_html = "<li class='activity-item'>No recent activity</li>"

    # Calculate usage
    usage_percent = min(100, int((stats['scan_count'] / max(1, client.monthly_scan_limit)) * 100))

    return DASHBOARD_HTML.format(
        company=client.name,
        total_actions=stats.get('action_count', 0),
        user_commands=stats.get('session_count', 0),
        sessions=len(sessions),
        agents=len(set(s.agent_name for s in sessions)) if sessions else 0,
        activity_list=activity_html,
        plan=client.plan.value.upper(),
        scans_used=stats['scan_count'],
        scan_limit=client.monthly_scan_limit,
        usage_percent=usage_percent
    )


@app.get("/api/search")
async def api_search(request: Request, q: str = "", type: str = ""):
    client = get_current_client(request)
    if not client:
        raise HTTPException(401, "Not authenticated")

    # Initialize trace DB
    init_trace_db()

    if type == "agent":
        result = trace_agent("Claude Code", limit=20)
    elif type == "decisions":
        result = trace_decision("decision")
    elif type == "files":
        from .trace_finder import trace_file
        result = trace_file("")
    elif type == "errors":
        from .trace_finder import trace_error
        result = trace_error("")
    elif q:
        result = quick_search(q)
    else:
        result = trace_agent("Claude Code", limit=10)

    return {"records": result.records, "summary": result.summary}


@app.get("/export/json")
async def export_json(request: Request):
    client = get_current_client(request)
    if not client:
        return RedirectResponse("/login")

    sessions = manager.get_client_sessions(client.client_id)
    if sessions:
        content = export_session_json(sessions[0].session_id)
        return JSONResponse(json.loads(content))
    return JSONResponse({"error": "No sessions found"})


@app.get("/export/certificate", response_class=HTMLResponse)
async def export_certificate(request: Request):
    client = get_current_client(request)
    if not client:
        return RedirectResponse("/login")

    sessions = manager.get_client_sessions(client.client_id)
    if sessions:
        cert = generate_certificate(sessions[0].session_id)
        return cert.to_html()
    return "<h1>No sessions found</h1>"


def run_dashboard(host: str = "0.0.0.0", port: int = 8080):
    """Run the dashboard server."""
    from dotenv import load_dotenv
    load_dotenv()

    print(f"\n{'='*50}")
    print("  InALign Dashboard")
    print(f"  http://localhost:{port}")
    print(f"{'='*50}\n")

    uvicorn.run(app, host=host, port=port)


if __name__ == "__main__":
    run_dashboard()
