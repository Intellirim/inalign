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
import secrets
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
from .payments import router as payments_router
from .polygon_anchor import anchor_to_polygon, get_anchor_status, verify_anchor, setup_instructions
from .provenance_graph import (
    trace_record, trace_chain_path, trace_by_action,
    trace_full_graph, trace_timeline, get_record_content,
    init_neo4j as init_provenance_neo4j,
)

app = FastAPI(title="InALign Dashboard")

# Include payment routes
app.include_router(payments_router)
_session_secret = os.getenv("SESSION_SECRET") or secrets.token_hex(32)
app.add_middleware(SessionMiddleware, secret_key=_session_secret)

# Initialize
manager = get_client_manager()

# Initialize Neo4j for provenance graph (trace page)
_provenance_neo4j_initialized = False

def ensure_provenance_neo4j():
    """Lazy-initialize Neo4j connection for provenance graph queries."""
    global _provenance_neo4j_initialized
    if _provenance_neo4j_initialized:
        return
    _provenance_neo4j_initialized = True
    uri = os.getenv("NEO4J_URI")
    user = os.getenv("NEO4J_USERNAME", "neo4j")
    password = os.getenv("NEO4J_PASSWORD", "")
    if uri:
        init_provenance_neo4j(uri, user, password)


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
        <a href="/" style="text-decoration:none;"><div class="logo">InALign</div></a>
        <div class="subtitle">AI Agent Governance Platform</div>
        {error}
        <form method="post" action="/login">
            <div class="form-group">
                <label>API Key</label>
                <input type="text" name="api_key" placeholder="ial_xxxxxxxxxxxx" required>
            </div>
            <button type="submit">Login</button>
        </form>
        <div style="margin-top:20px; text-align:center;">
            <a href="/" style="color:#666; font-size:14px;">← Back to Home</a>
            <span style="color:#ccc; margin:0 10px;">|</span>
            <a href="/#pricing" style="color:#2563eb; font-size:14px;">Get API Key</a>
        </div>
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
        <div style="display:flex;align-items:center;gap:16px;">
            <a href="/trace" style="padding:8px 20px;background:#7c3aed;color:white;border-radius:8px;text-decoration:none;font-weight:600;font-size:14px;transition:background 0.2s;display:flex;align-items:center;gap:6px;">
                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><path d="M12 6v6l4 2"/></svg>
                Trace & Graph
            </a>
            <a href="/logout" class="logout">Logout</a>
        </div>
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
                    <div class="card-header">Blockchain Anchor</div>
                    <div class="card-body">
                        <div id="anchorStatus" style="margin-bottom:15px; padding:12px; background:#f0fdf4; border-radius:8px; display:none;">
                            <div style="color:#16a34a; font-weight:600;">Anchored to Polygon</div>
                            <div style="font-size:12px; color:#666; margin-top:4px;">
                                <span id="anchorTx"></span>
                            </div>
                            <a id="anchorLink" href="#" target="_blank" style="font-size:12px; color:#2563eb;">View on PolygonScan</a>
                        </div>
                        <div id="anchorPending" style="margin-bottom:15px; padding:12px; background:#fef3c7; border-radius:8px;">
                            <div style="color:#d97706; font-weight:600;">Not Anchored</div>
                            <div style="font-size:12px; color:#666; margin-top:4px;">
                                Anchor to Polygon for legal validity
                            </div>
                        </div>
                        <button onclick="anchorToBlockchain()" id="anchorBtn" class="btn btn-primary" style="width:100%; background:#8b5cf6;">
                            Anchor to Polygon (~$0.01)
                        </button>
                    </div>
                </div>

                <div class="card">
                    <div class="card-header">Quick Actions</div>
                    <div class="card-body">
                        <a href="/export/json" class="btn btn-primary" style="width:100%; margin-bottom:10px; text-align:center;">
                            Download Audit Log (JSON)
                        </a>
                        <a href="/export/certificate" class="btn btn-secondary" style="width:100%; margin-bottom:10px; text-align:center;">
                            Download Certificate
                        </a>
                        <a href="/export/csv" class="btn btn-secondary" style="width:100%; margin-bottom:10px; text-align:center;">
                            Export to CSV
                        </a>
                        <a href="/trace" class="btn btn-primary" style="width:100%; text-align:center; background:#7c3aed;">
                            Trace & Backtrack
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
        // Check anchor status on load
        document.addEventListener('DOMContentLoaded', checkAnchorStatus);

        async function checkAnchorStatus() {{
            try {{
                const res = await fetch('/api/anchor/status');
                const data = await res.json();
                if (data.anchored) {{
                    document.getElementById('anchorStatus').style.display = 'block';
                    document.getElementById('anchorPending').style.display = 'none';
                    document.getElementById('anchorTx').textContent = data.transaction_hash.substring(0, 20) + '...';
                    document.getElementById('anchorLink').href = data.explorer_url;
                    document.getElementById('anchorBtn').textContent = 'Re-anchor (new records)';
                    document.getElementById('anchorBtn').style.background = '#6b7280';
                    if (data.mock) {{
                        document.getElementById('anchorStatus').style.background = '#fef3c7';
                        document.getElementById('anchorStatus').querySelector('div').textContent = 'Mock Anchor (Test)';
                        document.getElementById('anchorStatus').querySelector('div').style.color = '#d97706';
                    }}
                }}
            }} catch (e) {{
                console.error('Failed to check anchor status:', e);
            }}
        }}

        async function anchorToBlockchain() {{
            const btn = document.getElementById('anchorBtn');
            btn.disabled = true;
            btn.textContent = 'Anchoring...';

            try {{
                const res = await fetch('/api/anchor', {{ method: 'POST' }});
                const data = await res.json();

                if (data.success) {{
                    alert('Successfully anchored to Polygon!\\n\\nTransaction: ' + data.transaction_hash + '\\n\\nView at: ' + data.explorer_url);
                    checkAnchorStatus();
                }} else {{
                    alert('Anchor failed: ' + data.error);
                }}
            }} catch (e) {{
                alert('Error: ' + e.message);
            }}

            btn.disabled = false;
            btn.textContent = 'Anchor to Polygon (~$0.01)';
        }}

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


TRACE_HTML = """
<!DOCTYPE html>
<html>
<head>
    <title>InALign - Trace & Backtrack</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ font-family: 'Segoe UI', system-ui, sans-serif; background: #0f172a; color: #e2e8f0; }}
        .header {{
            background: linear-gradient(135deg, #1e3a5f 0%, #0d1b2a 100%);
            padding: 14px 32px; display: flex; justify-content: space-between; align-items: center;
            border-bottom: 1px solid #1e3a5f;
        }}
        .logo {{ font-size: 20px; font-weight: bold; color: white; }}
        .logo span {{ color: #60a5fa; }}
        .nav a {{ color: #93c5fd; text-decoration: none; margin-left: 18px; font-size: 14px; }}
        .nav a:hover {{ color: white; }}
        .container {{ max-width: 1600px; margin: 0 auto; padding: 16px; }}

        /* Search Panel */
        .search-panel {{
            background: #1e293b; border-radius: 10px; padding: 16px 20px;
            margin-bottom: 16px; border: 1px solid #334155;
        }}
        .search-row {{ display: flex; gap: 10px; margin-bottom: 10px; }}
        .search-row input {{
            flex: 1; padding: 8px 14px; background: #0f172a; border: 1px solid #475569;
            border-radius: 6px; color: #e2e8f0; font-size: 13px; outline: none;
        }}
        .search-row input:focus {{ border-color: #60a5fa; }}
        .search-row select {{
            min-width: 150px; padding: 8px 12px; background: #0f172a; border: 1px solid #475569;
            border-radius: 6px; color: #e2e8f0; font-size: 13px;
        }}
        .btn {{ padding: 8px 16px; border: none; border-radius: 6px; cursor: pointer; font-weight: 600; font-size: 13px; transition: all 0.2s; }}
        .btn-blue {{ background: #2563eb; color: white; }}
        .btn-blue:hover {{ background: #1d4ed8; }}
        .btn-purple {{ background: #7c3aed; color: white; }}
        .btn-purple:hover {{ background: #6d28d9; }}
        .btn-gray {{ background: #374151; color: #e2e8f0; }}
        .btn-gray:hover {{ background: #4b5563; }}
        .quick-btns {{ display: flex; gap: 6px; flex-wrap: wrap; }}
        .quick-btns button {{
            padding: 5px 12px; background: #1e293b; border: 1px solid #475569;
            border-radius: 5px; cursor: pointer; font-size: 12px; color: #94a3b8; transition: all 0.2s;
        }}
        .quick-btns button:hover {{ background: #334155; color: white; border-color: #60a5fa; }}

        /* Graph Panel */
        .graph-panel {{
            background: #1e293b; border-radius: 10px; margin-bottom: 16px;
            border: 1px solid #334155; overflow: hidden;
        }}
        .graph-header {{
            padding: 12px 20px; display: flex; justify-content: space-between; align-items: center;
            border-bottom: 1px solid #334155;
        }}
        .graph-title {{ font-weight: 700; font-size: 15px; color: #f1f5f9; }}
        .graph-stats {{ display: flex; gap: 16px; font-size: 12px; color: #94a3b8; }}
        .graph-stats .stat {{ display: flex; align-items: center; gap: 4px; }}
        .graph-stats .dot {{ width: 8px; height: 8px; border-radius: 50%; display: inline-block; }}
        #graphContainer {{ width: 100%; height: 520px; background: #0d1117; position: relative; overflow: hidden; cursor: grab; }}
        #graphContainer.dragging {{ cursor: grabbing; }}
        #graphCanvas {{ width: 100%; height: 100%; display: block; }}
        .zoom-controls {{
            position: absolute; top: 12px; right: 12px; display: flex; flex-direction: column; gap: 4px; z-index: 10;
        }}
        .zoom-btn {{
            width: 32px; height: 32px; border-radius: 6px; border: 1px solid #334155;
            background: rgba(30, 41, 59, 0.9); color: #94a3b8; font-size: 16px; cursor: pointer;
            display: flex; align-items: center; justify-content: center; transition: all 0.15s;
            backdrop-filter: blur(8px);
        }}
        .zoom-btn:hover {{ background: rgba(51, 65, 85, 0.95); color: white; border-color: #60a5fa; }}
        .zoom-btn svg {{ width: 16px; height: 16px; }}
        .legend {{
            padding: 8px 20px; display: flex; gap: 16px; border-top: 1px solid #334155;
            flex-wrap: wrap; align-items: center;
        }}
        .legend-item {{ display: flex; align-items: center; gap: 5px; font-size: 11px; color: #94a3b8; }}
        .legend-dot {{ width: 10px; height: 10px; border-radius: 50%; display: inline-block; box-shadow: 0 0 6px rgba(255,255,255,0.15); }}

        /* Bottom Panels */
        .bottom-layout {{ display: grid; grid-template-columns: 380px 1fr; gap: 16px; }}
        .panel {{
            background: #1e293b; border-radius: 10px; border: 1px solid #334155;
            max-height: 55vh; overflow-y: auto;
        }}
        .panel-header {{
            padding: 12px 16px; font-weight: 700; font-size: 14px; color: #f1f5f9;
            border-bottom: 1px solid #334155; position: sticky; top: 0; background: #1e293b; z-index: 2;
        }}
        .panel-body {{ padding: 8px; }}

        /* Timeline Items */
        .tl-item {{
            padding: 8px 12px; margin: 4px 0; border-left: 3px solid #334155;
            border-radius: 0 6px 6px 0; cursor: pointer; transition: all 0.15s;
        }}
        .tl-item:hover {{ background: #334155; border-left-color: #60a5fa; }}
        .tl-item.active {{ background: #1e3a5f; border-left-color: #3b82f6; }}
        .tl-action {{ font-weight: 600; font-size: 13px; color: #e2e8f0; }}
        .tl-badge {{
            font-size: 10px; padding: 1px 6px; border-radius: 3px; display: inline-block;
            margin-top: 2px; font-weight: 600;
        }}
        .badge-tool {{ background: #064e3b; color: #34d399; }}
        .badge-decision {{ background: #7f1d1d; color: #fca5a5; }}
        .badge-input {{ background: #312e81; color: #a5b4fc; }}
        .badge-file {{ background: #713f12; color: #fcd34d; }}
        .badge-llm {{ background: #164e63; color: #67e8f9; }}
        .tl-time {{ font-size: 11px; color: #64748b; margin-top: 2px; }}
        .tl-hash {{ font-family: monospace; font-size: 10px; color: #475569; }}

        /* Detail Panel */
        .detail-section {{ margin-bottom: 14px; padding: 0 8px; }}
        .detail-section h4 {{
            color: #64748b; font-size: 11px; text-transform: uppercase; letter-spacing: 0.5px;
            margin-bottom: 6px; padding-bottom: 4px; border-bottom: 1px solid #1e293b;
        }}
        .detail-row {{ display: flex; padding: 3px 0; }}
        .detail-label {{ width: 100px; color: #64748b; font-size: 12px; flex-shrink: 0; }}
        .detail-value {{ flex: 1; font-size: 12px; word-break: break-all; color: #cbd5e1; }}
        .detail-value.mono {{ font-family: monospace; font-size: 11px; color: #94a3b8; }}
        .chain-nav {{
            display: inline-flex; align-items: center; gap: 6px; padding: 4px 10px;
            background: #0f172a; border-radius: 6px; cursor: pointer; font-size: 11px;
            color: #60a5fa; border: 1px solid #1e3a5f; transition: all 0.15s;
        }}
        .chain-nav:hover {{ background: #1e3a5f; color: white; }}
        .chain-current {{
            padding: 4px 10px; background: #1e3a5f; border-radius: 6px;
            font-size: 11px; font-weight: 700; color: #60a5fa;
        }}
        .content-box {{
            background: #0f172a; color: #94a3b8; padding: 10px; border-radius: 6px;
            font-family: monospace; font-size: 11px; white-space: pre-wrap;
            max-height: 180px; overflow-y: auto; border: 1px solid #1e293b; margin-top: 4px;
        }}
        .empty-state {{ text-align: center; color: #475569; padding: 40px 20px; font-size: 13px; }}

        /* Scrollbar */
        ::-webkit-scrollbar {{ width: 6px; }}
        ::-webkit-scrollbar-track {{ background: #0f172a; }}
        ::-webkit-scrollbar-thumb {{ background: #334155; border-radius: 3px; }}
        ::-webkit-scrollbar-thumb:hover {{ background: #475569; }}

        /* Help Panel */
        .help-panel {{
            margin-top: 10px; padding: 12px 16px; background: #0f172a; border-radius: 8px;
            border: 1px solid #1e3a5f; font-size: 12px; color: #94a3b8; line-height: 1.6;
        }}
        .help-panel b {{ color: #60a5fa; }}
        .help-panel code {{
            background: #1e293b; padding: 1px 5px; border-radius: 3px; font-size: 11px; color: #67e8f9;
        }}

        /* Node tooltip */
        .node-tooltip {{
            position: absolute; pointer-events: none; z-index: 20;
            background: rgba(15, 23, 42, 0.95); border: 1px solid #334155;
            border-radius: 8px; padding: 10px 14px; font-size: 12px;
            color: #e2e8f0; box-shadow: 0 8px 32px rgba(0,0,0,0.5);
            backdrop-filter: blur(12px); max-width: 320px; display: none;
            transform: translate(-50%, -100%); margin-top: -12px;
        }}
        .node-tooltip .tt-label {{ font-weight: 700; font-size: 13px; margin-bottom: 4px; }}
        .node-tooltip .tt-type {{ font-size: 10px; text-transform: uppercase; letter-spacing: 0.5px; opacity: 0.7; margin-bottom: 6px; }}
        .node-tooltip .tt-row {{ font-size: 11px; color: #94a3b8; margin: 2px 0; }}
        .node-tooltip .tt-row b {{ color: #cbd5e1; font-weight: 500; }}
    </style>
</head>
<body>
    <div class="header">
        <div class="logo">InALign <span>| Trace & Backtrack</span></div>
        <div class="nav">
            <a href="/dashboard">Dashboard</a>
            <a href="/trace">Trace</a>
            <a href="/logout">Logout</a>
        </div>
    </div>

    <div class="container">
        <!-- Search Panel -->
        <div class="search-panel">
            <div class="search-row">
                <input type="text" id="searchInput" placeholder="Search by action name (e.g. record_action, Edit, read_file...)">
                <select id="typeFilter">
                    <option value="">All Types</option>
                    <option value="user_input">User Input</option>
                    <option value="tool_call">Tool Call</option>
                    <option value="decision">Decision</option>
                    <option value="llm_request">LLM Request</option>
                    <option value="file_read">File Read</option>
                    <option value="file_write">File Write</option>
                </select>
                <button class="btn btn-blue" onclick="searchActions()">Search</button>
                <button class="btn btn-purple" onclick="loadFullGraph()">Load Graph</button>
                <button class="btn btn-gray" onclick="toggleHelp()">? Help</button>
            </div>
            <div class="quick-btns">
                <button onclick="loadTimeline()">Full Timeline</button>
                <button onclick="searchType('tool_call')">Tool Calls</button>
                <button onclick="searchType('decision')">Decisions</button>
                <button onclick="searchType('user_input')">Prompts</button>
                <button onclick="searchType('file_write')">File Changes</button>
                <button onclick="searchType('file_read')">File Reads</button>
            </div>
            <div class="help-panel" id="helpPanel" style="display:none;">
                <b>By name:</b> Type action name (<code>record_action</code>, <code>Edit</code>, <code>read_file</code>)<br>
                <b>By type:</b> Select from dropdown (User Input = prompts, Tool Call = agent actions)<br>
                <b>Quick filters:</b> Click buttons to filter by type<br>
                <b>Graph:</b> Click "Load Graph" to see all nodes. Click nodes to see details.<br>
                <b>Timeline + Graph sync:</b> Click any record in timeline to highlight in graph and vice versa<br>
                <b>Chain nav:</b> Use the arrow buttons in detail panel to walk the hash chain<br>
                <b>Scroll:</b> Mouse wheel to zoom, drag to pan
            </div>
        </div>

        <!-- Graph Visualization -->
        <div class="graph-panel">
            <div class="graph-header">
                <div class="graph-title">Provenance Graph</div>
                <div class="graph-stats" id="graphStats">
                    <span class="stat">Click "Load Graph" to visualize</span>
                </div>
            </div>
            <div id="graphContainer">
                <canvas id="graphCanvas"></canvas>
                <div class="zoom-controls">
                    <button class="zoom-btn" onclick="zoomIn()" title="Zoom In">
                        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="12" y1="5" x2="12" y2="19"/><line x1="5" y1="12" x2="19" y2="12"/></svg>
                    </button>
                    <button class="zoom-btn" onclick="zoomOut()" title="Zoom Out">
                        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="5" y1="12" x2="19" y2="12"/></svg>
                    </button>
                    <button class="zoom-btn" onclick="zoomFit()" title="Fit to View">
                        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M15 3h6v6M9 21H3v-6M21 3l-7 7M3 21l7-7"/></svg>
                    </button>
                </div>
                <div class="node-tooltip" id="nodeTooltip"></div>
            </div>
            <div class="legend">
                <div class="legend-item"><div class="legend-dot" style="background:#4C8EDA;"></div> Record</div>
                <div class="legend-item"><div class="legend-dot" style="background:#8b5cf6;"></div> Session</div>
                <div class="legend-item"><div class="legend-dot" style="background:#F79767;"></div> Agent</div>
                <div class="legend-item"><div class="legend-dot" style="background:#8DCC93;"></div> Tool</div>
                <div class="legend-item"><div class="legend-dot" style="background:#F16667;"></div> Decision</div>
                <div class="legend-item"><div class="legend-dot" style="background:#57C7E3;"></div> Content</div>
                <div class="legend-item"><div class="legend-dot" style="background:#ECB83D;"></div> Blockchain</div>
                <div style="margin-left:auto;font-size:11px;color:#475569;">Scroll to zoom | Drag to pan | Click node for details</div>
            </div>
        </div>

        <!-- Bottom: Timeline + Detail -->
        <div class="bottom-layout">
            <div class="panel">
                <div class="panel-header">Timeline <span id="timelineCount" style="font-weight:400;color:#64748b;font-size:12px;"></span></div>
                <div class="panel-body" id="timeline">
                    <div class="empty-state">Load timeline or search to see records</div>
                </div>
            </div>
            <div class="panel">
                <div class="panel-header">Record Detail</div>
                <div class="panel-body" id="detail">
                    <div class="empty-state">Click a record in timeline or graph to see details</div>
                </div>
            </div>
        </div>
    </div>

    <script>
        // ============================================
        // Canvas Graph - Neo4j Bloom Style
        // ============================================

        let canvas, ctx, containerEl;
        let graphWidth = 0, graphHeight = 0;
        let positions = new Map();
        let graphData = {{ nodes: [], edges: [] }};
        let allNodeData = {{}};
        let hoveredNodeId = null;
        let selectedNodeId = null;
        let scale = 1;
        let panX = 0, panY = 0;
        let isDragging = false;
        let dragStartX = 0, dragStartY = 0;
        let dragStartPanX = 0, dragStartPanY = 0;
        let isSimulating = false;
        let animationId = null;
        let simulationSteps = 0;
        const MAX_SIM_STEPS = 300;

        // Neo4j Bloom colors for InALign node types
        const NODE_COLORS = {{
            record:     {{ bg: '#4C8EDA', border: '#3A7BC8' }},
            session:    {{ bg: '#8b5cf6', border: '#7c3aed' }},
            agent:      {{ bg: '#F79767', border: '#E08050' }},
            tool:       {{ bg: '#8DCC93', border: '#76B57C' }},
            decision:   {{ bg: '#F16667', border: '#D94F50' }},
            content:    {{ bg: '#57C7E3', border: '#40B0CC' }},
            blockchain: {{ bg: '#ECB83D', border: '#D4A12E' }},
        }};
        const DEFAULT_COLOR = {{ bg: '#A5ABB6', border: '#8E9AA6' }};

        const NODE_RADII = {{
            record: 14, session: 22, agent: 20,
            tool: 16, decision: 14, content: 11, blockchain: 18,
        }};

        // ============================================
        // Force-Directed Physics (from ontix-web)
        // ============================================

        function runSimulation() {{
            const centerX = graphWidth / 2;
            const centerY = graphHeight / 2;
            const nodeCount = positions.size;
            if (nodeCount === 0) return 0;
            const k = Math.sqrt((graphWidth * graphHeight) / Math.max(nodeCount, 1)) * 0.6;

            // Repulsion between all nodes
            const posArr = Array.from(positions.entries());
            for (let i = 0; i < posArr.length; i++) {{
                const [idA, posA] = posArr[i];
                for (let j = i + 1; j < posArr.length; j++) {{
                    const [idB, posB] = posArr[j];
                    const dx = posA.x - posB.x;
                    const dy = posA.y - posB.y;
                    const dist = Math.sqrt(dx * dx + dy * dy) || 1;
                    const minDist = posA.radius + posB.radius + 20;

                    if (dist < minDist * 3) {{
                        const force = (k * k) / dist;
                        const fx = (dx / dist) * force * 0.015;
                        const fy = (dy / dist) * force * 0.015;
                        posA.vx += fx;
                        posA.vy += fy;
                        posB.vx -= fx;
                        posB.vy -= fy;
                    }}
                }}
            }}

            // Attraction along edges
            graphData.edges.forEach(function(edge) {{
                const source = positions.get(edge.source);
                const target = positions.get(edge.target);
                if (!source || !target) return;

                const dx = target.x - source.x;
                const dy = target.y - source.y;
                const dist = Math.sqrt(dx * dx + dy * dy) || 1;
                const idealDist = k * 1.2;
                const force = (dist - idealDist) * 0.01;

                source.vx += (dx / dist) * force;
                source.vy += (dy / dist) * force;
                target.vx -= (dx / dist) * force;
                target.vy -= (dy / dist) * force;
            }});

            // Center gravity
            positions.forEach(function(pos) {{
                const dx = centerX - pos.x;
                const dy = centerY - pos.y;
                pos.vx += dx * 0.0008;
                pos.vy += dy * 0.0008;
            }});

            // Apply velocities with damping
            let totalMovement = 0;
            const margin = 50;
            positions.forEach(function(pos) {{
                pos.vx *= 0.88;
                pos.vy *= 0.88;
                pos.x += pos.vx;
                pos.y += pos.vy;
                pos.x = Math.max(margin, Math.min(graphWidth - margin, pos.x));
                pos.y = Math.max(margin, Math.min(graphHeight - margin, pos.y));
                totalMovement += Math.abs(pos.vx) + Math.abs(pos.vy);
            }});

            return totalMovement;
        }}

        // ============================================
        // Canvas Rendering
        // ============================================

        function getConnectedEdges(nodeId) {{
            return graphData.edges.filter(function(e) {{ return e.source === nodeId || e.target === nodeId; }});
        }}

        function render() {{
            if (!ctx) return;
            const dpr = window.devicePixelRatio || 1;
            ctx.setTransform(dpr, 0, 0, dpr, 0, 0);

            // Dark background with radial gradient
            const bgGrad = ctx.createRadialGradient(
                graphWidth / 2, graphHeight / 2, 0,
                graphWidth / 2, graphHeight / 2, Math.max(graphWidth, graphHeight) / 2
            );
            bgGrad.addColorStop(0, '#1a1f2e');
            bgGrad.addColorStop(1, '#0d1117');
            ctx.fillStyle = bgGrad;
            ctx.fillRect(0, 0, graphWidth, graphHeight);

            // Apply pan + zoom transform
            ctx.save();
            ctx.translate(graphWidth / 2 + panX, graphHeight / 2 + panY);
            ctx.scale(scale, scale);
            ctx.translate(-graphWidth / 2, -graphHeight / 2);

            // Run simulation
            if (isSimulating && simulationSteps < MAX_SIM_STEPS) {{
                const movement = runSimulation();
                simulationSteps++;
                if (movement < 0.3 || simulationSteps >= MAX_SIM_STEPS) {{
                    isSimulating = false;
                }}
            }}

            var activeNode = selectedNodeId || hoveredNodeId;
            var connectedSet = new Set();
            if (activeNode) {{
                getConnectedEdges(activeNode).forEach(function(e) {{
                    connectedSet.add(e.source);
                    connectedSet.add(e.target);
                }});
                connectedSet.add(activeNode);
            }}

            // ---- Draw Edges ----
            graphData.edges.forEach(function(edge) {{
                var source = positions.get(edge.source);
                var target = positions.get(edge.target);
                if (!source || !target) return;

                var isHighlighted = activeNode && (edge.source === activeNode || edge.target === activeNode);
                var isDimmed = activeNode && !isHighlighted;

                // Edge line
                ctx.beginPath();
                ctx.moveTo(source.x, source.y);
                ctx.lineTo(target.x, target.y);

                if (isHighlighted) {{
                    ctx.strokeStyle = 'rgba(96, 165, 250, 0.85)';
                    ctx.lineWidth = 2.5 / scale;
                }} else if (isDimmed) {{
                    ctx.strokeStyle = 'rgba(255, 255, 255, 0.04)';
                    ctx.lineWidth = 0.5 / scale;
                }} else {{
                    ctx.strokeStyle = 'rgba(255, 255, 255, 0.12)';
                    ctx.lineWidth = 1 / scale;
                }}
                ctx.stroke();

                // Arrow head
                if (!isDimmed) {{
                    var dx = target.x - source.x;
                    var dy = target.y - source.y;
                    var dist = Math.sqrt(dx * dx + dy * dy) || 1;
                    var targetR = target.radius + 4;
                    var arrowX = target.x - (dx / dist) * targetR;
                    var arrowY = target.y - (dy / dist) * targetR;
                    var angle = Math.atan2(dy, dx);
                    var arrowLen = isHighlighted ? 10 / scale : 7 / scale;
                    var arrowWidth = Math.PI / 7;

                    ctx.beginPath();
                    ctx.moveTo(arrowX, arrowY);
                    ctx.lineTo(arrowX - arrowLen * Math.cos(angle - arrowWidth), arrowY - arrowLen * Math.sin(angle - arrowWidth));
                    ctx.lineTo(arrowX - arrowLen * Math.cos(angle + arrowWidth), arrowY - arrowLen * Math.sin(angle + arrowWidth));
                    ctx.closePath();
                    ctx.fillStyle = isHighlighted ? 'rgba(96, 165, 250, 0.85)' : 'rgba(255, 255, 255, 0.2)';
                    ctx.fill();
                }}

                // Edge label (only when highlighted or zoomed in)
                if (isHighlighted || (scale > 1.2 && !isDimmed)) {{
                    var midX = (source.x + target.x) / 2;
                    var midY = (source.y + target.y) / 2;
                    var label = (edge.type || '').replace('_', ' ');
                    if (label) {{
                        ctx.font = (9 / scale) + 'px Segoe UI, sans-serif';
                        var tw = ctx.measureText(label).width;
                        ctx.fillStyle = 'rgba(15, 23, 42, 0.8)';
                        ctx.fillRect(midX - tw / 2 - 3, midY - 6, tw + 6, 12);
                        ctx.fillStyle = isHighlighted ? '#93c5fd' : '#64748b';
                        ctx.textAlign = 'center';
                        ctx.textBaseline = 'middle';
                        ctx.fillText(label, midX, midY);
                    }}
                }}
            }});

            // ---- Draw Nodes ----
            positions.forEach(function(pos, nodeId) {{
                var node = pos.node;
                var isHovered = hoveredNodeId === nodeId;
                var isSelected = selectedNodeId === nodeId;
                var isConnected = activeNode && connectedSet.has(nodeId) && nodeId !== activeNode;
                var isActive = isHovered || isSelected;
                var isDimmed = activeNode && !connectedSet.has(nodeId);

                var colors = NODE_COLORS[node.type] || DEFAULT_COLOR;
                var radius = pos.radius;
                if (isHovered) radius *= 1.25;

                // Dimmed nodes
                if (isDimmed) {{
                    ctx.globalAlpha = 0.12;
                }}

                // Glow effect for active/connected nodes
                if (isActive || isConnected) {{
                    var glow = ctx.createRadialGradient(pos.x, pos.y, radius * 0.5, pos.x, pos.y, radius * 3);
                    glow.addColorStop(0, colors.bg + '50');
                    glow.addColorStop(1, 'rgba(0,0,0,0)');
                    ctx.beginPath();
                    ctx.arc(pos.x, pos.y, radius * 3, 0, Math.PI * 2);
                    ctx.fillStyle = glow;
                    ctx.fill();
                }}

                // Node shadow
                ctx.beginPath();
                ctx.arc(pos.x + 2, pos.y + 2, radius, 0, Math.PI * 2);
                ctx.fillStyle = 'rgba(0, 0, 0, 0.35)';
                ctx.fill();

                // Node fill with radial gradient
                var nodeGrad = ctx.createRadialGradient(
                    pos.x - radius * 0.3, pos.y - radius * 0.3, 0,
                    pos.x, pos.y, radius
                );
                nodeGrad.addColorStop(0, colors.bg);
                nodeGrad.addColorStop(1, colors.border);

                ctx.beginPath();
                ctx.arc(pos.x, pos.y, radius, 0, Math.PI * 2);
                ctx.fillStyle = nodeGrad;
                ctx.fill();

                // Node border
                ctx.strokeStyle = (isActive || isConnected) ? '#ffffff' : colors.border;
                ctx.lineWidth = (isActive ? 3 : isConnected ? 2 : 1.5) / scale;
                ctx.stroke();

                // Node icon character (type abbreviation inside the node)
                var iconChar = {{ record: 'R', session: 'S', agent: 'A', tool: 'T', decision: 'D', content: 'C', blockchain: 'B' }}[node.type] || '?';
                ctx.font = 'bold ' + (radius * 0.8) + 'px Segoe UI, sans-serif';
                ctx.fillStyle = 'rgba(255,255,255,0.85)';
                ctx.textAlign = 'center';
                ctx.textBaseline = 'middle';
                ctx.fillText(iconChar, pos.x, pos.y + 0.5);

                // Always show label for session/agent nodes, or when zoomed in
                if (!isDimmed && (node.type === 'session' || node.type === 'agent' || scale > 1.5)) {{
                    var lbl = (node.label || '').length > 20 ? node.label.substring(0, 18) + '..' : (node.label || '');
                    ctx.font = (10 / scale) + 'px Segoe UI, sans-serif';
                    ctx.fillStyle = 'rgba(226, 232, 240, 0.7)';
                    ctx.textAlign = 'center';
                    ctx.textBaseline = 'top';
                    ctx.fillText(lbl, pos.x, pos.y + radius + 4);
                }}

                ctx.globalAlpha = 1;
            }});

            // ---- Hovered/Selected label popup (on top) ----
            if (hoveredNodeId || selectedNodeId) {{
                var targetId = hoveredNodeId || selectedNodeId;
                var pos = positions.get(targetId);
                if (pos) {{
                    var node = pos.node;
                    var colors = NODE_COLORS[node.type] || DEFAULT_COLOR;
                    var radius = pos.radius;
                    var label = (node.label || '').length > 30 ? node.label.substring(0, 28) + '...' : (node.label || '');

                    ctx.font = 'bold ' + (12 / scale) + 'px Segoe UI, sans-serif';
                    var textW = ctx.measureText(label).width;

                    // Label background pill
                    var labelY = pos.y - radius - (16 / scale);
                    ctx.fillStyle = 'rgba(15, 23, 42, 0.92)';
                    ctx.beginPath();
                    var pillX = pos.x - textW / 2 - 10;
                    var pillY = labelY - (14 / scale);
                    var pillW = textW + 20;
                    var pillH = 26 / scale;
                    var pillR = 6 / scale;
                    ctx.moveTo(pillX + pillR, pillY);
                    ctx.lineTo(pillX + pillW - pillR, pillY);
                    ctx.quadraticCurveTo(pillX + pillW, pillY, pillX + pillW, pillY + pillR);
                    ctx.lineTo(pillX + pillW, pillY + pillH - pillR);
                    ctx.quadraticCurveTo(pillX + pillW, pillY + pillH, pillX + pillW - pillR, pillY + pillH);
                    ctx.lineTo(pillX + pillR, pillY + pillH);
                    ctx.quadraticCurveTo(pillX, pillY + pillH, pillX, pillY + pillH - pillR);
                    ctx.lineTo(pillX, pillY + pillR);
                    ctx.quadraticCurveTo(pillX, pillY, pillX + pillR, pillY);
                    ctx.closePath();
                    ctx.fill();
                    ctx.strokeStyle = colors.bg + '60';
                    ctx.lineWidth = 1 / scale;
                    ctx.stroke();

                    // Label text
                    ctx.fillStyle = '#ffffff';
                    ctx.textAlign = 'center';
                    ctx.textBaseline = 'middle';
                    ctx.fillText(label, pos.x, labelY - (1 / scale));

                    // Type badge below
                    ctx.font = (9 / scale) + 'px Segoe UI, sans-serif';
                    ctx.fillStyle = colors.bg;
                    ctx.textBaseline = 'top';
                    ctx.fillText(node.type.toUpperCase(), pos.x, pos.y + radius + (4 / scale));
                }}
            }}

            ctx.restore();

            // Continue animation
            animationId = requestAnimationFrame(render);
        }}

        // ============================================
        // Graph Init & Data Loading
        // ============================================

        function initCanvas() {{
            canvas = document.getElementById('graphCanvas');
            containerEl = document.getElementById('graphContainer');
            ctx = canvas.getContext('2d');

            var rect = containerEl.getBoundingClientRect();
            var dpr = window.devicePixelRatio || 1;
            graphWidth = rect.width;
            graphHeight = rect.height;
            canvas.width = graphWidth * dpr;
            canvas.height = graphHeight * dpr;
            canvas.style.width = graphWidth + 'px';
            canvas.style.height = graphHeight + 'px';
            ctx.scale(dpr, dpr);
        }}

        var graphLoadedFromApi = false;

        function loadFullGraph() {{
            document.getElementById('graphStats').innerHTML = '<span class="stat">Loading graph data...</span>';

            fetch('/api/trace/graph')
                .then(function(r) {{ return r.json(); }})
                .then(function(data) {{
                    if (data.error) {{
                        document.getElementById('graphStats').innerHTML = '<span class="stat" style="color:#ef4444;">' + data.error + '</span>';
                        // Fallback to timeline
                        return fallbackToTimeline();
                    }}
                    if (data.nodes && data.nodes.length > 0) {{
                        graphLoadedFromApi = true;
                        populateGraph(data);
                    }} else {{
                        // Graph API returned empty - fallback to timeline
                        fallbackToTimeline();
                    }}
                }})
                .catch(function(e) {{
                    document.getElementById('graphStats').innerHTML = '<span class="stat" style="color:#ef4444;">Error: ' + e.message + '</span>';
                    fallbackToTimeline();
                }});
        }}

        function fallbackToTimeline() {{
            fetch('/api/trace/timeline')
                .then(function(r) {{ return r.json(); }})
                .then(function(tlData) {{
                    var records = tlData.timeline || [];
                    if (records.length > 0) {{
                        buildGraphFromTimeline(records);
                    }} else {{
                        document.getElementById('graphStats').innerHTML = '<span class="stat">No data available</span>';
                    }}
                }})
                .catch(function(e) {{
                    document.getElementById('graphStats').innerHTML = '<span class="stat">No graph data</span>';
                }});
        }}

        function populateGraph(data) {{
            if (!canvas) initCanvas();

            graphData.nodes = data.nodes || [];
            graphData.edges = data.edges || [];
            positions.clear();
            allNodeData = {{}};

            var centerX = graphWidth / 2;
            var centerY = graphHeight / 2;

            // Group nodes by type
            var nodesByType = {{}};
            graphData.nodes.forEach(function(node) {{
                allNodeData[node.id] = node;
                if (!nodesByType[node.type]) nodesByType[node.type] = [];
                nodesByType[node.type].push(node);
            }});

            // Place session node at center (largest)
            var sessionNodes = nodesByType['session'] || [];
            sessionNodes.forEach(function(node, i) {{
                var angle = (i / Math.max(sessionNodes.length, 1)) * Math.PI * 2;
                var r = sessionNodes.length > 1 ? 50 : 0;
                positions.set(node.id, {{
                    x: centerX + Math.cos(angle) * r,
                    y: centerY + Math.sin(angle) * r,
                    vx: 0, vy: 0,
                    node: node,
                    radius: NODE_RADII['session'] || 22,
                }});
            }});

            // Place other nodes in orbital rings by type
            var types = Object.keys(nodesByType).filter(function(t) {{ return t !== 'session'; }});
            var typeIndex = 0;
            types.forEach(function(type) {{
                var typeNodes = nodesByType[type];
                var baseAngle = (typeIndex / types.length) * Math.PI * 2 - Math.PI / 2;
                var ringRadius = Math.min(graphWidth, graphHeight) * 0.3;

                typeNodes.forEach(function(node, i) {{
                    var angleSpread = (Math.PI * 0.5) / Math.max(typeNodes.length, 1);
                    var angle = baseAngle + (i - (typeNodes.length - 1) / 2) * angleSpread;
                    var r = ringRadius + (Math.random() - 0.5) * 40;

                    positions.set(node.id, {{
                        x: centerX + Math.cos(angle) * r,
                        y: centerY + Math.sin(angle) * r,
                        vx: 0, vy: 0,
                        node: node,
                        radius: NODE_RADII[type] || 14,
                    }});
                }});
                typeIndex++;
            }});

            // Start simulation
            isSimulating = true;
            simulationSteps = 0;
            scale = 1;
            panX = 0;
            panY = 0;

            // Start animation loop if not running
            if (!animationId) {{
                render();
            }}

            updateGraphStats();
        }}

        function updateGraphStats() {{
            var nodeCount = graphData.nodes.length;
            var edgeCount = graphData.edges.length;
            var types = {{}};
            graphData.nodes.forEach(function(n) {{
                types[n.type] = (types[n.type] || 0) + 1;
            }});

            var html = '<span class="stat"><b>' + nodeCount + '</b> nodes</span>';
            html += '<span class="stat"><b>' + edgeCount + '</b> edges</span>';
            var typeOrder = ['record', 'session', 'agent', 'tool', 'decision', 'content', 'blockchain'];
            for (var i = 0; i < typeOrder.length; i++) {{
                var type = typeOrder[i];
                var count = types[type];
                if (!count) continue;
                var color = (NODE_COLORS[type] || DEFAULT_COLOR).bg;
                html += '<span class="stat"><span class="dot" style="background:' + color + '"></span>' + count + ' ' + type + '</span>';
            }}
            document.getElementById('graphStats').innerHTML = html;
        }}

        // ============================================
        // Build Graph from Timeline Records
        // ============================================

        function buildGraphFromTimeline(records) {{
            if (!records || !records.length) return;

            var nodes = [];
            var edges = [];
            var seen = {{}};
            var toolNodes = {{}};
            var typeGroups = {{}};

            records.forEach(function(r, i) {{
                var nodeId = r.id;
                if (!nodeId || seen[nodeId]) return;

                // Record node
                nodes.push({{
                    id: nodeId,
                    label: r.action || r.type || '-',
                    type: 'record',
                    group: r.type || 'unknown',
                    time: r.time || '',
                    hash: r.hash || '',
                }});
                seen[nodeId] = true;

                // Group by action_type for type-hub nodes
                var actionType = r.type || 'unknown';
                if (!typeGroups[actionType]) {{
                    typeGroups[actionType] = [];
                }}
                typeGroups[actionType].push(nodeId);

                // Tool node (deduplicated)
                if (r.tool) {{
                    var toolId = 'tool:' + r.tool;
                    if (!toolNodes[toolId]) {{
                        toolNodes[toolId] = true;
                        nodes.push({{
                            id: toolId,
                            label: r.tool,
                            type: 'tool',
                            group: 'tool',
                        }});
                    }}
                    edges.push({{ source: nodeId, target: toolId, type: 'CALLED' }});
                }}

                // FOLLOWS edge to previous record (provenance chain)
                if (i > 0 && records[i - 1].id) {{
                    edges.push({{ source: nodeId, target: records[i - 1].id, type: 'FOLLOWS' }});
                }}
            }});

            // Create type-hub nodes for grouping (if more than 2 records of same type)
            Object.keys(typeGroups).forEach(function(actionType) {{
                var group = typeGroups[actionType];
                if (group.length >= 2) {{
                    var hubId = 'type:' + actionType;
                    var typeMap = {{
                        'tool_call': 'tool',
                        'decision': 'decision',
                        'file_read': 'content',
                        'file_write': 'content',
                        'llm_request': 'agent',
                        'user_input': 'session',
                    }};
                    nodes.push({{
                        id: hubId,
                        label: actionType.replace('_', ' '),
                        type: typeMap[actionType] || 'session',
                        group: actionType,
                    }});
                    seen[hubId] = true;
                    group.forEach(function(recId) {{
                        edges.push({{ source: recId, target: hubId, type: 'BELONGS_TO' }});
                    }});
                }}
            }});

            if (nodes.length > 0) {{
                populateGraph({{ nodes: nodes, edges: edges }});
            }}
        }}

        // ============================================
        // Mouse Interaction
        // ============================================

        function screenToGraph(sx, sy) {{
            return {{
                x: (sx - graphWidth / 2 - panX) / scale + graphWidth / 2,
                y: (sy - graphHeight / 2 - panY) / scale + graphHeight / 2,
            }};
        }}

        function findNodeAt(gx, gy) {{
            var found = null;
            var minDist = Infinity;
            positions.forEach(function(pos, nodeId) {{
                var dx = gx - pos.x;
                var dy = gy - pos.y;
                var dist = Math.sqrt(dx * dx + dy * dy);
                if (dist < pos.radius + 5 && dist < minDist) {{
                    found = nodeId;
                    minDist = dist;
                }}
            }});
            return found;
        }}

        document.addEventListener('DOMContentLoaded', function() {{
            var container = document.getElementById('graphContainer');
            var tooltip = document.getElementById('nodeTooltip');

            container.addEventListener('mousemove', function(e) {{
                if (isDragging) {{
                    panX = dragStartPanX + (e.clientX - dragStartX);
                    panY = dragStartPanY + (e.clientY - dragStartY);
                    return;
                }}

                var rect = container.getBoundingClientRect();
                var sx = e.clientX - rect.left;
                var sy = e.clientY - rect.top;
                var gp = screenToGraph(sx, sy);
                var found = findNodeAt(gp.x, gp.y);

                hoveredNodeId = found;
                canvas.style.cursor = found ? 'pointer' : (isDragging ? 'grabbing' : 'grab');

                // Tooltip
                if (found) {{
                    var node = allNodeData[found];
                    if (node) {{
                        var colors = NODE_COLORS[node.type] || DEFAULT_COLOR;
                        var html = '<div class="tt-label" style="color:' + colors.bg + ';">' + escapeHtml(node.label || node.id) + '</div>';
                        html += '<div class="tt-type">' + (node.type || 'unknown') + '</div>';
                        if (node.time) html += '<div class="tt-row"><b>Time:</b> ' + node.time.substring(0, 19).replace('T', ' ') + '</div>';
                        if (node.hash) html += '<div class="tt-row"><b>Hash:</b> ' + node.hash.substring(0, 24) + '...</div>';
                        tooltip.innerHTML = html;
                        tooltip.style.display = 'block';
                        tooltip.style.left = sx + 'px';
                        tooltip.style.top = sy + 'px';
                    }}
                }} else {{
                    tooltip.style.display = 'none';
                }}
            }});

            container.addEventListener('mousedown', function(e) {{
                isDragging = true;
                dragStartX = e.clientX;
                dragStartY = e.clientY;
                dragStartPanX = panX;
                dragStartPanY = panY;
                container.classList.add('dragging');
                e.preventDefault();
            }});

            window.addEventListener('mouseup', function() {{
                if (isDragging) {{
                    isDragging = false;
                    containerEl && containerEl.classList.remove('dragging');
                }}
            }});

            container.addEventListener('click', function(e) {{
                // Only trigger click if not dragging significantly
                var movedX = Math.abs(e.clientX - dragStartX);
                var movedY = Math.abs(e.clientY - dragStartY);
                if (movedX > 5 || movedY > 5) return;

                var rect = container.getBoundingClientRect();
                var sx = e.clientX - rect.left;
                var sy = e.clientY - rect.top;
                var gp = screenToGraph(sx, sy);
                var found = findNodeAt(gp.x, gp.y);

                if (found) {{
                    selectedNodeId = found === selectedNodeId ? null : found;
                    var nodeData = allNodeData[found];
                    if (nodeData && (nodeData.type === 'record' || nodeData.group === 'record')) {{
                        loadDetail(found);
                        highlightTimelineItem(found);
                    }}
                }} else {{
                    selectedNodeId = null;
                }}
            }});

            container.addEventListener('wheel', function(e) {{
                e.preventDefault();
                var delta = e.deltaY > 0 ? 0.9 : 1.1;
                var newScale = Math.max(0.3, Math.min(5, scale * delta));

                // Zoom toward mouse position
                var rect = container.getBoundingClientRect();
                var mx = e.clientX - rect.left;
                var my = e.clientY - rect.top;

                panX = mx - (mx - panX) * (newScale / scale);
                panY = my - (my - panY) * (newScale / scale);
                panX += (graphWidth / 2 - mx) * (newScale / scale - 1) * 0;

                scale = newScale;
            }}, {{ passive: false }});

            container.addEventListener('mouseleave', function() {{
                hoveredNodeId = null;
                tooltip.style.display = 'none';
            }});

            // Keyboard enter for search
            document.getElementById('searchInput').addEventListener('keydown', function(e) {{
                if (e.key === 'Enter') searchActions();
            }});

            // Auto-load graph and timeline on page open
            loadFullGraph();
            loadTimeline();
        }});

        // Zoom controls
        function zoomIn() {{ scale = Math.min(5, scale * 1.3); }}
        function zoomOut() {{ scale = Math.max(0.3, scale * 0.7); }}
        function zoomFit() {{ scale = 1; panX = 0; panY = 0; }}

        // Focus on a specific node (called from timeline click)
        function focusGraphNode(nodeId) {{
            var pos = positions.get(nodeId);
            if (!pos) return;

            selectedNodeId = nodeId;

            // Smooth zoom to node
            var targetScale = 1.8;
            var targetPanX = -(pos.x - graphWidth / 2) * targetScale;
            var targetPanY = -(pos.y - graphHeight / 2) * targetScale;

            // Animate to target
            var startScale = scale;
            var startPanX = panX;
            var startPanY = panY;
            var startTime = performance.now();
            var duration = 500;

            function animateZoom(now) {{
                var t = Math.min(1, (now - startTime) / duration);
                // ease in-out
                t = t < 0.5 ? 2 * t * t : -1 + (4 - 2 * t) * t;
                scale = startScale + (targetScale - startScale) * t;
                panX = startPanX + (targetPanX - startPanX) * t;
                panY = startPanY + (targetPanY - startPanY) * t;
                if (t < 1) requestAnimationFrame(animateZoom);
            }}
            requestAnimationFrame(animateZoom);
        }}

        // ============================================
        // Timeline
        // ============================================

        async function loadTimeline() {{
            var res = await fetch('/api/trace/timeline');
            var data = await res.json();
            var records = data.timeline || [];
            renderTimeline(records);
            // If graph was not loaded from API, build from timeline
            if (!graphLoadedFromApi && graphData.nodes.length === 0 && records.length > 0) {{
                buildGraphFromTimeline(records);
            }}
        }}

        async function searchActions() {{
            var name = document.getElementById('searchInput').value;
            var type = document.getElementById('typeFilter').value;
            var url = '/api/trace/action?';
            if (name) url += 'name=' + encodeURIComponent(name) + '&';
            if (type) url += 'type=' + type + '&';
            var res = await fetch(url);
            var data = await res.json();
            var records = data.records || [];
            renderTimeline(records);
            // Always rebuild graph from search results
            buildGraphFromTimeline(records);
        }}

        function searchType(type) {{
            document.getElementById('typeFilter').value = type;
            document.getElementById('searchInput').value = '';
            searchActions();
        }}

        function getBadgeClass(type) {{
            return {{
                'tool_call': 'badge-tool', 'decision': 'badge-decision',
                'user_input': 'badge-input', 'file_read': 'badge-file',
                'file_write': 'badge-file', 'llm_request': 'badge-llm',
            }}[type] || 'badge-tool';
        }}

        function renderTimeline(records) {{
            var div = document.getElementById('timeline');
            document.getElementById('timelineCount').textContent = '(' + records.length + ' records)';

            if (!records.length) {{
                div.innerHTML = '<div class="empty-state">No records found</div>';
                return;
            }}

            div.innerHTML = records.map(function(r) {{
                var timeStr = (r.time || '').substring(0, 19).replace('T', ' ');
                var hashStr = (r.hash || '').substring(0, 24);
                return '<div class="tl-item" id="tl-' + r.id + '" onclick="onTimelineClick(\\'' + r.id + '\\', this)">' +
                    '<div class="tl-action">' + escapeHtml(r.action || '-') + '</div>' +
                    '<span class="tl-badge ' + getBadgeClass(r.type) + '">' + (r.type || r.tool || '-') + '</span>' +
                    '<div class="tl-time">' + timeStr + '</div>' +
                    '<div class="tl-hash">' + hashStr + '</div>' +
                '</div>';
            }}).join('');
        }}

        function onTimelineClick(recordId, el) {{
            document.querySelectorAll('.tl-item').forEach(function(e) {{ e.classList.remove('active'); }});
            el.classList.add('active');
            loadDetail(recordId);
            focusGraphNode(recordId);
        }}

        function highlightTimelineItem(recordId) {{
            document.querySelectorAll('.tl-item').forEach(function(e) {{ e.classList.remove('active'); }});
            var el = document.getElementById('tl-' + recordId);
            if (el) {{
                el.classList.add('active');
                el.scrollIntoView({{ behavior: 'smooth', block: 'center' }});
            }}
        }}

        // ============================================
        // Detail Panel
        // ============================================

        async function loadDetail(recordId) {{
            var res = await fetch('/api/trace/record/' + recordId);
            var data = await res.json();

            if (data.error) {{
                document.getElementById('detail').innerHTML = '<div class="empty-state">' + data.error + '</div>';
                return;
            }}

            var r = data.record || {{}};
            var html = '<div class="detail-section"><h4>Record Info</h4>';
            html += detailRow('ID', r.id, true);
            html += detailRow('Action', r.activity_name);
            html += '<div class="detail-row"><span class="detail-label">Type</span><span class="detail-value"><span class="tl-badge ' + getBadgeClass(r.activity_type) + '">' + r.activity_type + '</span></span></div>';
            html += detailRow('Time', (r.timestamp || '').replace('T', ' '));
            html += detailRow('Hash', r.hash, true);
            html += detailRow('Prev Hash', r.previous_hash || 'genesis (first record)', true);
            html += detailRow('Sequence', '#' + r.sequence);
            html += '</div>';

            if (data.agent) {{
                html += '<div class="detail-section"><h4>Agent</h4>';
                html += detailRow('Name', data.agent.name);
                html += detailRow('ID', data.agent.id, true);
                html += '</div>';
            }}
            if (data.tool) {{
                html += '<div class="detail-section"><h4>Tool Called</h4>';
                html += '<div class="detail-row"><span class="detail-label">Tool</span><span class="detail-value" style="color:#34d399;font-weight:600;">' + escapeHtml(data.tool) + '</span></div>';
                html += '</div>';
            }}
            if (data.decision) {{
                html += '<div class="detail-section"><h4>Decision</h4>';
                html += '<div class="detail-row"><span class="detail-label">Decision</span><span class="detail-value" style="color:#fca5a5;font-weight:600;">' + escapeHtml(data.decision) + '</span></div>';
                html += '</div>';
            }}
            if (data.session) {{
                html += '<div class="detail-section"><h4>Session</h4>';
                html += detailRow('Session', data.session.id, true);
                html += detailRow('Client', data.session.client_id || '-', true);
                html += '</div>';
            }}

            // Hash Chain Navigation
            html += '<div class="detail-section"><h4>Hash Chain Navigation</h4>';
            html += '<div style="display:flex;align-items:center;gap:8px;flex-wrap:wrap;">';
            if (data.previous_record) {{
                html += '<span class="chain-nav" onclick="navigateChain(\\'' + data.previous_record.id + '\\')">&larr; ' + escapeHtml(data.previous_record.action) + '</span>';
            }}
            html += '<span class="chain-current">CURRENT #' + r.sequence + '</span>';
            if (data.next_record) {{
                html += '<span class="chain-nav" onclick="navigateChain(\\'' + data.next_record.id + '\\')">' + escapeHtml(data.next_record.action) + ' &rarr;</span>';
            }}
            html += '</div></div>';

            // Stored Content
            if (data.contents && data.contents.length > 0) {{
                html += '<div class="detail-section"><h4>Stored Content</h4>';
                for (var ci = 0; ci < data.contents.length; ci++) {{
                    var c = data.contents[ci];
                    html += '<div class="detail-row"><span class="detail-label">' + c.type + '</span><span class="detail-value">' + c.size + ' bytes ';
                    html += '<button class="btn btn-gray" style="padding:2px 8px;font-size:10px;margin-left:6px;" onclick="loadContent(\\'' + r.id + '\\')">View</button>';
                    html += '</span></div>';
                }}
                html += '</div>';
            }}

            // Entities
            if (data.used_entities && data.used_entities.length > 0) {{
                html += '<div class="detail-section"><h4>Used Entities</h4>';
                data.used_entities.forEach(function(e) {{
                    html += detailRow(e.type, e.id, true);
                }});
                html += '</div>';
            }}
            if (data.generated_entities && data.generated_entities.length > 0) {{
                html += '<div class="detail-section"><h4>Generated Entities</h4>';
                data.generated_entities.forEach(function(e) {{
                    html += detailRow(e.type, e.id, true);
                }});
                html += '</div>';
            }}

            document.getElementById('detail').innerHTML = html;
        }}

        function navigateChain(recordId) {{
            loadDetail(recordId);
            highlightTimelineItem(recordId);
            focusGraphNode(recordId);
        }}

        function detailRow(label, value, mono) {{
            return '<div class="detail-row"><span class="detail-label">' + label + '</span><span class="detail-value' + (mono ? ' mono' : '') + '">' + escapeHtml(String(value || '-')) + '</span></div>';
        }}

        async function loadContent(recordId) {{
            var res = await fetch('/api/trace/content/' + recordId);
            var data = await res.json();
            var html = '';
            for (var type in data) {{
                var info = data[type];
                html += '<div class="detail-section"><h4>Content: ' + type + '</h4><div class="content-box">' + escapeHtml(info.content || '') + '</div></div>';
            }}
            if (!html) html = '<div class="empty-state">No content stored</div>';

            var panel = document.getElementById('detail');
            var contentDiv = document.createElement('div');
            contentDiv.innerHTML = html;
            panel.appendChild(contentDiv);
        }}

        // ============================================
        // Helpers
        // ============================================

        function toggleHelp() {{
            var panel = document.getElementById('helpPanel');
            panel.style.display = panel.style.display === 'none' ? 'block' : 'none';
        }}

        function escapeHtml(text) {{
            return String(text).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
        }}
    </script>
</body>
</html>
"""



# ============================================
# Auth Helpers
# ============================================

class SimpleClient:
    """Simple client object for payments-based users."""
    def __init__(self, client_id: str, api_key: str = "", email: str = "", plan: str = "starter"):
        self.client_id = client_id
        self.api_key = api_key
        self.email = email
        self.plan = plan


def get_current_client(request: Request) -> Optional[Client]:
    """Get client from session."""
    client_id = request.session.get("client_id")
    if not client_id:
        return None

    # First try client_manager
    client = manager.get_client(client_id)
    if client:
        return client

    # Fallback for payments-based users (session has client_id but manager doesn't know about it)
    api_key = request.session.get("api_key", "")
    email = request.session.get("email", "")
    plan = request.session.get("plan", "starter")
    return SimpleClient(client_id, api_key, email, plan)


# ============================================
# Routes
# ============================================

@app.get("/health")
async def health():
    """Health check endpoint."""
    return {"status": "healthy", "service": "inalign"}


@app.get("/", response_class=HTMLResponse)
async def home(request: Request):
    """Serve landing page or redirect to dashboard."""
    client = get_current_client(request)
    if client:
        return RedirectResponse("/dashboard")

    # Try to serve landing page
    landing_path = os.path.join(os.path.dirname(__file__), "..", "..", "landing", "index.html")
    if not os.path.exists(landing_path):
        landing_path = "/app/landing/index.html"

    if os.path.exists(landing_path):
        with open(landing_path, "r") as f:
            return HTMLResponse(f.read())

    return RedirectResponse("/login")


@app.get("/login", response_class=HTMLResponse)
async def login_page(error: str = ""):
    error_html = f'<div class="error">{error}</div>' if error else ""
    return LOGIN_HTML.format(error=error_html)


@app.post("/login")
async def login(request: Request, api_key: str = Form(...)):
    # Debug logging
    print(f"[LOGIN] Received API key: '{api_key}' (length: {len(api_key)})")

    # First try client_manager
    valid, client, error = manager.validate_api_key(api_key)

    if not valid or not client:
        # Try payments CUSTOMERS
        from .payments import CUSTOMERS, get_client_id
        print(f"[LOGIN] Checking against {len(CUSTOMERS)} customers")
        for email, data in CUSTOMERS.items():
            stored_key = data.get("api_key")
            print(f"[LOGIN] Comparing with {email}: '{stored_key}' == '{api_key}' ? {stored_key == api_key}")
            if stored_key == api_key:
                # Create a temporary client object
                client_id = data.get("client_id") or get_client_id(api_key)
                request.session["client_id"] = client_id
                request.session["api_key"] = api_key
                request.session["email"] = email
                request.session["plan"] = data.get("plan", "starter")
                return RedirectResponse("/dashboard", status_code=303)

        return RedirectResponse(f"/login?error={error or 'Invalid API key'}", status_code=303)

    request.session["client_id"] = client.client_id
    request.session["api_key"] = api_key
    return RedirectResponse("/dashboard", status_code=303)


@app.get("/logout")
async def logout(request: Request):
    request.session.clear()
    return RedirectResponse("/login")


@app.get("/api/download/install-script")
async def download_install_script(api_key: str):
    """Generate and download personalized install script (API proxy mode — no DB creds)."""
    from fastapi.responses import Response

    script = f'''#!/usr/bin/env python3
"""
InALign MCP Server - One-Click Installer
API Key: {api_key}
"""

import os
import sys
import json
import subprocess
import platform
from pathlib import Path

API_KEY = "{api_key}"
API_URL = "http://3.36.132.4:8080"

def get_python_path():
    return sys.executable

def main():
    print("\\n" + "="*50)
    print("  InALign MCP Server Installer")
    print("="*50 + "\\n")

    python = get_python_path()

    # 1. Install inalign-mcp from PyPI
    print("[1/4] Installing inalign-mcp from PyPI...")
    ret = subprocess.run([python, "-m", "pip", "install", "inalign-mcp", "--upgrade", "-q"],
        capture_output=True, text=True)
    if ret.returncode != 0:
        print(f"      Warning: pip install returned {{ret.returncode}}")
    else:
        print("      Done!")

    # 2. Create ~/.inalign.env (API proxy — no database credentials)
    env_path = Path.home() / ".inalign.env"
    print(f"[2/4] Creating {{env_path}}...")
    with open(env_path, "w") as f:
        f.write(f"API_KEY={{API_KEY}}\\n")
        f.write(f"API_URL={{API_URL}}\\n")
    print("      Done!")

    # 3. Update Claude settings.json
    settings_path = Path.home() / ".claude" / "settings.json"
    settings_path.parent.mkdir(parents=True, exist_ok=True)
    print(f"[3/4] Updating {{settings_path}}...")

    settings = {{}}
    if settings_path.exists():
        with open(settings_path) as f:
            settings = json.load(f)

    if "mcpServers" not in settings:
        settings["mcpServers"] = {{}}

    settings["mcpServers"]["inalign"] = {{
        "command": python,
        "args": ["-m", "inalign_mcp.server"],
        "env": {{
            "API_KEY": API_KEY,
        }}
    }}

    with open(settings_path, "w") as f:
        json.dump(settings, f, indent=2)
    print("      Done!")

    # 4. Create CLAUDE.md
    claude_md = Path.home() / "CLAUDE.md"
    print(f"[4/4] Creating {{claude_md}}...")
    if not claude_md.exists():
        with open(claude_md, "w") as f:
            f.write("""# Claude Code Instructions

## InALign Integration
IMPORTANT: At the start of EVERY conversation, call `mcp__inalign__record_user_command` to record the user's request.
""")
        print("      Done!")
    else:
        print("      Already exists, skipping.")

    print("\\n" + "="*50)
    print("  Installation Complete!")
    print("="*50)
    print(f"""
Your API Key: {{API_KEY}}
Client ID: {{API_KEY[:12]}}

Next Steps:
1. Restart Claude Code (close/reopen terminal or VSCode)
2. Start using Claude Code normally
3. View activity at: http://3.36.132.4:8080/login

All activity will be automatically recorded and governed by InALign!
""")

if __name__ == "__main__":
    main()
'''

    return Response(
        content=script,
        media_type="application/x-python",
        headers={"Content-Disposition": "attachment; filename=inalign_install.py"}
    )


@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard(request: Request):
    client = get_current_client(request)
    client_id = request.session.get("client_id")

    # Handle payments-based login (SimpleClient or no client object)
    # SimpleClient doesn't have monthly_scan_limit attribute
    is_simple_client = isinstance(client, SimpleClient) if client else False
    if (not client and client_id) or is_simple_client:
        email = request.session.get("email") or (client.email if is_simple_client else "User")
        plan = request.session.get("plan") or (client.plan if is_simple_client else "starter")
        client_id = client_id or (client.client_id if is_simple_client else None)

        # Initialize trace DB and get stats from Neo4j
        init_trace_db()

        # Get stats from Neo4j
        try:
            from .trace_finder import trace_by_client_id, get_client_stats
            neo4j_stats = get_client_stats(client_id)
            trace_result = trace_by_client_id(client_id, limit=20)
        except Exception as e:
            neo4j_stats = {"total_actions": 0, "sessions": 0, "agents": 0, "user_commands": 0}
            trace_result = None

        # Also get usage from limiter for comparison
        try:
            from .usage_limiter import get_usage_stats
            usage = get_usage_stats(client_id)
            limiter_count = usage.get("actions_used", 0)
        except:
            limiter_count = 0

        # Use max of Neo4j or limiter count
        total_actions = max(neo4j_stats.get("total_actions", 0), limiter_count)

        # Build activity list from Neo4j trace
        activity_html = ""
        if trace_result and trace_result.records:
            for record in trace_result.records[:10]:
                icon_class = "icon-tool"
                if record.get("type") == "decision":
                    icon_class = "icon-decision"
                elif record.get("type") == "error":
                    icon_class = "icon-error"

                action_name = record.get("action", "unknown")
                time_str = record.get("time", "")[:19] if record.get("time") else ""
                activity_html += f"""
                <li class="activity-item">
                    <div class="activity-icon {icon_class}">A</div>
                    <div class="activity-info">
                        <div class="activity-name">{action_name}</div>
                        <div class="activity-time">{time_str}</div>
                        <div class="activity-hash">{record.get("hash", "")}</div>
                    </div>
                </li>
                """

        if not activity_html:
            activity_html = "<li class='activity-item'>No activity recorded yet. Use Claude Code with your API key to see activity.</li>"

        return DASHBOARD_HTML.format(
            company=email,
            total_actions=total_actions,
            user_commands=neo4j_stats.get("user_commands", 0),
            sessions=neo4j_stats.get("sessions", 0),
            agents=neo4j_stats.get("agents", 0),
            activity_list=activity_html,
            plan=plan.upper(),
            scans_used=total_actions,
            scan_limit=1000 if plan == "starter" else 50000,
            usage_percent=min(100, int(total_actions / 10))
        )

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


def get_recent_neo4j_sessions(limit: int = 10, client_id: str = None) -> list:
    """Get recent sessions from Neo4j ProvenanceRecords, optionally filtered by client_id."""
    try:
        from .graph_store import get_graph_store
        store = get_graph_store()
        if not store:
            return []

        with store.session() as session:
            if client_id:
                # Get unique sessions from ProvenanceRecords filtered by client_id
                result = session.run("""
                    MATCH (r:ProvenanceRecord)
                    WHERE r.client_id = $client_id
                    WITH r ORDER BY r.timestamp DESC
                    WITH collect(r)[0] as latest, collect(r) as all_records
                    UNWIND all_records as rec
                    WITH latest.client_id as client_id,
                         count(rec) as activity_count,
                         max(rec.timestamp) as last_activity,
                         min(rec.timestamp) as created_at
                    RETURN 'session-' + client_id as session_id,
                           'Claude Code' as agent_name,
                           created_at, client_id, activity_count
                    LIMIT $limit
                """, limit=limit, client_id=client_id)
            else:
                # Get all recent records grouped by client_id
                result = session.run("""
                    MATCH (r:ProvenanceRecord)
                    WHERE r.client_id IS NOT NULL
                    WITH r.client_id as client_id, count(r) as activity_count,
                         max(r.timestamp) as last_activity,
                         min(r.timestamp) as created_at
                    RETURN 'session-' + client_id as session_id,
                           'Claude Code' as agent_name,
                           created_at, client_id, activity_count
                    ORDER BY last_activity DESC
                    LIMIT $limit
                """, limit=limit)
            return [dict(row) for row in result]
    except Exception as e:
        print(f"Error getting Neo4j sessions: {e}")
        return []


def search_records(client_id: str, keyword: str = None, action_type: str = None,
                   start_time: str = None, end_time: str = None, limit: int = 100) -> dict:
    """Search provenance records with filters."""
    try:
        from .graph_store import get_graph_store
        from datetime import datetime, timezone
        store = get_graph_store()
        if not store:
            return {"error": "Neo4j not available"}

        with store.session() as session:
            # Build dynamic query
            conditions = ["r.client_id = $client_id"]
            params = {"client_id": client_id, "limit": limit}

            if keyword:
                conditions.append("(r.activity_name CONTAINS $keyword OR r.activity_attributes CONTAINS $keyword)")
                params["keyword"] = keyword

            if action_type:
                conditions.append("r.activity_type = $action_type")
                params["action_type"] = action_type

            if start_time:
                conditions.append("r.timestamp >= $start_time")
                params["start_time"] = start_time

            if end_time:
                conditions.append("r.timestamp <= $end_time")
                params["end_time"] = end_time

            where_clause = " AND ".join(conditions)
            query = f"""
                MATCH (r:ProvenanceRecord)
                WHERE {where_clause}
                OPTIONAL MATCH (r)-[:BELONGS_TO]->(s:Session)
                OPTIONAL MATCH (r)-[:PERFORMED_BY]->(a:Agent)
                RETURN r.record_id as id, r.timestamp as timestamp,
                       r.activity_type as type, r.activity_name as action,
                       r.record_hash as hash, r.activity_attributes as attributes,
                       s.session_id as session, a.name as agent
                ORDER BY r.timestamp DESC
                LIMIT $limit
            """

            result = session.run(query, **params)
            records = [dict(row) for row in result]

            return {
                "search_info": {
                    "client_id": client_id,
                    "keyword": keyword,
                    "action_type": action_type,
                    "time_range": f"{start_time or 'any'} ~ {end_time or 'any'}",
                    "result_count": len(records),
                },
                "records": records
            }
    except Exception as e:
        return {"error": str(e)}


def export_records_by_client_id(client_id: str) -> dict:
    """Export all provenance records for a client_id from Neo4j."""
    try:
        from .graph_store import get_graph_store
        from datetime import datetime, timezone
        store = get_graph_store()
        if not store:
            return {"error": "Neo4j not available"}

        with store.session() as session:
            result = session.run("""
                MATCH (r:ProvenanceRecord)
                WHERE r.client_id = $client_id
                RETURN r.record_id as id, r.timestamp as timestamp,
                       r.activity_type as activity_type, r.activity_name as activity_name,
                       r.record_hash as record_hash, r.previous_hash as previous_hash,
                       r.sequence_number as sequence_number, r.activity_attributes as attributes
                ORDER BY r.timestamp ASC
            """, client_id=client_id)

            records = [dict(row) for row in result]

            return {
                "export_info": {
                    "client_id": client_id,
                    "exported_at": datetime.now(timezone.utc).isoformat(),
                    "record_count": len(records),
                },
                "records": records
            }
    except Exception as e:
        return {"error": str(e)}


@app.get("/api/search")
async def api_search(
    request: Request,
    keyword: str = None,
    action: str = None,
    start: str = None,
    end: str = None,
    limit: int = 100
):
    """Search provenance records with filters.

    Query params:
    - keyword: Search in action name or attributes
    - action: Filter by action type (user_input, tool_call, decision, etc.)
    - start: Start time (ISO format)
    - end: End time (ISO format)
    - limit: Max results (default 100)
    """
    client = get_current_client(request)
    if not client:
        return JSONResponse({"error": "Not authenticated"}, status_code=401)

    result = search_records(
        client_id=client.client_id,
        keyword=keyword,
        action_type=action,
        start_time=start,
        end_time=end,
        limit=limit
    )
    return JSONResponse(result)


@app.get("/export/json")
async def export_json(request: Request, session_id: str = None):
    client = get_current_client(request)
    if not client:
        return RedirectResponse("/login")

    # If session_id provided, use it directly
    if session_id:
        try:
            content = export_session_json(session_id)
            return JSONResponse(json.loads(content))
        except Exception as e:
            return JSONResponse({"error": str(e)})

    # Export by client_id directly from Neo4j
    export_data = export_records_by_client_id(client.client_id)
    if export_data.get("records"):
        return JSONResponse(export_data)

    # Try manager sessions as fallback
    sessions = manager.get_client_sessions(client.client_id)
    if sessions:
        content = export_session_json(sessions[0].session_id)
        return JSONResponse(json.loads(content))

    return JSONResponse({"error": "No records found for your account", "client_id": client.client_id})


@app.get("/export/certificate", response_class=HTMLResponse)
async def export_certificate(request: Request, session_id: str = None):
    client = get_current_client(request)
    if not client:
        return RedirectResponse("/login")

    # If session_id provided, use it directly
    if session_id:
        try:
            cert = generate_certificate(session_id, client_id=client.client_id)
            return cert.to_html()
        except Exception as e:
            return f"<h1>Error: {e}</h1>"

    # Try manager sessions first
    sessions = manager.get_client_sessions(client.client_id)
    if sessions:
        cert = generate_certificate(sessions[0].session_id, client_id=client.client_id)
        return cert.to_html()

    # Try Neo4j sessions filtered by client_id
    neo4j_sessions = get_recent_neo4j_sessions(5, client.client_id)
    if neo4j_sessions:
        # If only one session, show certificate directly
        if len(neo4j_sessions) == 1:
            cert = generate_certificate(neo4j_sessions[0]["session_id"], client_id=client.client_id)
            return cert.to_html()
        # Show list to select
        session_list = "".join([
            f'<li><a href="/export/certificate?session_id={s["session_id"]}">{s["session_id"]}</a> - {s.get("agent_name", "unknown")} ({s.get("activity_count", 0)} activities)</li>'
            for s in neo4j_sessions
        ])
        return f"""
        <html>
        <head><title>Select Session</title></head>
        <body style="font-family: sans-serif; padding: 20px;">
            <h1>Select a Session</h1>
            <p>Found {len(neo4j_sessions)} sessions for your account:</p>
            <ul>{session_list}</ul>
        </body>
        </html>
        """

    # Fallback to all recent sessions
    all_sessions = get_recent_neo4j_sessions(5)
    if all_sessions:
        session_list = "".join([
            f'<li><a href="/export/certificate?session_id={s["session_id"]}">{s["session_id"]}</a> - {s.get("agent_name", "unknown")} ({s.get("activity_count", 0)} activities)</li>'
            for s in all_sessions
        ])
        return f"""
        <html>
        <head><title>Select Session</title></head>
        <body style="font-family: sans-serif; padding: 20px;">
            <h1>Select a Session</h1>
            <p>No sessions found for your account. Recent sessions:</p>
            <ul>{session_list}</ul>
        </body>
        </html>
        """

    return "<h1>No sessions found</h1>"


# ============================================
# Trace & Backtrack API (역추적)
# ============================================

@app.get("/api/trace/record/{record_id}")
async def api_trace_record(record_id: str, request: Request):
    """특정 레코드 역추적 - 연결된 모든 노드 반환."""
    client = get_current_client(request)
    if not client:
        return JSONResponse({"error": "Not authenticated"}, status_code=401)
    ensure_provenance_neo4j()
    return JSONResponse(trace_record(record_id))


@app.get("/api/trace/chain/{record_id}")
async def api_trace_chain(record_id: str, request: Request, direction: str = "both", depth: int = 20):
    """해시체인 경로 추적 - 이전/이후 레코드 경로."""
    client = get_current_client(request)
    if not client:
        return JSONResponse({"error": "Not authenticated"}, status_code=401)
    ensure_provenance_neo4j()
    return JSONResponse(trace_chain_path(record_id, direction, depth))


@app.get("/api/trace/action")
async def api_trace_action(request: Request, name: str = None, type: str = None, limit: int = 50):
    """액션/도구/결정별 추적."""
    client = get_current_client(request)
    if not client:
        return JSONResponse({"error": "Not authenticated"}, status_code=401)
    ensure_provenance_neo4j()
    return JSONResponse(trace_by_action(client.client_id, name, type, limit))


@app.get("/api/trace/graph")
async def api_trace_graph(request: Request, limit: int = 100):
    """전체 프로비넌스 그래프 (시각화용)."""
    client = get_current_client(request)
    if not client:
        return JSONResponse({"error": "Not authenticated"}, status_code=401)
    ensure_provenance_neo4j()
    return JSONResponse(trace_full_graph(client.client_id, limit))


@app.get("/api/trace/timeline")
async def api_trace_timeline(request: Request, limit: int = 200):
    """시간순 타임라인."""
    client = get_current_client(request)
    if not client:
        return JSONResponse({"error": "Not authenticated"}, status_code=401)
    ensure_provenance_neo4j()
    return JSONResponse(trace_timeline(client.client_id, limit))


@app.get("/api/trace/content/{record_id}")
async def api_trace_content(record_id: str, request: Request):
    """레코드에 저장된 전체 내용 조회 (프롬프트/응답)."""
    client = get_current_client(request)
    if not client:
        return JSONResponse({"error": "Not authenticated"}, status_code=401)
    ensure_provenance_neo4j()
    return JSONResponse(get_record_content(record_id))


@app.get("/trace", response_class=HTMLResponse)
async def trace_page(request: Request):
    """역추적 전용 페이지."""
    client = get_current_client(request)
    if not client:
        return RedirectResponse("/login")
    return TRACE_HTML.format(company=getattr(client, 'email', getattr(client, 'name', 'User')))


# ============================================
# Blockchain Anchoring API
# ============================================

@app.post("/api/anchor")
async def api_anchor_session(request: Request):
    """Anchor client's provenance chain to Polygon blockchain."""
    client = get_current_client(request)
    if not client:
        return JSONResponse({"error": "Not authenticated"}, status_code=401)

    result = anchor_to_polygon(client.client_id)

    if result.success:
        return JSONResponse({
            "success": True,
            "message": "Successfully anchored to Polygon",
            "transaction_hash": result.transaction_hash,
            "block_number": result.block_number,
            "merkle_root": result.merkle_root,
            "explorer_url": result.explorer_url,
            "cost": {
                "matic": result.cost_matic,
                "usd": result.cost_usd,
            },
            "mock": result.mock,
        })
    else:
        return JSONResponse({
            "success": False,
            "error": result.error,
        }, status_code=400)


@app.get("/api/anchor/status")
async def api_anchor_status(request: Request):
    """Get latest anchor status for client."""
    client = get_current_client(request)
    if not client:
        return JSONResponse({"error": "Not authenticated"}, status_code=401)

    status = get_anchor_status(client.client_id)

    if status:
        return JSONResponse({
            "anchored": True,
            "merkle_root": status.get("merkle_root"),
            "transaction_hash": status.get("tx_hash"),
            "block_number": status.get("block_number"),
            "timestamp": str(status.get("timestamp")) if status.get("timestamp") else None,
            "explorer_url": status.get("explorer_url"),
            "record_count": status.get("record_count"),
            "mock": status.get("mock", False),
        })
    else:
        return JSONResponse({
            "anchored": False,
            "message": "No blockchain anchor found. Click 'Anchor to Blockchain' to create one.",
        })


@app.get("/api/anchor/verify/{tx_hash}")
async def api_verify_anchor(tx_hash: str):
    """Verify an anchor transaction on Polygon."""
    result = verify_anchor(tx_hash)
    return JSONResponse(result)


@app.get("/api/anchor/setup")
async def api_anchor_setup():
    """Get wallet setup instructions."""
    return JSONResponse({
        "instructions": setup_instructions(),
        "wallet_configured": bool(os.getenv("POLYGON_PRIVATE_KEY")),
    })


# ============================================
# API v1 — MCP Server Proxy Endpoints
# Client MCP servers call these instead of Neo4j directly.
# Auth: X-API-Key header validated against CUSTOMERS.
# ============================================

from fastapi import Header
from pydantic import BaseModel
from typing import List, Dict

class _StoreRecordBody(BaseModel):
    record_id: str
    timestamp: str
    activity_type: str
    activity_name: str
    record_hash: str
    previous_hash: str = ""
    sequence_number: int = 0
    session_id: str = ""
    client_id: str = ""
    agent_id: str = ""
    agent_name: str = ""
    agent_type: str = ""
    activity_attributes: str = "{}"

class _RiskAnalyzeBody(BaseModel):
    session_id: str = ""

class _AgentRiskBody(BaseModel):
    agent_id: str

class _UserRiskBody(BaseModel):
    user_id: str

class _AgentsListBody(BaseModel):
    limit: int = 20


def _validate_api_key(api_key: str) -> str:
    """Validate API key and return client_id. Raises HTTPException if invalid."""
    from .payments import CUSTOMERS, get_client_id
    if not api_key or not api_key.startswith("ial_"):
        raise HTTPException(status_code=401, detail="Unauthorized")
    # Check against registered customers only
    for _email, data in CUSTOMERS.items():
        if data.get("api_key") == api_key:
            return data.get("client_id") or get_client_id(api_key)
    raise HTTPException(status_code=401, detail="Unauthorized")


@app.post("/api/v1/provenance/store")
async def api_v1_store_record(body: _StoreRecordBody, x_api_key: str = Header(...)):
    """Store a provenance record from a remote MCP server."""
    client_id = _validate_api_key(x_api_key)
    ensure_provenance_neo4j()

    from .provenance_graph import _neo4j_driver
    if not _neo4j_driver:
        raise HTTPException(status_code=503, detail="Neo4j not available")

    try:
        import json as _json
        with _neo4j_driver.session() as session:
            # Store the record node
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
                "record_id": body.record_id,
                "timestamp": body.timestamp,
                "activity_type": body.activity_type,
                "activity_name": body.activity_name,
                "record_hash": body.record_hash,
                "previous_hash": body.previous_hash,
                "sequence_number": body.sequence_number,
                "session_id": body.session_id,
                "client_id": client_id,
                "activity_attributes": body.activity_attributes,
            })

            # Session relationship
            if body.session_id:
                session.run("""
                    MERGE (s:Session {session_id: $session_id})
                    SET s.client_id = $client_id
                    WITH s
                    MATCH (r:ProvenanceRecord {record_id: $record_id})
                    SET r.client_id = $client_id
                    MERGE (r)-[:BELONGS_TO]->(s)
                """, {
                    "session_id": body.session_id,
                    "record_id": body.record_id,
                    "client_id": client_id,
                })

            # Agent relationship
            if body.agent_id:
                session.run("""
                    MERGE (a:Agent {agent_id: $agent_id})
                    SET a.name = $agent_name, a.type = $agent_type
                    WITH a
                    MATCH (r:ProvenanceRecord {record_id: $record_id})
                    MERGE (r)-[:PERFORMED_BY]->(a)
                """, {
                    "agent_id": body.agent_id,
                    "agent_name": body.agent_name,
                    "agent_type": body.agent_type,
                    "record_id": body.record_id,
                })

            # FOLLOWS chain
            if body.previous_hash:
                session.run("""
                    MATCH (prev:ProvenanceRecord {record_hash: $previous_hash})
                    MATCH (curr:ProvenanceRecord {record_id: $record_id})
                    MERGE (curr)-[:FOLLOWS]->(prev)
                """, {
                    "previous_hash": body.previous_hash,
                    "record_id": body.record_id,
                })

            # Tool/Decision node
            if body.activity_type == "tool_call":
                session.run("""
                    MERGE (t:Tool {name: $tool_name})
                    WITH t
                    MATCH (r:ProvenanceRecord {record_id: $record_id})
                    MERGE (r)-[:CALLED]->(t)
                """, {"tool_name": body.activity_name, "record_id": body.record_id})
            elif body.activity_type == "decision":
                session.run("""
                    MERGE (d:Decision {name: $decision_name})
                    WITH d
                    MATCH (r:ProvenanceRecord {record_id: $record_id})
                    MERGE (r)-[:MADE]->(d)
                """, {"decision_name": body.activity_name, "record_id": body.record_id})

        return {"status": "ok", "record_id": body.record_id}

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/v1/risk/analyze")
async def api_v1_risk_analyze(body: _RiskAnalyzeBody, x_api_key: str = Header(...)):
    """Run GraphRAG risk analysis for a session."""
    client_id = _validate_api_key(x_api_key)
    ensure_provenance_neo4j()

    from .provenance_graph import _neo4j_driver
    if not _neo4j_driver:
        raise HTTPException(status_code=503, detail="Neo4j not available")

    session_id = body.session_id

    # Auto-discover latest session for this client if not specified
    if not session_id:
        with _neo4j_driver.session() as neo_session:
            result = neo_session.run(
                "MATCH (r:ProvenanceRecord)-[:BELONGS_TO]->(s:Session) "
                "WHERE r.client_id = $client_id "
                "RETURN s.session_id as sid, count(r) as cnt "
                "ORDER BY cnt DESC LIMIT 1",
                client_id=client_id,
            )
            row = result.single()
            session_id = row["sid"] if row else ""

    if not session_id:
        return {"error": "No sessions found for this client", "client_id": client_id}

    from .graph_rag import analyze_session_risk
    risk = analyze_session_risk(session_id, _neo4j_driver)
    return risk


@app.post("/api/v1/risk/agent")
async def api_v1_risk_agent(body: _AgentRiskBody, x_api_key: str = Header(...)):
    """Get agent risk profile."""
    _validate_api_key(x_api_key)
    ensure_provenance_neo4j()

    from .provenance_graph import _neo4j_driver
    if not _neo4j_driver:
        raise HTTPException(status_code=503, detail="Neo4j not available")

    from .graph_rag import get_agent_risk
    return get_agent_risk(body.agent_id, _neo4j_driver)


@app.post("/api/v1/risk/user")
async def api_v1_risk_user(body: _UserRiskBody, x_api_key: str = Header(...)):
    """Get user risk profile."""
    _validate_api_key(x_api_key)
    ensure_provenance_neo4j()

    from .provenance_graph import _neo4j_driver
    if not _neo4j_driver:
        raise HTTPException(status_code=503, detail="Neo4j not available")

    from .graph_rag import get_user_risk
    return get_user_risk(body.user_id, _neo4j_driver)


@app.post("/api/v1/risk/agents")
async def api_v1_risk_agents(body: _AgentsListBody, x_api_key: str = Header(...)):
    """List all agents risk summary."""
    _validate_api_key(x_api_key)
    ensure_provenance_neo4j()

    from .provenance_graph import _neo4j_driver
    if not _neo4j_driver:
        raise HTTPException(status_code=503, detail="Neo4j not available")

    from .graph_rag import get_all_agents_summary
    return get_all_agents_summary(_neo4j_driver, limit=body.limit)


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
