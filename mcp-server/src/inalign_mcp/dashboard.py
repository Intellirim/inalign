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
from .payments import router as payments_router
from .polygon_anchor import anchor_to_polygon, get_anchor_status, verify_anchor, setup_instructions
from .provenance_graph import (
    trace_record, trace_chain_path, trace_by_action,
    trace_full_graph, trace_timeline, get_record_content,
)

app = FastAPI(title="InALign Dashboard")

# Include payment routes
app.include_router(payments_router)
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
    <script src="https://unpkg.com/vis-network@9.1.9/standalone/umd/vis-network.min.js"></script>
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
        #graphContainer {{ width: 100%; height: 520px; background: #0f172a; }}
        .legend {{
            padding: 8px 20px; display: flex; gap: 16px; border-top: 1px solid #334155;
            flex-wrap: wrap;
        }}
        .legend-item {{ display: flex; align-items: center; gap: 5px; font-size: 11px; color: #94a3b8; }}
        .legend-shape {{ width: 12px; height: 12px; display: inline-block; }}

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
                <b>Double-click:</b> Double-click a graph node to zoom/focus on it
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
            <div id="graphContainer"></div>
            <div class="legend">
                <div class="legend-item"><div class="legend-shape" style="background:#3b82f6;border-radius:50%;"></div> Record</div>
                <div class="legend-item"><div class="legend-shape" style="background:#8b5cf6;transform:rotate(45deg);"></div> Session</div>
                <div class="legend-item"><div class="legend-shape" style="background:#f59e0b;clip-path:polygon(50% 0%,100% 38%,82% 100%,18% 100%,0% 38%);"></div> Agent</div>
                <div class="legend-item"><div class="legend-shape" style="background:#10b981;clip-path:polygon(50% 0%,100% 100%,0% 100%);"></div> Tool</div>
                <div class="legend-item"><div class="legend-shape" style="background:#ef4444;"></div> Decision</div>
                <div class="legend-item"><div class="legend-shape" style="background:#06b6d4;border-radius:50%;"></div> Content</div>
                <div class="legend-item"><div class="legend-shape" style="background:#eab308;border-radius:3px;"></div> Blockchain</div>
                <div style="margin-left:auto;font-size:11px;color:#475569;">Drag to pan | Scroll to zoom | Click node for details | Double-click to focus</div>
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
        // vis.js Network Graph
        // ============================================
        let network = null;
        let graphNodes = null;
        let graphEdges = null;
        let allNodeData = {{}};
        let selectedNodeId = null;
        let highlightTimer = null;

        const NODE_COLORS = {{
            record:     {{ background: '#3b82f6', border: '#2563eb', highlight: {{ background: '#60a5fa', border: '#3b82f6' }}, hover: {{ background: '#60a5fa', border: '#3b82f6' }} }},
            session:    {{ background: '#8b5cf6', border: '#7c3aed', highlight: {{ background: '#a78bfa', border: '#8b5cf6' }}, hover: {{ background: '#a78bfa', border: '#8b5cf6' }} }},
            agent:      {{ background: '#f59e0b', border: '#d97706', highlight: {{ background: '#fbbf24', border: '#f59e0b' }}, hover: {{ background: '#fbbf24', border: '#f59e0b' }} }},
            tool:       {{ background: '#10b981', border: '#059669', highlight: {{ background: '#34d399', border: '#10b981' }}, hover: {{ background: '#34d399', border: '#10b981' }} }},
            decision:   {{ background: '#ef4444', border: '#dc2626', highlight: {{ background: '#f87171', border: '#ef4444' }}, hover: {{ background: '#f87171', border: '#ef4444' }} }},
            content:    {{ background: '#06b6d4', border: '#0891b2', highlight: {{ background: '#22d3ee', border: '#06b6d4' }}, hover: {{ background: '#22d3ee', border: '#06b6d4' }} }},
            blockchain: {{ background: '#eab308', border: '#ca8a04', highlight: {{ background: '#facc15', border: '#eab308' }}, hover: {{ background: '#facc15', border: '#eab308' }} }},
        }};

        const NODE_SHAPES = {{
            record: 'dot', session: 'diamond', agent: 'star',
            tool: 'triangle', decision: 'square', content: 'hexagon', blockchain: 'database',
        }};

        const NODE_SIZES = {{
            record: 14, session: 20, agent: 22,
            tool: 18, decision: 16, content: 11, blockchain: 20,
        }};

        const EDGE_STYLES = {{
            FOLLOWS:      {{ color: '#475569', dashes: [8, 4], width: 2.0 }},
            BELONGS_TO:   {{ color: '#8b5cf6', dashes: false, width: 1.0 }},
            PERFORMED_BY: {{ color: '#f59e0b', dashes: false, width: 1.2 }},
            CALLED:       {{ color: '#10b981', dashes: false, width: 1.5 }},
            MADE:         {{ color: '#ef4444', dashes: false, width: 1.2 }},
            HAS_CONTENT:  {{ color: '#06b6d4', dashes: [3, 3], width: 0.8 }},
            ANCHORED_BY:  {{ color: '#eab308', dashes: false, width: 1.5 }},
        }};

        function initGraph() {{
            const container = document.getElementById('graphContainer');
            graphNodes = new vis.DataSet([]);
            graphEdges = new vis.DataSet([]);

            const options = {{
                nodes: {{
                    borderWidth: 2,
                    shadow: {{ enabled: true, color: 'rgba(0,0,0,0.4)', size: 8, x: 2, y: 2 }},
                    font: {{ size: 11, color: '#e2e8f0', face: 'Segoe UI, sans-serif', strokeWidth: 3, strokeColor: '#0f172a' }},
                }},
                edges: {{
                    width: 1.2,
                    shadow: false,
                    smooth: {{ type: 'continuous', roundness: 0.2 }},
                    arrows: {{ to: {{ enabled: true, scaleFactor: 0.5, type: 'arrow' }} }},
                    font: {{ size: 8, color: '#475569', face: 'Segoe UI, sans-serif', strokeWidth: 2, strokeColor: '#0f172a', align: 'middle' }},
                }},
                physics: {{
                    forceAtlas2Based: {{
                        gravitationalConstant: -45,
                        centralGravity: 0.008,
                        springLength: 130,
                        springConstant: 0.05,
                        damping: 0.4,
                        avoidOverlap: 0.3,
                    }},
                    solver: 'forceAtlas2Based',
                    stabilization: {{ iterations: 200, fit: true }},
                    maxVelocity: 40,
                }},
                interaction: {{
                    hover: true,
                    tooltipDelay: 100,
                    zoomView: true,
                    dragView: true,
                    multiselect: false,
                }},
                layout: {{ improvedLayout: true }},
            }};

            network = new vis.Network(container, {{ nodes: graphNodes, edges: graphEdges }}, options);

            // Click event - show details
            network.on('click', function(params) {{
                if (params.nodes.length > 0) {{
                    const nodeId = params.nodes[0];
                    const nodeData = allNodeData[nodeId];
                    if (nodeData && nodeData.type === 'record') {{
                        loadDetail(nodeId);
                        highlightTimelineItem(nodeId);
                    }}
                    highlightConnected(nodeId);
                }} else {{
                    resetHighlight();
                }}
            }});

            // Double-click to zoom/focus
            network.on('doubleClick', function(params) {{
                if (params.nodes.length > 0) {{
                    network.focus(params.nodes[0], {{
                        scale: 1.8,
                        animation: {{ duration: 500, easingFunction: 'easeInOutQuad' }},
                    }});
                }}
            }});

            // Stabilization progress
            network.on('stabilizationProgress', function(params) {{
                const pct = Math.round(params.iterations / params.total * 100);
                document.getElementById('graphStats').innerHTML = '<span class="stat">Stabilizing layout... ' + pct + '%</span>';
            }});

            network.on('stabilizationIterationsDone', function() {{
                updateGraphStats();
                network.fit({{ animation: {{ duration: 600, easingFunction: 'easeInOutQuad' }} }});
            }});
        }}

        function loadFullGraph() {{
            if (!network) initGraph();

            document.getElementById('graphStats').innerHTML = '<span class="stat">Loading graph data...</span>';

            fetch('/api/trace/graph')
                .then(r => r.json())
                .then(data => {{
                    if (data.error) {{
                        document.getElementById('graphStats').innerHTML = '<span class="stat" style="color:#ef4444;">' + data.error + '</span>';
                        return;
                    }}
                    populateGraph(data);
                }})
                .catch(e => {{
                    document.getElementById('graphStats').innerHTML = '<span class="stat" style="color:#ef4444;">Error: ' + e.message + '</span>';
                }});
        }}

        function populateGraph(data) {{
            const nodes = data.nodes || [];
            const edges = data.edges || [];

            graphNodes.clear();
            graphEdges.clear();
            allNodeData = {{}};

            // Add nodes
            const visNodes = nodes.map(n => {{
                allNodeData[n.id] = n;
                const type = n.type || 'record';
                const color = NODE_COLORS[type] || NODE_COLORS.record;
                const shape = NODE_SHAPES[type] || 'dot';
                const size = NODE_SIZES[type] || 14;
                const label = (n.label || '').length > 28 ? n.label.substring(0, 25) + '...' : (n.label || '');

                // Build tooltip
                let tooltip = '<div style="font-family:Segoe UI;font-size:12px;max-width:300px;">';
                tooltip += '<b>' + escapeHtml(n.label || n.id) + '</b><br>';
                tooltip += '<span style="color:#888;">Type:</span> ' + type + '<br>';
                if (n.time) tooltip += '<span style="color:#888;">Time:</span> ' + n.time.substring(0, 19).replace('T', ' ') + '<br>';
                if (n.hash) tooltip += '<span style="color:#888;">Hash:</span> <code>' + n.hash.substring(0, 20) + '...</code><br>';
                tooltip += '<span style="color:#888;">ID:</span> ' + n.id.substring(0, 32) + (n.id.length > 32 ? '...' : '');
                tooltip += '</div>';

                return {{
                    id: n.id,
                    label: label,
                    shape: shape,
                    size: size,
                    color: color,
                    title: tooltip,
                    font: {{ color: '#e2e8f0' }},
                }};
            }});
            graphNodes.add(visNodes);

            // Add edges
            const visEdges = edges.map((e, i) => {{
                const style = EDGE_STYLES[e.type] || EDGE_STYLES.FOLLOWS;
                const isChain = e.type === 'FOLLOWS';

                // Reverse FOLLOWS to show time flow (prev -> current)
                const from = isChain ? e.target : e.source;
                const to = isChain ? e.source : e.target;

                return {{
                    id: 'e' + i,
                    from: from,
                    to: to,
                    label: isChain ? '' : e.type.replace('_', ' '),
                    color: {{ color: style.color, opacity: 0.65, highlight: style.color, hover: style.color }},
                    dashes: style.dashes,
                    width: style.width,
                    arrows: {{ to: {{ enabled: true, scaleFactor: isChain ? 0.7 : 0.4 }} }},
                    smooth: isChain
                        ? {{ type: 'curvedCW', roundness: 0.08 }}
                        : {{ type: 'continuous', roundness: 0.2 }},
                }};
            }});
            graphEdges.add(visEdges);

            updateGraphStats();
        }}

        function updateGraphStats() {{
            const nodeCount = graphNodes.length;
            const edgeCount = graphEdges.length;
            const types = {{}};
            Object.values(allNodeData).forEach(n => {{
                types[n.type] = (types[n.type] || 0) + 1;
            }});

            let html = '<span class="stat"><b>' + nodeCount + '</b> nodes</span>';
            html += '<span class="stat"><b>' + edgeCount + '</b> edges</span>';
            const typeOrder = ['record', 'session', 'agent', 'tool', 'decision', 'content', 'blockchain'];
            for (const type of typeOrder) {{
                const count = types[type];
                if (!count) continue;
                const color = (NODE_COLORS[type] || NODE_COLORS.record).background;
                html += '<span class="stat"><span class="dot" style="background:' + color + '"></span>' + count + ' ' + type + '</span>';
            }}
            document.getElementById('graphStats').innerHTML = html;
        }}

        function highlightConnected(nodeId) {{
            if (!network || !graphNodes.get(nodeId)) return;

            clearTimeout(highlightTimer);

            const connectedNodes = network.getConnectedNodes(nodeId);
            const connectedEdges = network.getConnectedEdges(nodeId);
            const connectedSet = new Set(connectedNodes);
            connectedSet.add(nodeId);
            const edgeSet = new Set(connectedEdges);

            // Dim non-connected nodes
            const updatedNodes = graphNodes.get().map(n => {{
                const type = (allNodeData[n.id] || {{}}).type || 'record';
                const baseColor = NODE_COLORS[type] || NODE_COLORS.record;
                if (n.id === nodeId) {{
                    return {{ id: n.id, borderWidth: 4, shadow: {{ enabled: true, size: 15, color: baseColor.background + '66' }},
                        font: {{ color: '#ffffff', size: 13 }}, opacity: 1.0 }};
                }} else if (connectedSet.has(n.id)) {{
                    return {{ id: n.id, borderWidth: 2, opacity: 1.0, font: {{ color: '#e2e8f0', size: 11 }} }};
                }} else {{
                    return {{ id: n.id, borderWidth: 1, opacity: 0.12, font: {{ color: '#e2e8f066', size: 10 }} }};
                }}
            }});
            graphNodes.update(updatedNodes);

            // Dim non-connected edges
            const updatedEdges = graphEdges.get().map(e => {{
                if (edgeSet.has(e.id)) {{
                    return {{ id: e.id, width: (e.width || 1.2) * 1.8, hidden: false }};
                }} else {{
                    return {{ id: e.id, hidden: true }};
                }}
            }});
            graphEdges.update(updatedEdges);

            selectedNodeId = nodeId;

            // Auto-reset after 10 seconds
            highlightTimer = setTimeout(resetHighlight, 10000);
        }}

        function resetHighlight() {{
            if (!network) return;
            clearTimeout(highlightTimer);

            // Restore all nodes
            const updatedNodes = graphNodes.get().map(n => {{
                const type = (allNodeData[n.id] || {{}}).type || 'record';
                const baseColor = NODE_COLORS[type] || NODE_COLORS.record;
                return {{
                    id: n.id, borderWidth: 2, opacity: 1.0,
                    color: baseColor,
                    shadow: {{ enabled: true, color: 'rgba(0,0,0,0.4)', size: 8, x: 2, y: 2 }},
                    font: {{ color: '#e2e8f0', size: 11 }},
                }};
            }});
            graphNodes.update(updatedNodes);

            // Restore all edges
            const updatedEdges = graphEdges.get().map(e => {{
                const origStyle = EDGE_STYLES[e._type] || {{}};
                return {{ id: e.id, hidden: false, width: origStyle.width || 1.2 }};
            }});
            graphEdges.update(updatedEdges);

            selectedNodeId = null;
        }}

        function focusGraphNode(nodeId) {{
            if (!network || !graphNodes.get(nodeId)) return;
            network.selectNodes([nodeId]);
            network.focus(nodeId, {{
                scale: 1.3,
                animation: {{ duration: 400, easingFunction: 'easeInOutQuad' }},
            }});
            highlightConnected(nodeId);
        }}

        // ============================================
        // Timeline
        // ============================================

        async function loadTimeline() {{
            const res = await fetch('/api/trace/timeline');
            const data = await res.json();
            renderTimeline(data.timeline || []);
        }}

        async function searchActions() {{
            const name = document.getElementById('searchInput').value;
            const type = document.getElementById('typeFilter').value;
            let url = '/api/trace/action?';
            if (name) url += 'name=' + encodeURIComponent(name) + '&';
            if (type) url += 'type=' + type + '&';
            const res = await fetch(url);
            const data = await res.json();
            renderTimeline(data.records || []);
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
            const div = document.getElementById('timeline');
            document.getElementById('timelineCount').textContent = '(' + records.length + ' records)';

            if (!records.length) {{
                div.innerHTML = '<div class="empty-state">No records found</div>';
                return;
            }}

            div.innerHTML = records.map(r => {{
                const timeStr = (r.time || '').substring(0, 19).replace('T', ' ');
                const hashStr = (r.hash || '').substring(0, 24);
                return '<div class="tl-item" id="tl-' + r.id + '" onclick="onTimelineClick(\\'' + r.id + '\\', this)">' +
                    '<div class="tl-action">' + escapeHtml(r.action || '-') + '</div>' +
                    '<span class="tl-badge ' + getBadgeClass(r.type) + '">' + (r.type || r.tool || '-') + '</span>' +
                    '<div class="tl-time">' + timeStr + '</div>' +
                    '<div class="tl-hash">' + hashStr + '</div>' +
                '</div>';
            }}).join('');
        }}

        function onTimelineClick(recordId, el) {{
            document.querySelectorAll('.tl-item').forEach(e => e.classList.remove('active'));
            el.classList.add('active');
            loadDetail(recordId);
            focusGraphNode(recordId);
        }}

        function highlightTimelineItem(recordId) {{
            document.querySelectorAll('.tl-item').forEach(e => e.classList.remove('active'));
            const el = document.getElementById('tl-' + recordId);
            if (el) {{
                el.classList.add('active');
                el.scrollIntoView({{ behavior: 'smooth', block: 'center' }});
            }}
        }}

        // ============================================
        // Detail Panel
        // ============================================

        async function loadDetail(recordId) {{
            const res = await fetch('/api/trace/record/' + recordId);
            const data = await res.json();

            if (data.error) {{
                document.getElementById('detail').innerHTML = '<div class="empty-state">' + data.error + '</div>';
                return;
            }}

            const r = data.record || {{}};
            let html = '<div class="detail-section"><h4>Record Info</h4>';
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
                for (const c of data.contents) {{
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
            const res = await fetch('/api/trace/content/' + recordId);
            const data = await res.json();
            let html = '';
            for (const [type, info] of Object.entries(data)) {{
                html += '<div class="detail-section"><h4>Content: ' + type + '</h4><div class="content-box">' + escapeHtml(info.content || '') + '</div></div>';
            }}
            if (!html) html = '<div class="empty-state">No content stored</div>';

            const panel = document.getElementById('detail');
            const contentDiv = document.createElement('div');
            contentDiv.innerHTML = html;
            panel.appendChild(contentDiv);
        }}

        // ============================================
        // Helpers
        // ============================================

        function toggleHelp() {{
            const panel = document.getElementById('helpPanel');
            panel.style.display = panel.style.display === 'none' ? 'block' : 'none';
        }}

        function escapeHtml(text) {{
            return String(text).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
        }}

        // Enter key triggers search
        document.addEventListener('DOMContentLoaded', function() {{
            document.getElementById('searchInput').addEventListener('keydown', function(e) {{
                if (e.key === 'Enter') searchActions();
            }});
        }});
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
    """Generate and download personalized install script."""
    from fastapi.responses import Response

    script = f'''#!/usr/bin/env python3
"""
InALign MCP Server - One-Click Installer
API Key: {api_key}
"""

import os
import sys
import json
import platform
from pathlib import Path

API_KEY = "{api_key}"
NEO4J_URI = "***REDACTED_URI***"
NEO4J_USERNAME = "neo4j"
NEO4J_PASSWORD = "***REDACTED***"

def get_python_path():
    return sys.executable

def main():
    print("\\n" + "="*50)
    print("  InALign MCP Server Installer")
    print("="*50 + "\\n")

    # 1. Create ~/.inalign.env
    env_path = Path.home() / ".inalign.env"
    print(f"[1/3] Creating {{env_path}}...")
    with open(env_path, "w") as f:
        f.write(f"API_KEY={{API_KEY}}\\n")
        f.write(f"NEO4J_URI={{NEO4J_URI}}\\n")
        f.write(f"NEO4J_USERNAME={{NEO4J_USERNAME}}\\n")
        f.write(f"NEO4J_PASSWORD={{NEO4J_PASSWORD}}\\n")
    print("      Done!")

    # 2. Update Claude settings.json
    settings_path = Path.home() / ".claude" / "settings.json"
    settings_path.parent.mkdir(parents=True, exist_ok=True)
    print(f"[2/3] Updating {{settings_path}}...")

    settings = {{}}
    if settings_path.exists():
        with open(settings_path) as f:
            settings = json.load(f)

    if "mcpServers" not in settings:
        settings["mcpServers"] = {{}}

    settings["mcpServers"]["inalign"] = {{
        "command": get_python_path(),
        "args": ["-m", "inalign_mcp.server"],
        "env": {{
            "API_KEY": API_KEY,
            "NEO4J_URI": NEO4J_URI,
            "NEO4J_USERNAME": NEO4J_USERNAME,
            "NEO4J_PASSWORD": NEO4J_PASSWORD
        }}
    }}

    with open(settings_path, "w") as f:
        json.dump(settings, f, indent=2)
    print("      Done!")

    # 3. Create CLAUDE.md
    claude_md = Path.home() / "CLAUDE.md"
    print(f"[3/3] Creating {{claude_md}}...")
    if not claude_md.exists():
        with open(claude_md, "w") as f:
            f.write("""# Claude Code Instructions

## InALign Integration
IMPORTANT: At the start of EVERY conversation, call `mcp__inalign__record_user_command` to record the user's request.
""")
    print("      Done!")

    # Install dependencies
    print("\\nInstalling dependencies...")
    os.system(f"{{get_python_path()}} -m pip install neo4j -q")

    print("\\n" + "="*50)
    print("  Installation Complete!")
    print("="*50)
    print(f"""
Your API Key: {{API_KEY}}
Client ID: {{API_KEY[:12]}}

Next Steps:
1. Restart Claude Code (close/reopen VSCode)
2. Start using Claude Code normally
3. View activity at: http://3.36.132.4:8080/login

All activity will be automatically recorded!
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
    return JSONResponse(trace_record(record_id))


@app.get("/api/trace/chain/{record_id}")
async def api_trace_chain(record_id: str, request: Request, direction: str = "both", depth: int = 20):
    """해시체인 경로 추적 - 이전/이후 레코드 경로."""
    client = get_current_client(request)
    if not client:
        return JSONResponse({"error": "Not authenticated"}, status_code=401)
    return JSONResponse(trace_chain_path(record_id, direction, depth))


@app.get("/api/trace/action")
async def api_trace_action(request: Request, name: str = None, type: str = None, limit: int = 50):
    """액션/도구/결정별 추적."""
    client = get_current_client(request)
    if not client:
        return JSONResponse({"error": "Not authenticated"}, status_code=401)
    return JSONResponse(trace_by_action(client.client_id, name, type, limit))


@app.get("/api/trace/graph")
async def api_trace_graph(request: Request, limit: int = 100):
    """전체 프로비넌스 그래프 (시각화용)."""
    client = get_current_client(request)
    if not client:
        return JSONResponse({"error": "Not authenticated"}, status_code=401)
    return JSONResponse(trace_full_graph(client.client_id, limit))


@app.get("/api/trace/timeline")
async def api_trace_timeline(request: Request, limit: int = 200):
    """시간순 타임라인."""
    client = get_current_client(request)
    if not client:
        return JSONResponse({"error": "Not authenticated"}, status_code=401)
    return JSONResponse(trace_timeline(client.client_id, limit))


@app.get("/api/trace/content/{record_id}")
async def api_trace_content(record_id: str, request: Request):
    """레코드에 저장된 전체 내용 조회 (프롬프트/응답)."""
    client = get_current_client(request)
    if not client:
        return JSONResponse({"error": "Not authenticated"}, status_code=401)
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
