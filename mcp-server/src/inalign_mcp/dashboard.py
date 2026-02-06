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
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ font-family: 'Segoe UI', sans-serif; background: #f3f4f6; }}
        .header {{
            background: linear-gradient(135deg, #1e3a5f 0%, #0d1b2a 100%);
            color: white; padding: 16px 40px;
            display: flex; justify-content: space-between; align-items: center;
        }}
        .logo {{ font-size: 22px; font-weight: bold; }}
        .nav a {{ color: #93c5fd; text-decoration: none; margin-left: 20px; }}
        .container {{ max-width: 1400px; margin: 0 auto; padding: 20px; }}
        .search-panel {{
            background: white; border-radius: 12px; padding: 24px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.08); margin-bottom: 20px;
        }}
        .search-row {{ display: flex; gap: 12px; margin-bottom: 12px; }}
        .search-row input, .search-row select {{
            padding: 10px 14px; border: 2px solid #e5e7eb; border-radius: 8px; font-size: 14px;
        }}
        .search-row input {{ flex: 1; }}
        .search-row select {{ min-width: 160px; }}
        .btn {{ padding: 10px 20px; border: none; border-radius: 8px; cursor: pointer; font-weight: 600; font-size: 14px; }}
        .btn-blue {{ background: #2563eb; color: white; }}
        .btn-purple {{ background: #7c3aed; color: white; }}
        .btn-gray {{ background: #e5e7eb; color: #333; }}
        .btn:hover {{ opacity: 0.9; }}
        .quick-btns {{ display: flex; gap: 8px; flex-wrap: wrap; }}
        .quick-btns button {{ padding: 6px 14px; background: #f3f4f6; border: 1px solid #e5e7eb; border-radius: 6px; cursor: pointer; font-size: 13px; }}
        .quick-btns button:hover {{ background: #e5e7eb; }}
        .layout {{ display: grid; grid-template-columns: 1fr 1fr; gap: 20px; }}
        .panel {{
            background: white; border-radius: 12px; padding: 20px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.08); max-height: 70vh; overflow-y: auto;
        }}
        .panel-title {{ font-weight: 700; font-size: 16px; margin-bottom: 12px; color: #1e3a5f; }}
        .timeline-item {{
            padding: 10px 12px; border-left: 3px solid #2563eb; margin-bottom: 8px;
            background: #f9fafb; border-radius: 0 8px 8px 0; cursor: pointer;
            transition: background 0.2s;
        }}
        .timeline-item:hover {{ background: #eff6ff; }}
        .timeline-item.active {{ background: #dbeafe; border-left-color: #7c3aed; }}
        .tl-action {{ font-weight: 600; font-size: 14px; }}
        .tl-type {{ font-size: 11px; color: #2563eb; background: #dbeafe; padding: 2px 8px; border-radius: 4px; display: inline-block; }}
        .tl-time {{ font-size: 12px; color: #999; margin-top: 2px; }}
        .tl-hash {{ font-family: monospace; font-size: 11px; color: #bbb; }}
        .detail-section {{ margin-bottom: 16px; }}
        .detail-section h4 {{ color: #666; font-size: 13px; margin-bottom: 6px; }}
        .detail-field {{ display: flex; padding: 4px 0; border-bottom: 1px solid #f3f4f6; }}
        .detail-label {{ width: 120px; color: #999; font-size: 13px; }}
        .detail-value {{ flex: 1; font-size: 13px; word-break: break-all; }}
        .detail-value.mono {{ font-family: monospace; font-size: 12px; }}
        .chain-link {{
            display: inline-block; padding: 4px 10px; background: #f0fdf4; color: #16a34a;
            border-radius: 6px; font-size: 12px; cursor: pointer; margin: 2px;
        }}
        .chain-link:hover {{ background: #dcfce7; }}
        .content-box {{
            background: #1e293b; color: #e2e8f0; padding: 12px; border-radius: 8px;
            font-family: monospace; font-size: 12px; white-space: pre-wrap;
            max-height: 200px; overflow-y: auto; margin-top: 6px;
        }}
        #graphCanvas {{
            width: 100%; height: 400px; background: #0f172a; border-radius: 8px;
            position: relative; overflow: hidden;
        }}
        .graph-node {{
            position: absolute; padding: 4px 10px; border-radius: 20px;
            font-size: 11px; font-weight: 600; color: white; cursor: pointer;
            white-space: nowrap; transition: transform 0.3s;
        }}
        .graph-node:hover {{ transform: scale(1.15); z-index: 10; }}
        .node-record {{ background: #2563eb; }}
        .node-tool {{ background: #16a34a; }}
        .node-agent {{ background: #d97706; }}
        .node-session {{ background: #7c3aed; }}
        .node-decision {{ background: #dc2626; }}
        .node-content {{ background: #0891b2; }}
        .node-blockchain {{ background: #f59e0b; }}
        .empty-state {{ text-align: center; color: #999; padding: 40px; }}
    </style>
</head>
<body>
    <div class="header">
        <div class="logo">InALign <span style="color:#93c5fd">| Trace</span></div>
        <div class="nav">
            <a href="/dashboard">Dashboard</a>
            <a href="/trace">Trace</a>
            <a href="/logout">Logout</a>
        </div>
    </div>

    <div class="container">
        <div class="search-panel">
            <div class="search-row">
                <input type="text" id="searchInput" placeholder="e.g. record_action, Edit, file_write, read_file...">
                <select id="typeFilter">
                    <option value="">All Types</option>
                    <option value="user_input">User Input (prompts)</option>
                    <option value="tool_call">Tool Call (actions)</option>
                    <option value="decision">Decision (AI choices)</option>
                    <option value="llm_request">LLM Request</option>
                    <option value="file_read">File Read</option>
                    <option value="file_write">File Write</option>
                </select>
                <button class="btn btn-blue" onclick="searchActions()">Search</button>
                <button class="btn btn-purple" onclick="loadGraph()">Graph View</button>
            </div>
            <div class="quick-btns">
                <button onclick="loadTimeline()">Full Timeline</button>
                <button onclick="searchType('tool_call')">All Tool Calls</button>
                <button onclick="searchType('decision')">All Decisions</button>
                <button onclick="searchType('user_input')">All Prompts</button>
                <button onclick="searchType('file_write')">File Changes</button>
            </div>
            <div style="margin-top:14px; padding:14px; background:#f0f9ff; border-radius:8px; border:1px solid #bae6fd;">
                <div style="font-weight:600; font-size:13px; color:#0369a1; margin-bottom:6px;">How to Search</div>
                <div style="font-size:12px; color:#475569; line-height:1.7;">
                    <b>By name:</b> Type action name in search box (e.g. <code style="background:#e0f2fe;padding:1px 4px;border-radius:3px;">record_action</code>, <code style="background:#e0f2fe;padding:1px 4px;border-radius:3px;">Edit</code>, <code style="background:#e0f2fe;padding:1px 4px;border-radius:3px;">read_file</code>)<br>
                    <b>By type:</b> Select type from dropdown (User Input = prompts, Tool Call = agent actions)<br>
                    <b>Quick filters:</b> Click buttons above to see all records of that type<br>
                    <b>Detail view:</b> Click any record in timeline to see full details + hash chain navigation<br>
                    <b>View content:</b> Click "View" button in detail panel to see stored prompt/response<br>
                    <b>Graph:</b> Click "Graph View" to see all nodes and relationships visually
                </div>
            </div>
        </div>

        <div class="layout">
            <div class="panel" id="timelinePanel">
                <div class="panel-title">Timeline</div>
                <div id="timeline" class="empty-state">Click search or timeline to load records</div>
            </div>

            <div class="panel" id="detailPanel">
                <div class="panel-title">Record Detail</div>
                <div id="detail" class="empty-state">Click a record to see details</div>
            </div>
        </div>

        <div style="margin-top:20px;">
            <div class="panel">
                <div class="panel-title">Provenance Graph</div>
                <div id="graphCanvas">
                    <div class="empty-state" style="color:#666; padding-top:180px;">Click "Graph View" to load</div>
                </div>
            </div>
        </div>
    </div>

    <script>
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

        function renderTimeline(records) {{
            const div = document.getElementById('timeline');
            if (!records.length) {{
                div.innerHTML = '<div class="empty-state">No records found</div>';
                return;
            }}
            div.innerHTML = records.map(r => `
                <div class="timeline-item" onclick="loadDetail('${{r.id}}')">
                    <div class="tl-action">${{r.action || '-'}}</div>
                    <span class="tl-type">${{r.type || r.tool || '-'}}</span>
                    <div class="tl-time">${{(r.time || '').substring(0, 19)}}</div>
                    <div class="tl-hash">${{(r.hash || '').substring(0, 24)}}...</div>
                </div>
            `).join('');
        }}

        async function loadDetail(recordId) {{
            // Highlight active
            document.querySelectorAll('.timeline-item').forEach(el => el.classList.remove('active'));
            event.currentTarget?.classList.add('active');

            const res = await fetch('/api/trace/record/' + recordId);
            const data = await res.json();

            if (data.error) {{
                document.getElementById('detail').innerHTML = '<div class="empty-state">' + data.error + '</div>';
                return;
            }}

            const r = data.record || {{}};
            let html = `
                <div class="detail-section">
                    <h4>Record Info</h4>
                    <div class="detail-field"><span class="detail-label">ID</span><span class="detail-value mono">${{r.id}}</span></div>
                    <div class="detail-field"><span class="detail-label">Action</span><span class="detail-value">${{r.activity_name}}</span></div>
                    <div class="detail-field"><span class="detail-label">Type</span><span class="detail-value">${{r.activity_type}}</span></div>
                    <div class="detail-field"><span class="detail-label">Time</span><span class="detail-value">${{r.timestamp}}</span></div>
                    <div class="detail-field"><span class="detail-label">Hash</span><span class="detail-value mono">${{r.hash}}</span></div>
                    <div class="detail-field"><span class="detail-label">Prev Hash</span><span class="detail-value mono">${{r.previous_hash || 'genesis'}}</span></div>
                    <div class="detail-field"><span class="detail-label">Sequence</span><span class="detail-value">#${{r.sequence}}</span></div>
                </div>
            `;

            if (data.agent) {{
                html += `<div class="detail-section"><h4>Agent</h4>
                    <div class="detail-field"><span class="detail-label">Name</span><span class="detail-value">${{data.agent.name}}</span></div>
                </div>`;
            }}
            if (data.tool) {{
                html += `<div class="detail-section"><h4>Tool Called</h4>
                    <div class="detail-field"><span class="detail-label">Tool</span><span class="detail-value">${{data.tool}}</span></div>
                </div>`;
            }}
            if (data.decision) {{
                html += `<div class="detail-section"><h4>Decision Made</h4>
                    <div class="detail-field"><span class="detail-label">Decision</span><span class="detail-value">${{data.decision}}</span></div>
                </div>`;
            }}

            // Chain navigation
            html += '<div class="detail-section"><h4>Hash Chain</h4>';
            if (data.previous_record) {{
                html += `<span class="chain-link" onclick="loadDetail('${{data.previous_record.id}}')">&larr; ${{data.previous_record.action}}</span> `;
            }}
            html += `<span style="padding:4px 10px; background:#dbeafe; border-radius:6px; font-size:12px; font-weight:bold;">CURRENT</span> `;
            if (data.next_record) {{
                html += `<span class="chain-link" onclick="loadDetail('${{data.next_record.id}}')">${{data.next_record.action}} &rarr;</span>`;
            }}
            html += '</div>';

            // Contents
            if (data.contents && data.contents.length > 0) {{
                html += '<div class="detail-section"><h4>Stored Content</h4>';
                for (const c of data.contents) {{
                    html += `<div class="detail-field"><span class="detail-label">${{c.type}}</span><span class="detail-value">${{c.size}} bytes <button class="btn btn-gray" style="padding:2px 8px;font-size:11px;" onclick="loadContent('${{r.id}}')">View</button></span></div>`;
                }}
                html += '</div>';
            }}

            document.getElementById('detail').innerHTML = html;
        }}

        async function loadContent(recordId) {{
            const res = await fetch('/api/trace/content/' + recordId);
            const data = await res.json();
            let html = '';
            for (const [type, info] of Object.entries(data)) {{
                html += `<div class="detail-section"><h4>${{type}}</h4><div class="content-box">${{escapeHtml(info.content || '')}}</div></div>`;
            }}
            if (!html) html = '<div class="empty-state">No content stored</div>';

            // Append to detail panel
            const panel = document.getElementById('detail');
            const contentDiv = document.createElement('div');
            contentDiv.innerHTML = html;
            panel.appendChild(contentDiv);
        }}

        async function loadGraph() {{
            const res = await fetch('/api/trace/graph');
            const data = await res.json();
            renderGraph(data);
        }}

        function renderGraph(data) {{
            const canvas = document.getElementById('graphCanvas');
            if (!data.nodes || !data.nodes.length) {{
                canvas.innerHTML = '<div class="empty-state" style="color:#666;padding-top:180px;">No data</div>';
                return;
            }}

            const w = canvas.offsetWidth;
            const h = canvas.offsetHeight;
            let html = '';

            // Simple force-like layout
            const nodePositions = {{}};
            const typeGroups = {{}};

            data.nodes.forEach((n, i) => {{
                if (!typeGroups[n.type]) typeGroups[n.type] = [];
                typeGroups[n.type].push(n);
            }});

            const typeOrder = ['session', 'agent', 'record', 'tool', 'decision', 'content', 'blockchain'];
            let yOffset = 30;

            typeOrder.forEach(type => {{
                const group = typeGroups[type] || [];
                group.forEach((n, i) => {{
                    const x = 40 + (i % 8) * (w / 8.5);
                    const y = yOffset + Math.floor(i / 8) * 40;
                    nodePositions[n.id] = {{ x, y }};
                }});
                if (group.length > 0) yOffset += Math.ceil(group.length / 8) * 40 + 20;
            }});

            // Draw edges as SVG lines
            let svgLines = '';
            data.edges.forEach(e => {{
                const from = nodePositions[e.source];
                const to = nodePositions[e.target];
                if (from && to) {{
                    svgLines += `<line x1="${{from.x+30}}" y1="${{from.y+10}}" x2="${{to.x+30}}" y2="${{to.y+10}}" stroke="#334155" stroke-width="1" opacity="0.4"/>`;
                }}
            }});

            html += `<svg style="position:absolute;width:100%;height:100%;pointer-events:none;">${{svgLines}}</svg>`;

            // Draw nodes
            data.nodes.forEach(n => {{
                const pos = nodePositions[n.id];
                if (pos) {{
                    const cls = 'node-' + n.type;
                    const label = (n.label || '').substring(0, 20);
                    html += `<div class="graph-node ${{cls}}" style="left:${{pos.x}}px;top:${{pos.y}}px;" title="${{n.id}}">${{label}}</div>`;
                }}
            }});

            canvas.innerHTML = html;
            canvas.style.height = Math.max(400, yOffset + 50) + 'px';
        }}

        function escapeHtml(text) {{
            return text.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
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
