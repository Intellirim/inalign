"""
InALign HTML Report Generator

Generates standalone HTML audit dashboard viewable in any browser.
Features: provenance chain, session log, data export, AI analysis,
          compliance, OWASP, drift detection, permissions, cost, topology.
"""

import json
import html as html_mod
from datetime import datetime, timezone


def generate_html_report(
    session_id: str,
    records: list,
    verification: dict,
    stats: dict,
    session_log: list = None,
    compliance_data: dict = None,
    owasp_data: dict = None,
    drift_data: dict = None,
    permissions_data: dict = None,
    cost_data: dict = None,
    topology_data: dict = None,
) -> str:
    """Generate a self-contained HTML audit dashboard.

    Args:
        session_id: Current session ID
        records: List of provenance records (hash chain)
        verification: Chain verification result {valid, error, merkle_root}
        stats: Session statistics
        session_log: Full session conversation log (from json.gz)
        compliance_data: EU AI Act compliance report dict
        owasp_data: OWASP LLM Top 10 report dict
        drift_data: Behavior drift detection report dict
        permissions_data: Agent permission matrix dict
        cost_data: Cost tracking report dict
        topology_data: Agent topology graph dict

    Returns:
        Complete HTML string
    """
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    chain_class = "pass" if verification.get("valid") else "fail"
    merkle_root = verification.get("merkle_root", "N/A")
    total_records = len(records)
    session_log = session_log or []
    compliance_data = compliance_data or {}
    owasp_data = owasp_data or {}
    drift_data = drift_data or {}
    permissions_data = permissions_data or {}
    cost_data = cost_data or {}
    topology_data = topology_data or {}

    # === Build provenance chain rows ===
    records_html = ""
    for idx, r in enumerate(records):
        hash_short = r.get("hash", "")[:16] + "..."
        prev_short = r.get("previous_hash", "genesis")[:16] + "..." if r.get("previous_hash") else "genesis"
        action_type = r.get("type", "unknown")
        type_class = {
            "user_input": "type-user", "tool_call": "type-tool",
            "decision": "type-decision", "file_read": "type-file",
            "file_write": "type-file", "llm_request": "type-llm",
        }.get(action_type, "type-tool")

        attrs = r.get("attributes", {})
        detail_content = ""
        if isinstance(attrs, dict) and attrs:
            if "command" in attrs:
                detail_content += f'<div class="detail-label">Prompt</div><div class="detail-value">{html_mod.escape(str(attrs["command"]))}</div>'
            if "tool_name" in attrs:
                detail_content += f'<div class="detail-label">Tool</div><div class="detail-value">{html_mod.escape(str(attrs["tool_name"]))}</div>'
            if "arguments" in attrs and attrs["arguments"]:
                detail_content += f'<div class="detail-label">Arguments</div><pre class="detail-pre">{html_mod.escape(json.dumps(attrs["arguments"], ensure_ascii=False, indent=2)[:1000])}</pre>'
            shown = {"command", "tool_name", "arguments", "storage_type", "client_id"}
            for k, v in attrs.items():
                if k not in shown and v:
                    detail_content += f'<div class="detail-label">{html_mod.escape(k)}</div><div class="detail-value">{html_mod.escape(str(v)[:500])}</div>'

        has_detail = bool(detail_content)
        toggle_class = "expandable" if has_detail else ""
        arrow = '<span class="arrow">&#9654;</span>' if has_detail else '<span class="arrow empty"></span>'

        records_html += f"""
        <tr class="record-row {toggle_class}" data-idx="{idx}">
            <td class="seq">{arrow} #{r.get('sequence', '?')}</td>
            <td><span class="badge {type_class}">{action_type}</span></td>
            <td class="action-name">{r.get('name', 'unknown')}</td>
            <td class="hash" title="{r.get('hash', '')}">{hash_short}</td>
            <td class="hash" title="{r.get('previous_hash', '')}">{prev_short}</td>
            <td class="timestamp">{r.get('timestamp', '')[:19]}</td>
        </tr>"""
        if has_detail:
            records_html += f"""
        <tr class="detail-row" id="detail-{idx}" style="display:none;">
            <td colspan="6"><div class="detail-box">{detail_content}</div></td>
        </tr>"""

    # === Build session log rows ===
    session_log_html = ""
    for i, r in enumerate(session_log):
        role = r.get("role", "")
        rtype = r.get("type", r.get("record_type", ""))
        content = r.get("content", "")
        tool_name = r.get("tool_name", "")
        tool_input = r.get("tool_input", "")
        tool_output = r.get("tool_output", "")
        ts = r.get("timestamp", "")[:19]

        # Role styling
        if role == "user":
            role_class = "role-user"
            role_label = "USER"
        elif role == "assistant" and rtype == "thinking":
            role_class = "role-thinking"
            role_label = "THINKING"
        elif role == "assistant":
            role_class = "role-assistant"
            role_label = "ASSISTANT"
        else:
            role_class = "role-tool"
            role_label = rtype.upper() if rtype else "TOOL"

        # Content preview
        preview = ""
        if rtype == "tool_call" and tool_name:
            preview = f"<strong>{html_mod.escape(tool_name)}</strong>"
            if tool_input:
                ti = str(tool_input)[:200]
                preview += f'<span class="log-muted"> &mdash; {html_mod.escape(ti)}</span>'
        elif rtype == "tool_result":
            tn = html_mod.escape(tool_name) if tool_name else "result"
            to = str(tool_output or content)[:200]
            preview = f"<strong>{tn}</strong> <span class='log-muted'>&rarr; {html_mod.escape(to)}</span>"
        elif content:
            preview = html_mod.escape(content[:300])
            if len(content) > 300:
                preview += "..."

        # Full content for expansion
        full_content = ""
        if content and len(content) > 300:
            full_content = html_mod.escape(content)
        if tool_input and len(str(tool_input)) > 200:
            full_content += f'\n\n--- Tool Input ---\n{html_mod.escape(str(tool_input))}'
        if tool_output and len(str(tool_output)) > 200:
            full_content += f'\n\n--- Tool Output ---\n{html_mod.escape(str(tool_output))}'

        has_full = bool(full_content)
        log_toggle = "log-expandable" if has_full else ""
        log_arrow = '<span class="arrow">&#9654;</span>' if has_full else ''

        session_log_html += f"""
        <div class="log-entry {log_toggle}" data-log="{i}">
            <div class="log-header">
                <span class="log-badge {role_class}">{role_label}</span>
                <span class="log-preview">{log_arrow} {preview}</span>
                <span class="log-ts">{ts}</span>
            </div>
        </div>"""
        if has_full:
            session_log_html += f"""
        <div class="log-full" id="log-{i}" style="display:none;">
            <pre class="log-pre">{full_content}</pre>
        </div>"""

    total_log = len(session_log)

    # === Export data ===
    export_data = {
        "session_id": session_id,
        "generated_at": now,
        "chain_integrity": verification,
        "total_records": total_records,
        "records": records,
        "session_log_count": total_log,
    }
    export_json_escaped = json.dumps(export_data, indent=2, ensure_ascii=False).replace("</", "<\\/")

    # Type counts
    type_counts = {}
    for r in records:
        t = r.get("type", "unknown")
        type_counts[t] = type_counts.get(t, 0) + 1
    type_summary_html = "".join(f'<span class="stat-chip">{t}: {c}</span>' for t, c in sorted(type_counts.items(), key=lambda x: -x[1]))

    # Session log type counts
    log_type_counts = {}
    for r in session_log:
        t = r.get("type", r.get("record_type", "unknown"))
        log_type_counts[t] = log_type_counts.get(t, 0) + 1
    log_summary_html = "".join(f'<span class="stat-chip">{t}: {c}</span>' for t, c in sorted(log_type_counts.items(), key=lambda x: -x[1]))

    # === Prepare v0.5.0 feature data for overview cards ===
    owasp_score = owasp_data.get("overall_score", 0)
    owasp_status = owasp_data.get("overall_status", "N/A")
    owasp_status_class = {"PASS": "pass", "WARN": "warn", "FAIL": "fail"}.get(owasp_status, "na")

    compliance_status = compliance_data.get("overall_status", "N/A")
    compliance_status_class = {"PASS": "pass", "PARTIAL": "warn", "FAIL": "fail"}.get(compliance_status, "na")
    compliance_pass = compliance_data.get("summary", {}).get("PASS", 0)
    compliance_total = compliance_data.get("total_checks", 0)

    drift_detected = drift_data.get("drift_detected", False)
    drift_score = drift_data.get("drift_score", 0)
    drift_class = "fail" if drift_detected else "pass"
    anomaly_count = drift_data.get("anomaly_count", 0)

    total_cost = cost_data.get("total_cost_usd", 0)
    total_input_tokens = cost_data.get("total_input_tokens", 0)
    total_output_tokens = cost_data.get("total_output_tokens", 0)
    total_tokens = total_input_tokens + total_output_tokens

    unique_agents = topology_data.get("unique_agents", 0)
    total_interactions = topology_data.get("total_interactions", 0)

    has_security_data = bool(owasp_data.get("checks") or compliance_data.get("checks") or drift_data.get("anomalies") is not None)
    has_governance_data = bool(permissions_data.get("agents") or cost_data.get("by_model") or topology_data.get("nodes"))

    # === Build OWASP table rows ===
    owasp_rows_html = ""
    for check in owasp_data.get("checks", []):
        st = check.get("status", "N/A")
        sc = {"PASS": "st-pass", "WARN": "st-warn", "FAIL": "st-fail"}.get(st, "st-na")
        owasp_rows_html += f"""
        <tr>
          <td><span class="badge {sc}">{st}</span></td>
          <td class="mono-sm">{html_mod.escape(check.get("item_id", ""))}</td>
          <td>{html_mod.escape(check.get("name", ""))}</td>
          <td>{check.get("score", 0)}/100</td>
          <td class="desc-cell">{html_mod.escape(check.get("description", "")[:200])}</td>
        </tr>"""

    # === Build compliance table rows ===
    compliance_rows_html = ""
    for check in compliance_data.get("checks", []):
        st = check.get("status", "N/A")
        sc = {"PASS": "st-pass", "PARTIAL": "st-warn", "FAIL": "st-fail"}.get(st, "st-na")
        evidence = " | ".join(html_mod.escape(str(e)[:100]) for e in check.get("evidence", []))
        compliance_rows_html += f"""
        <tr>
          <td><span class="badge {sc}">{st}</span></td>
          <td class="mono-sm">{html_mod.escape(check.get("check_id", ""))}</td>
          <td>{html_mod.escape(check.get("article", ""))}</td>
          <td>{html_mod.escape(check.get("requirement", "")[:120])}</td>
          <td class="desc-cell">{evidence if evidence else '<span style="color:var(--muted);">&mdash;</span>'}</td>
        </tr>"""

    # === Build drift anomalies rows ===
    anomalies_rows_html = ""
    for a in drift_data.get("anomalies", []):
        sev = a.get("severity", "low")
        sc = {"high": "st-fail", "medium": "st-warn", "low": "st-pass"}.get(sev, "st-na")
        anomalies_rows_html += f"""
        <tr>
          <td><span class="badge {sc}">{sev.upper()}</span></td>
          <td>{html_mod.escape(a.get("type", ""))}</td>
          <td>{html_mod.escape(a.get("description", ""))}</td>
        </tr>"""

    # === Build permissions table rows ===
    permissions_rows_html = ""
    for agent_id, agent_info in permissions_data.get("agents", {}).items():
        default_perm = agent_info.get("default_permission", "allow")
        tools = agent_info.get("tools", {})
        if tools:
            for tool_name, tool_info in tools.items():
                perm = tool_info.get("permission", "allow")
                pc = {"allow": "st-pass", "deny": "st-fail", "audit": "st-warn"}.get(perm, "st-na")
                permissions_rows_html += f"""
        <tr>
          <td>{html_mod.escape(str(agent_id))}</td>
          <td>{html_mod.escape(str(tool_name))}</td>
          <td><span class="badge {pc}">{perm.upper()}</span></td>
          <td>{html_mod.escape(str(tool_info.get("reason", "")))}</td>
        </tr>"""
        else:
            pc = {"allow": "st-pass", "deny": "st-fail", "audit": "st-warn"}.get(default_perm, "st-na")
            permissions_rows_html += f"""
        <tr>
          <td>{html_mod.escape(str(agent_id))}</td>
          <td><em>All tools</em></td>
          <td><span class="badge {pc}">{default_perm.upper()}</span></td>
          <td>Default policy</td>
        </tr>"""

    # === Build cost table rows ===
    cost_model_rows_html = ""
    for model, info in cost_data.get("by_model", {}).items():
        cost_model_rows_html += f"""
        <tr>
          <td>{html_mod.escape(str(model))}</td>
          <td>{info.get("calls", 0)}</td>
          <td>{info.get("input_tokens", 0):,}</td>
          <td>{info.get("output_tokens", 0):,}</td>
          <td>${info.get("cost", 0):.4f}</td>
        </tr>"""

    cost_agent_rows_html = ""
    for agent, info in cost_data.get("by_agent", {}).items():
        cost_agent_rows_html += f"""
        <tr>
          <td>{html_mod.escape(str(agent))}</td>
          <td>{info.get("calls", 0)}</td>
          <td>{info.get("input_tokens", 0):,}</td>
          <td>{info.get("output_tokens", 0):,}</td>
          <td>${info.get("cost", 0):.4f}</td>
        </tr>"""

    # === Build topology rows ===
    topo_nodes_html = ""
    for node in topology_data.get("nodes", []):
        topo_nodes_html += f'<span class="stat-chip">{html_mod.escape(str(node.get("label", node.get("id", ""))))}</span>'

    topo_edges_html = ""
    for edge in topology_data.get("edges", []):
        etype = edge.get("type", "delegate")
        ec = {"delegate": "type-tool", "query": "type-decision", "respond": "type-user"}.get(etype, "type-tool")
        topo_edges_html += f"""
        <tr>
          <td>{html_mod.escape(str(edge.get("source", "")))}</td>
          <td><span class="badge {ec}">{etype}</span></td>
          <td>{html_mod.escape(str(edge.get("target", "")))}</td>
          <td>{edge.get("weight", 0)}</td>
        </tr>"""

    # === Empty state messages ===
    no_owasp = '<p style="color:var(--muted);font-size:0.82rem;">No OWASP data. Run <code>check_owasp_compliance</code> via MCP to generate.</p>'
    no_compliance = '<p style="color:var(--muted);font-size:0.82rem;">No compliance data. Run <code>generate_compliance_report</code> via MCP to generate.</p>'
    no_drift = '<p style="color:var(--muted);font-size:0.82rem;">No drift data. Run <code>detect_drift</code> via MCP to analyze behavior.</p>'
    no_perms = '<p style="color:var(--muted);font-size:0.82rem;">No permissions configured. Use <code>set_agent_permissions</code> via MCP to set up access controls.</p>'
    no_cost = '<p style="color:var(--muted);font-size:0.82rem;">No cost data recorded. Use <code>track_cost</code> via MCP to log token usage.</p>'
    no_topo = '<p style="color:var(--muted);font-size:0.82rem;">No agent interactions recorded. Use <code>track_agent_interaction</code> via MCP to build topology.</p>'

    # === Build OWASP section HTML ===
    if owasp_rows_html:
        owasp_section = f"""
    <div class="section">
      <h2>OWASP LLM Top 10</h2>
      <div class="cards" style="margin-bottom:1rem;">
        <div class="card">
          <div class="label">Risk Score</div>
          <div class="value {owasp_status_class}">{owasp_score}/100</div>
          <div class="score-bar"><div class="score-fill" style="width:{owasp_score}%;background:var(--{'red' if owasp_score >= 60 else 'orange' if owasp_score >= 30 else 'green'});"></div></div>
        </div>
        <div class="card">
          <div class="label">Status</div>
          <div class="value {owasp_status_class}">{owasp_status}</div>
        </div>
      </div>
      <div style="overflow-x:auto;">
      <table>
        <thead><tr><th>Status</th><th>ID</th><th>Check</th><th>Score</th><th>Details</th></tr></thead>
        <tbody>{owasp_rows_html}</tbody>
      </table>
      </div>
    </div>"""
    else:
        owasp_section = f'<div class="section"><h2>OWASP LLM Top 10</h2>{no_owasp}</div>'

    # === Build compliance section HTML ===
    if compliance_rows_html:
        compliance_section = f"""
    <div class="section">
      <h2>EU AI Act Compliance</h2>
      <div class="cards" style="margin-bottom:1rem;">
        <div class="card">
          <div class="label">Status</div>
          <div class="value {compliance_status_class}">{compliance_status}</div>
        </div>
        <div class="card">
          <div class="label">Checks Passed</div>
          <div class="value">{compliance_pass}/{compliance_total}</div>
        </div>
      </div>
      <div style="overflow-x:auto;">
      <table>
        <thead><tr><th>Status</th><th>ID</th><th>Article</th><th>Requirement</th><th>Evidence</th></tr></thead>
        <tbody>{compliance_rows_html}</tbody>
      </table>
      </div>
    </div>"""
    else:
        compliance_section = f'<div class="section"><h2>EU AI Act Compliance</h2>{no_compliance}</div>'

    # === Build drift section HTML ===
    drift_baseline = drift_data.get("baseline", {})
    drift_baseline_info = ""
    if drift_baseline and drift_baseline.get("session_count"):
        drift_baseline_info = f"""
      <div style="margin-top:0.8rem;">
        <div class="detail-label">Baseline</div>
        <div style="font-size:0.82rem;">{drift_baseline.get("session_count", 0)} sessions, {drift_baseline.get("known_tools", 0)} known tools, avg interval {drift_baseline.get("avg_interval", 0):.1f}s</div>
      </div>"""

    if drift_data.get("anomalies") is not None:
        anomalies_table = ""
        if anomalies_rows_html:
            anomalies_table = f"""
      <div style="overflow-x:auto;">
      <table>
        <thead><tr><th>Severity</th><th>Type</th><th>Description</th></tr></thead>
        <tbody>{anomalies_rows_html}</tbody>
      </table>
      </div>"""
        else:
            anomalies_table = '<p style="color:var(--green);font-size:0.82rem;">No anomalies detected. Behavior is within normal range.</p>'

        drift_section = f"""
    <div class="section">
      <h2>Behavior Drift Detection</h2>
      <div class="cards" style="margin-bottom:1rem;">
        <div class="card">
          <div class="label">Status</div>
          <div class="value {drift_class}">{"DRIFT DETECTED" if drift_detected else "NORMAL"}</div>
        </div>
        <div class="card">
          <div class="label">Drift Score</div>
          <div class="value">{drift_score:.0f}/100</div>
          <div class="score-bar"><div class="score-fill" style="width:{drift_score}%;background:var(--{'red' if drift_score >= 60 else 'orange' if drift_score >= 30 else 'green'});"></div></div>
        </div>
        <div class="card">
          <div class="label">Anomalies</div>
          <div class="value">{anomaly_count}</div>
        </div>
      </div>
      {anomalies_table}
      {drift_baseline_info}
    </div>"""
    else:
        drift_section = f'<div class="section"><h2>Behavior Drift Detection</h2>{no_drift}</div>'

    # === Build permissions section HTML ===
    if permissions_rows_html:
        permissions_section = f"""
    <div class="section">
      <h2>Agent Permissions</h2>
      <div style="overflow-x:auto;">
      <table>
        <thead><tr><th>Agent</th><th>Tool</th><th>Permission</th><th>Reason</th></tr></thead>
        <tbody>{permissions_rows_html}</tbody>
      </table>
      </div>
    </div>"""
    else:
        permissions_section = f'<div class="section"><h2>Agent Permissions</h2>{no_perms}</div>'

    # === Build cost section HTML ===
    if cost_model_rows_html or cost_agent_rows_html:
        cost_tables = ""
        if cost_model_rows_html:
            cost_tables += f"""
      <h3 style="font-size:0.85rem;color:var(--muted);margin:1rem 0 0.4rem;">By Model</h3>
      <div style="overflow-x:auto;">
      <table>
        <thead><tr><th>Model</th><th>Calls</th><th>Input Tokens</th><th>Output Tokens</th><th>Cost (USD)</th></tr></thead>
        <tbody>{cost_model_rows_html}</tbody>
      </table>
      </div>"""
        if cost_agent_rows_html:
            cost_tables += f"""
      <h3 style="font-size:0.85rem;color:var(--muted);margin:1rem 0 0.4rem;">By Agent</h3>
      <div style="overflow-x:auto;">
      <table>
        <thead><tr><th>Agent</th><th>Calls</th><th>Input Tokens</th><th>Output Tokens</th><th>Cost (USD)</th></tr></thead>
        <tbody>{cost_agent_rows_html}</tbody>
      </table>
      </div>"""

        cost_section = f"""
    <div class="section">
      <h2>Cost Tracking</h2>
      <div class="cards" style="margin-bottom:1rem;">
        <div class="card">
          <div class="label">Total Cost</div>
          <div class="value">${total_cost:.4f}</div>
        </div>
        <div class="card">
          <div class="label">Total Tokens</div>
          <div class="value">{total_tokens:,}</div>
        </div>
        <div class="card">
          <div class="label">Input / Output</div>
          <div class="value" style="font-size:1rem;">{total_input_tokens:,} / {total_output_tokens:,}</div>
        </div>
      </div>
      {cost_tables}
    </div>"""
    else:
        cost_section = f'<div class="section"><h2>Cost Tracking</h2>{no_cost}</div>'

    # === Build topology section HTML ===
    if topo_nodes_html or topo_edges_html:
        edges_table = ""
        if topo_edges_html:
            edges_table = f"""
      <div style="overflow-x:auto;">
      <table>
        <thead><tr><th>Source</th><th>Type</th><th>Target</th><th>Count</th></tr></thead>
        <tbody>{topo_edges_html}</tbody>
      </table>
      </div>"""

        topo_section = f"""
    <div class="section">
      <h2>Agent Topology</h2>
      <div class="cards" style="margin-bottom:1rem;">
        <div class="card">
          <div class="label">Agents</div>
          <div class="value">{unique_agents}</div>
        </div>
        <div class="card">
          <div class="label">Interactions</div>
          <div class="value">{total_interactions}</div>
        </div>
      </div>
      <div class="detail-label" style="margin-bottom:0.3rem;">Agents</div>
      <div style="margin-bottom:0.8rem;">{topo_nodes_html}</div>
      {edges_table}
    </div>"""
    else:
        topo_section = f'<div class="section"><h2>Agent Topology</h2>{no_topo}</div>'

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>InALign Dashboard — {session_id}</title>
<style>
  :root {{
    --bg: #0d1117; --card: #161b22; --border: #30363d;
    --text: #e6edf3; --muted: #8b949e;
    --green: #3fb950; --red: #f85149; --blue: #58a6ff;
    --purple: #bc8cff; --orange: #d29922; --yellow: #e3b341;
  }}
  * {{ margin: 0; padding: 0; box-sizing: border-box; }}
  body {{
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Helvetica, Arial, sans-serif;
    background: var(--bg); color: var(--text);
    line-height: 1.6; padding: 2rem; max-width: 1200px; margin: 0 auto;
  }}
  .header {{ text-align: center; margin-bottom: 1.5rem; padding-bottom: 1rem; border-bottom: 1px solid var(--border); }}
  .header h1 {{ font-size: 1.8rem; margin-bottom: 0.3rem; }}
  .header .subtitle {{ color: var(--muted); font-size: 0.9rem; }}

  /* Tabs */
  .tabs {{ display: flex; gap: 0; margin-bottom: 1.5rem; border-bottom: 2px solid var(--border); overflow-x: auto; }}
  .tab {{
    padding: 0.6rem 1.2rem; cursor: pointer; color: var(--muted);
    font-weight: 500; font-size: 0.85rem; border-bottom: 2px solid transparent;
    margin-bottom: -2px; transition: all 0.15s; white-space: nowrap;
  }}
  .tab:hover {{ color: var(--text); }}
  .tab.active {{ color: var(--blue); border-bottom-color: var(--blue); }}
  .tab-panel {{ display: none; }}
  .tab-panel.active {{ display: block; }}

  /* Toolbar */
  .toolbar {{ display: flex; gap: 0.5rem; justify-content: flex-end; margin-bottom: 1rem; flex-wrap: wrap; }}
  .dl-btn {{
    display: inline-flex; align-items: center; gap: 0.4rem;
    padding: 0.4rem 1rem; background: var(--card); border: 1px solid var(--border);
    border-radius: 6px; color: var(--blue); font-size: 0.8rem; font-weight: 500;
    cursor: pointer; transition: background 0.15s, border-color 0.15s;
  }}
  .dl-btn:hover {{ background: rgba(88,166,255,0.1); border-color: var(--blue); }}
  .dl-btn svg {{ width: 14px; height: 14px; fill: currentColor; }}

  /* Cards */
  .cards {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(160px, 1fr)); gap: 0.8rem; margin-bottom: 1.5rem; }}
  .card {{ background: var(--card); border: 1px solid var(--border); border-radius: 8px; padding: 1rem; }}
  .card .label {{ color: var(--muted); font-size: 0.75rem; text-transform: uppercase; letter-spacing: 0.05em; margin-bottom: 0.2rem; }}
  .card .value {{ font-size: 1.4rem; font-weight: 600; }}
  .card .value.pass {{ color: var(--green); }}
  .card .value.fail {{ color: var(--red); }}
  .card .value.warn {{ color: var(--orange); }}
  .card .value.na {{ color: var(--muted); }}

  .section {{ background: var(--card); border: 1px solid var(--border); border-radius: 8px; padding: 1.2rem; margin-bottom: 1.2rem; }}
  .section h2 {{ font-size: 1rem; margin-bottom: 0.8rem; padding-bottom: 0.4rem; border-bottom: 1px solid var(--border); }}

  /* Score bar */
  .score-bar {{ height: 6px; background: var(--bg); border-radius: 3px; overflow: hidden; margin-top: 0.3rem; }}
  .score-fill {{ height: 100%; border-radius: 3px; }}

  /* Table */
  table {{ width: 100%; border-collapse: collapse; font-size: 0.82rem; }}
  th {{ text-align: left; color: var(--muted); font-weight: 500; padding: 0.4rem 0.6rem; border-bottom: 1px solid var(--border); font-size: 0.72rem; text-transform: uppercase; letter-spacing: 0.05em; }}
  td {{ padding: 0.4rem 0.6rem; border-bottom: 1px solid var(--border); vertical-align: middle; }}
  .record-row.expandable {{ cursor: pointer; }}
  .record-row.expandable:hover {{ background: rgba(88,166,255,0.06); }}
  .record-row .arrow {{ display: inline-block; font-size: 0.55rem; margin-right: 0.2rem; transition: transform 0.15s; color: var(--muted); }}
  .record-row .arrow.empty {{ visibility: hidden; }}
  .record-row.open .arrow {{ transform: rotate(90deg); }}
  .seq {{ color: var(--muted); font-weight: 500; }}
  .hash, .timestamp {{ font-family: 'SF Mono', Monaco, Consolas, monospace; font-size: 0.75rem; color: var(--muted); }}
  .action-name {{ font-weight: 500; }}
  .badge {{ display: inline-block; padding: 0.12rem 0.45rem; border-radius: 4px; font-size: 0.68rem; font-weight: 500; text-transform: uppercase; }}
  .type-user {{ background: rgba(63,185,80,0.15); color: var(--green); }}
  .type-tool {{ background: rgba(88,166,255,0.15); color: var(--blue); }}
  .type-decision {{ background: rgba(188,140,255,0.15); color: var(--purple); }}
  .type-file {{ background: rgba(210,153,34,0.15); color: var(--orange); }}
  .type-llm {{ background: rgba(248,81,73,0.15); color: var(--red); }}

  /* Status badges */
  .st-pass {{ background: rgba(63,185,80,0.15); color: var(--green); }}
  .st-warn {{ background: rgba(210,153,34,0.15); color: var(--orange); }}
  .st-fail {{ background: rgba(248,81,73,0.15); color: var(--red); }}
  .st-na {{ background: rgba(139,148,158,0.15); color: var(--muted); }}

  .mono-sm {{ font-family: 'SF Mono', Monaco, Consolas, monospace; font-size: 0.75rem; }}
  .desc-cell {{ max-width: 300px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }}

  .detail-row td {{ padding: 0; }}
  .detail-box {{ background: var(--bg); padding: 0.6rem 1rem; margin: 0.2rem 0.6rem 0.4rem 1.5rem; border-radius: 6px; border-left: 3px solid var(--blue); font-size: 0.8rem; }}
  .detail-label {{ color: var(--muted); font-size: 0.68rem; text-transform: uppercase; letter-spacing: 0.05em; margin-top: 0.3rem; }}
  .detail-label:first-child {{ margin-top: 0; }}
  .detail-value {{ color: var(--text); word-break: break-word; margin-bottom: 0.2rem; }}
  .detail-pre {{ color: var(--text); font-family: 'SF Mono', Monaco, Consolas, monospace; font-size: 0.75rem; white-space: pre-wrap; word-break: break-word; background: rgba(88,166,255,0.04); padding: 0.3rem; border-radius: 4px; margin-bottom: 0.2rem; }}

  .merkle {{ font-family: monospace; font-size: 0.8rem; color: var(--blue); word-break: break-all; background: rgba(88,166,255,0.08); padding: 0.6rem; border-radius: 6px; margin-top: 0.4rem; }}
  .stat-chip {{ display: inline-block; padding: 0.15rem 0.5rem; background: var(--bg); border: 1px solid var(--border); border-radius: 12px; font-size: 0.75rem; margin: 0.15rem; }}

  /* Session Log */
  .log-entry {{ padding: 0.4rem 0.6rem; border-bottom: 1px solid rgba(48,54,61,0.5); font-size: 0.82rem; }}
  .log-entry.log-expandable {{ cursor: pointer; }}
  .log-entry.log-expandable:hover {{ background: rgba(88,166,255,0.04); }}
  .log-entry .arrow {{ font-size: 0.55rem; color: var(--muted); transition: transform 0.15s; display: inline-block; }}
  .log-entry.open .arrow {{ transform: rotate(90deg); }}
  .log-header {{ display: flex; align-items: center; gap: 0.5rem; }}
  .log-badge {{ display: inline-block; padding: 0.1rem 0.4rem; border-radius: 4px; font-size: 0.65rem; font-weight: 600; min-width: 65px; text-align: center; }}
  .role-user {{ background: rgba(63,185,80,0.15); color: var(--green); }}
  .role-assistant {{ background: rgba(88,166,255,0.15); color: var(--blue); }}
  .role-thinking {{ background: rgba(188,140,255,0.15); color: var(--purple); }}
  .role-tool {{ background: rgba(210,153,34,0.15); color: var(--orange); }}
  .log-preview {{ flex: 1; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }}
  .log-muted {{ color: var(--muted); }}
  .log-ts {{ color: var(--muted); font-size: 0.72rem; font-family: monospace; white-space: nowrap; }}
  .log-full {{ padding: 0 0.6rem 0.5rem 5rem; }}
  .log-pre {{ font-family: 'SF Mono', Monaco, Consolas, monospace; font-size: 0.75rem; color: var(--text); white-space: pre-wrap; word-break: break-word; background: var(--bg); padding: 0.6rem; border-radius: 6px; border-left: 3px solid var(--purple); max-height: 400px; overflow-y: auto; }}
  .log-filter {{ display: flex; gap: 0.4rem; margin-bottom: 0.8rem; flex-wrap: wrap; }}
  .log-filter-btn {{ padding: 0.2rem 0.6rem; background: var(--bg); border: 1px solid var(--border); border-radius: 12px; color: var(--muted); font-size: 0.75rem; cursor: pointer; }}
  .log-filter-btn.active {{ border-color: var(--blue); color: var(--blue); }}

  /* AI Analysis */
  .ai-section {{ background: var(--card); border: 1px solid var(--border); border-radius: 8px; padding: 1.5rem; }}
  .ai-input {{ display: flex; gap: 0.5rem; margin-bottom: 1rem; }}
  .ai-input input {{ flex: 1; padding: 0.5rem 0.8rem; background: var(--bg); border: 1px solid var(--border); border-radius: 6px; color: var(--text); font-size: 0.85rem; }}
  .ai-input input::placeholder {{ color: var(--muted); }}
  .ai-input select {{ padding: 0.5rem; background: var(--bg); border: 1px solid var(--border); border-radius: 6px; color: var(--text); font-size: 0.85rem; }}
  .ai-btn {{ padding: 0.5rem 1.2rem; background: var(--blue); border: none; border-radius: 6px; color: #fff; font-weight: 600; cursor: pointer; font-size: 0.85rem; }}
  .ai-btn:hover {{ opacity: 0.9; }}
  .ai-btn:disabled {{ opacity: 0.5; cursor: not-allowed; }}
  .ai-result {{ background: var(--bg); border-radius: 6px; padding: 1rem; margin-top: 1rem; display: none; }}

  .footer {{ text-align: center; color: var(--muted); font-size: 0.75rem; margin-top: 2rem; padding-top: 0.8rem; border-top: 1px solid var(--border); }}
  .footer a {{ color: var(--blue); text-decoration: none; }}

  @media (max-width: 600px) {{
    body {{ padding: 1rem; }}
    .cards {{ grid-template-columns: 1fr 1fr; }}
    .tabs {{ overflow-x: auto; }}
    .log-preview {{ max-width: 200px; }}
    .desc-cell {{ max-width: 150px; }}
  }}
</style>
</head>
<body>

<div class="header">
  <h1>InALign Dashboard</h1>
  <div class="subtitle">Tamper-proof audit trail &mdash; {now}</div>
</div>

<div class="tabs">
  <div class="tab active" data-tab="overview">Overview</div>
  <div class="tab" data-tab="chain">Provenance Chain</div>
  <div class="tab" data-tab="log">Session Log ({total_log})</div>
  <div class="tab" data-tab="security">Security</div>
  <div class="tab" data-tab="governance">Governance</div>
  <div class="tab" data-tab="ai">AI Analysis</div>
</div>

<!-- === OVERVIEW === -->
<div class="tab-panel active" id="panel-overview">
  <div class="toolbar">
    <button class="dl-btn" onclick="downloadJSON()">
      <svg viewBox="0 0 16 16"><path d="M2.75 14A1.75 1.75 0 011 12.25v-2.5a.75.75 0 011.5 0v2.5c0 .138.112.25.25.25h10.5a.25.25 0 00.25-.25v-2.5a.75.75 0 011.5 0v2.5A1.75 1.75 0 0113.25 14H2.75z"/><path d="M7.25 7.689V2a.75.75 0 011.5 0v5.689l1.97-1.969a.749.749 0 111.06 1.06l-3.25 3.25a.749.749 0 01-1.06 0L4.22 6.78a.749.749 0 111.06-1.06l1.97 1.969z"/></svg>
      JSON
    </button>
    <button class="dl-btn" onclick="downloadCSV()">
      <svg viewBox="0 0 16 16"><path d="M2.75 14A1.75 1.75 0 011 12.25v-2.5a.75.75 0 011.5 0v2.5c0 .138.112.25.25.25h10.5a.25.25 0 00.25-.25v-2.5a.75.75 0 011.5 0v2.5A1.75 1.75 0 0113.25 14H2.75z"/><path d="M7.25 7.689V2a.75.75 0 011.5 0v5.689l1.97-1.969a.749.749 0 111.06 1.06l-3.25 3.25a.749.749 0 01-1.06 0L4.22 6.78a.749.749 0 111.06-1.06l1.97 1.969z"/></svg>
      CSV
    </button>
  </div>

  <div class="cards">
    <div class="card">
      <div class="label">Session</div>
      <div class="value" style="font-size:1rem; font-family:monospace;">{session_id}</div>
    </div>
    <div class="card">
      <div class="label">Chain Integrity</div>
      <div class="value {chain_class}">{"VERIFIED" if verification.get("valid") else "BROKEN"}</div>
    </div>
    <div class="card">
      <div class="label">Records</div>
      <div class="value">{total_records}</div>
    </div>
    <div class="card">
      <div class="label">Session Log</div>
      <div class="value">{total_log}</div>
    </div>
    <div class="card">
      <div class="label">OWASP Score</div>
      <div class="value {owasp_status_class}">{owasp_score if owasp_data.get("checks") else "—"}</div>
      {"<div class='score-bar'><div class='score-fill' style='width:" + str(owasp_score) + "%;background:var(--" + ("red" if owasp_score >= 60 else "orange" if owasp_score >= 30 else "green") + ");'></div></div>" if owasp_data.get("checks") else ""}
    </div>
    <div class="card">
      <div class="label">Compliance</div>
      <div class="value {compliance_status_class}">{compliance_status if compliance_data.get("checks") else "—"}</div>
    </div>
    <div class="card">
      <div class="label">Drift</div>
      <div class="value {drift_class}">{"DETECTED" if drift_detected else "NORMAL" if drift_data.get("anomalies") is not None else "—"}</div>
    </div>
  </div>

  <div class="section">
    <h2>Merkle Root</h2>
    <div class="merkle">{merkle_root}</div>
  </div>

  <div class="section">
    <h2>Provenance Summary</h2>
    <div>{type_summary_html}</div>
  </div>

  {"<div class='section'><h2>Session Log Summary</h2><div>" + log_summary_html + "</div></div>" if log_summary_html else ""}
</div>

<!-- === PROVENANCE CHAIN === -->
<div class="tab-panel" id="panel-chain">
  <div class="section">
    <h2>Provenance Chain ({total_records} records)</h2>
    <p style="color:var(--muted);font-size:0.75rem;margin-bottom:0.6rem;">Click a row to see details</p>
    <table>
      <thead><tr><th>#</th><th>Type</th><th>Action</th><th>Hash</th><th>Previous</th><th>Time</th></tr></thead>
      <tbody>{records_html}</tbody>
    </table>
  </div>
</div>

<!-- === SESSION LOG === -->
<div class="tab-panel" id="panel-log">
  <div class="section">
    <h2>Full Session Log ({total_log} events)</h2>
    <div class="log-filter">
      <span class="log-filter-btn active" data-filter="all">All</span>
      <span class="log-filter-btn" data-filter="user">User</span>
      <span class="log-filter-btn" data-filter="assistant">Assistant</span>
      <span class="log-filter-btn" data-filter="thinking">Thinking</span>
      <span class="log-filter-btn" data-filter="tool_call">Tool Call</span>
      <span class="log-filter-btn" data-filter="tool_result">Tool Result</span>
    </div>
    <div id="session-log-container">
      {session_log_html if session_log_html else '<p style="color:var(--muted);">No session log data. Run <code>inalign-install --ingest</code> to import Claude Code sessions.</p>'}
    </div>
  </div>
</div>

<!-- === SECURITY === -->
<div class="tab-panel" id="panel-security">
  {owasp_section}
  {compliance_section}
  {drift_section}
</div>

<!-- === GOVERNANCE === -->
<div class="tab-panel" id="panel-governance">
  {permissions_section}
  {cost_section}
  {topo_section}
</div>

<!-- === AI ANALYSIS === -->
<div class="tab-panel" id="panel-ai">
  <div class="ai-section">
    <h2 style="margin-bottom:1rem;">AI Security Analysis</h2>
    <p style="color:var(--muted);font-size:0.82rem;margin-bottom:1rem;">Enter your API key to run AI-powered deep analysis on this session. Your key is never stored — it stays in your browser only.</p>
    <div class="ai-input">
      <select id="ai-provider">
        <option value="openai">OpenAI (GPT-4o-mini)</option>
        <option value="anthropic">Anthropic (Claude Sonnet)</option>
      </select>
      <input type="password" id="ai-key" placeholder="API Key (sk-... or sk-ant-...)" />
      <button class="ai-btn" id="ai-run" onclick="runAI()">Analyze</button>
    </div>
    <div id="ai-status" style="color:var(--muted);font-size:0.82rem;"></div>
    <div class="ai-result" id="ai-result"></div>
    <div style="margin-top:1.2rem;padding:0.8rem;background:var(--bg);border-radius:6px;border:1px solid var(--border);">
      <p style="color:var(--muted);font-size:0.78rem;margin-bottom:0.4rem;"><strong>Tip:</strong> For best results, serve this report with the local proxy:</p>
      <code style="color:var(--blue);font-size:0.78rem;">inalign-report</code>
      <span style="color:var(--muted);font-size:0.72rem;"> &mdash; enables both OpenAI &amp; Anthropic from browser</span>
      <br/><span style="color:var(--muted);font-size:0.72rem;">Or use CLI: <code style="color:var(--blue);">inalign-analyze --api-key KEY --provider openai --latest --save</code></span>
    </div>
  </div>
</div>

<div class="footer">
  <p>Generated by <a href="https://github.com/Intellirim/inalign">InALign</a> &mdash; AI Agent Governance Platform</p>
</div>

SCRIPT_PLACEHOLDER

</body>
</html>"""

    # Build script outside f-string to avoid JSON {} conflicts
    script_tag = (
        "<script>\n"
        "const _DATA = " + export_json_escaped + ";\n"
        "\n"
        "// === Tabs ===\n"
        "document.querySelectorAll('.tab').forEach(tab => {\n"
        "  tab.addEventListener('click', () => {\n"
        "    document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));\n"
        "    document.querySelectorAll('.tab-panel').forEach(p => p.classList.remove('active'));\n"
        "    tab.classList.add('active');\n"
        "    document.getElementById('panel-' + tab.dataset.tab).classList.add('active');\n"
        "  });\n"
        "});\n"
        "\n"
        "// === Provenance row toggle ===\n"
        "document.querySelectorAll('.record-row.expandable').forEach(row => {\n"
        "  row.addEventListener('click', () => {\n"
        "    const d = document.getElementById('detail-' + row.dataset.idx);\n"
        "    if (!d) return;\n"
        "    const open = d.style.display !== 'none';\n"
        "    d.style.display = open ? 'none' : 'table-row';\n"
        "    row.classList.toggle('open', !open);\n"
        "  });\n"
        "});\n"
        "\n"
        "// === Session log toggle ===\n"
        "document.querySelectorAll('.log-entry.log-expandable').forEach(entry => {\n"
        "  entry.addEventListener('click', () => {\n"
        "    const d = document.getElementById('log-' + entry.dataset.log);\n"
        "    if (!d) return;\n"
        "    const open = d.style.display !== 'none';\n"
        "    d.style.display = open ? 'none' : 'block';\n"
        "    entry.classList.toggle('open', !open);\n"
        "  });\n"
        "});\n"
        "\n"
        "// === Session log filter ===\n"
        "document.querySelectorAll('.log-filter-btn').forEach(btn => {\n"
        "  btn.addEventListener('click', () => {\n"
        "    document.querySelectorAll('.log-filter-btn').forEach(b => b.classList.remove('active'));\n"
        "    btn.classList.add('active');\n"
        "    const f = btn.dataset.filter;\n"
        "    document.querySelectorAll('.log-entry').forEach(e => {\n"
        "      if (f === 'all') { e.style.display = ''; return; }\n"
        "      const badge = e.querySelector('.log-badge');\n"
        "      const t = badge ? badge.textContent.toLowerCase().replace(/\\s/g,'_') : '';\n"
        "      e.style.display = t.includes(f) ? '' : 'none';\n"
        "      const full = document.getElementById('log-' + e.dataset.log);\n"
        "      if (full && e.style.display === 'none') full.style.display = 'none';\n"
        "    });\n"
        "  });\n"
        "});\n"
        "\n"
        "// === Downloads ===\n"
        "function downloadJSON() {\n"
        "  const blob = new Blob([JSON.stringify(_DATA, null, 2)], {type: 'application/json'});\n"
        "  const a = document.createElement('a');\n"
        "  a.href = URL.createObjectURL(blob);\n"
        "  a.download = 'inalign-' + _DATA.session_id + '.json';\n"
        "  a.click(); URL.revokeObjectURL(a.href);\n"
        "}\n"
        "function downloadCSV() {\n"
        "  const h = ['sequence','type','action','hash','previous_hash','timestamp'];\n"
        "  const rows = _DATA.records.map(r => [r.sequence,r.type,r.name,r.hash,r.previous_hash||'genesis',r.timestamp]"
        '.map(v=>\'"\'+String(v).replace(/"/g,\'""\')+ \'"\').join(\',\'));\n'
        "  const csv = h.join(',')+'\\n'+rows.join('\\n');\n"
        "  const blob = new Blob([csv], {type: 'text/csv'});\n"
        "  const a = document.createElement('a');\n"
        "  a.href = URL.createObjectURL(blob);\n"
        "  a.download = 'inalign-' + _DATA.session_id + '.csv';\n"
        "  a.click(); URL.revokeObjectURL(a.href);\n"
        "}\n"
        "\n"
        "// === AI Analysis ===\n"
        "async function runAI() {\n"
        "  const key = document.getElementById('ai-key').value.trim();\n"
        "  const provider = document.getElementById('ai-provider').value;\n"
        "  const status = document.getElementById('ai-status');\n"
        "  const resultEl = document.getElementById('ai-result');\n"
        "  const btn = document.getElementById('ai-run');\n"
        "  if (!key) { status.textContent = 'Enter an API key.'; return; }\n"
        "  btn.disabled = true;\n"
        "  status.textContent = 'Analyzing session... (this may take 30-60s)';\n"
        "  resultEl.style.display = 'none';\n"
        "  const logText = document.getElementById('session-log-container').innerText.slice(0, 15000);\n"
        "  try {\n"
        "    // Try local proxy first (works for both OpenAI & Anthropic)\n"
        "    let text = await tryLocalProxy(provider, key, logText);\n"
        "    if (!text) {\n"
        "      // Fallback: direct API call (Anthropic supports CORS, OpenAI does not)\n"
        "      text = await tryDirectAPI(provider, key, logText);\n"
        "    }\n"
        "    resultEl.style.display = 'block';\n"
        "    resultEl.innerHTML = '<pre style=\"white-space:pre-wrap;color:var(--text);font-size:0.82rem;\">' + text.replace(/</g,'&lt;') + '</pre>';\n"
        "    status.textContent = 'Analysis complete.';\n"
        "  } catch(e) {\n"
        "    status.innerHTML = '<span style=\"color:var(--red)\">Error: ' + e.message + '</span>';\n"
        "    if (e.message.includes('CORS') || e.message.includes('Failed to fetch') || e.message.includes('NetworkError')) {\n"
        "      status.innerHTML += '<br><span style=\"color:var(--muted);font-size:0.78rem;\">Tip: Run <code style=\"color:var(--blue)\">inalign-report</code> to enable browser API calls, or use CLI: <code style=\"color:var(--blue)\">inalign-analyze --api-key KEY --provider '+provider+' --latest --save</code></span>';\n"
        "    }\n"
        "  }\n"
        "  btn.disabled = false;\n"
        "}\n"
        "\n"
        "async function tryLocalProxy(provider, key, sessionData) {\n"
        "  // Check if local proxy is running (inalign-report server)\n"
        "  const proxyUrl = window.location.origin + '/api/analyze';\n"
        "  if (window.location.protocol === 'file:') return null;\n"
        "  try {\n"
        "    const resp = await fetch(proxyUrl, {\n"
        "      method: 'POST',\n"
        "      headers: {'Content-Type': 'application/json'},\n"
        "      body: JSON.stringify({provider, api_key: key, session_data: sessionData})\n"
        "    });\n"
        "    const data = await resp.json();\n"
        "    if (data.error) throw new Error(data.error);\n"
        "    return data.result;\n"
        "  } catch(e) {\n"
        "    if (e.message.includes('Failed to fetch')) return null;\n"
        "    throw e;\n"
        "  }\n"
        "}\n"
        "\n"
        "async function tryDirectAPI(provider, key, sessionData) {\n"
        "  const prompt = 'Analyze this AI agent session for security risks. Return JSON with: risk_score (0-100), risk_level (LOW/MEDIUM/HIGH/CRITICAL), summary, findings (array of {severity,title,description}), recommendations (array of strings).\\n\\nSession data:\\n' + sessionData;\n"
        "  let body, url, headers;\n"
        "  if (provider === 'openai') {\n"
        "    url = 'https://api.openai.com/v1/chat/completions';\n"
        "    headers = {'Content-Type':'application/json','Authorization':'Bearer '+key};\n"
        "    body = JSON.stringify({model:'gpt-4o-mini',messages:[{role:'user',content:prompt}],max_completion_tokens:2000});\n"
        "  } else {\n"
        "    url = 'https://api.anthropic.com/v1/messages';\n"
        "    headers = {'Content-Type':'application/json','x-api-key':key,'anthropic-version':'2023-06-01','anthropic-dangerous-direct-browser-access':'true'};\n"
        "    body = JSON.stringify({model:'claude-sonnet-4-5-20250929',max_tokens:2000,messages:[{role:'user',content:prompt}]});\n"
        "  }\n"
        "  const resp = await fetch(url, {method:'POST',headers,body});\n"
        "  const data = await resp.json();\n"
        "  if (provider === 'openai') return data.choices?.[0]?.message?.content || JSON.stringify(data);\n"
        "  return data.content?.[0]?.text || JSON.stringify(data);\n"
        "}\n"
        "</script>"
    )

    html = html.replace("SCRIPT_PLACEHOLDER", script_tag)
    return html
