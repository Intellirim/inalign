"""
InALign HTML Report Generator

Generates standalone HTML audit reports viewable in any browser.
Works with all storage modes including in-memory (local).
"""

import json
from datetime import datetime, timezone


def generate_html_report(session_id: str, records: list, verification: dict, stats: dict) -> str:
    """Generate a self-contained HTML audit report.

    Args:
        session_id: Current session ID
        records: List of provenance records
        verification: Chain verification result {valid, error, merkle_root}
        stats: Session statistics

    Returns:
        Complete HTML string
    """
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    chain_status = "VERIFIED" if verification.get("valid") else "BROKEN"
    chain_class = "pass" if verification.get("valid") else "fail"
    merkle_root = verification.get("merkle_root", "N/A")

    # Build records HTML
    records_html = ""
    for r in records:
        hash_short = r.get("hash", "")[:16] + "..."
        prev_short = r.get("previous_hash", "genesis")[:16] + "..." if r.get("previous_hash") else "genesis"
        action_type = r.get("type", "unknown")
        type_class = {
            "user_input": "type-user",
            "tool_call": "type-tool",
            "decision": "type-decision",
            "file_read": "type-file",
            "file_write": "type-file",
            "llm_request": "type-llm",
        }.get(action_type, "type-tool")

        records_html += f"""
        <tr>
            <td class="seq">#{r.get('sequence', '?')}</td>
            <td><span class="badge {type_class}">{action_type}</span></td>
            <td class="action-name">{r.get('name', 'unknown')}</td>
            <td class="hash" title="{r.get('hash', '')}">{hash_short}</td>
            <td class="hash" title="{r.get('previous_hash', '')}">{prev_short}</td>
            <td class="timestamp">{r.get('timestamp', '')[:19]}</td>
        </tr>"""

    total_records = len(records)

    # Count by type
    type_counts = {}
    for r in records:
        t = r.get("type", "unknown")
        type_counts[t] = type_counts.get(t, 0) + 1

    type_summary_html = ""
    for t, count in sorted(type_counts.items(), key=lambda x: -x[1]):
        type_summary_html += f'<span class="stat-chip">{t}: {count}</span>'

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>InALign Audit Report — {session_id}</title>
<style>
  :root {{
    --bg: #0d1117;
    --card: #161b22;
    --border: #30363d;
    --text: #e6edf3;
    --muted: #8b949e;
    --green: #3fb950;
    --red: #f85149;
    --blue: #58a6ff;
    --purple: #bc8cff;
    --orange: #d29922;
  }}
  * {{ margin: 0; padding: 0; box-sizing: border-box; }}
  body {{
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Helvetica, Arial, sans-serif;
    background: var(--bg);
    color: var(--text);
    line-height: 1.6;
    padding: 2rem;
    max-width: 1100px;
    margin: 0 auto;
  }}
  .header {{
    text-align: center;
    margin-bottom: 2rem;
    padding-bottom: 1.5rem;
    border-bottom: 1px solid var(--border);
  }}
  .header h1 {{
    font-size: 1.8rem;
    margin-bottom: 0.3rem;
  }}
  .header .subtitle {{
    color: var(--muted);
    font-size: 0.95rem;
  }}
  .cards {{
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
    gap: 1rem;
    margin-bottom: 2rem;
  }}
  .card {{
    background: var(--card);
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 1.2rem;
  }}
  .card .label {{
    color: var(--muted);
    font-size: 0.8rem;
    text-transform: uppercase;
    letter-spacing: 0.05em;
    margin-bottom: 0.3rem;
  }}
  .card .value {{
    font-size: 1.5rem;
    font-weight: 600;
  }}
  .card .value.pass {{ color: var(--green); }}
  .card .value.fail {{ color: var(--red); }}
  .section {{
    background: var(--card);
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 1.5rem;
    margin-bottom: 1.5rem;
  }}
  .section h2 {{
    font-size: 1.1rem;
    margin-bottom: 1rem;
    padding-bottom: 0.5rem;
    border-bottom: 1px solid var(--border);
  }}
  table {{
    width: 100%;
    border-collapse: collapse;
    font-size: 0.85rem;
  }}
  th {{
    text-align: left;
    color: var(--muted);
    font-weight: 500;
    padding: 0.5rem 0.8rem;
    border-bottom: 1px solid var(--border);
    font-size: 0.75rem;
    text-transform: uppercase;
    letter-spacing: 0.05em;
  }}
  td {{
    padding: 0.5rem 0.8rem;
    border-bottom: 1px solid var(--border);
    vertical-align: middle;
  }}
  tr:last-child td {{ border-bottom: none; }}
  tr:hover {{ background: rgba(88,166,255,0.04); }}
  .seq {{ color: var(--muted); font-weight: 500; }}
  .hash {{
    font-family: 'SF Mono', Monaco, Consolas, monospace;
    font-size: 0.78rem;
    color: var(--muted);
  }}
  .timestamp {{
    font-family: 'SF Mono', Monaco, Consolas, monospace;
    font-size: 0.78rem;
    color: var(--muted);
  }}
  .action-name {{ font-weight: 500; }}
  .badge {{
    display: inline-block;
    padding: 0.15rem 0.5rem;
    border-radius: 4px;
    font-size: 0.72rem;
    font-weight: 500;
    text-transform: uppercase;
  }}
  .type-user {{ background: rgba(63,185,80,0.15); color: var(--green); }}
  .type-tool {{ background: rgba(88,166,255,0.15); color: var(--blue); }}
  .type-decision {{ background: rgba(188,140,255,0.15); color: var(--purple); }}
  .type-file {{ background: rgba(210,153,34,0.15); color: var(--orange); }}
  .type-llm {{ background: rgba(248,81,73,0.15); color: var(--red); }}
  .merkle {{
    font-family: 'SF Mono', Monaco, Consolas, monospace;
    font-size: 0.82rem;
    color: var(--blue);
    word-break: break-all;
    background: rgba(88,166,255,0.08);
    padding: 0.8rem;
    border-radius: 6px;
    margin-top: 0.5rem;
  }}
  .chain-viz {{
    display: flex;
    align-items: center;
    gap: 0.3rem;
    flex-wrap: wrap;
    margin-top: 0.8rem;
  }}
  .chain-block {{
    width: 28px;
    height: 28px;
    border-radius: 4px;
    background: rgba(88,166,255,0.2);
    border: 1px solid rgba(88,166,255,0.3);
    display: flex;
    align-items: center;
    justify-content: center;
    font-size: 0.6rem;
    color: var(--blue);
    font-weight: 600;
  }}
  .chain-arrow {{
    color: var(--muted);
    font-size: 0.7rem;
  }}
  .stat-chip {{
    display: inline-block;
    padding: 0.2rem 0.6rem;
    background: var(--bg);
    border: 1px solid var(--border);
    border-radius: 12px;
    font-size: 0.8rem;
    margin: 0.2rem;
  }}
  .footer {{
    text-align: center;
    color: var(--muted);
    font-size: 0.8rem;
    margin-top: 2rem;
    padding-top: 1rem;
    border-top: 1px solid var(--border);
  }}
  .footer a {{ color: var(--blue); text-decoration: none; }}
  @media (max-width: 600px) {{
    body {{ padding: 1rem; }}
    .cards {{ grid-template-columns: 1fr 1fr; }}
    table {{ font-size: 0.75rem; }}
    td, th {{ padding: 0.3rem 0.4rem; }}
  }}
</style>
</head>
<body>

<div class="header">
  <h1>InALign Audit Report</h1>
  <div class="subtitle">Tamper-proof provenance chain &mdash; generated {now}</div>
</div>

<div class="cards">
  <div class="card">
    <div class="label">Session</div>
    <div class="value" style="font-size:1.1rem; font-family:monospace;">{session_id}</div>
  </div>
  <div class="card">
    <div class="label">Chain Integrity</div>
    <div class="value {chain_class}">{"VERIFIED" if verification.get("valid") else "BROKEN"}</div>
  </div>
  <div class="card">
    <div class="label">Total Records</div>
    <div class="value">{total_records}</div>
  </div>
  <div class="card">
    <div class="label">Generated</div>
    <div class="value" style="font-size:0.95rem;">{now[:10]}</div>
  </div>
</div>

<div class="section">
  <h2>Merkle Root</h2>
  <div class="merkle">{merkle_root}</div>
  <div class="chain-viz">
    {"".join(f'<div class="chain-block">{i+1}</div><span class="chain-arrow">→</span>' if i < min(total_records, 20) - 1 else f'<div class="chain-block">{i+1}</div>' for i in range(min(total_records, 20)))}
    {"<span class='chain-arrow'>... +" + str(total_records - 20) + " more</span>" if total_records > 20 else ""}
  </div>
</div>

<div class="section">
  <h2>Action Summary</h2>
  <div>{type_summary_html}</div>
</div>

<div class="section">
  <h2>Provenance Chain ({total_records} records)</h2>
  <table>
    <thead>
      <tr>
        <th>#</th>
        <th>Type</th>
        <th>Action</th>
        <th>Hash</th>
        <th>Previous</th>
        <th>Time</th>
      </tr>
    </thead>
    <tbody>
      {records_html}
    </tbody>
  </table>
</div>

<div class="footer">
  <p>Generated by <a href="https://github.com/Intellirim/inalign">InALign</a> &mdash; AI Agent Governance Platform</p>
  <p style="margin-top:0.3rem;">Verify: Each record's SHA-256 hash chains to the next. Modify one record &rarr; chain breaks.</p>
</div>

</body>
</html>"""

    return html
