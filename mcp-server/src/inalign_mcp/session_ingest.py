"""
InALign Session Log Ingestor

Parses session logs from AI coding agents and stores full conversation data
(prompts, responses, tool calls) into InALign provenance chain.

Supported agents:
  - Claude Code (.jsonl)
  - Cursor (.jsonl)
  - Generic JSONL (any agent that outputs {role, content} messages)

Usage:
  inalign-ingest <path-to-session.jsonl> [--output report.html]
  inalign-ingest --dir ~/.claude/projects/ [--latest]
"""

import json
import os
import sys
import hashlib
import gzip
import argparse
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional


def _hash(data: str) -> str:
    return hashlib.sha256(data.encode("utf-8")).hexdigest()


def _truncate(text: str, max_len: int = 500) -> str:
    if len(text) <= max_len:
        return text
    return text[:max_len] + f"... [{len(text) - max_len} chars truncated]"


def _extract_text(content) -> str:
    """Extract text from various content formats."""
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts = []
        for item in content:
            if isinstance(item, dict):
                if item.get("type") == "text":
                    parts.append(item.get("text", ""))
                elif item.get("type") == "thinking":
                    parts.append(f"[thinking] {item.get('thinking', '')}")
                elif item.get("type") == "tool_use":
                    name = item.get("name", "unknown")
                    inp = json.dumps(item.get("input", {}), ensure_ascii=False)
                    parts.append(f"[tool_use: {name}] {_truncate(inp, 300)}")
                elif item.get("type") == "tool_result":
                    parts.append(f"[tool_result] {_truncate(str(item.get('content', '')), 300)}")
            elif isinstance(item, str):
                parts.append(item)
        return "\n".join(parts)
    return str(content) if content else ""


class ConversationRecord:
    """A single turn in the conversation."""

    def __init__(
        self,
        role: str,
        content: str,
        timestamp: str,
        record_type: str = "message",
        tool_name: Optional[str] = None,
        tool_input: Optional[str] = None,
        tool_output: Optional[str] = None,
        model: Optional[str] = None,
        token_usage: Optional[dict] = None,
        sequence: int = 0,
    ):
        self.role = role
        self.content = content
        self.timestamp = timestamp
        self.record_type = record_type  # message, tool_call, tool_result, thinking
        self.tool_name = tool_name
        self.tool_input = tool_input
        self.tool_output = tool_output
        self.model = model
        self.token_usage = token_usage or {}
        self.sequence = sequence
        self.content_hash = _hash(content) if content else _hash("")

    def to_dict(self) -> dict:
        d = {
            "sequence": self.sequence,
            "role": self.role,
            "type": self.record_type,
            "timestamp": self.timestamp,
            "content": self.content,
            "content_hash": self.content_hash,
        }
        if self.tool_name:
            d["tool_name"] = self.tool_name
        if self.tool_input:
            d["tool_input"] = self.tool_input
        if self.tool_output:
            d["tool_output"] = self.tool_output
        if self.model:
            d["model"] = self.model
        if self.token_usage:
            d["token_usage"] = self.token_usage
        return d


class SessionIngestor:
    """Parse and ingest session logs from various AI agents."""

    def __init__(self):
        self.records: list[ConversationRecord] = []
        self.session_id: str = ""
        self.agent_type: str = "unknown"
        self.metadata: dict = {}

    def detect_agent_type(self, first_line: dict) -> str:
        """Detect which agent produced this log."""
        # Claude Code: has sessionId (slug is optional in newer versions)
        if "sessionId" in first_line and ("slug" in first_line or "version" in first_line):
            return "claude-code"
        # Cursor: has composerId or similar
        if "composerId" in first_line or "cursorVersion" in first_line:
            return "cursor"
        # Windsurf / Continue / other
        if "role" in first_line.get("message", {}):
            return "generic-agent"
        return "unknown"

    def parse_claude_code(self, lines: list[dict]) -> list[ConversationRecord]:
        """Parse Claude Code .jsonl format."""
        records = []
        seq = 0

        for line in lines:
            msg_type = line.get("type", "")
            message = line.get("message", {})
            timestamp = line.get("timestamp", "")
            role = message.get("role", msg_type)

            # Skip non-message lines (file-history-snapshot, etc.)
            if msg_type == "file-history-snapshot":
                continue

            content_raw = message.get("content", "")
            if not content_raw and msg_type not in ("user", "assistant"):
                continue

            # Extract content
            content_parts = []
            tool_calls = []

            if isinstance(content_raw, str):
                content_parts.append(content_raw)
            elif isinstance(content_raw, list):
                for item in content_raw:
                    if not isinstance(item, dict):
                        content_parts.append(str(item))
                        continue
                    itype = item.get("type", "")
                    if itype == "text":
                        text = item.get("text", "").strip()
                        if text:
                            content_parts.append(text)
                    elif itype == "thinking":
                        thinking = item.get("thinking", "").strip()
                        if thinking:
                            records.append(ConversationRecord(
                                role="assistant",
                                content=thinking,
                                timestamp=timestamp,
                                record_type="thinking",
                                model=message.get("model"),
                                sequence=seq,
                            ))
                            seq += 1
                    elif itype == "tool_use":
                        tool_name = item.get("name", "unknown")
                        tool_input = json.dumps(
                            item.get("input", {}), ensure_ascii=False, indent=None
                        )
                        tool_calls.append((tool_name, tool_input))
                        records.append(ConversationRecord(
                            role="assistant",
                            content=f"Called tool: {tool_name}",
                            timestamp=timestamp,
                            record_type="tool_call",
                            tool_name=tool_name,
                            tool_input=tool_input,
                            model=message.get("model"),
                            sequence=seq,
                        ))
                        seq += 1
                    elif itype == "tool_result":
                        result_content = _extract_text(item.get("content", ""))
                        if result_content:
                            records.append(ConversationRecord(
                                role="tool",
                                content=result_content,
                                timestamp=timestamp,
                                record_type="tool_result",
                                tool_name=item.get("tool_use_id"),
                                sequence=seq,
                            ))
                            seq += 1

            # Main message content
            main_text = "\n".join(content_parts).strip()
            if main_text:
                token_usage = {}
                usage = message.get("usage", {})
                if usage:
                    token_usage = {
                        "input_tokens": usage.get("input_tokens", 0),
                        "output_tokens": usage.get("output_tokens", 0),
                        "cache_read": usage.get("cache_read_input_tokens", 0),
                    }

                records.append(ConversationRecord(
                    role=role,
                    content=main_text,
                    timestamp=timestamp,
                    record_type="message",
                    model=message.get("model"),
                    token_usage=token_usage if token_usage else None,
                    sequence=seq,
                ))
                seq += 1

        return records

    def parse_generic(self, lines: list[dict]) -> list[ConversationRecord]:
        """Parse generic JSONL format (Cursor, Windsurf, etc.)."""
        records = []
        seq = 0
        for line in lines:
            message = line.get("message", line)
            role = message.get("role", "unknown")
            content = _extract_text(message.get("content", ""))
            timestamp = line.get("timestamp", datetime.now(timezone.utc).isoformat())

            if content.strip():
                records.append(ConversationRecord(
                    role=role,
                    content=content,
                    timestamp=timestamp,
                    record_type="message",
                    model=message.get("model"),
                    sequence=seq,
                ))
                seq += 1
        return records

    def ingest_file(self, filepath: str) -> dict:
        """Ingest a session log file and return parsed data."""
        path = Path(filepath)
        if not path.exists():
            raise FileNotFoundError(f"Session log not found: {filepath}")

        lines = []
        with open(path, "r", encoding="utf-8") as f:
            for raw_line in f:
                raw_line = raw_line.strip()
                if not raw_line:
                    continue
                try:
                    lines.append(json.loads(raw_line))
                except json.JSONDecodeError:
                    continue

        if not lines:
            raise ValueError(f"No valid JSON lines found in {filepath}")

        # Detect agent type from first meaningful line
        first_msg = next(
            (l for l in lines if l.get("type") in ("user", "assistant") or "message" in l),
            lines[0],
        )
        self.agent_type = self.detect_agent_type(first_msg)

        # Extract session metadata
        self.session_id = first_msg.get("sessionId", path.stem)
        self.metadata = {
            "source_file": str(path),
            "agent_type": self.agent_type,
            "version": first_msg.get("version", "unknown"),
            "cwd": first_msg.get("cwd", ""),
            "slug": first_msg.get("slug", ""),
        }

        # Parse based on agent type
        if self.agent_type == "claude-code":
            self.records = self.parse_claude_code(lines)
        else:
            self.records = self.parse_generic(lines)

        return self.to_summary()

    def to_summary(self) -> dict:
        """Return session summary."""
        type_counts = {}
        total_tokens = {"input": 0, "output": 0}
        for r in self.records:
            type_counts[r.record_type] = type_counts.get(r.record_type, 0) + 1
            if r.token_usage:
                total_tokens["input"] += r.token_usage.get("input_tokens", 0)
                total_tokens["output"] += r.token_usage.get("output_tokens", 0)

        return {
            "session_id": self.session_id,
            "agent_type": self.agent_type,
            "total_records": len(self.records),
            "type_breakdown": type_counts,
            "total_tokens": total_tokens,
            "metadata": self.metadata,
        }

    def to_compressed_json(self) -> bytes:
        """Export all records as gzipped JSON for storage."""
        data = {
            "session_id": self.session_id,
            "agent_type": self.agent_type,
            "metadata": self.metadata,
            "ingested_at": datetime.now(timezone.utc).isoformat(),
            "records": [r.to_dict() for r in self.records],
        }
        json_bytes = json.dumps(data, ensure_ascii=False).encode("utf-8")
        return gzip.compress(json_bytes)

    def save_compressed(self, output_dir: Optional[str] = None) -> str:
        """Save compressed session data to disk."""
        if not output_dir:
            output_dir = os.path.join(os.path.expanduser("~"), ".inalign", "sessions")
        os.makedirs(output_dir, exist_ok=True)

        filename = f"{self.session_id}.json.gz"
        filepath = os.path.join(output_dir, filename)

        compressed = self.to_compressed_json()
        with open(filepath, "wb") as f:
            f.write(compressed)

        return filepath

    def generate_conversation_html(self) -> str:
        """Generate a self-contained HTML file with full conversation + interactive graph."""
        now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

        # Build conversation timeline
        conversation_html = ""
        for r in self.records:
            role_class = {
                "user": "msg-user",
                "assistant": "msg-assistant",
                "tool": "msg-tool",
            }.get(r.role, "msg-system")

            type_badge = ""
            if r.record_type == "thinking":
                type_badge = '<span class="badge badge-thinking">thinking</span>'
            elif r.record_type == "tool_call":
                type_badge = f'<span class="badge badge-tool">tool: {r.tool_name or "?"}</span>'
            elif r.record_type == "tool_result":
                type_badge = '<span class="badge badge-result">result</span>'

            # Escape HTML
            safe_content = (
                r.content.replace("&", "&amp;")
                .replace("<", "&lt;")
                .replace(">", "&gt;")
                .replace("\n", "<br>")
            )

            model_tag = f'<span class="model-tag">{r.model}</span>' if r.model else ""

            conversation_html += f"""
            <div class="msg {role_class}" data-seq="{r.sequence}" data-type="{r.record_type}" data-role="{r.role}">
              <div class="msg-header">
                <span class="msg-role">{r.role}</span>
                {type_badge}
                {model_tag}
                <span class="msg-time">{r.timestamp[:19] if r.timestamp else ""}</span>
                <span class="msg-seq">#{r.sequence}</span>
              </div>
              <div class="msg-body">{safe_content}</div>
              <div class="msg-hash" title="{r.content_hash}">SHA-256: {r.content_hash[:16]}...</div>
            </div>"""

        # Build graph nodes/edges JSON for vis
        nodes_json = []
        edges_json = []
        for r in self.records:
            color = {
                "user": "#3fb950",
                "assistant": "#58a6ff",
                "tool": "#d29922",
            }.get(r.role, "#8b949e")

            shape = "dot"
            if r.record_type == "tool_call":
                shape = "diamond"
            elif r.record_type == "thinking":
                shape = "triangle"

            label = r.role
            if r.record_type == "tool_call" and r.tool_name:
                label = r.tool_name
            elif r.record_type == "thinking":
                label = "think"

            nodes_json.append({
                "id": r.sequence,
                "label": f"{label}\\n#{r.sequence}",
                "color": color,
                "shape": shape,
                "title": _truncate(r.content, 200),
                "type": r.record_type,
                "role": r.role,
            })

            if r.sequence > 0:
                edges_json.append({
                    "from": r.sequence - 1,
                    "to": r.sequence,
                    "arrows": "to",
                })

        nodes_str = json.dumps(nodes_json, ensure_ascii=False)
        edges_str = json.dumps(edges_json, ensure_ascii=False)

        # Stats
        type_counts = {}
        role_counts = {}
        for r in self.records:
            type_counts[r.record_type] = type_counts.get(r.record_type, 0) + 1
            role_counts[r.role] = role_counts.get(r.role, 0) + 1

        stats_html = ""
        for t, c in sorted(type_counts.items(), key=lambda x: -x[1]):
            stats_html += f'<span class="stat-chip">{t}: {c}</span>'

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>InALign Session Report — {self.session_id}</title>
<script src="https://unpkg.com/vis-network@9.1.9/standalone/umd/vis-network.min.js"></script>
<style>
  :root {{
    --bg: #0d1117; --card: #161b22; --border: #30363d;
    --text: #e6edf3; --muted: #8b949e; --green: #3fb950;
    --red: #f85149; --blue: #58a6ff; --purple: #bc8cff; --orange: #d29922;
  }}
  * {{ margin:0; padding:0; box-sizing:border-box; }}
  body {{ font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Helvetica,Arial,sans-serif; background:var(--bg); color:var(--text); line-height:1.6; }}

  /* Layout */
  .top-bar {{ background:var(--card); border-bottom:1px solid var(--border); padding:1rem 2rem; display:flex; justify-content:space-between; align-items:center; }}
  .top-bar h1 {{ font-size:1.3rem; }}
  .top-bar .meta {{ color:var(--muted); font-size:0.85rem; }}
  .container {{ display:grid; grid-template-columns:1fr 1fr; height:calc(100vh - 60px); }}
  .panel {{ overflow-y:auto; padding:1rem; }}
  .panel-graph {{ border-right:1px solid var(--border); padding:0; position:relative; }}
  #graph {{ width:100%; height:100%; }}

  /* Tabs */
  .tabs {{ display:flex; border-bottom:1px solid var(--border); background:var(--card); }}
  .tab {{ padding:0.6rem 1.2rem; cursor:pointer; color:var(--muted); border-bottom:2px solid transparent; font-size:0.85rem; }}
  .tab.active {{ color:var(--blue); border-bottom-color:var(--blue); }}
  .tab-content {{ display:none; }}
  .tab-content.active {{ display:block; }}

  /* Stats */
  .stats {{ display:flex; flex-wrap:wrap; gap:0.5rem; padding:0.8rem 1rem; border-bottom:1px solid var(--border); }}
  .stat-chip {{ padding:0.2rem 0.6rem; background:var(--bg); border:1px solid var(--border); border-radius:12px; font-size:0.78rem; color:var(--muted); }}

  /* Messages */
  .msg {{ margin:0.5rem 0; padding:0.8rem 1rem; border-radius:8px; border:1px solid var(--border); background:var(--card); cursor:pointer; transition:border-color 0.2s; }}
  .msg:hover {{ border-color:var(--blue); }}
  .msg.highlight {{ border-color:var(--blue); box-shadow:0 0 10px rgba(88,166,255,0.2); }}
  .msg-user {{ border-left:3px solid var(--green); }}
  .msg-assistant {{ border-left:3px solid var(--blue); }}
  .msg-tool {{ border-left:3px solid var(--orange); }}
  .msg-system {{ border-left:3px solid var(--muted); }}
  .msg-header {{ display:flex; align-items:center; gap:0.5rem; margin-bottom:0.4rem; flex-wrap:wrap; }}
  .msg-role {{ font-weight:600; font-size:0.8rem; text-transform:uppercase; }}
  .msg-user .msg-role {{ color:var(--green); }}
  .msg-assistant .msg-role {{ color:var(--blue); }}
  .msg-tool .msg-role {{ color:var(--orange); }}
  .msg-time {{ color:var(--muted); font-size:0.72rem; font-family:monospace; margin-left:auto; }}
  .msg-seq {{ color:var(--muted); font-size:0.72rem; }}
  .msg-body {{ font-size:0.85rem; line-height:1.5; max-height:200px; overflow-y:auto; word-break:break-word; }}
  .msg-body::-webkit-scrollbar {{ width:4px; }}
  .msg-body::-webkit-scrollbar-thumb {{ background:var(--border); border-radius:2px; }}
  .msg-hash {{ font-family:monospace; font-size:0.68rem; color:var(--muted); margin-top:0.3rem; opacity:0.6; }}

  /* Badges */
  .badge {{ padding:0.1rem 0.4rem; border-radius:3px; font-size:0.68rem; font-weight:500; }}
  .badge-thinking {{ background:rgba(188,140,255,0.15); color:var(--purple); }}
  .badge-tool {{ background:rgba(210,153,34,0.15); color:var(--orange); }}
  .badge-result {{ background:rgba(63,185,80,0.15); color:var(--green); }}
  .model-tag {{ font-size:0.68rem; color:var(--muted); background:var(--bg); padding:0.1rem 0.4rem; border-radius:3px; }}

  /* Filter */
  .filter-bar {{ padding:0.6rem 1rem; border-bottom:1px solid var(--border); display:flex; gap:0.5rem; flex-wrap:wrap; }}
  .filter-btn {{ padding:0.2rem 0.6rem; background:var(--bg); border:1px solid var(--border); border-radius:4px; color:var(--muted); cursor:pointer; font-size:0.75rem; }}
  .filter-btn.active {{ border-color:var(--blue); color:var(--blue); }}

  /* Search */
  .search-box {{ padding:0.6rem 1rem; border-bottom:1px solid var(--border); }}
  .search-box input {{ width:100%; padding:0.4rem 0.8rem; background:var(--bg); border:1px solid var(--border); border-radius:4px; color:var(--text); font-size:0.85rem; }}
  .search-box input:focus {{ outline:none; border-color:var(--blue); }}

  /* Graph legend */
  .graph-legend {{ position:absolute; bottom:10px; left:10px; background:rgba(22,27,34,0.9); border:1px solid var(--border); border-radius:6px; padding:0.5rem 0.8rem; font-size:0.72rem; z-index:10; }}
  .legend-item {{ display:flex; align-items:center; gap:0.4rem; margin:0.2rem 0; }}
  .legend-dot {{ width:10px; height:10px; border-radius:50%; }}

  /* Download buttons */
  .download-bar {{ display:flex; gap:0.5rem; }}
  .dl-btn {{ padding:0.3rem 0.8rem; background:var(--card); border:1px solid var(--border); border-radius:4px; color:var(--blue); cursor:pointer; font-size:0.78rem; text-decoration:none; }}
  .dl-btn:hover {{ border-color:var(--blue); }}

  @media (max-width:900px) {{
    .container {{ grid-template-columns:1fr; grid-template-rows:40vh 1fr; }}
  }}
</style>
</head>
<body>

<div class="top-bar">
  <div>
    <h1>InALign Session Report</h1>
    <div class="meta">
      Session: {self.session_id} &bull; Agent: {self.agent_type} &bull; {len(self.records)} records &bull; {now}
    </div>
  </div>
  <div class="download-bar">
    <a class="dl-btn" onclick="downloadJSON()">Download JSON</a>
    <a class="dl-btn" onclick="downloadCSV()">Download CSV</a>
  </div>
</div>

<div class="container">
  <!-- Left: Interactive Graph -->
  <div class="panel panel-graph">
    <div id="graph"></div>
    <div class="graph-legend">
      <div class="legend-item"><div class="legend-dot" style="background:var(--green)"></div> User</div>
      <div class="legend-item"><div class="legend-dot" style="background:var(--blue)"></div> Assistant</div>
      <div class="legend-item"><div class="legend-dot" style="background:var(--orange)"></div> Tool</div>
      <div class="legend-item"><div class="legend-dot" style="background:var(--purple)"></div> Thinking</div>
    </div>
  </div>

  <!-- Right: Conversation Timeline -->
  <div class="panel" style="padding:0; display:flex; flex-direction:column;">
    <div class="search-box">
      <input type="text" id="search" placeholder="Search conversations..." oninput="filterMessages()">
    </div>
    <div class="filter-bar">
      <button class="filter-btn active" onclick="toggleFilter(this,'all')">All</button>
      <button class="filter-btn" onclick="toggleFilter(this,'message')">Messages</button>
      <button class="filter-btn" onclick="toggleFilter(this,'tool_call')">Tools</button>
      <button class="filter-btn" onclick="toggleFilter(this,'thinking')">Thinking</button>
      <button class="filter-btn" onclick="toggleFilter(this,'tool_result')">Results</button>
    </div>
    <div class="stats">{stats_html}</div>
    <div class="panel" id="timeline" style="flex:1; overflow-y:auto;">
      {conversation_html}
    </div>
  </div>
</div>

<script>
// --- Data ---
const NODES = {nodes_str};
const EDGES = {edges_str};
const SESSION = {{
  id: "{self.session_id}",
  agent: "{self.agent_type}",
  records: {json.dumps([r.to_dict() for r in self.records], ensure_ascii=False)}
}};

// --- Graph ---
const container = document.getElementById('graph');
const network = new vis.Network(container, {{
  nodes: new vis.DataSet(NODES),
  edges: new vis.DataSet(EDGES)
}}, {{
  layout: {{ hierarchical: {{ direction: 'UD', sortMethod: 'directed', levelSeparation: 80, nodeSpacing: 120 }} }},
  physics: {{ enabled: false }},
  interaction: {{ hover: true, tooltipDelay: 100, zoomView: true, dragView: true }},
  nodes: {{ size: 16, font: {{ size: 10, color: '#e6edf3' }}, borderWidth: 2 }},
  edges: {{ color: {{ color: '#30363d', hover: '#58a6ff' }}, width: 1.5, smooth: {{ type: 'cubicBezier' }} }},
}});

// Click graph node → scroll to message
network.on('click', function(params) {{
  if (params.nodes.length > 0) {{
    const seq = params.nodes[0];
    const el = document.querySelector(`.msg[data-seq="${{seq}}"]`);
    if (el) {{
      document.querySelectorAll('.msg.highlight').forEach(m => m.classList.remove('highlight'));
      el.classList.add('highlight');
      el.scrollIntoView({{ behavior: 'smooth', block: 'center' }});
    }}
  }}
}});

// Click message → focus graph node
document.querySelectorAll('.msg').forEach(el => {{
  el.addEventListener('click', () => {{
    const seq = parseInt(el.dataset.seq);
    network.selectNodes([seq]);
    network.focus(seq, {{ scale: 1.5, animation: true }});
    document.querySelectorAll('.msg.highlight').forEach(m => m.classList.remove('highlight'));
    el.classList.add('highlight');
  }});
}});

// --- Filters ---
let activeFilter = 'all';
function toggleFilter(btn, type) {{
  document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
  btn.classList.add('active');
  activeFilter = type;
  filterMessages();
}}

function filterMessages() {{
  const query = document.getElementById('search').value.toLowerCase();
  document.querySelectorAll('.msg').forEach(el => {{
    const matchType = activeFilter === 'all' || el.dataset.type === activeFilter;
    const matchSearch = !query || el.textContent.toLowerCase().includes(query);
    el.style.display = (matchType && matchSearch) ? '' : 'none';
  }});
}}

// --- Downloads ---
function downloadJSON() {{
  const blob = new Blob([JSON.stringify(SESSION, null, 2)], {{ type: 'application/json' }});
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = `inalign-session-${{SESSION.id}}.json`;
  a.click();
}}

function downloadCSV() {{
  let csv = 'sequence,role,type,timestamp,tool_name,content_hash,content\\n';
  SESSION.records.forEach(r => {{
    const content = (r.content || '').replace(/"/g, '""').replace(/\\n/g, ' ');
    csv += `${{r.sequence}},"${{r.role}}","${{r.type}}","${{r.timestamp}}","${{r.tool_name || ''}}","${{r.content_hash}}","${{content}}"\\n`;
  }});
  const blob = new Blob([csv], {{ type: 'text/csv' }});
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = `inalign-session-${{SESSION.id}}.csv`;
  a.click();
}}
</script>
</body>
</html>"""


def convert_session_log_to_chain(
    session_log: list[dict],
    session_id: str,
    agent_name: str = "Claude Code",
):
    """Convert session log events into a SHA-256 hash-chained provenance chain.

    Bridges the gap between rich session logs (unverified, tamper-possible) and
    the cryptographic provenance chain (SHA-256 hash chained, tamper-proof).

    Each session log event becomes a ProvenanceRecord where:
    - content_hash in attributes links to original content (tamper detection)
    - Each record's hash includes previous record's hash (chain integrity)
    - Deterministic IDs enable safe re-runs (idempotent)

    Args:
        session_log: List of ConversationRecord dicts (from json.gz)
        session_id: Session identifier (from Claude Code)
        agent_name: Name of the AI agent

    Returns:
        ProvenanceChain with all events as hash-chained records, or None
    """
    from .provenance import ProvenanceChain, ProvenanceRecord, ActivityType, Agent, Entity
    from .sqlite_storage import init_sqlite, store_session, load_chain, store_records_batch

    if not session_log:
        return None

    init_sqlite()

    # Idempotent: skip if already converted
    existing = load_chain(session_id)
    if existing and len(existing.records) >= len(session_log):
        return existing

    agent = Agent(
        id=f"agent:{agent_name.lower().replace(' ', '-')}:{session_id[:8]}",
        type="ai_agent",
        name=agent_name,
    )

    store_session(session_id, agent)
    chain = ProvenanceChain(session_id, agent)

    # Session log type → ProvenanceRecord ActivityType
    _TYPE_MAP = {
        ("message", "user"): ActivityType.USER_INPUT,
        ("message", "assistant"): ActivityType.LLM_RESPONSE,
        ("tool_call", "assistant"): ActivityType.TOOL_CALL,
        ("tool_result", "tool"): ActivityType.TOOL_RESULT,
        ("thinking", "assistant"): ActivityType.DECISION,
    }
    _FALLBACK = {
        "tool_call": ActivityType.TOOL_CALL,
        "tool_result": ActivityType.TOOL_RESULT,
        "thinking": ActivityType.DECISION,
        "message": ActivityType.LLM_RESPONSE,
    }

    # Entity direction: used (input) vs generated (output)
    _ENTITY_DIR = {
        ActivityType.USER_INPUT: ("prompt", "used"),
        ActivityType.LLM_RESPONSE: ("response", "generated"),
        ActivityType.TOOL_CALL: ("tool_input", "used"),
        ActivityType.TOOL_RESULT: ("tool_output", "generated"),
        ActivityType.DECISION: ("reasoning", "generated"),
    }

    batch = []

    for event in session_log:
        rtype = event.get("type", "message")
        role = event.get("role", "unknown")

        # Map activity type
        atype = _TYPE_MAP.get((rtype, role)) or _FALLBACK.get(rtype, ActivityType.TOOL_CALL)

        # Activity name
        if rtype == "tool_call":
            aname = event.get("tool_name", "unknown_tool")
        elif rtype == "tool_result":
            tn = event.get("tool_name", "unknown")
            aname = f"result:{tn[:30]}"
        elif rtype == "thinking":
            aname = "thinking"
        else:
            aname = f"{role}_message"

        # Attributes: metadata + content_hash for tamper detection
        attrs = {
            "content_hash": event.get("content_hash", ""),
            "role": role,
            "record_type": rtype,
        }
        if event.get("tool_name"):
            attrs["tool_name"] = event["tool_name"]
        if event.get("model"):
            attrs["model"] = event["model"]
        if event.get("token_usage"):
            attrs["token_usage"] = event["token_usage"]

        # Create entity (links content hash to chain)
        content_hash = event.get("content_hash", "")
        edir = _ENTITY_DIR.get(atype, ("data", "used"))
        entity = Entity(
            id=f"entity:ingest:{session_id[:8]}:{chain._sequence:06d}",
            type=edir[0],
            value_hash=content_hash,
        )
        used = [entity] if edir[1] == "used" else []
        generated = [entity] if edir[1] == "generated" else []

        # Timestamp from original event
        ts = event.get("timestamp", "") or datetime.now(timezone.utc).isoformat()

        # Deterministic ID for idempotent re-runs
        record = ProvenanceRecord(
            id=f"prov:ingest:{session_id[:8]}:{chain._sequence:06d}",
            timestamp=ts,
            activity_type=atype,
            activity_name=aname,
            activity_attributes=attrs,
            used_entities=used,
            generated_entities=generated,
            agent=agent,
            previous_hash=chain.latest_hash,
            sequence_number=chain._sequence,
            session_id=session_id,
        )
        record.record_hash = record.compute_hash()

        chain.records.append(record)
        chain._sequence += 1
        batch.append(record)

    # Single-transaction batch write to SQLite
    store_records_batch(batch, session_id)

    return chain


def find_latest_session(base_dir: str) -> Optional[str]:
    """Find the most recently modified .jsonl session file."""
    base = Path(base_dir)
    if not base.exists():
        return None

    jsonl_files = []
    for f in base.rglob("*.jsonl"):
        # Skip subagent files
        if "subagent" in str(f) or "compact" in str(f):
            continue
        jsonl_files.append(f)

    if not jsonl_files:
        return None

    return str(max(jsonl_files, key=lambda f: f.stat().st_mtime))


def main():
    parser = argparse.ArgumentParser(
        description="InALign Session Log Ingestor — Parse AI agent logs into provenance data"
    )
    parser.add_argument(
        "path",
        nargs="?",
        help="Path to .jsonl session file (or directory with --dir)",
    )
    parser.add_argument(
        "--dir",
        action="store_true",
        help="Treat path as directory, find all session files",
    )
    parser.add_argument(
        "--latest",
        action="store_true",
        help="Only process the most recent session file",
    )
    parser.add_argument(
        "--output", "-o",
        help="Output HTML report path (default: ~/inalign-session-report.html)",
    )
    parser.add_argument(
        "--save",
        action="store_true",
        help="Save compressed session data to ~/.inalign/sessions/",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output JSON summary to stdout",
    )

    args = parser.parse_args()

    # Default to Claude Code sessions directory
    if not args.path:
        # Try common locations
        candidates = [
            os.path.join(os.path.expanduser("~"), ".claude", "projects"),
            os.path.join(os.path.expanduser("~"), ".cursor", "sessions"),
        ]
        for c in candidates:
            if os.path.exists(c):
                args.path = c
                args.dir = True
                args.latest = True
                break

    if not args.path:
        print("Error: No session file specified and no default session directory found.")
        print("Usage: inalign-ingest <session.jsonl>")
        sys.exit(1)

    ingestor = SessionIngestor()

    if args.dir or os.path.isdir(args.path):
        if args.latest:
            filepath = find_latest_session(args.path)
            if not filepath:
                print(f"No .jsonl files found in {args.path}")
                sys.exit(1)
            print(f"Latest session: {filepath}")
        else:
            # Process all session files
            base = Path(args.path)
            files = [
                f for f in base.rglob("*.jsonl")
                if "subagent" not in str(f) and "compact" not in str(f)
            ]
            if not files:
                print(f"No .jsonl files found in {args.path}")
                sys.exit(1)
            filepath = str(max(files, key=lambda f: f.stat().st_mtime))
            print(f"Processing: {filepath}")
    else:
        filepath = args.path

    # Parse
    summary = ingestor.ingest_file(filepath)

    if args.json:
        print(json.dumps(summary, indent=2, ensure_ascii=False))
        return

    print(f"\nSession: {summary['session_id']}")
    print(f"Agent:   {summary['agent_type']}")
    print(f"Records: {summary['total_records']}")
    print(f"Types:   {summary['type_breakdown']}")
    print(f"Tokens:  {summary['total_tokens']}")

    # Save compressed
    if args.save:
        saved_path = ingestor.save_compressed()
        print(f"Saved:   {saved_path}")

    # Generate HTML
    output_path = args.output or os.path.join(
        os.path.expanduser("~"), "inalign-session-report.html"
    )
    html = ingestor.generate_conversation_html()
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html)
    print(f"Report:  {output_path}")


if __name__ == "__main__":
    main()
