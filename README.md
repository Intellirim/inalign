<p align="center">
  <h1 align="center">InALign</h1>
  <p align="center"><strong>Tamper-proof audit trails for AI coding agents</strong></p>
  <p align="center">Know what your AI agents did. Prove it. Cryptographically.</p>
</p>

<p align="center">
  <a href="https://pypi.org/project/inalign-mcp/"><img src="https://img.shields.io/pypi/v/inalign-mcp?color=blue" alt="PyPI"></a>
  <a href="https://github.com/Intellirim/inalign/blob/main/LICENSE"><img src="https://img.shields.io/github/license/Intellirim/inalign" alt="License"></a>
  <a href="https://pypi.org/project/inalign-mcp/"><img src="https://img.shields.io/pypi/pyversions/inalign-mcp" alt="Python"></a>
  <a href="https://modelcontextprotocol.io"><img src="https://img.shields.io/badge/MCP-compatible-green" alt="MCP"></a>
</p>

---

## The Problem

AI coding agents (Claude Code, Cursor, Copilot) can read, write, and execute anything on your machine. When something goes wrong, you have no reliable way to answer:

- **What** did the agent actually do?
- **Who** told it to do that?
- **When** did it happen?
- **Can I prove it** to my team, auditors, or a court?

Logs can be edited. Memory fades. You need a chain of evidence that **cannot be tampered with**.

## The Solution

InALign is an open-source [MCP server](https://modelcontextprotocol.io/) that sits inside your AI agent and records every action into a **SHA-256 hash chain** -- each record cryptographically linked to the previous one. Modify any record and the chain breaks. Immediately detectable.

```
User prompt ──> Agent action ──> InALign records it
                                  │
                                  ├─ SHA-256 hash chain (tamper-proof)
                                  ├─ Full conversation capture (prompts + responses)
                                  ├─ Interactive HTML reports (graph + timeline)
                                  ├─ Risk analysis (pattern detection)
                                  └─ Policy engine (real-time guardrails)
```

## Quick Start

**One command. No account needed.**

```bash
pip install inalign-mcp
inalign-install --local
```

That's it. Restart your editor. Every agent action is now recorded locally with SHA-256 hash chains. When you close a session, a full conversation report is automatically saved.

> **100% local. Zero telemetry. No API key required.**

<details>
<summary><strong>Manual setup (Claude Code)</strong></summary>

```bash
pip install inalign-mcp
```

Add to `~/.claude/settings.json`:

```json
{
  "mcpServers": {
    "inalign": {
      "command": "python",
      "args": ["-m", "inalign_mcp.server"]
    }
  }
}
```

</details>

<details>
<summary><strong>Manual setup (Cursor)</strong></summary>

```bash
pip install inalign-mcp
```

Add to `~/.cursor/mcp.json`:

```json
{
  "mcpServers": {
    "inalign": {
      "command": "python",
      "args": ["-m", "inalign_mcp.server"]
    }
  }
}
```

</details>

## What You Get

### 16 MCP Tools + Session Capture

Once installed, your AI agent gains these capabilities automatically:

| Category | Tools | What it does |
|----------|-------|-------------|
| **Provenance** | `record_action`, `record_user_command`, `get_provenance`, `verify_provenance` | Cryptographic audit trail for every action |
| **Audit** | `generate_audit_report`, `verify_third_party`, `export_report` | Compliance reports, interactive HTML reports, third-party verifiable proof |
| **Risk** | `analyze_risk`, `get_behavior_profile`, `get_agent_risk`, `get_user_risk`, `list_agents_risk` | GraphRAG pattern detection: data exfiltration, privilege escalation, suspicious tool chains |
| **Policy** | `get_policy`, `set_policy`, `list_policies`, `simulate_policy` | Runtime guardrails with 3 presets (Strict / Balanced / Sandbox) |

### Full Conversation Capture

InALign captures **everything** -- not just metadata:

- **User prompts**: What you asked the agent to do
- **Agent responses**: What the agent said back (including thinking blocks)
- **Tool calls**: Every file read, write, search, and execution with full inputs/outputs
- **Token usage**: Model, tokens used per interaction
- **Timestamps**: Precise timing for every action

All stored as compressed `.json.gz` files locally at `~/.inalign/sessions/`.

### Interactive HTML Reports

Every session generates a self-contained HTML report with:

- **Graph visualization** (vis.js): Interactive node graph showing conversation flow
- **Conversation timeline**: Full chronological view of prompts, responses, and tool calls
- **Search & filter**: Find specific actions, filter by type (user/assistant/tool)
- **SHA-256 verification**: Every record shows its hash for tamper detection
- **Export**: Download as JSON or CSV for further analysis

Reports auto-generate when sessions end. Or generate manually:

```bash
inalign-ingest --latest --save
```

### Provenance Chain

Every action creates an immutable record:

```
Record #1 ──hash──> Record #2 ──hash──> Record #3
   │                    │                    │
   └── user_command     └── file_write       └── tool_call
       timestamp            timestamp            timestamp
       sha256: a1b2c3       sha256: d4e5f6       sha256: g7h8i9
       prev:   000000       prev:   a1b2c3       prev:   d4e5f6
```

Modify record #2? The hash changes. Record #3's `prev` no longer matches. **Chain broken. Tamper detected.**

### Risk Analysis

GraphRAG-powered pattern detection catches:

- **Data exfiltration** -- reading secrets then making network calls
- **Privilege escalation** -- unusual permission patterns
- **Suspicious tool chains** -- uncommon sequences of actions
- **Anomalous behavior** -- deviations from baseline patterns

### Policy Engine

Three presets, runtime-switchable:

| Preset | Use case |
|--------|----------|
| `STRICT_ENTERPRISE` | Production, regulated environments |
| `BALANCED` | Default, everyday development |
| `DEV_SANDBOX` | Experimentation, permissive |

Simulate any policy against historical events before deploying:

```
simulate_policy("STRICT_ENTERPRISE")
→ 12 actions would be blocked, 3 masked, 47 allowed
```

## Supported Agents

Works with any agent that supports [MCP (Model Context Protocol)](https://modelcontextprotocol.io/):

| Agent | Status |
|-------|--------|
| **Claude Code** | Full support (auto-report on session end) |
| **Cursor** | Full support |
| **Windsurf** | Full support |
| **Continue.dev** | Full support |
| **Cline** | Full support |
| Custom agents | MCP Protocol compatible |

## Example: Incident Investigation

**Scenario**: Production config was modified unexpectedly.

```
You:    "Who modified config.py and why?"

InALign: Found 1 match across 23 sessions.

         Session:  abc123def456
         Time:     2026-02-05T11:12:06Z
         Action:   file_write → config.py
         Command:  "Delete all logs from /var/log"
         Agent:    claude-code

         Chain Integrity: VERIFIED
         Full conversation available in session report.
```

From vague concern to **cryptographic proof** in seconds. Open the session report to see the exact prompts, agent reasoning, and tool calls that led to the change.

## Architecture

```
┌──────────────────────────────────────────────────┐
│  Your AI Agent (Claude Code / Cursor / etc.)     │
│                                                  │
│  ┌────────────────────────────────────────────┐  │
│  │  InALign MCP Server (runs locally)         │  │
│  │                                            │  │
│  │  Action → Hash Chain → Local SQLite        │  │
│  │  Session Logs → Compressed JSON            │  │
│  │           ↓                                │  │
│  │  Risk Analysis (GraphRAG)                  │  │
│  │  Policy Engine (3 presets)                 │  │
│  │  Auto HTML Reports (session end)           │  │
│  └────────────────────────────────────────────┘  │
└──────────────────────────────────────────────────┘
```

**Key design decisions**:

- **Local-first**: Everything works offline with SQLite. No cloud required.
- **Zero telemetry**: Your data never leaves your machine.
- **Full content**: Captures actual prompts and responses, not just metadata.
- **Auto-reports**: Interactive HTML reports generated automatically when sessions end.

## CLI Commands

```bash
inalign-install --local  # One-command installer (local SQLite mode)
inalign-mcp              # Start MCP server (stdio)
inalign-ingest           # Parse session logs → interactive HTML reports
inalign-dashboard        # Web dashboard (port 8080)
inalign-clients          # Manage API keys
inalign-anchor           # Blockchain anchoring service
```

### inalign-ingest

Parse any AI agent session log and generate an interactive report:

```bash
# Auto-detect latest Claude Code session
inalign-ingest --latest --save

# Parse a specific session file
inalign-ingest path/to/session.jsonl --save --output report.html

# Export as JSON
inalign-ingest --latest --json
```

## Storage

| Mode | Backend | Use case |
|------|---------|----------|
| **Local** (default) | SQLite (`~/.inalign/provenance.db`) | Personal use, no setup |
| **Cloud** | Neo4j + API | Team use, dashboard, advanced queries |

Session reports are always stored locally at `~/.inalign/sessions/` regardless of mode.

## Self-Hosting

InALign is fully open-source. Run everything on your own infrastructure:

```bash
pip install inalign-mcp[full]

# Set environment variables
export NEO4J_URI=neo4j://localhost:7687
export NEO4J_USER=neo4j
export NEO4J_PASSWORD=your-password

# Start the dashboard
inalign-dashboard
```

## Development

```bash
git clone https://github.com/Intellirim/inalign.git
cd inalign/mcp-server
pip install -e ".[dev]"
pytest
```

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## Security

See [SECURITY.md](SECURITY.md) for vulnerability reporting.

## License

[MIT](LICENSE) -- use it however you want.

## Links

- **PyPI**: [pypi.org/project/inalign-mcp](https://pypi.org/project/inalign-mcp/)
- **Issues**: [github.com/Intellirim/inalign/issues](https://github.com/Intellirim/inalign/issues)
