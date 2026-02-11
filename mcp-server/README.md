<p align="center">
  <h1 align="center">InALign</h1>
  <p align="center"><strong>Tamper-proof audit trails for AI agents</strong></p>
  <p align="center">Know what your AI agents did. Prove it. Cryptographically.</p>
</p>

<p align="center">
  <a href="https://pypi.org/project/inalign-mcp/"><img src="https://img.shields.io/pypi/v/inalign-mcp?color=blue" alt="PyPI"></a>
  <a href="https://github.com/Intellirim/inalign/blob/main/LICENSE"><img src="https://img.shields.io/github/license/Intellirim/inalign" alt="License"></a>
  <a href="https://pypi.org/project/inalign-mcp/"><img src="https://img.shields.io/pypi/pyversions/inalign-mcp" alt="Python"></a>
</p>

---

## The Problem

AI coding agents (Claude Code, Cursor, Copilot) can read, write, and execute anything on your machine. When something goes wrong:

- **What** did the agent actually do?
- **Who** told it to do that?
- **Can you prove it?**

Logs can be edited. Memory fades. You need evidence that **cannot be tampered with**.

## Why Not Just Use Logs?

| | Traditional Logs | InALign |
|---|---|---|
| **Tamper resistance** | None. Anyone with access can edit. | SHA-256 hash chain. Modify one record → chain breaks. |
| **Provenance** | "Something happened at 3pm" | Who commanded it, what the agent did, full causal chain |
| **Risk detection** | Manual review | Automatic: data exfiltration, privilege escalation, suspicious patterns |
| **Guardrails** | After the fact | Runtime policy engine blocks dangerous actions |
| **Audit proof** | "Trust me" | Third-party verifiable cryptographic proof |

## Quick Start

```bash
pip install inalign-mcp && inalign-install --local
```

Restart Claude Code. Done. Every agent action is now recorded with SHA-256 hash chains.

> **That's it.** No API key needed. No account. No cloud. Runs 100% locally in memory.
>
> Want persistent storage? Use `inalign-install YOUR_API_KEY` or [self-host with Neo4j](#self-hosting).

<details>
<summary><strong>Manual setup (without install script)</strong></summary>

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

## What You Get

### 16 MCP Tools, Zero Configuration

Once installed, your AI agent automatically gains:

| Category | Tools | What it does |
|----------|-------|-------------|
| **Provenance** | `record_action`, `record_user_command`, `get_provenance`, `verify_provenance` | Cryptographic audit trail for every action |
| **Audit** | `generate_audit_report`, `verify_third_party` | Compliance reports, third-party verifiable proof |
| **Risk** | `analyze_risk`, `get_behavior_profile`, `get_agent_risk`, `get_user_risk`, `list_agents_risk` | Pattern detection: data exfiltration, privilege escalation, suspicious tool chains |
| **Policy** | `get_policy`, `set_policy`, `list_policies`, `simulate_policy` | Runtime guardrails with 3 presets |

### How the Hash Chain Works

```
Record #1 ──hash──▶ Record #2 ──hash──▶ Record #3
   │                    │                    │
   └── user_command     └── file_write       └── tool_call
       sha256: a1b2c3       sha256: d4e5f6       sha256: g7h8i9
       prev:   000000       prev:   a1b2c3       prev:   d4e5f6
```

Modify record #2? Its hash changes. Record #3's `prev` no longer matches. **Chain broken. Tamper detected.**

This is the same principle behind Git commits and blockchains — except applied to AI agent actions.

### Risk Analysis

GraphRAG-powered pattern detection catches:

- **Data exfiltration** — reading secrets then making network calls
- **Privilege escalation** — unusual permission patterns
- **Suspicious tool chains** — uncommon sequences of actions
- **Anomalous behavior** — deviations from baseline patterns

### Policy Engine

Three presets, switchable at runtime:

| Preset | Use case |
|--------|----------|
| `STRICT_ENTERPRISE` | Production, regulated environments |
| `BALANCED` | Default, everyday development |
| `DEV_SANDBOX` | Experimentation, permissive |

Simulate before deploying:

```
simulate_policy("STRICT_ENTERPRISE")
→ 12 actions would be blocked, 3 masked, 47 allowed
```

## Supported Agents

Works with any agent that supports [MCP (Model Context Protocol)](https://modelcontextprotocol.io/):

| Agent | Status |
|-------|--------|
| **Claude Code** | ✅ Native MCP |
| **Cursor** | ✅ Native MCP |
| **Windsurf** | ✅ Native MCP |
| **Continue.dev** | ✅ Native MCP |
| **Cline** | ✅ Native MCP |
| Custom agents | Via MCP protocol |

## Example: Incident Investigation

Production config was modified unexpectedly. Who did it?

```
You:    "generate an audit report for this session"

InALign: Audit Report
         ─────────────────────────────────
         Session:  abc123def456
         Records:  23 actions recorded
         Chain:    VERIFIED ✓ (all hashes valid)

         Timeline:
         11:12:06  user_command  "Delete all logs from /var/log"
         11:12:08  file_write    config.py (modified)
         11:12:09  tool_call     bash: rm -rf /var/log/*

         Risk:     HIGH — destructive file operations detected
         Policy:   2 actions would be blocked under STRICT_ENTERPRISE
```

From vague concern to **cryptographic proof** in seconds.

## Architecture

```
┌──────────────────────────────────────────────────┐
│  Your AI Agent (Claude Code / Cursor / etc.)     │
│                                                  │
│  ┌────────────────────────────────────────────┐  │
│  │  InALign MCP Server (runs locally)         │  │
│  │                                            │  │
│  │  Action → SHA-256 Hash Chain               │  │
│  │              │                             │  │
│  │     ┌────────┼────────┐                    │  │
│  │     ▼        ▼        ▼                    │  │
│  │  Memory   Neo4j    Cloud API               │  │
│  │  (local)  (self)   (managed)               │  │
│  │                                            │  │
│  │  + Risk Analysis (GraphRAG)                │  │
│  │  + Policy Engine (3 presets)               │  │
│  └────────────────────────────────────────────┘  │
└──────────────────────────────────────────────────┘
```

**Privacy**: The MCP server runs locally. Only provenance metadata (action names, hashes, timestamps) leaves your machine. Your code and credentials stay local.

**Performance**: Recording 1,000 actions adds ~50ms total overhead. Hash chain verification of 10,000 records completes in <200ms. No measurable impact on agent response time.

## Storage Modes

| Mode | Setup | Persistence | Best for |
|------|-------|-------------|----------|
| **Memory** | `--local` (default) | Per session | Trying it out, local dev |
| **Neo4j** | Self-host Neo4j | Permanent | Teams, compliance |
| **Cloud API** | API key | Permanent | Managed service |

## Self-Hosting

Run everything on your own infrastructure:

```bash
pip install inalign-mcp[full]

export NEO4J_URI=neo4j://localhost:7687
export NEO4J_USER=neo4j
export NEO4J_PASSWORD=your-password

# Start the dashboard
inalign-dashboard
```

All data stays on your servers. No external dependencies.

## Development

```bash
git clone https://github.com/Intellirim/inalign.git
cd inalign/mcp-server
pip install -e ".[dev]"
pytest
```

## License

[MIT](LICENSE) — use it however you want.

## Links

- **PyPI**: [pypi.org/project/inalign-mcp](https://pypi.org/project/inalign-mcp/)
- **Issues**: [github.com/Intellirim/inalign/issues](https://github.com/Intellirim/inalign/issues)
