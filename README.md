<p align="center">
  <h1 align="center">InALign</h1>
  <p align="center"><strong>Tamper-proof audit trails for AI agents</strong></p>
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
                                  ├─ Graph database (searchable)
                                  ├─ Risk analysis (pattern detection)
                                  └─ Policy engine (real-time guardrails)
```

## Quick Start

**One command. 30 seconds.**

```bash
pip install inalign-mcp && python -m inalign_mcp.install YOUR_API_KEY
```

That's it. Restart your editor. Every agent action is now recorded.

> Get your free API key at [in-a-lign.com](https://in-a-lign.com) (1,000 actions/month free)

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
      "command": "inalign-mcp",
      "env": {
        "API_KEY": "ial_your_key_here"
      }
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
      "command": "inalign-mcp",
      "env": {
        "API_KEY": "ial_your_key_here"
      }
    }
  }
}
```

</details>

## What You Get

### 16 MCP Tools, Zero Configuration

Once installed, your AI agent gains these capabilities automatically:

| Category | Tools | What it does |
|----------|-------|-------------|
| **Provenance** | `record_action`, `record_user_command`, `get_provenance`, `verify_provenance` | Cryptographic audit trail for every action |
| **Audit** | `generate_audit_report`, `verify_third_party` | Compliance reports, third-party verifiable proof |
| **Risk** | `analyze_risk`, `get_behavior_profile`, `get_agent_risk`, `get_user_risk`, `list_agents_risk` | GraphRAG pattern detection: data exfiltration, privilege escalation, suspicious tool chains |
| **Policy** | `get_policy`, `set_policy`, `list_policies`, `simulate_policy` | Runtime guardrails with 3 presets (Strict / Balanced / Sandbox) |

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
| **Claude Code** | Native MCP |
| **Cursor** | Native MCP |
| **Windsurf** | Native MCP |
| **Continue.dev** | Native MCP |
| **Cline** | Native MCP |
| Custom agents | MCP Protocol |

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
         Hash:     e46903fe63f24a3e...

         Chain Integrity: VERIFIED
         Cryptographically proven. Cannot be denied.
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
│  │  Action → Hash Chain → API → Neo4j Graph   │  │
│  │                    ↓                       │  │
│  │           Risk Analysis (GraphRAG)         │  │
│  │           Policy Engine (3 presets)        │  │
│  └────────────────────────────────────────────┘  │
└──────────────────────────────────────────────────┘
                        │
                        ▼
┌──────────────────────────────────────────────────┐
│  InALign Cloud API                               │
│  - Neo4j graph storage                           │
│  - Dashboard (activity, search, audit certs)     │
│  - No agent credentials leave your machine       │
└──────────────────────────────────────────────────┘
```

**Key design decision**: The MCP server runs locally inside your agent. Only provenance data (action names, hashes, timestamps) is sent to the API. Your code and credentials never leave your machine.

## CLI Commands

```bash
inalign-mcp          # Start MCP server (stdio)
inalign-dashboard    # Web dashboard (port 8080)
inalign-install      # One-command installer
inalign-clients      # Manage API keys
inalign-anchor       # Blockchain anchoring service
```

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
