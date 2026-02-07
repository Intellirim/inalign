# InALign - AI Agent Governance Platform

**Know what your AI agents did. Prove it.**

Tamper-proof audit trails for AI agents with cryptographic provenance tracking. Essential for compliance, incident response, and trust.

## Features

### Provenance Chain
- **SHA-256 Hash Chain**: Every action creates a cryptographic record linked to the previous one
- **Tamper-Proof**: Modification of any record breaks the chain—immediately detectable
- **W3C PROV Compatible**: Export provenance in standard PROV-JSON format

### User Command Tracking
- **Prompt Recording**: Know exactly what command triggered each action
- **Privacy Options**: Store full commands or hash-only for sensitive data
- **Complete Attribution**: Chain from human intent to agent execution

### Instant Search & Trace
- **Sub-second Search**: Find any action across all sessions instantly
- **Incident Investigation**: "Who modified config.py?" → immediate answer
- **Session Timeline**: Full chronological view of agent activity

### Audit & Compliance
- **Merkle Root Certificates**: Cryptographic proof of chain integrity
- **Export Reports**: JSON, summary, or PROV-JSONLD formats
- **Third-Party Verification**: Verify without trusting InALign

### Policy Engine
- **Configurable Presets**: STRICT_ENTERPRISE, BALANCED, DEV_SANDBOX
- **Runtime Switching**: Change policies without restart
- **Policy Simulation**: Test policies against historical events

## Supported Agents

| Agent | Support |
|-------|---------|
| Claude Code | Native MCP |
| Cursor | Native MCP |
| Windsurf | Native MCP |
| Continue.dev | Native MCP |
| Cline | Native MCP |
| Custom Agents | MCP Protocol |

## Quick Start

### 1. Install

```bash
pip install inalign-mcp
```

### 2. Configure Claude Code

Add to `~/.claude/settings.json`:

```json
{
  "mcpServers": {
    "inalign": {
      "command": "inalign-mcp",
      "env": {
        "API_KEY": "your-api-key"
      }
    }
  }
}
```

### 3. Done!

All agent actions are now automatically recorded with cryptographic provenance.

## MCP Tools

### Provenance Tools

| Tool | Description |
|------|-------------|
| `record_user_command` | Record the user's command/prompt that triggered actions |
| `record_action` | Record an agent action with cryptographic hash |
| `get_provenance` | Get provenance chain (summary/full/prov-jsonld) |
| `verify_provenance` | Verify chain integrity |
| `generate_audit_report` | Generate comprehensive audit report |
| `verify_third_party` | Generate third-party verifiable proof |

### Risk Analysis Tools

| Tool | Description |
|------|-------------|
| `analyze_risk` | Run GraphRAG pattern detection on session |
| `get_behavior_profile` | Get behavioral analysis |
| `get_agent_risk` | Get long-term risk profile for an agent |
| `get_user_risk` | Get aggregated risk for a user/team |
| `list_agents_risk` | Get risk summary for all agents |

### Policy Tools

| Tool | Description |
|------|-------------|
| `get_policy` | Get current policy settings |
| `set_policy` | Change policy preset |
| `list_policies` | List all available presets |
| `simulate_policy` | Test policy against historical events |

## Example: Incident Investigation

**Scenario**: `config.py` was unexpectedly modified.

```python
# Search for who touched the file
results = trace_file("config.py")

# Output:
# Time: 2026-02-05T11:12:06
# Action: write_file
# User Command: "Delete all logs from /var/log"
# User ID: suspicious-user-123
# Hash: e46903fe63f24a3e...
#
# Chain Integrity: VERIFIED
# Cannot be denied - cryptographically proven.
```

## Dashboard

Start the dashboard:

```bash
inalign-dashboard
```

Access at `http://localhost:8080` with your API key.

**Features**:
- Real-time activity monitoring
- Search & trace interface
- Audit report export
- Policy management

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│  AI Agent (Claude Code / Cursor / etc.)                 │
│                                                         │
│  ┌─────────────────────────────────────────────────┐   │
│  │ InALign MCP Server                               │   │
│  │                                                  │   │
│  │  Every tool call → Provenance Chain             │   │
│  │  SHA-256 Hash → Previous Hash Link              │   │
│  │  Neo4j Storage → Graph Analysis                 │   │
│  └─────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────┐
│  Dashboard                                              │
│  - Activity monitoring                                  │
│  - Search & trace                                       │
│  - Audit export                                         │
│  - Policy management                                    │
└─────────────────────────────────────────────────────────┘
```

## Neo4j Graph Schema

```cypher
// Nodes
(:Session {session_id, created_at, agent_name, user_id})
(:Agent {id, type, name})
(:ProvenanceRecord {id, timestamp, activity_type, activity_name, record_hash})
(:Entity {id, type, value_hash})

// Relationships
(ProvenanceRecord)-[:BELONGS_TO]->(Session)
(ProvenanceRecord)-[:PERFORMED_BY]->(Agent)
(ProvenanceRecord)-[:USED]->(Entity)
(ProvenanceRecord)-[:GENERATED]->(Entity)
(ProvenanceRecord)-[:FOLLOWS]->(ProvenanceRecord)
```

## Pricing

| Plan | Actions/mo | Retention | Agents | Price |
|------|-----------|-----------|--------|-------|
| Starter | 1,000 | 7 days | 1 | Free |
| Pro | 50,000 | 30 days | 10 | $49/mo |
| Enterprise | Unlimited | 1 year | Unlimited | Custom |

## Environment Variables

```bash
# Required (get from https://in-a-lign.com)
API_KEY=ial_your_api_key_here

# Optional: Self-hosted API endpoint
API_URL=http://localhost:8080
```

## Development

```bash
# Install
pip install -e ".[dev]"

# Run tests
pytest

# Format
black src/
```

## License

MIT License

## Contact

- Website: [https://in-a-lign.com](https://in-a-lign.com)
- GitHub: [https://github.com/Intellirim/inalign](https://github.com/Intellirim/inalign)
- PyPI: [https://pypi.org/project/inalign-mcp/](https://pypi.org/project/inalign-mcp/)
