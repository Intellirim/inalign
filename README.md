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
                                  |
                                  +-- SHA-256 hash chain (tamper-proof)
                                  +-- W3C PROV knowledge graph (ontology)
                                  +-- Full conversation capture (prompts + responses)
                                  +-- 6-tab interactive HTML dashboard
                                  +-- GraphRAG risk analysis (11 MITRE ATT&CK patterns)
                                  +-- Compliance (EU AI Act + OWASP LLM Top 10)
                                  +-- Policy engine (real-time guardrails)
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

### 32 MCP Tools + Session Capture

Once installed, your AI agent gains these capabilities automatically:

| Category | Tools | What it does |
|----------|-------|-------------|
| **Provenance** | `record_action`, `record_user_command`, `get_provenance`, `verify_provenance` | Cryptographic audit trail for every action |
| **Audit** | `generate_audit_report`, `verify_third_party`, `export_report`, `list_sessions` | Compliance reports, interactive HTML dashboard, third-party verifiable proof |
| **Risk** | `analyze_risk`, `get_behavior_profile`, `get_agent_risk`, `get_user_risk`, `list_agents_risk` | GraphRAG pattern detection with 11 MITRE ATT&CK-mapped patterns |
| **Policy** | `get_policy`, `set_policy`, `list_policies`, `simulate_policy` | Runtime guardrails with 3 presets (Strict / Balanced / Sandbox) |
| **Compliance** | `generate_compliance_report`, `check_owasp_compliance` | EU AI Act (Articles 9, 12, 14, 15) + OWASP LLM Top 10 |
| **Permissions** | `get_permission_matrix`, `set_agent_permissions` | Per-agent tool access control (allow / deny / audit) |
| **Drift** | `detect_drift`, `get_behavior_baseline` | Behavioral anomaly detection via z-score baseline comparison |
| **Export** | `export_otel` | OpenTelemetry OTLP JSON export (file + optional endpoint push) |
| **Topology** | `track_agent_interaction`, `get_agent_topology`, `track_cost`, `get_cost_report` | Multi-agent interaction graph + token/cost attribution |
| **Ontology** | `ontology_populate`, `ontology_query`, `ontology_stats` | W3C PROV knowledge graph with competency queries |
| **Security Scan** | `ontology_security_scan` | Graph-powered security analysis over the knowledge graph |

### Full Conversation Capture

InALign captures **everything** -- not just metadata:

- **User prompts**: What you asked the agent to do
- **Agent responses**: What the agent said back (including thinking blocks)
- **Tool calls**: Every file read, write, search, and execution with full inputs/outputs
- **Token usage**: Model, tokens used per interaction
- **Timestamps**: Precise timing for every action

All stored as compressed `.json.gz` files locally at `~/.inalign/sessions/`.

### Interactive HTML Dashboard

Every session generates a self-contained 6-tab HTML dashboard:

| Tab | What it shows |
|-----|---------------|
| **Overview** | Session summary, key metrics, hash chain status |
| **Provenance Chain** | Interactive graph (vis.js) of the full hash chain with verification |
| **Session Log** | Chronological conversation timeline with search and filter |
| **Security** | Risk score, detected patterns, MITRE ATT&CK mapping |
| **Governance** | Policy compliance, permission matrix, drift analysis |
| **AI Analysis** | Deep session analysis with causal chain visualization |

Reports auto-generate when sessions end. View them in your browser:

```bash
inalign-report             # Launch dashboard at localhost:8275
inalign-ingest --latest --save  # Generate report for latest session
```

### Provenance Chain

Every action creates an immutable record:

```
Record #1 ──hash──> Record #2 ──hash──> Record #3
   |                    |                    |
   +-- user_command     +-- file_write       +-- tool_call
       timestamp            timestamp            timestamp
       sha256: a1b2c3       sha256: d4e5f6       sha256: g7h8i9
       prev:   000000       prev:   a1b2c3       prev:   d4e5f6
```

Modify record #2? The hash changes. Record #3's `prev` no longer matches. **Chain broken. Tamper detected.**

### Risk Analysis (GraphRAG)

GraphRAG-powered engine using SQLite + in-memory graph (no external database required). Detects 11 attack patterns mapped to MITRE ATT&CK and ATLAS frameworks:

| Pattern | Description | MITRE Mapping |
|---------|-------------|---------------|
| PAT-MFR | Mass File Read | TA0009 Collection (T1005, T1119) |
| PAT-DEX | Data Exfiltration | TA0010 Exfiltration (T1048, T1567) |
| PAT-PEX | Privilege Escalation | TA0004 (T1068, T1548, T1552) |
| PAT-RTC | Rapid Tool Calls | TA0002 Execution (T1059) |
| PAT-SCM | Suspicious Commands | TA0002 Execution (T1059.004) |
| PAT-INJ | Prompt Injection | ATLAS AML.T0051 |
| PAT-REC | Reconnaissance | TA0043 (T1595.002, T1592) |
| PAT-PER | Persistence | TA0003 (T1053, T1546) |
| PAT-EVA | Defense Evasion | TA0005 (T1070, T1027) |
| PAT-GAP | Chain Sequence Gap | INALIGN-001 |
| PAT-BRK | Chain Hash Break | INALIGN-001 |

**Causal chain extraction**: Automatically builds `user_input -> thinking -> tool_call -> tool_result` graphs to trace exactly how agent decisions flow from prompts to actions.

### W3C PROV Knowledge Graph

SQLite-backed knowledge graph following the W3C PROV ontology standard:

- **7 node classes**: Agent, Session, ToolCall, Entity, Decision, Risk, Policy
- **Competency queries** (cq1-cq5):
  - `cq1`: Entity access audit -- which agents accessed which files/resources
  - `cq2`: Exfiltration detection -- read-then-network patterns
  - `cq3`: Policy violations -- actions that violated active policies
  - `cq4`: Impact analysis -- blast radius of a specific action
  - `cq5`: Hash break context -- what happened around chain integrity failures
- **Interactive Canvas visualization**: Click-to-inspect nodes and relationships
- **Security scan**: Graph-powered analysis that traverses relationships to find threats invisible in flat logs

### Compliance Frameworks

**EU AI Act** -- Automated checks against Articles 9, 12, 14, 15 with PASS/PARTIAL/FAIL scoring:
- Risk management documentation (Art. 9)
- Record-keeping and traceability (Art. 12)
- Human oversight mechanisms (Art. 14)
- Accuracy and robustness (Art. 15)

**OWASP LLM Top 10** -- Per-item compliance scoring across all 10 categories including prompt injection, output handling, data poisoning, DoS, supply chain, sensitive information disclosure, plugin security, excessive agency, and overreliance.

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
-> 12 actions would be blocked, 3 masked, 47 allowed
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
         Action:   file_write -> config.py
         Command:  "Delete all logs from /var/log"
         Agent:    claude-code

         Chain Integrity: VERIFIED
         Full conversation available in session report.
```

From vague concern to **cryptographic proof** in seconds. Open the session report to see the exact prompts, agent reasoning, and tool calls that led to the change.

## Architecture

```
+-----------------------------------------------------------+
|  Your AI Agent (Claude Code / Cursor / etc.)              |
|                                                           |
|  +-----------------------------------------------------+ |
|  |  InALign MCP Server (runs locally)                   | |
|  |                                                      | |
|  |  Action --> SHA-256 Hash Chain --> Local SQLite       | |
|  |         --> W3C PROV Ontology  --> Knowledge Graph    | |
|  |  Session Logs --> Compressed JSON (.json.gz)         | |
|  |            |                                         | |
|  |  GraphRAG Risk Analysis (11 MITRE ATT&CK patterns)  | |
|  |  Compliance Engine (EU AI Act + OWASP LLM Top 10)   | |
|  |  Policy Engine (3 presets + permissions)             | |
|  |  Drift Detector (behavioral anomaly z-scores)       | |
|  |  Multi-Agent Topology + Cost Tracking                | |
|  |  OpenTelemetry Export (OTLP JSON)                    | |
|  |  Auto HTML Dashboard (6-tab, session end)            | |
|  +-----------------------------------------------------+ |
+-----------------------------------------------------------+
```

**Key design decisions**:

- **Local-first**: Everything works offline with SQLite. No cloud required. No external databases.
- **Zero telemetry**: Your data never leaves your machine.
- **Full content**: Captures actual prompts and responses, not just metadata.
- **Auto-reports**: 6-tab interactive HTML dashboard generated automatically when sessions end.
- **Standards-based**: W3C PROV ontology, MITRE ATT&CK/ATLAS, OWASP, EU AI Act.

## CLI Commands

```bash
inalign-install --local     # One-command installer (local SQLite mode)
inalign-mcp                 # Start MCP server (stdio)
inalign-ingest              # Parse session logs -> interactive HTML reports
inalign-report              # Launch report dashboard (localhost:8275)
inalign-analyze             # AI-powered deep session analysis (Pro)
inalign-dashboard           # Web dashboard
inalign-anchor              # Blockchain anchoring service
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

### inalign-report

Launch the local report dashboard with API proxy:

```bash
inalign-report              # Opens browser at localhost:8275
```

Session logs are automatically converted to provenance chains on first load (idempotent).

## Storage

InALign uses SQLite as its primary storage engine. No external databases required.

| Component | Location | Format |
|-----------|----------|--------|
| **Provenance chain** | `~/.inalign/provenance.db` | SQLite (WAL mode) |
| **Session reports** | `~/.inalign/sessions/` | Compressed `.json.gz` |
| **Knowledge graph** | `~/.inalign/provenance.db` | SQLite (ontology tables) |
| **Analysis reports** | `~/.inalign/analysis/` | HTML + JSON |

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

- **Website**: [inalign.dev](https://inalign.dev)
- **PyPI**: [pypi.org/project/inalign-mcp](https://pypi.org/project/inalign-mcp/)
- **Issues**: [github.com/Intellirim/inalign/issues](https://github.com/Intellirim/inalign/issues)
