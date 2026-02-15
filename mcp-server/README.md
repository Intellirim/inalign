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

## Zero Trust. Zero Cloud. Zero Telemetry.

InALign is **fully decentralized by design**. There is no InALign server. No account. No telemetry. Nothing leaves your machine — ever.

| | Other audit tools | InALign |
|---|---|---|
| **Where data lives** | Their cloud | Your machine only |
| **Account required** | Yes | No |
| **Telemetry** | "Anonymous" usage data | Zero. Not a single byte. |
| **Paid features** | Require their servers | Run 100% locally with your own API key |
| **What they see** | Your agent's actions | Nothing. We can't see anything even if we wanted to. |

Even Pro features like the AI Security Analyzer use **your own LLM API key** and run entirely on your machine. Your data never touches our infrastructure because **we don't have infrastructure**.

## What's New in v0.9.0

- **PROV-AGENT Ontology** — W3C PROV + PROV-AGENT compliant knowledge graph with 8 node classes, 13 relation types, and LLM reasoning tracked as first-class PROV activities
- **AI Security Analysis** — Two modes: Zero-Trust (local Ollama, data never leaves your machine) and Advanced (Claude/OpenAI API with 14 PII patterns masked)
- **React SPA Dashboard** — Modern dark-theme dashboard at `localhost:8275` with Overview, Sessions, Security, and AI Analysis pages
- **Performance** — Session detail API optimized from 57s to 0.2s (600s cache + truncated payloads)
- **AIModelInvocation** — LLM reasoning steps tracked as first-class PROV activities in the knowledge graph

## The Problem

AI coding agents (Claude Code, Cursor, Copilot) can read, write, and execute anything on your machine. When something goes wrong:

- **What** did the agent actually do?
- **Who** told it to do that?
- **Can you prove it?**

Logs can be edited. Memory fades. You need evidence that **cannot be tampered with**.

## Why Not Just Use Logs?

| | Traditional Logs | InALign |
|---|---|---|
| **Tamper resistance** | None. Anyone with access can edit. | SHA-256 hash chain + Ed25519 signatures. Modify one record -> chain breaks. Replace the DB -> signature check fails. |
| **Provenance** | "Something happened at 3pm" | Who commanded it, what the agent did, full causal chain |
| **Risk detection** | Manual review | Automatic: data exfiltration, privilege escalation, suspicious patterns |
| **Guardrails** | After the fact | Runtime policy engine blocks dangerous actions |
| **Audit proof** | "Trust me" | Third-party verifiable cryptographic proof |

## Quick Start

```bash
pip install inalign-mcp && inalign-install --local
```

Restart Claude Code. Done. Every agent action is now recorded in a local SQLite database with SHA-256 hash chains.

> **That's it.** No API key. No account. No cloud. No telemetry. Everything runs on your machine and stays on your machine.
>
> Data is stored at `~/.inalign/provenance.db`. Persists across sessions. Nothing is ever sent anywhere.

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

## CLI Commands

InALign provides four CLI commands:

### `inalign-install` — Setup & Configuration

```bash
inalign-install --local              # Install with SQLite (recommended)
inalign-install --license KEY        # Install with Pro/Enterprise license
inalign-install --activate KEY       # Activate or update a license key
inalign-install --status             # Show current license status
inalign-install --uninstall          # Remove InALign configuration
```

### `inalign-report` — React Dashboard

```bash
inalign-report                       # Open dashboard in browser (port 8275)
inalign-report --port 9000           # Custom port
inalign-report --no-open             # Start server without opening browser
inalign-report --legacy              # Serve old single-HTML report
```

Opens a React SPA dashboard with dark theme. See [Report Dashboard](#report-dashboard) below.

### `inalign-ingest` — Session Log Parser

```bash
inalign-ingest --latest --save       # Parse most recent session, save compressed
inalign-ingest path/to/session.jsonl # Parse specific session file
inalign-ingest --dir ~/.claude/projects  # Find all sessions in directory
inalign-ingest --latest -o report.html   # Generate HTML report
inalign-ingest --latest --json           # Output JSON summary to stdout
```

Parses Claude Code session logs (`.jsonl`) and saves compressed session data to `~/.inalign/sessions/` for use in the dashboard and AI analysis.

### `inalign-analyze` — AI Security Analysis (Pro)

```bash
# Zero-Trust mode (local Ollama — data never leaves your machine)
inalign-analyze --provider local --latest --save
inalign-analyze --provider local --model llama3.2 --latest

# Advanced mode (cloud LLM — PII masked, your own API key)
inalign-analyze --api-key sk-ant-xxx --latest --save     # Analyze with Claude API
inalign-analyze --api-key sk-xxx --provider openai --latest  # Analyze with OpenAI
inalign-analyze --latest --api-key KEY --max-records 50  # Limit records
inalign-analyze --latest --api-key KEY --json            # Raw JSON output
```

Deep security analysis powered by LLM. See [AI Security Analyzer](#ai-security-analyzer-pro) below.

## What You Get

### 32 MCP Tools, Zero Configuration

Once installed, your AI agent automatically gains:

| Category | Tools | What it does |
|----------|-------|-------------|
| **Provenance** | `record_action`, `record_user_command`, `get_provenance`, `verify_provenance` | Cryptographic audit trail for every action |
| **Audit** | `generate_audit_report`, `verify_third_party`, `export_report` | Compliance reports, HTML export, third-party verifiable proof |
| **Risk** | `analyze_risk`, `ontology_security_scan`, `get_behavior_profile`, `get_agent_risk`, `get_user_risk`, `list_agents_risk` | Pattern detection: data exfiltration, privilege escalation, suspicious tool chains |
| **Policy** | `get_policy`, `set_policy`, `list_policies`, `simulate_policy` | Runtime guardrails with 3 presets |
| **Compliance** | `generate_compliance_report`, `check_owasp_compliance` | EU AI Act, OWASP LLM Top 10 |
| **Permissions** | `get_permission_matrix`, `set_agent_permissions` | Per-tool allow/deny/audit controls |
| **Drift** | `detect_drift`, `get_behavior_baseline` | Behavioral anomaly detection (z-score) |
| **Telemetry** | `export_otel` | OpenTelemetry OTLP JSON export |
| **Topology** | `track_agent_interaction`, `get_agent_topology`, `track_cost`, `get_cost_report` | Multi-agent graph + cost tracking |
| **Ontology** | `ontology_populate`, `ontology_query`, `ontology_stats` | PROV-AGENT knowledge graph |
| **Sessions** | `list_sessions` | Browse past audit sessions |

### PROV-AGENT Ontology (v0.9.0)

InALign builds a W3C PROV + PROV-AGENT compliant knowledge graph from every agent session:

**8 Node Classes:**

| Class | W3C PROV Type | Description |
|-------|---------------|-------------|
| `Agent` | prov:Agent | AI agent (Claude, GPT, Cursor) |
| `Session` | prov:Activity | Work session |
| `ToolCall` | prov:Activity | Tool invocation |
| `AIModelInvocation` | prov:Activity | LLM API call (PROV-AGENT extension) |
| `Entity` | prov:Entity | Artifact (file, URL, secret, prompt, response) |
| `Decision` | — | Agent judgment/choice |
| `Risk` | — | Detected risk pattern |
| `Policy` | — | Applied policy rule |

**13 Relation Types** including PROV-AGENT extensions:

| Relation | Path | Standard |
|----------|------|----------|
| `performed` | Agent -> ToolCall | prov:wasAssociatedWith |
| `partOf` | ToolCall -> Session | prov:wasInformedBy |
| `used` | ToolCall -> Entity | prov:used |
| `generated` | ToolCall -> Entity | prov:wasGeneratedBy |
| `derivedFrom` | Entity -> Entity | prov:wasDerivedFrom |
| `precedes` | ToolCall -> ToolCall | inalign:precedes |
| `sameAs` | Entity -> Entity | cross-session identity |
| `signedBy` | Session -> Agent | — |
| `triggeredBy` | ToolCall -> Decision | — |
| `detected` | ToolCall -> Risk | — |
| `violates` | ToolCall -> Policy | — |
| `invokedModel` | ToolCall -> AIModelInvocation | **PROV-AGENT** |
| `usedPrompt` | AIModelInvocation -> Prompt | **PROV-AGENT** |

The `AIModelInvocation` class and `invokedModel`/`usedPrompt` relations are PROV-AGENT extensions that track LLM reasoning steps as first-class PROV activities — enabling questions like "Which prompts led to sensitive file access?" and "What model was used when this risky action was taken?"

### How the Hash Chain Works

Every agent action is recorded as a provenance record with a SHA-256 hash that includes the previous record's hash:

```
Record #1 ──hash──> Record #2 ──hash──> Record #3
   |                    |                    |
   +-- user_command     +-- file_write       +-- tool_call
       sha256: a1b2c3       sha256: d4e5f6       sha256: g7h8i9
       prev:   000000       prev:   a1b2c3       prev:   d4e5f6
```

Each record's hash is computed from: `action_type + action_name + timestamp + activity_attributes + previous_hash`. Modify any record? Its hash changes. The next record's `prev` no longer matches. **Chain broken. Tamper detected.**

This is the same principle behind Git commits and blockchains — except applied to AI agent actions.

**Verification methods:**
- `verify_provenance` — Checks the entire hash chain for integrity
- `verify_third_party` — Generates a self-contained proof package that anyone can independently verify without trusting InALign
- **Merkle Root** — Session-level summary hash for efficient batch verification

**Current status & roadmap:**
- SHA-256 hash chains with local SQLite storage (shipping now)
- Ed25519 digital signatures (shipping now)
- Blockchain anchoring for additional tamper evidence (planned)

### Ed25519 Digital Signatures

Every record is automatically **signed** with a machine-local Ed25519 private key. This adds non-repudiation on top of the hash chain:

| Attack | Hash chain only | Hash chain + signatures |
|--------|----------------|------------------------|
| Modify a single record | Detected | Detected |
| Replace entire database | **Not detected** | **Detected** — attacker doesn't have the private key |
| Prove which machine created it | Cannot | **Can** — signature ties record to a specific keypair |

**How it works:**
1. On first run, a keypair is generated at `~/.inalign/signing_key` (private) and `~/.inalign/signing_key.pub` (public)
2. Every provenance record is signed: `Ed25519(private_key, record_hash)` -> 64-byte signature
3. `verify_provenance` checks both hash chain integrity AND signature validity
4. `verify_third_party` exports the public key so anyone can independently verify signatures

**Zero configuration required.** If the `cryptography` library is installed (it usually is), signing happens automatically. If not, records are still hash-chained — just unsigned.

```bash
# Enable signing (if not already installed)
pip install cryptography
```

### Risk Analysis

Pattern detection catches:

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
-> 12 actions would be blocked, 3 masked, 47 allowed
```

## Report Dashboard

Run `inalign-report` to open a React SPA dashboard (dark theme) at `localhost:8275`:

| Page | What it shows |
|------|---------------|
| **Overview** | Session summary, record counts, verification status, risk score |
| **Sessions** | Session list with drill-down to full conversation history and provenance chain |
| **Security** | Ontology security scan results, graph-based threat analysis |
| **AI Analysis** | Deep LLM-powered security analysis results (requires API key or local Ollama) |

The dashboard includes JSON/CSV export for all data. Session logs are loaded from `~/.inalign/sessions/` (use `inalign-ingest --latest --save` to populate).

**Performance:** Session detail API optimized from 57s to 0.2s with 600s caching and truncated payloads.

## AI Security Analyzer (Pro)

Deep LLM-powered security analysis of agent sessions with two modes:

### Zero-Trust Mode (Local Ollama)

Data **never leaves your machine**. Runs entirely on local Ollama:

```bash
inalign-analyze --provider local --latest --save
```

Requires [Ollama](https://ollama.com) running locally. No API key needed.

### Advanced Mode (Cloud LLM)

Uses **your own API key** — data goes directly from your machine to your LLM provider. InALign never sees it. Before sending, 14 PII patterns are automatically masked (API keys, passwords, emails, SSH keys, JWTs, sensitive file paths, and more).

> **Zero-trust exception disclosure:** In Advanced mode, PII-masked session data is sent to your chosen LLM provider (Anthropic or OpenAI) via your own API key. This is the only scenario where any data leaves your machine, and you opt in explicitly by providing an API key.

**How it works:**
1. Reads your session data locally
2. Masks PII (API keys, passwords, emails, SSH keys, JWTs — 14 patterns)
3. Sends masked data to your chosen LLM provider for analysis
4. Returns risk score, findings, and recommendations

**Supported providers:**
- **Local Ollama** — zero-trust, no data leaves your machine
- **Claude API** (Anthropic) — auto-detected from `sk-ant-*` keys
- **OpenAI API** (GPT-4o) — auto-detected from `sk-*` keys

**Analysis includes:**
- Causal chain analysis (user_prompt -> thinking -> tool_call -> tool_result)
- Risk scoring (0-100 with LOW/MEDIUM/HIGH/CRITICAL levels)
- Specific security findings with evidence
- Actionable recommendations

```bash
inalign-analyze --api-key YOUR_KEY --latest --save
```

Reports are saved to `~/.inalign/analysis/`.

## Supported Agents

Works with any agent that supports [MCP (Model Context Protocol)](https://modelcontextprotocol.io/):

| Agent | Status |
|-------|--------|
| **Claude Code** | Fully tested |
| **Cursor** | MCP compatible |
| **Windsurf** | MCP compatible |
| **Continue.dev** | MCP compatible |
| **Cline** | MCP compatible |
| Custom agents | Via MCP protocol |

## Example: Incident Investigation

Production config was modified unexpectedly. Who did it?

```
You:    "generate an audit report for this session"

InALign: Audit Report
         ---
         Session:  abc123def456
         Records:  23 actions recorded
         Chain:    VERIFIED (all hashes valid)

         Timeline:
         11:12:06  user_command  "Delete all logs from /var/log"
         11:12:08  file_write    config.py (modified)
         11:12:09  tool_call     bash: rm -rf /var/log/*

         Risk:     HIGH - destructive file operations detected
         Policy:   2 actions would be blocked under STRICT_ENTERPRISE
```

From vague concern to **cryptographic proof** in seconds.

## Architecture

```
+--------------------------------------------------+
|  Your AI Agent (Claude Code / Cursor / etc.)      |
|                                                   |
|  +---------------------------------------------+ |
|  |  InALign MCP Server (runs locally)           | |
|  |                                              | |
|  |  Action -> SHA-256 Hash Chain + Ed25519 Sign  | |
|  |              |                               | |
|  |     +--------+--------+                      | |
|  |     v        v        v                      | |
|  |  SQLite   Memory   PROV-AGENT                | |
|  |  (default) (fallback) Ontology               | |
|  |                                              | |
|  |  + GraphRAG Risk Analysis (11 patterns)      | |
|  |  + Policy Engine (3 presets)                 | |
|  |  + React Dashboard (4-page SPA)              | |
|  |  + AI Security Analyzer (Ollama / Cloud)     | |
|  |  + Ontology Security Engine                  | |
|  |  + EU AI Act & OWASP Compliance              | |
|  +---------------------------------------------+ |
+--------------------------------------------------+
```

**Privacy by architecture**: InALign has no server, no cloud, no database you connect to. The MCP server runs entirely on your machine. Your code, credentials, and session data never leave your local environment. Even Pro features (AI analysis) can run fully local with Ollama — or use your own API key with automatic PII masking.

**Performance**: Recording 1,000 actions adds ~50ms total overhead. Hash chain verification of 10,000 records completes in <200ms. No measurable impact on agent response time.

## Storage Modes

| Mode | Setup | Persistence | Best for |
|------|-------|-------------|----------|
| **SQLite** | `--local` (default) | Permanent, `~/.inalign/provenance.db` | Most users, local dev, compliance |
| **Memory** | Automatic fallback | Per session only | Quick testing |

SQLite is the recommended default. It requires no external services and persists across sessions.

## Self-Hosting

Everything runs on your own machine by default:

```bash
pip install inalign-mcp && inalign-install --local
```

That's it. SQLite storage, local dashboard, full functionality. No external dependencies.

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

- **Website**: [inalign.dev](https://inalign.dev)
- **PyPI**: [pypi.org/project/inalign-mcp](https://pypi.org/project/inalign-mcp/)
- **Issues**: [github.com/Intellirim/inalign/issues](https://github.com/Intellirim/inalign/issues)
