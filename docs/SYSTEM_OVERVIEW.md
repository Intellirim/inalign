# InALign - AI Agent Governance Platform

## What is InALign?

InALign is a governance layer for AI coding agents. It records every agent action in a cryptographic hash chain, analyzes behavioral patterns via GraphRAG, and provides tamper-proof audit trails anchored to the blockchain.

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│            AI Agent (Claude Code / Cursor / Windsurf)           │
└──────────────────────────────┬──────────────────────────────────┘
                               │ MCP Protocol (stdio)
                               ▼
┌─────────────────────────────────────────────────────────────────┐
│                      InALign MCP Server                         │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐             │
│  │ Provenance  │  │   Pattern   │  │   Policy    │             │
│  │   Engine    │  │  Detection  │  │   Engine    │             │
│  │ (SHA-256)   │  │(290+ rules) │  │(3 presets)  │             │
│  └─────────────┘  └─────────────┘  └─────────────┘             │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐             │
│  │  GraphRAG   │  │  Behavior   │  │  Blockchain │             │
│  │  Analysis   │  │  Profiler   │  │  Anchoring  │             │
│  └─────────────┘  └─────────────┘  └─────────────┘             │
└──────────────────────────────┬──────────────────────────────────┘
                               │
              ┌────────────────┼────────────────┐
              ▼                ▼                ▼
        ┌──────────┐   ┌──────────┐   ┌──────────────┐
        │  Neo4j   │   │ Polygon  │   │ Dashboard    │
        │ (Graph)  │   │ (Chain)  │   │ (Web UI)     │
        └──────────┘   └──────────┘   └──────────────┘
```

## Core Components

### 1. Provenance Engine
- Records every agent action (user commands, file reads/writes, tool calls, decisions)
- Each record is SHA-256 hashed and linked to the previous record
- Tamper-proof: modifying any record breaks the entire chain
- W3C PROV compatible, JSON-LD export

### 2. Pattern Detection
- 290+ regex patterns across 8 languages
- Detects prompt injection, jailbreak attempts, PII leakage
- Fast, deterministic, zero external dependencies
- Runs on every input automatically

### 3. GraphRAG Analysis
- Neo4j knowledge graph stores all provenance records
- Behavioral pattern analysis across sessions
- Detects: data exfiltration, privilege escalation, suspicious tool chains
- Cross-session anomaly detection

### 4. Policy Engine
- Three governance presets: STRICT_ENTERPRISE, BALANCED, DEV_SANDBOX
- Runtime policy switching (no restart required)
- Policy simulation against historical events
- Per-category rules (block, warn, mask, log)

### 5. Blockchain Anchoring
- Merkle root of provenance chain anchored to Polygon
- Third-party verifiable proofs
- Permanent, immutable record on-chain
- Supports both testnet (Amoy) and mainnet

### 6. Web Dashboard
- Canvas-based force-directed graph visualization
- Timeline view of all agent actions
- Risk analysis and behavioral profiling
- Policy management UI
- Export: JSON, PROV-JSONLD

## Current Status

| Component | Status | Notes |
|-----------|--------|-------|
| MCP Server | Working | Claude Code, Cursor, Windsurf |
| Provenance Chain | Working | SHA-256 hash chain, verified |
| Pattern Detection | Working | 290+ patterns |
| GraphRAG (Neo4j) | Working | Connected to Neo4j Aura |
| Policy Engine | Working | 3 presets, runtime switching |
| Blockchain Anchoring | Code complete | Polygon Amoy/Mainnet support |
| Web Dashboard | Working | EC2 deployed |
| Stripe Billing | Working | Starter/Pro/Enterprise |
| PyPI Package | Published | `pip install inalign-mcp` |

## Performance

| Metric | Current |
|--------|---------|
| Provenance recording | <5ms per record |
| Pattern scan | <10ms |
| GraphRAG query | ~50ms |
| Chain verification | <100ms (1000 records) |
| Dashboard load | <2s |

## API Example

```python
# MCP server auto-records everything. For programmatic access:
from inalign import InALign

client = InALign(api_key="your-api-key")
client.record("user_command", "Fix the login bug", session_id="sess-001")
client.record("file_write", "src/auth.py", session_id="sess-001")

result = client.verify(session_id="sess-001")
print(f"Chain valid: {result.is_valid}")

report = client.audit_report(session_id="sess-001")
```

## Key Differentiators

| Existing Solutions | InALign |
|-------------------|---------|
| Logs only | Cryptographic hash chain + blockchain anchoring |
| Static policies | Runtime policy switching + simulation |
| Vendor lock-in | MCP standard — works with any agent |
| Self-verified | Third-party independent verification |
| English only | 290+ patterns across 8 languages |

---

**InALign: Record, verify, and prove every AI agent action.**
