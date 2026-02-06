# InALign Architecture

## System Overview

InALign is an AI Agent Governance Platform that provides cryptographic provenance tracking, behavioral analysis, and tamper-proof audit trails. It operates as an MCP (Model Context Protocol) server, integrating natively with AI coding agents.

```
                    +------------------+
                    |   AI Agent       |
                    | (Claude/Cursor)  |
                    +--------+---------+
                             |
                             | MCP (stdio)
                             |
                    +--------v---------+
                    |  InALign MCP     |
                    |  Server          |
                    +--------+---------+
                             |
              +--------------+--------------+
              |              |              |
     +--------v----+  +-----v------+  +----v--------+
     | Neo4j Aura  |  |  Polygon   |  | Dashboard   |
     | (Provenance |  | (Blockchain|  | (Web UI)    |
     |  Graphs)    |  |  Anchoring)|  |             |
     +-------------+  +------------+  +-------------+
```

## Core Components

### 1. MCP Server (`server.py`)

The main entry point. Handles MCP protocol communication with AI agents.

**Key modules:**
- `server.py` — MCP tool registration and request handling
- `provenance.py` — SHA-256 hash chain engine
- `scanner.py` — Pattern-based threat detection (290+ rules)
- `graph_rag.py` — GraphRAG behavioral analysis
- `policy.py` — Governance policy engine
- `polygon_anchor.py` — Blockchain anchoring (Polygon)
- `dashboard.py` — Web dashboard with graph visualization

### 2. Neo4j (Graph Database)

Stores provenance records as a knowledge graph.

**Stores:**
- Provenance records (actions, commands, file changes)
- Session graphs (action sequences per conversation)
- Agent behavior profiles
- Cross-session patterns

**Use cases:**
- GraphRAG behavioral analysis
- Anomaly detection across sessions
- Visual graph exploration in dashboard
- Risk scoring

### 3. Polygon (Blockchain)

Anchors provenance chain hashes to the blockchain.

**How it works:**
1. Compute merkle root of all session records
2. Submit merkle root as transaction data to Polygon
3. Transaction hash serves as immutable proof
4. Anyone can verify by checking on-chain data

**Supports:**
- Amoy testnet (free, for development)
- Polygon mainnet (production, ~$0.01/tx)

### 4. Web Dashboard (`dashboard.py`)

Single-file web application served by the MCP server.

**Features:**
- Canvas-based force-directed graph (Neo4j Bloom style)
- Timeline view with search and filter
- Risk analysis panel
- Policy management
- Export (JSON, PROV-JSONLD)

## Data Flow

### Recording Flow

```
1. User gives command to AI agent ("Fix the login bug")
2. Agent calls InALign MCP tool: record_user_command
3. InALign creates provenance record with SHA-256 hash
4. Record linked to previous record (hash chain)
5. Stored in Neo4j graph + local session
6. Agent continues working, each action recorded similarly
```

### Verification Flow

```
1. User or auditor calls verify_provenance
2. InALign walks the hash chain from first to last record
3. Recomputes each hash, checks linkage
4. If any record was modified, chain breaks → tampering detected
5. Returns verification result with details
```

### Anchoring Flow

```
1. Session ends or anchor triggered
2. Compute merkle root of all record hashes
3. Submit to Polygon as transaction data
4. Store TX hash as proof
5. Third party can verify: fetch TX → compare merkle root
```

## Technology Stack

| Component | Technology | Rationale |
|-----------|-----------|-----------|
| MCP Server | Python + MCP SDK | Native MCP support, async |
| Provenance | SHA-256 + dataclasses | Zero dependencies, fast |
| Graph DB | Neo4j Aura | Managed graph, Cypher queries |
| Blockchain | Polygon (web3.py) | Low cost, fast finality |
| Dashboard | FastAPI + Canvas 2D | Single-file, no build step |
| Package | PyPI (hatchling) | `pip install inalign-mcp` |

## Security

### Authentication
- API key-based (`INALIGN_API_KEY` / `API_KEY`)
- Client ID derived from API key for data isolation
- Per-client data separation in Neo4j

### Data Protection
- TLS for Neo4j connections (`neo4j+s://`)
- No plaintext credentials in code
- Environment variable configuration
- PII detection and masking in pattern scanner

## Scalability

- **Single agent**: MCP server runs per-agent (stdio)
- **Multi-agent**: Each agent gets its own MCP server instance
- **Dashboard**: Shared web UI aggregates all agent data
- **Neo4j Aura**: Managed, scales automatically
- **Blockchain**: One TX per session (not per record), cost-efficient
