# InALign Architecture

## System Overview

InALign is an AI Agent Security Platform designed to provide real-time security monitoring, threat detection, and audit logging for AI agents. The platform sits between user interactions and AI agent actions, scanning inputs/outputs and monitoring behavior patterns.

```
                    +------------------+
                    |   User / Client  |
                    +--------+---------+
                             |
                    +--------v---------+
                    |  InALign SDK |
                    | (Python / JS)    |
                    +--------+---------+
                             |
                    +--------v---------+
                    |   API Gateway    |
                    |  (Ingress/NGINX) |
                    +--------+---------+
                             |
              +--------------+--------------+
              |                             |
     +--------v---------+         +--------v---------+
     |  Backend API      |         |   Frontend App   |
     |  (FastAPI)        |         |   (Next.js)      |
     +--------+---------+         +------------------+
              |
     +--------+---------+---------+---------+
     |        |         |         |         |
+----v---+ +--v----+ +-v------+ +-v-----+ +v--------+
|Postgres| | Neo4j | | Redis  | |Celery | |  LLM    |
|  (SQL) | |(Graph)| |(Cache) | |Worker | | APIs    |
+--------+ +-------+ +--------+ +-------+ +---------+
```

## Core Components

### 1. Backend API (FastAPI)

The core API service built with Python FastAPI.

**Responsibilities:**
- Request validation and authentication
- Input/output threat scanning
- PII detection and sanitization
- Action logging and anomaly detection
- Session management
- Report generation
- Alert management

**Key modules:**
- `app/api/` - API route handlers
- `app/core/` - Configuration, security, middleware
- `app/models/` - SQLAlchemy and Pydantic models
- `app/services/` - Business logic services
  - `scanner.py` - Threat and PII scanning engine
  - `anomaly_detector.py` - Behavioral anomaly detection
  - `report_generator.py` - Report generation with LLM
  - `alert_manager.py` - Alert creation and notification

### 2. Frontend Dashboard (Next.js)

A React-based dashboard for monitoring and management.

**Features:**
- Real-time session monitoring
- Threat visualization and analytics
- Alert management interface
- Report viewing and export
- Agent configuration management
- User and API key management

### 3. PostgreSQL (Relational Database)

Primary data store for structured data.

**Stores:**
- User accounts and API keys
- Agent configurations
- Scan results and action logs
- Alert records
- Report metadata
- Session summaries

### 4. Neo4j (Graph Database)

Graph database for behavioral analysis and relationship mapping.

**Stores:**
- Agent behavior graphs (action sequences)
- Session flow patterns
- Anomaly relationship networks
- Threat propagation paths

**Use cases:**
- Pattern matching for anomaly detection
- Behavioral baseline computation
- Attack path analysis
- Relationship-based risk scoring

**Plugins:**
- APOC - Utility procedures for data import/export, graph algorithms
- Graph Data Science (GDS) - Machine learning and graph analytics

### 5. Redis

In-memory data store for caching and real-time operations.

**Use cases:**
- API response caching
- Rate limiting counters
- Session state caching
- Real-time event pub/sub
- Celery task broker and result backend

### 6. Celery Workers

Background task processing for async operations.

**Tasks:**
- Asynchronous deep scanning
- Report generation (LLM-powered)
- Alert notification dispatch (Slack, Telegram, Email)
- Periodic anomaly analysis
- Data aggregation and cleanup

## Data Flow

### Input Scanning Flow

```
1. User sends message to AI agent
2. SDK intercepts and calls POST /v1/scan/input
3. Backend receives request, validates authentication
4. Scanner service analyzes text:
   a. Threat detection (prompt injection, jailbreak, etc.)
   b. PII detection (SSN, email, phone, etc.)
   c. Risk scoring
5. Results stored in PostgreSQL
6. Action graph updated in Neo4j
7. Response returned to SDK
8. SDK decides whether to proceed or block
```

### Output Scanning Flow

```
1. AI agent generates response
2. SDK intercepts and calls POST /v1/scan/output
3. Backend scans for:
   a. PII leakage
   b. Sensitive data exposure
   c. Policy violations
4. If auto_sanitize enabled, redacts sensitive data
5. Results stored, response returned
6. SDK uses sanitized text if applicable
```

### Anomaly Detection Flow

```
1. Action logged via POST /v1/actions/log
2. Action stored in PostgreSQL
3. Neo4j graph updated with new action node
4. Anomaly detector compares against baseline:
   a. Frequency analysis
   b. Pattern deviation scoring
   c. Privilege escalation checks
5. If anomalous, alert created
6. Celery dispatches notifications
```

## Technology Choices

| Component | Technology | Rationale |
|-----------|-----------|-----------|
| Backend API | FastAPI (Python) | Async support, auto OpenAPI docs, Pydantic validation, rich ML/NLP ecosystem |
| Frontend | Next.js (React) | SSR for performance, TypeScript, rich component ecosystem |
| Relational DB | PostgreSQL 15 | ACID compliance, JSONB support, mature ecosystem |
| Graph DB | Neo4j 5 | Native graph storage, Cypher query language, GDS for ML |
| Cache | Redis 7 | Sub-millisecond latency, pub/sub, rate limiting |
| Task Queue | Celery | Python-native, Redis broker, reliable task execution |
| SDK (Python) | httpx + Pydantic | Async support, type safety, modern Python |
| SDK (JS) | Native fetch | Zero dependencies, TypeScript-first, Node 18+ |

## Security Architecture

### Authentication
- API key-based authentication (Bearer tokens)
- Keys scoped to organizations and projects
- Rate limiting per API key

### Data Protection
- All data encrypted at rest (PostgreSQL encryption, Neo4j encryption)
- TLS 1.3 for all data in transit
- PII values masked in logs and responses
- Configurable data retention policies

### Network Security
- Kubernetes network policies isolate services
- Ingress with TLS termination
- Internal services communicate via ClusterIP
- No direct database access from outside the cluster

## Scalability

### Horizontal Scaling
- Backend API: Stateless, scales via Kubernetes replicas
- Frontend: Stateless, scales via replicas
- Celery Workers: Scale independently based on queue depth

### Vertical Scaling
- Neo4j: Increase memory for larger graph datasets
- PostgreSQL: Increase resources for query-heavy workloads
- Redis: Increase memory for larger cache sizes

### Performance Targets
- Input scan latency: < 100ms (p95)
- Output scan latency: < 100ms (p95)
- Action logging: < 50ms (p95)
- Report generation: < 30s (async)
