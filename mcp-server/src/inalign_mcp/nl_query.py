"""
Natural Language Provenance Query Engine

Zero-trust: Only DB SCHEMA is sent to the LLM. Actual data stays local.
LLM generates SQL → SQL runs locally → results returned to user.

Usage:
    from .nl_query import query_provenance
    result = query_provenance("What files did the agent access?", "openai", api_key)
"""

import json
import os
import sqlite3
import logging
from pathlib import Path
from typing import Optional

logger = logging.getLogger("inalign-nl-query")

DB_PATH = Path.home() / ".inalign" / "provenance.db"

# DB schema (sent to LLM — no actual data, just structure)
SCHEMA_DESCRIPTION = """
## InALign Provenance Database Schema

### Table: records
Stores chronological provenance records (hash-chained audit trail).
- id TEXT PRIMARY KEY
- session_id TEXT — groups records by conversation session
- sequence_number INTEGER — order within session
- timestamp TEXT — ISO 8601
- activity_type TEXT — 'tool_call', 'user_input', 'llm_response', 'decision'
- activity_name TEXT — tool name or action description
- activity_attributes TEXT (JSON) — tool inputs, file paths, commands
- record_hash TEXT — SHA-256 hash for tamper detection
- agent_id TEXT, agent_name TEXT, agent_type TEXT

### Table: ontology_nodes
Knowledge graph nodes (W3C PROV ontology).
- id TEXT PRIMARY KEY
- node_class TEXT — 'ToolCall', 'Entity', 'Agent', 'Session', 'Decision', 'Risk', 'AIModelInvocation'
- label TEXT — human-readable name
- session_id TEXT
- timestamp TEXT
- attributes TEXT (JSON) — varies by class:
  - Entity: {entity_type, full_path, sensitivity (CRITICAL/HIGH/MEDIUM/LOW), injection_suspect}
  - ToolCall: {activity_type, tool_name, tool_input, sequence}
  - Risk: {risk_level, confidence, description, mitre_tactic, mitre_techniques}
  - Decision: {full_length, sequence_index}

### Table: ontology_edges
Knowledge graph relationships.
- source_id TEXT, target_id TEXT — node IDs
- relation TEXT — 'used', 'generated', 'precedes', 'performed', 'partOf', 'signedBy',
                   'triggeredBy', 'derivedFrom', 'detected', 'sameAs', 'usedPrompt'
- session_id TEXT
- confidence REAL — 0.0 to 1.0

### Table: blockchain_anchors
Blockchain anchoring proofs.
- id TEXT PRIMARY KEY
- session_id TEXT, merkle_root TEXT, transaction_hash TEXT
- block_number INTEGER, network TEXT, mock INTEGER
- created_at TEXT

### Common Query Patterns
- Files accessed: SELECT label FROM ontology_nodes WHERE node_class='Entity' AND json_extract(attributes,'$.entity_type')='file'
- Tool calls: SELECT label, json_extract(attributes,'$.tool_input') FROM ontology_nodes WHERE node_class='ToolCall'
- Sensitive entities: WHERE json_extract(attributes,'$.sensitivity') IN ('CRITICAL','HIGH')
- Data flows: SELECT * FROM ontology_edges WHERE relation IN ('used','generated','derivedFrom')
- Session list: SELECT DISTINCT session_id FROM records
"""

SYSTEM_PROMPT = f"""You are a SQL query generator for InALign's provenance database (SQLite).

{SCHEMA_DESCRIPTION}

RULES:
1. Generate ONLY valid SQLite SQL. No markdown, no explanation.
2. Use json_extract() for JSON fields in attributes column.
3. LIMIT results to 50 rows max unless user asks for more.
4. Only SELECT queries — never INSERT, UPDATE, DELETE, DROP.
5. If the question is ambiguous, make reasonable assumptions and add comments.
6. Return ONLY the SQL query, nothing else.
"""


def _call_llm_for_sql(question: str, provider: str, api_key: str,
                       model: str = None) -> str:
    """Send question + schema to LLM, get SQL back."""
    import httpx

    if provider == "openai":
        api_key = api_key or os.getenv("OPENAI_API_KEY", "")
        if not api_key:
            return "-- ERROR: No OpenAI API key"
        model = model or "gpt-4o"

        with httpx.Client(timeout=60) as client:
            resp = client.post(
                "https://api.openai.com/v1/chat/completions",
                headers={
                    "Authorization": f"Bearer {api_key}",
                    "Content-Type": "application/json",
                },
                json={
                    "model": model,
                    "max_completion_tokens": 1024,
                    "messages": [
                        {"role": "system", "content": SYSTEM_PROMPT},
                        {"role": "user", "content": question},
                    ],
                },
            )
            if resp.status_code != 200:
                return f"-- ERROR: API {resp.status_code}: {resp.text[:200]}"
            content = resp.json()["choices"][0]["message"]["content"]

    elif provider == "anthropic":
        api_key = api_key or os.getenv("ANTHROPIC_API_KEY", "")
        if not api_key:
            return "-- ERROR: No Anthropic API key"
        model = model or "claude-sonnet-4-5-20250929"

        with httpx.Client(timeout=60) as client:
            resp = client.post(
                "https://api.anthropic.com/v1/messages",
                headers={
                    "x-api-key": api_key,
                    "anthropic-version": "2023-06-01",
                    "content-type": "application/json",
                },
                json={
                    "model": model,
                    "max_tokens": 1024,
                    "system": SYSTEM_PROMPT,
                    "messages": [{"role": "user", "content": question}],
                },
            )
            if resp.status_code != 200:
                return f"-- ERROR: API {resp.status_code}: {resp.text[:200]}"
            content = resp.json()["content"][0]["text"]

    elif provider == "local":
        with httpx.Client(timeout=120) as client:
            try:
                resp = client.post(
                    "http://localhost:11434/api/generate",
                    json={
                        "model": model or "llama3.2",
                        "prompt": f"{SYSTEM_PROMPT}\n\nQuestion: {question}",
                        "stream": False,
                        "options": {"num_predict": 1024},
                    },
                )
                content = resp.json().get("response", "")
            except Exception as e:
                return f"-- ERROR: Ollama not available: {e}"
    else:
        return f"-- ERROR: Unknown provider: {provider}"

    # Clean SQL from response
    sql = content.strip()
    if "```sql" in sql:
        sql = sql.split("```sql")[1].split("```")[0].strip()
    elif "```" in sql:
        sql = sql.split("```")[1].split("```")[0].strip()

    return sql


def _execute_sql(sql: str) -> dict:
    """Execute SQL locally against provenance.db. Read-only."""
    if not DB_PATH.exists():
        return {"error": "provenance.db not found"}

    # Safety: reject non-SELECT queries
    sql_upper = sql.upper().strip()
    if not sql_upper.startswith("SELECT") and not sql_upper.startswith("--"):
        return {"error": "Only SELECT queries allowed", "sql": sql}

    for forbidden in ["INSERT", "UPDATE", "DELETE", "DROP", "ALTER", "CREATE",
                       "ATTACH", "DETACH", "PRAGMA"]:
        if forbidden in sql_upper and not sql_upper.startswith("--"):
            return {"error": f"Forbidden operation: {forbidden}", "sql": sql}

    try:
        conn = sqlite3.connect(str(DB_PATH))
        conn.row_factory = sqlite3.Row
        rows = conn.execute(sql).fetchall()
        conn.close()

        results = [dict(r) for r in rows]
        return {
            "sql": sql,
            "row_count": len(results),
            "results": results[:50],
        }
    except Exception as e:
        return {"error": str(e), "sql": sql}


def query_provenance(question: str, provider: str = "openai",
                     api_key: str = None, model: str = None) -> dict:
    """
    Natural language → SQL → local execution.
    Zero-trust: only schema sent to LLM, data stays local.
    """
    logger.info(f"[NL-QUERY] Question: {question[:80]}...")

    sql = _call_llm_for_sql(question, provider, api_key, model)

    if sql.startswith("-- ERROR"):
        return {"error": sql, "question": question}

    result = _execute_sql(sql)
    result["question"] = question
    result["provider"] = provider
    result["zero_trust"] = "Only DB schema sent to LLM. Data queried locally."

    return result
