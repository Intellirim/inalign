"""
Multi-Agent Topology & Cost Attribution

Tracks inter-agent interactions and API cost attribution.
Stores in SQLite for 100% local operation.

Features:
- Agent interaction graph (who calls whom)
- Token usage tracking per agent/session
- Cost attribution by model/provider
- Topology visualization data
"""

import json
import logging
import sqlite3
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

logger = logging.getLogger("inalign-topology")

INALIGN_DIR = Path.home() / ".inalign"
DB_PATH = INALIGN_DIR / "provenance.db"

# Default pricing (per 1M tokens, USD) — user can override
DEFAULT_PRICING = {
    "claude-opus-4-6": {"input": 15.0, "output": 75.0},
    "claude-sonnet-4-5-20250929": {"input": 3.0, "output": 15.0},
    "claude-haiku-4-5-20251001": {"input": 0.80, "output": 4.0},
    "gpt-4o": {"input": 2.50, "output": 10.0},
    "gpt-4o-mini": {"input": 0.15, "output": 0.60},
    "gpt-5-mini": {"input": 0.30, "output": 1.20},
    "default": {"input": 3.0, "output": 15.0},
}


@dataclass
class AgentInteraction:
    source_agent: str
    target_agent: str
    interaction_type: str  # "delegate", "query", "respond"
    session_id: str
    timestamp: str
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class CostEntry:
    session_id: str
    agent_id: str
    model: str
    provider: str
    input_tokens: int = 0
    output_tokens: int = 0
    cost_usd: float = 0.0
    timestamp: str = ""


def _ensure_tables():
    """Create topology and cost tables."""
    if not DB_PATH.exists():
        INALIGN_DIR.mkdir(parents=True, exist_ok=True)
    try:
        conn = sqlite3.connect(str(DB_PATH), check_same_thread=False)
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS agent_interactions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                source_agent TEXT NOT NULL,
                target_agent TEXT NOT NULL,
                interaction_type TEXT DEFAULT 'delegate',
                session_id TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                metadata TEXT DEFAULT '{}'
            );

            CREATE INDEX IF NOT EXISTS idx_interactions_session
                ON agent_interactions(session_id);

            CREATE INDEX IF NOT EXISTS idx_interactions_agents
                ON agent_interactions(source_agent, target_agent);

            CREATE TABLE IF NOT EXISTS cost_tracking (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id TEXT NOT NULL,
                agent_id TEXT NOT NULL,
                model TEXT NOT NULL,
                provider TEXT DEFAULT 'unknown',
                input_tokens INTEGER DEFAULT 0,
                output_tokens INTEGER DEFAULT 0,
                cost_usd REAL DEFAULT 0.0,
                timestamp TEXT NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_cost_session
                ON cost_tracking(session_id);

            CREATE INDEX IF NOT EXISTS idx_cost_agent
                ON cost_tracking(agent_id);
        """)
        conn.commit()
        conn.close()
    except Exception as e:
        logger.warning(f"[TOPOLOGY] Table creation failed: {e}")


def track_agent_interaction(
    source_agent: str,
    target_agent: str,
    interaction_type: str = "delegate",
    session_id: str = "",
    metadata: dict = None,
) -> dict[str, Any]:
    """
    Record an interaction between two agents.

    Args:
        source_agent: Agent initiating the interaction
        target_agent: Agent receiving the interaction
        interaction_type: Type: "delegate", "query", "respond"
        session_id: Current session
        metadata: Additional context

    Returns:
        Result dict
    """
    _ensure_tables()
    now = datetime.now(timezone.utc).isoformat()

    try:
        conn = sqlite3.connect(str(DB_PATH), check_same_thread=False)
        conn.execute(
            """INSERT INTO agent_interactions
               (source_agent, target_agent, interaction_type, session_id, timestamp, metadata)
               VALUES (?, ?, ?, ?, ?, ?)""",
            (source_agent, target_agent, interaction_type, session_id, now,
             json.dumps(metadata or {})),
        )
        conn.commit()
        conn.close()

        return {
            "success": True,
            "interaction": {
                "source": source_agent,
                "target": target_agent,
                "type": interaction_type,
                "session_id": session_id,
            },
            "message": f"Tracked interaction: {source_agent} → {target_agent} ({interaction_type})",
        }
    except Exception as e:
        return {"success": False, "error": str(e)}


def track_cost(
    session_id: str,
    agent_id: str,
    model: str,
    input_tokens: int = 0,
    output_tokens: int = 0,
    provider: str = "unknown",
) -> dict[str, Any]:
    """
    Track token usage and compute cost for a session/agent.

    Args:
        session_id: Session identifier
        agent_id: Agent that used the tokens
        model: Model name (e.g., "claude-opus-4-6")
        input_tokens: Input/prompt tokens used
        output_tokens: Output/completion tokens used
        provider: API provider ("anthropic", "openai", etc.)

    Returns:
        Result dict with computed cost
    """
    _ensure_tables()
    now = datetime.now(timezone.utc).isoformat()

    # Compute cost
    pricing = DEFAULT_PRICING.get(model, DEFAULT_PRICING["default"])
    cost = (input_tokens * pricing["input"] / 1_000_000) + (output_tokens * pricing["output"] / 1_000_000)
    cost = round(cost, 6)

    try:
        conn = sqlite3.connect(str(DB_PATH), check_same_thread=False)
        conn.execute(
            """INSERT INTO cost_tracking
               (session_id, agent_id, model, provider, input_tokens, output_tokens, cost_usd, timestamp)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (session_id, agent_id, model, provider, input_tokens, output_tokens, cost, now),
        )
        conn.commit()
        conn.close()

        return {
            "success": True,
            "cost_entry": {
                "session_id": session_id,
                "agent_id": agent_id,
                "model": model,
                "input_tokens": input_tokens,
                "output_tokens": output_tokens,
                "cost_usd": cost,
            },
            "message": f"Tracked ${cost:.6f} for {agent_id} ({model})",
        }
    except Exception as e:
        return {"success": False, "error": str(e)}


def get_agent_topology(session_id: str = None) -> dict[str, Any]:
    """
    Get agent interaction topology.

    Args:
        session_id: Filter by session (None = all sessions)

    Returns:
        Topology data with nodes (agents) and edges (interactions)
    """
    _ensure_tables()
    if not DB_PATH.exists():
        return {"nodes": [], "edges": [], "message": "No interaction data"}

    try:
        conn = sqlite3.connect(str(DB_PATH), check_same_thread=False)
        conn.row_factory = sqlite3.Row

        if session_id:
            rows = conn.execute(
                "SELECT * FROM agent_interactions WHERE session_id=? ORDER BY timestamp",
                (session_id,),
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT * FROM agent_interactions ORDER BY timestamp"
            ).fetchall()

        conn.close()

        # Build graph
        agents = set()
        edge_counts = defaultdict(int)

        for r in rows:
            src = r["source_agent"]
            tgt = r["target_agent"]
            agents.add(src)
            agents.add(tgt)
            edge_key = (src, tgt, r["interaction_type"])
            edge_counts[edge_key] += 1

        nodes = [{"id": a, "label": a} for a in sorted(agents)]
        edges = [
            {
                "source": k[0],
                "target": k[1],
                "type": k[2],
                "weight": v,
            }
            for k, v in edge_counts.items()
        ]

        return {
            "nodes": nodes,
            "edges": edges,
            "total_interactions": len(rows),
            "unique_agents": len(agents),
            "session_filter": session_id,
        }
    except Exception as e:
        return {"nodes": [], "edges": [], "error": str(e)}


def get_cost_report(session_id: str = None, agent_id: str = None) -> dict[str, Any]:
    """
    Get cost attribution report.

    Args:
        session_id: Filter by session
        agent_id: Filter by agent

    Returns:
        Cost breakdown by agent, model, and total
    """
    _ensure_tables()
    if not DB_PATH.exists():
        return {"total_cost_usd": 0, "entries": [], "message": "No cost data"}

    try:
        conn = sqlite3.connect(str(DB_PATH), check_same_thread=False)
        conn.row_factory = sqlite3.Row

        query = "SELECT * FROM cost_tracking"
        params = []
        conditions = []

        if session_id:
            conditions.append("session_id=?")
            params.append(session_id)
        if agent_id:
            conditions.append("agent_id=?")
            params.append(agent_id)

        if conditions:
            query += " WHERE " + " AND ".join(conditions)
        query += " ORDER BY timestamp"

        rows = conn.execute(query, params).fetchall()
        conn.close()

        # Aggregate
        total_cost = 0.0
        total_input = 0
        total_output = 0
        by_agent = defaultdict(lambda: {"cost": 0.0, "input_tokens": 0, "output_tokens": 0, "calls": 0})
        by_model = defaultdict(lambda: {"cost": 0.0, "input_tokens": 0, "output_tokens": 0, "calls": 0})

        for r in rows:
            cost = r["cost_usd"]
            inp = r["input_tokens"]
            out = r["output_tokens"]
            total_cost += cost
            total_input += inp
            total_output += out

            by_agent[r["agent_id"]]["cost"] += cost
            by_agent[r["agent_id"]]["input_tokens"] += inp
            by_agent[r["agent_id"]]["output_tokens"] += out
            by_agent[r["agent_id"]]["calls"] += 1

            by_model[r["model"]]["cost"] += cost
            by_model[r["model"]]["input_tokens"] += inp
            by_model[r["model"]]["output_tokens"] += out
            by_model[r["model"]]["calls"] += 1

        return {
            "total_cost_usd": round(total_cost, 6),
            "total_input_tokens": total_input,
            "total_output_tokens": total_output,
            "total_entries": len(rows),
            "by_agent": {
                k: {**v, "cost": round(v["cost"], 6)}
                for k, v in sorted(by_agent.items(), key=lambda x: -x[1]["cost"])
            },
            "by_model": {
                k: {**v, "cost": round(v["cost"], 6)}
                for k, v in sorted(by_model.items(), key=lambda x: -x[1]["cost"])
            },
            "filters": {"session_id": session_id, "agent_id": agent_id},
        }
    except Exception as e:
        return {"total_cost_usd": 0, "error": str(e)}
