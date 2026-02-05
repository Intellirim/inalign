"""
Trace Finder - Find related records when problems occur.

Given a problem (file, error, decision), traces back through
the provenance chain to show how it happened.
"""

import os
import logging
from datetime import datetime, timedelta
from typing import Optional, Any
from dataclasses import dataclass

logger = logging.getLogger("inalign-trace")

# Neo4j connection
_driver = None


def init_trace_db(uri: str = None, user: str = None, password: str = None):
    """Initialize Neo4j connection for tracing."""
    global _driver
    try:
        from neo4j import GraphDatabase
        _driver = GraphDatabase.driver(
            uri or os.getenv("NEO4J_URI"),
            auth=(user or os.getenv("NEO4J_USERNAME"),
                  password or os.getenv("NEO4J_PASSWORD"))
        )
        return True
    except Exception as e:
        logger.error(f"Failed to init trace DB: {e}")
        return False


@dataclass
class TraceResult:
    """Result of a trace query."""
    query_type: str
    query_value: str
    found: bool
    records: list[dict]
    timeline: list[dict]
    root_cause: Optional[dict] = None
    summary: str = ""


def trace_file(file_path: str, limit: int = 20) -> TraceResult:
    """
    Trace all actions related to a file.

    "Who touched /app/config.py and what did they do?"
    """
    if not _driver:
        return TraceResult("file", file_path, False, [], [], summary="DB not connected")

    records = []
    with _driver.session() as session:
        # Find all records that touched this file
        result = session.run("""
            MATCH (r:ProvenanceRecord)
            WHERE r.activity_name IN ['read_file', 'write_file', 'delete_file']
            RETURN r.activity_name as action,
                   r.activity_type as type,
                   r.timestamp as time,
                   r.record_hash as hash
            ORDER BY r.timestamp DESC
            LIMIT $limit
        """, {"file_path": file_path, "limit": limit})

        for rec in result:
            records.append({
                "action": rec["action"],
                "type": rec["type"],
                "time": rec["time"],
                "hash": rec["hash"][:16] + "..."
            })

    timeline = _build_timeline(records)

    return TraceResult(
        query_type="file",
        query_value=file_path,
        found=len(records) > 0,
        records=records,
        timeline=timeline,
        summary=f"Found {len(records)} actions on file"
    )


def trace_decision(decision_type: str, time_range_hours: int = 24) -> TraceResult:
    """
    Trace why a decision was made.

    "Why was this request blocked?"
    """
    if not _driver:
        return TraceResult("decision", decision_type, False, [], [], summary="DB not connected")

    records = []
    with _driver.session() as session:
        # Find decision and what led to it
        result = session.run("""
            MATCH (r:ProvenanceRecord)
            WHERE r.activity_type = 'decision'
            OPTIONAL MATCH (r)-[:FOLLOWS*1..5]->(prev:ProvenanceRecord)
            RETURN r.activity_name as decision,
                   r.timestamp as time,
                   r.record_hash as hash,
                   collect(prev.activity_name) as prior_actions
            ORDER BY r.timestamp DESC
            LIMIT 10
        """, {"decision_type": decision_type})

        for rec in result:
            records.append({
                "decision": rec["decision"],
                "time": rec["time"],
                "hash": rec["hash"][:16] + "...",
                "prior_actions": rec["prior_actions"][:5] if rec["prior_actions"] else []
            })

    # Find root cause (first action in chain)
    root_cause = None
    if records and records[0].get("prior_actions"):
        root_cause = {"action": records[0]["prior_actions"][-1] if records[0]["prior_actions"] else None}

    return TraceResult(
        query_type="decision",
        query_value=decision_type,
        found=len(records) > 0,
        records=records,
        timeline=_build_timeline(records),
        root_cause=root_cause,
        summary=f"Found {len(records)} decisions"
    )


def trace_agent(agent_name: str, limit: int = 50) -> TraceResult:
    """
    Trace everything an agent did.

    "What did Claude Code do in this session?"
    """
    if not _driver:
        return TraceResult("agent", agent_name, False, [], [], summary="DB not connected")

    records = []
    with _driver.session() as session:
        result = session.run("""
            MATCH (r:ProvenanceRecord)-[:PERFORMED_BY]->(a:Agent)
            WHERE a.name = $agent_name
            RETURN r.activity_name as action,
                   r.activity_type as type,
                   r.timestamp as time,
                   r.record_hash as hash
            ORDER BY r.timestamp DESC
            LIMIT $limit
        """, {"agent_name": agent_name, "limit": limit})

        for rec in result:
            records.append({
                "action": rec["action"],
                "type": rec["type"],
                "time": rec["time"],
                "hash": rec["hash"][:16] + "..."
            })

    # Categorize actions
    action_counts = {}
    for r in records:
        t = r["type"]
        action_counts[t] = action_counts.get(t, 0) + 1

    return TraceResult(
        query_type="agent",
        query_value=agent_name,
        found=len(records) > 0,
        records=records,
        timeline=_build_timeline(records),
        summary=f"Agent performed {len(records)} actions: {action_counts}"
    )


def trace_error(error_keyword: str, limit: int = 20) -> TraceResult:
    """
    Trace actions around an error.

    "What happened before this error?"
    """
    if not _driver:
        return TraceResult("error", error_keyword, False, [], [], summary="DB not connected")

    records = []
    with _driver.session() as session:
        # Find error records and preceding actions
        result = session.run("""
            MATCH (r:ProvenanceRecord)
            WHERE r.activity_type = 'error' OR r.activity_type = 'decision'
            OPTIONAL MATCH (r)-[:FOLLOWS*1..10]->(prev:ProvenanceRecord)
            RETURN r.activity_name as action,
                   r.activity_type as type,
                   r.timestamp as time,
                   r.record_hash as hash,
                   collect({
                       action: prev.activity_name,
                       type: prev.activity_type,
                       time: prev.timestamp
                   })[0..5] as chain
            ORDER BY r.timestamp DESC
            LIMIT $limit
        """, {"limit": limit})

        for rec in result:
            records.append({
                "action": rec["action"],
                "type": rec["type"],
                "time": rec["time"],
                "hash": rec["hash"][:16] + "...",
                "chain": rec["chain"]
            })

    # First action in chain is likely root cause
    root_cause = None
    if records and records[0].get("chain"):
        chain = records[0]["chain"]
        if chain:
            root_cause = chain[-1]

    return TraceResult(
        query_type="error",
        query_value=error_keyword,
        found=len(records) > 0,
        records=records,
        timeline=_build_timeline(records),
        root_cause=root_cause,
        summary=f"Found {len(records)} related records"
    )


def trace_session(session_id: str) -> TraceResult:
    """
    Get complete trace of a session.

    "Show me everything that happened in session X"
    """
    if not _driver:
        return TraceResult("session", session_id, False, [], [], summary="DB not connected")

    records = []
    with _driver.session() as session:
        result = session.run("""
            MATCH (s:Session {session_id: $session_id})<-[:BELONGS_TO]-(r:ProvenanceRecord)
            OPTIONAL MATCH (r)-[:PERFORMED_BY]->(a:Agent)
            RETURN r.activity_name as action,
                   r.activity_type as type,
                   r.timestamp as time,
                   r.record_hash as hash,
                   r.sequence_number as seq,
                   a.name as agent
            ORDER BY r.sequence_number
        """, {"session_id": session_id})

        for rec in result:
            records.append({
                "seq": rec["seq"],
                "action": rec["action"],
                "type": rec["type"],
                "time": rec["time"],
                "agent": rec["agent"],
                "hash": rec["hash"][:16] + "..." if rec["hash"] else None
            })

    return TraceResult(
        query_type="session",
        query_value=session_id,
        found=len(records) > 0,
        records=records,
        timeline=_build_timeline(records),
        summary=f"Session has {len(records)} records"
    )


def _build_timeline(records: list[dict]) -> list[dict]:
    """Build a visual timeline from records."""
    timeline = []
    for i, r in enumerate(records[:10]):  # Limit to 10 for display
        timeline.append({
            "step": i + 1,
            "action": r.get("action", "unknown"),
            "type": r.get("type", "unknown"),
            "time": r.get("time", "")[:19] if r.get("time") else ""
        })
    return timeline


def format_trace_report(result: TraceResult) -> str:
    """Format trace result as readable report."""
    lines = []
    lines.append("=" * 60)
    lines.append(f"  TRACE REPORT: {result.query_type.upper()}")
    lines.append("=" * 60)
    lines.append(f"\nQuery: {result.query_value}")
    lines.append(f"Found: {result.found}")
    lines.append(f"Summary: {result.summary}")

    if result.root_cause:
        lines.append(f"\nROOT CAUSE: {result.root_cause}")

    lines.append("\nTIMELINE:")
    lines.append("-" * 50)
    for t in result.timeline:
        lines.append(f"  [{t['step']}] {t['time']} | {t['type']:12} | {t['action']}")
    lines.append("-" * 50)

    lines.append("\n" + "=" * 60)
    return "\n".join(lines)


# Quick search function for API
def quick_search(query: str) -> TraceResult:
    """
    Natural language search.

    Examples:
    - "what did Claude Code do"
    - "why was request blocked"
    - "who touched config.py"
    """
    query_lower = query.lower()

    if "agent" in query_lower or "claude" in query_lower or "cursor" in query_lower:
        # Extract agent name
        for agent in ["Claude Code", "Cursor", "Windsurf"]:
            if agent.lower() in query_lower:
                return trace_agent(agent)
        return trace_agent("Claude Code")  # Default

    elif "decision" in query_lower or "block" in query_lower or "why" in query_lower:
        return trace_decision("decision")

    elif "file" in query_lower or "touched" in query_lower:
        return trace_file("")

    elif "error" in query_lower or "fail" in query_lower:
        return trace_error("")

    elif "session" in query_lower:
        return trace_session("")

    else:
        # Default: show recent activity
        return trace_agent("Claude Code", limit=20)


if __name__ == "__main__":
    from dotenv import load_dotenv
    load_dotenv()

    init_trace_db()

    print("\n=== TRACE FINDER DEMO ===\n")

    # Example queries
    result = trace_agent("Claude Code", limit=10)
    print(format_trace_report(result))

    result = trace_decision("decision")
    print(format_trace_report(result))
