"""
Behavior Drift Detection

Statistical anomaly detection for AI agent behavior.
Learns baseline from historical sessions, flags deviations.
100% local — uses SQLite, no external services.

Detection methods:
- Tool usage frequency deviation (z-score)
- New tool introduction (unseen tools)
- Timing anomalies (unusual activity speed)
- Pattern shift (tool combination changes)
"""

import json
import logging
import math
import sqlite3
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

logger = logging.getLogger("inalign-drift")

INALIGN_DIR = Path.home() / ".inalign"
DB_PATH = INALIGN_DIR / "provenance.db"


@dataclass
class DriftAnomaly:
    anomaly_type: str  # "new_tool", "frequency_spike", "timing_anomaly", "pattern_shift"
    severity: str  # "low", "medium", "high"
    description: str
    evidence: dict[str, Any] = field(default_factory=dict)


@dataclass
class BehaviorBaseline:
    agent_id: str
    session_count: int = 0
    total_actions: int = 0
    tool_frequency: dict[str, float] = field(default_factory=dict)  # avg per session
    tool_stddev: dict[str, float] = field(default_factory=dict)
    avg_session_length: float = 0.0
    avg_interval_seconds: float = 0.0
    known_tools: set = field(default_factory=set)
    updated_at: str = ""


@dataclass
class DriftReport:
    session_id: str
    agent_id: str
    generated_at: str
    drift_detected: bool = False
    drift_score: float = 0.0  # 0-100
    anomalies: list[DriftAnomaly] = field(default_factory=list)
    baseline: Optional[dict] = None


def _ensure_table():
    """Create drift baseline tables."""
    if not DB_PATH.exists():
        return
    try:
        conn = sqlite3.connect(str(DB_PATH), check_same_thread=False)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS behavior_baselines (
                agent_id TEXT PRIMARY KEY,
                session_count INTEGER DEFAULT 0,
                total_actions INTEGER DEFAULT 0,
                tool_frequency TEXT DEFAULT '{}',
                tool_stddev TEXT DEFAULT '{}',
                avg_session_length REAL DEFAULT 0,
                avg_interval_seconds REAL DEFAULT 0,
                known_tools TEXT DEFAULT '[]',
                updated_at TEXT NOT NULL
            )
        """)
        conn.commit()
        conn.close()
    except Exception as e:
        logger.warning(f"[DRIFT] Table creation failed: {e}")


def _load_baseline(agent_id: str) -> Optional[BehaviorBaseline]:
    """Load baseline from SQLite."""
    _ensure_table()
    if not DB_PATH.exists():
        return None
    try:
        conn = sqlite3.connect(str(DB_PATH), check_same_thread=False)
        conn.row_factory = sqlite3.Row
        row = conn.execute(
            "SELECT * FROM behavior_baselines WHERE agent_id=?", (agent_id,)
        ).fetchone()
        conn.close()
        if not row:
            return None
        return BehaviorBaseline(
            agent_id=row["agent_id"],
            session_count=row["session_count"],
            total_actions=row["total_actions"],
            tool_frequency=json.loads(row["tool_frequency"]),
            tool_stddev=json.loads(row["tool_stddev"]),
            avg_session_length=row["avg_session_length"],
            avg_interval_seconds=row["avg_interval_seconds"],
            known_tools=set(json.loads(row["known_tools"])),
            updated_at=row["updated_at"],
        )
    except Exception as e:
        logger.warning(f"[DRIFT] Load baseline failed: {e}")
        return None


def _save_baseline(baseline: BehaviorBaseline):
    """Save baseline to SQLite."""
    _ensure_table()
    if not DB_PATH.exists():
        return
    try:
        conn = sqlite3.connect(str(DB_PATH), check_same_thread=False)
        conn.execute(
            """INSERT INTO behavior_baselines
               (agent_id, session_count, total_actions, tool_frequency, tool_stddev,
                avg_session_length, avg_interval_seconds, known_tools, updated_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
               ON CONFLICT(agent_id) DO UPDATE SET
                   session_count=?, total_actions=?, tool_frequency=?, tool_stddev=?,
                   avg_session_length=?, avg_interval_seconds=?, known_tools=?, updated_at=?""",
            (
                baseline.agent_id, baseline.session_count, baseline.total_actions,
                json.dumps(baseline.tool_frequency), json.dumps(baseline.tool_stddev),
                baseline.avg_session_length, baseline.avg_interval_seconds,
                json.dumps(sorted(baseline.known_tools)), baseline.updated_at,
                # ON CONFLICT values
                baseline.session_count, baseline.total_actions,
                json.dumps(baseline.tool_frequency), json.dumps(baseline.tool_stddev),
                baseline.avg_session_length, baseline.avg_interval_seconds,
                json.dumps(sorted(baseline.known_tools)), baseline.updated_at,
            ),
        )
        conn.commit()
        conn.close()
    except Exception as e:
        logger.warning(f"[DRIFT] Save baseline failed: {e}")


def _load_session_records(session_id: str) -> list[dict]:
    """Load records for a session."""
    if not DB_PATH.exists():
        return []
    try:
        conn = sqlite3.connect(str(DB_PATH), check_same_thread=False)
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            "SELECT * FROM records WHERE session_id=? ORDER BY sequence_number ASC",
            (session_id,),
        ).fetchall()
        conn.close()
        return [dict(r) for r in rows]
    except Exception:
        return []


def _load_all_agent_sessions(agent_id: str) -> list[str]:
    """Get all session IDs for an agent."""
    if not DB_PATH.exists():
        return []
    try:
        conn = sqlite3.connect(str(DB_PATH), check_same_thread=False)
        conn.row_factory = sqlite3.Row
        # Match agent_id pattern (agent:<name>:<session>)
        agent_prefix = agent_id.split(":")[1] if ":" in agent_id else agent_id
        rows = conn.execute(
            "SELECT DISTINCT session_id FROM sessions WHERE agent_name LIKE ?",
            (f"%{agent_prefix}%",),
        ).fetchall()
        conn.close()
        return [r["session_id"] for r in rows]
    except Exception:
        return []


def _parse_ts(ts: str) -> Optional[datetime]:
    if not ts:
        return None
    try:
        return datetime.fromisoformat(ts.replace("Z", "+00:00"))
    except Exception:
        return None


def build_baseline(agent_id: str) -> BehaviorBaseline:
    """
    Build or update behavior baseline from historical sessions.

    Computes average tool usage frequencies and standard deviations
    across all known sessions for this agent.
    """
    sessions = _load_all_agent_sessions(agent_id)
    if not sessions:
        baseline = BehaviorBaseline(
            agent_id=agent_id,
            updated_at=datetime.now(timezone.utc).isoformat(),
        )
        _save_baseline(baseline)
        return baseline

    all_tool_counts = []  # list of Counter per session
    all_intervals = []
    all_lengths = []
    all_tools = set()

    for sid in sessions:
        records = _load_session_records(sid)
        if not records:
            continue

        # Tool frequency for this session
        tool_counter = Counter()
        for r in records:
            tool_counter[r.get("activity_name", "unknown")] += 1
        all_tool_counts.append(tool_counter)
        all_tools.update(tool_counter.keys())

        # Session length
        all_lengths.append(len(records))

        # Compute intervals
        timestamps = []
        for r in records:
            ts = _parse_ts(r.get("timestamp", ""))
            if ts:
                timestamps.append(ts)
        timestamps.sort()
        if len(timestamps) > 1:
            intervals = [(timestamps[i] - timestamps[i-1]).total_seconds()
                         for i in range(1, len(timestamps))]
            all_intervals.extend(intervals)

    # Compute averages and stddev per tool
    n_sessions = len(all_tool_counts)
    tool_avg = {}
    tool_std = {}

    for tool in all_tools:
        counts = [tc.get(tool, 0) for tc in all_tool_counts]
        avg = sum(counts) / n_sessions
        variance = sum((c - avg) ** 2 for c in counts) / max(n_sessions, 1)
        tool_avg[tool] = round(avg, 2)
        tool_std[tool] = round(math.sqrt(variance), 2)

    avg_session_len = sum(all_lengths) / max(len(all_lengths), 1)
    avg_interval = sum(all_intervals) / max(len(all_intervals), 1) if all_intervals else 0

    baseline = BehaviorBaseline(
        agent_id=agent_id,
        session_count=n_sessions,
        total_actions=sum(all_lengths),
        tool_frequency=tool_avg,
        tool_stddev=tool_std,
        avg_session_length=round(avg_session_len, 2),
        avg_interval_seconds=round(avg_interval, 3),
        known_tools=all_tools,
        updated_at=datetime.now(timezone.utc).isoformat(),
    )

    _save_baseline(baseline)
    return baseline


def detect_drift(session_id: str, agent_id: str = None) -> DriftReport:
    """
    Detect behavioral drift in a session compared to baseline.

    Returns DriftReport with anomalies and drift score.
    """
    records = _load_session_records(session_id)
    if not agent_id:
        # Try to infer from session
        if not DB_PATH.exists():
            agent_id = "unknown"
        else:
            try:
                conn = sqlite3.connect(str(DB_PATH), check_same_thread=False)
                conn.row_factory = sqlite3.Row
                row = conn.execute(
                    "SELECT agent_name FROM sessions WHERE session_id=?", (session_id,)
                ).fetchone()
                conn.close()
                agent_id = row["agent_name"] if row else "unknown"
            except Exception:
                agent_id = "unknown"

    baseline = _load_baseline(agent_id)
    anomalies = []

    if not baseline or baseline.session_count < 2:
        # Not enough data for drift detection — build baseline
        baseline = build_baseline(agent_id)
        return DriftReport(
            session_id=session_id,
            agent_id=agent_id,
            generated_at=datetime.now(timezone.utc).isoformat(),
            drift_detected=False,
            drift_score=0.0,
            anomalies=[],
            baseline={
                "session_count": baseline.session_count,
                "message": "Insufficient historical data. Baseline updated with current session.",
            },
        )

    # Current session tool counts
    current_tools = Counter()
    for r in records:
        current_tools[r.get("activity_name", "unknown")] += 1

    # 1. New tool detection
    new_tools = set(current_tools.keys()) - baseline.known_tools
    if new_tools:
        anomalies.append(DriftAnomaly(
            anomaly_type="new_tool",
            severity="medium" if len(new_tools) <= 2 else "high",
            description=f"Agent used {len(new_tools)} previously unseen tool(s)",
            evidence={"new_tools": sorted(new_tools)},
        ))

    # 2. Frequency deviation (z-score)
    for tool, count in current_tools.items():
        if tool in baseline.tool_frequency:
            avg = baseline.tool_frequency[tool]
            std = baseline.tool_stddev.get(tool, 1.0)
            if std > 0:
                z = (count - avg) / std
                if abs(z) > 3.0:
                    anomalies.append(DriftAnomaly(
                        anomaly_type="frequency_spike",
                        severity="high" if abs(z) > 5 else "medium",
                        description=f"Tool '{tool}' used {count}x (baseline avg: {avg:.1f}, z-score: {z:.1f})",
                        evidence={"tool": tool, "count": count, "avg": avg, "stddev": std, "z_score": round(z, 2)},
                    ))

    # 3. Timing anomalies
    timestamps = []
    for r in records:
        ts = _parse_ts(r.get("timestamp", ""))
        if ts:
            timestamps.append(ts)
    timestamps.sort()

    if len(timestamps) > 1 and baseline.avg_interval_seconds > 0:
        intervals = [(timestamps[i] - timestamps[i-1]).total_seconds()
                     for i in range(1, len(timestamps))]
        current_avg = sum(intervals) / len(intervals)

        if current_avg < baseline.avg_interval_seconds * 0.2:
            anomalies.append(DriftAnomaly(
                anomaly_type="timing_anomaly",
                severity="medium",
                description=f"Activity speed 5x faster than baseline ({current_avg:.2f}s vs {baseline.avg_interval_seconds:.2f}s avg)",
                evidence={"current_avg": round(current_avg, 3), "baseline_avg": baseline.avg_interval_seconds},
            ))

    # 4. Session length anomaly
    if baseline.avg_session_length > 0:
        length_ratio = len(records) / baseline.avg_session_length
        if length_ratio > 5:
            anomalies.append(DriftAnomaly(
                anomaly_type="pattern_shift",
                severity="medium",
                description=f"Session length {len(records)} is {length_ratio:.1f}x the baseline avg ({baseline.avg_session_length:.0f})",
                evidence={"current_length": len(records), "avg_length": baseline.avg_session_length},
            ))

    # Compute drift score
    severity_weights = {"low": 10, "medium": 25, "high": 40}
    drift_score = min(100, sum(severity_weights.get(a.severity, 10) for a in anomalies))

    return DriftReport(
        session_id=session_id,
        agent_id=agent_id,
        generated_at=datetime.now(timezone.utc).isoformat(),
        drift_detected=len(anomalies) > 0,
        drift_score=drift_score,
        anomalies=anomalies,
        baseline={
            "session_count": baseline.session_count,
            "avg_session_length": baseline.avg_session_length,
            "known_tools": len(baseline.known_tools),
            "avg_interval": baseline.avg_interval_seconds,
        },
    )


def drift_report_to_dict(report: DriftReport) -> dict[str, Any]:
    """Convert DriftReport to JSON-serializable dict."""
    return {
        "session_id": report.session_id,
        "agent_id": report.agent_id,
        "generated_at": report.generated_at,
        "drift_detected": report.drift_detected,
        "drift_score": report.drift_score,
        "anomaly_count": len(report.anomalies),
        "anomalies": [
            {
                "type": a.anomaly_type,
                "severity": a.severity,
                "description": a.description,
                "evidence": a.evidence,
            }
            for a in report.anomalies
        ],
        "baseline": report.baseline,
    }


def get_behavior_baseline(agent_id: str) -> dict[str, Any]:
    """Get or build behavior baseline for an agent."""
    baseline = _load_baseline(agent_id)
    if not baseline:
        baseline = build_baseline(agent_id)

    return {
        "agent_id": baseline.agent_id,
        "session_count": baseline.session_count,
        "total_actions": baseline.total_actions,
        "tool_frequency": baseline.tool_frequency,
        "known_tools": sorted(baseline.known_tools),
        "avg_session_length": baseline.avg_session_length,
        "avg_interval_seconds": baseline.avg_interval_seconds,
        "updated_at": baseline.updated_at,
    }
