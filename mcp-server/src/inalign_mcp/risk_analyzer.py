"""SQLite-Based Risk Analysis for InALign - local replacement for Neo4j GraphRAG.
Reads ~/.inalign/provenance.db + ~/.inalign/sessions/*.json.gz.
Patterns: MASS_FILE_READ, DATA_EXFILTRATION, PRIVILEGE_ESCALATION,
          RAPID_TOOL_CALLS, SUSPICIOUS_COMMANDS
Tiers: analyze_basic() = Free (3), analyze_full() = Pro (all 5 + recommendations)
"""

import gzip
import json
import logging
import re
import sqlite3
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, Optional

logger = logging.getLogger("inalign-risk")

INALIGN_DIR = Path.home() / ".inalign"
DB_PATH = INALIGN_DIR / "provenance.db"
SESSIONS_DIR = INALIGN_DIR / "sessions"

SENSITIVE_PATTERNS = [".env", ".ssh", "credentials", "secret", "password", ".key",
    ".pem", "id_rsa", "id_ed25519", ".aws", ".pypirc", ".npmrc", ".netrc",
    "token", ".kube/config"]
DANGEROUS_COMMANDS = [r"rm\s+-rf\s+/", r"curl\s+.*\|.*sh", r"wget\s+.*\|.*sh",
    r"curl\s+-[^\s]*d\s", r"nc\s+-[^\s]*l", r"chmod\s+777",
    r"eval\s*\(", r"base64\s+-d", r"python\s+-c\s", r"powershell\s+-enc"]
EXTERNAL_TOOLS = ["curl", "wget", "http", "upload", "send", "post",
    "llm_request", "api_call", "fetch", "request"]


class RiskLevel(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

@dataclass
class RiskPattern:
    pattern_id: str
    pattern_name: str
    risk_level: RiskLevel
    confidence: float
    description: str
    matched_records: list[str] = field(default_factory=list)
    evidence: dict[str, Any] = field(default_factory=dict)
    recommendation: str = ""

@dataclass
class BehaviorProfile:
    session_id: str
    total_activities: int
    tool_frequency: dict[str, int] = field(default_factory=dict)
    type_frequency: dict[str, int] = field(default_factory=dict)
    avg_interval_seconds: float = 0.0
    min_interval_seconds: float = 0.0
    first_activity: str = ""
    last_activity: str = ""
    anomalies: list[str] = field(default_factory=list)


@dataclass
class RiskReport:
    session_id: str
    overall_risk: RiskLevel
    risk_score: int  # 0-100
    patterns: list[RiskPattern] = field(default_factory=list)
    behavior: Optional[BehaviorProfile] = None
    recommendations: list[str] = field(default_factory=list)


# -- DB helpers ----------------------------------------------------------------
def _get_db() -> Optional[sqlite3.Connection]:
    if not DB_PATH.exists():
        return None
    conn = sqlite3.connect(str(DB_PATH), check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn


def _load_session_records(session_id: str) -> list[dict]:
    conn = _get_db()
    if not conn:
        return []
    try:
        rows = conn.execute(
            "SELECT * FROM records WHERE session_id=? ORDER BY sequence_number ASC",
            (session_id,),
        ).fetchall()
        return [dict(r) for r in rows]
    except Exception as e:
        logger.warning(f"[RISK] DB read failed: {e}")
        return []
    finally:
        conn.close()


def _load_session_json(session_id: str) -> list[dict]:
    if not SESSIONS_DIR.exists():
        return []
    extra: list[dict] = []
    for f in SESSIONS_DIR.iterdir():
        if session_id in f.name and f.suffix == ".gz":
            try:
                with gzip.open(f, "rt", encoding="utf-8") as gz:
                    data = json.load(gz)
                    if isinstance(data, list):
                        extra.extend(data)
                    elif isinstance(data, dict):
                        extra.extend(data.get("records", []))
            except Exception:
                pass
    return extra


def _parse_ts(ts: str) -> Optional[datetime]:
    if not ts:
        return None
    try:
        return datetime.fromisoformat(ts.replace("Z", "+00:00"))
    except Exception:
        return None


# -- Pattern detectors ---------------------------------------------------------
def _detect_mass_file_read(records: list[dict], threshold: int = 10) -> list[RiskPattern]:
    reads = [r for r in records if r.get("activity_type") == "file_read"]
    if len(reads) < threshold:
        return []
    rapid, ids = 0, []
    for i in range(1, len(reads)):
        t1, t2 = _parse_ts(reads[i-1].get("timestamp", "")), _parse_ts(reads[i].get("timestamp", ""))
        if t1 and t2 and (t2 - t1).total_seconds() < 2:
            rapid += 1
            ids.append(reads[i].get("id", ""))
    if rapid >= 5:
        return [RiskPattern(
            pattern_id="PAT-MFR", pattern_name="MASS_FILE_READ",
            risk_level=RiskLevel.HIGH, confidence=min(0.95, 0.6 + rapid * 0.03),
            description=f"{len(reads)} file reads, {rapid} rapid (<2s gaps)",
            matched_records=ids[:20],
            recommendation="Review file access patterns. May indicate reconnaissance.",
        )]
    return []


def _detect_data_exfiltration(records: list[dict]) -> list[RiskPattern]:
    reads = [r for r in records if r.get("activity_type") == "file_read"]
    externals = []
    for r in records:
        nm = (r.get("activity_name") or "").lower()
        at = r.get("activity_type", "")
        ax = (r.get("activity_attributes") or "").lower()
        if any(e in nm for e in EXTERNAL_TOOLS) or at == "llm_request" or any(e in ax for e in EXTERNAL_TOOLS):
            externals.append(r)
    pats = []
    for fr in reads:
        ft = _parse_ts(fr.get("timestamp", ""))
        if not ft:
            continue
        for ext in externals:
            et = _parse_ts(ext.get("timestamp", ""))
            if et and 0 < (delta := (et - ft).total_seconds()) < 60:
                pats.append(RiskPattern(
                    pattern_id="PAT-DEX", pattern_name="DATA_EXFILTRATION",
                    risk_level=RiskLevel.CRITICAL, confidence=0.85,
                    description=f"File read -> external call within {delta:.0f}s",
                    matched_records=[fr.get("id", ""), ext.get("id", "")],
                    evidence={"source": fr.get("activity_name", ""),
                              "target": ext.get("activity_name", ""),
                              "gap_seconds": round(delta, 1)},
                    recommendation="CRITICAL: File content may have been sent externally.",
                ))
                break
    return pats[:3]


def _detect_privilege_escalation(records: list[dict]) -> list[RiskPattern]:
    hits = []
    for r in records:
        nm = (r.get("activity_name") or "").lower()
        ax = (r.get("activity_attributes") or "").lower()
        for pat in SENSITIVE_PATTERNS:
            if pat in nm or pat in ax:
                hits.append((r.get("id", ""), r.get("activity_name", "")))
                break
    if not hits:
        return []
    files = list({h[1] for h in hits})
    return [RiskPattern(
        pattern_id="PAT-PEX", pattern_name="PRIVILEGE_ESCALATION",
        risk_level=RiskLevel.CRITICAL if len(hits) >= 3 else RiskLevel.HIGH,
        confidence=0.90,
        description=f"Sensitive file access: {', '.join(files[:5])}",
        matched_records=[h[0] for h in hits][:20],
        evidence={"sensitive_files": files[:10], "count": len(hits)},
        recommendation="Agent accessing credentials/keys. Restrict file access scope.",
    )]


def _detect_rapid_tool_calls(records: list[dict], threshold_ms: int = 200) -> list[RiskPattern]:
    if len(records) < 5:
        return []
    rapid, ids = 0, []
    for i in range(1, len(records)):
        t1, t2 = _parse_ts(records[i-1].get("timestamp", "")), _parse_ts(records[i].get("timestamp", ""))
        if t1 and t2 and 0 <= (t2 - t1).total_seconds() * 1000 < threshold_ms:
            rapid += 1
            ids.append(records[i].get("id", ""))
    if rapid >= 5:
        return [RiskPattern(
            pattern_id="PAT-RTC", pattern_name="RAPID_TOOL_CALLS",
            risk_level=RiskLevel.MEDIUM, confidence=min(0.90, 0.5 + rapid * 0.04),
            description=f"{rapid} tool calls faster than {threshold_ms}ms apart",
            matched_records=ids[:20],
            recommendation="Unusually rapid activity. May indicate automated probing.",
        )]
    return []


def _detect_suspicious_commands(records: list[dict]) -> list[RiskPattern]:
    hits = []
    for r in records:
        combined = f"{(r.get('activity_name') or '')} {r.get('activity_attributes') or ''}".lower()
        for pat in DANGEROUS_COMMANDS:
            if re.search(pat, combined):
                hits.append((r.get("id", ""), r.get("activity_name", "")))
                break
    if not hits:
        return []
    return [RiskPattern(
        pattern_id="PAT-SCM", pattern_name="SUSPICIOUS_COMMANDS",
        risk_level=RiskLevel.CRITICAL if len(hits) >= 2 else RiskLevel.HIGH,
        confidence=0.92, description=f"{len(hits)} suspicious command(s) detected",
        matched_records=[h[0] for h in hits][:20],
        evidence={"commands": [h[1] for h in hits][:10]},
        recommendation="Dangerous commands detected. Review and restrict bash access.",
    )]


# -- Behavior profiling -------------------------------------------------------
def _build_behavior_profile(session_id: str, records: list[dict]) -> BehaviorProfile:
    tool_freq: dict[str, int] = {}
    type_freq: dict[str, int] = {}
    timestamps: list[datetime] = []
    for r in records:
        aname = r.get("activity_name", "unknown")
        atype = r.get("activity_type", "unknown")
        tool_freq[aname] = tool_freq.get(aname, 0) + 1
        type_freq[atype] = type_freq.get(atype, 0) + 1
        ts = _parse_ts(r.get("timestamp", ""))
        if ts:
            timestamps.append(ts)
    timestamps.sort()

    avg_iv, min_iv = 0.0, float("inf")
    if len(timestamps) > 1:
        diffs = [(timestamps[i] - timestamps[i-1]).total_seconds() for i in range(1, len(timestamps))]
        avg_iv = sum(diffs) / len(diffs)
        min_iv = min(diffs)

    anomalies: list[str] = []
    if avg_iv < 0.5 and len(records) > 10:
        anomalies.append("Unusually rapid activity (avg < 0.5s)")
    if type_freq.get("file_read", 0) > 20:
        anomalies.append(f"High file read volume: {type_freq['file_read']}")
    bash_n = sum(v for k, v in tool_freq.items() if "bash" in k.lower())
    if bash_n > 15:
        anomalies.append(f"High bash usage: {bash_n}")
    if any(any(p in (r.get("activity_name") or "").lower() for p in SENSITIVE_PATTERNS) for r in records):
        anomalies.append("Sensitive resource access detected")

    return BehaviorProfile(
        session_id=session_id, total_activities=len(records),
        tool_frequency=dict(sorted(tool_freq.items(), key=lambda x: -x[1])[:15]),
        type_frequency=type_freq,
        avg_interval_seconds=round(avg_iv, 3),
        min_interval_seconds=round(min_iv, 3) if min_iv != float("inf") else 0.0,
        first_activity=timestamps[0].isoformat() if timestamps else "",
        last_activity=timestamps[-1].isoformat() if timestamps else "",
        anomalies=anomalies,
    )


# -- Risk scoring --------------------------------------------------------------
def _compute_risk_score(patterns: list[RiskPattern], profile: BehaviorProfile) -> int:
    score = 0
    weights = {RiskLevel.CRITICAL: 30, RiskLevel.HIGH: 15, RiskLevel.MEDIUM: 7, RiskLevel.LOW: 2}
    for p in patterns:
        score += int(weights.get(p.risk_level, 0) * p.confidence)
    score += len(profile.anomalies) * 5
    if profile.total_activities > 100:
        score += 5
    if profile.total_activities > 500:
        score += 10
    return min(100, max(0, score))


def _score_to_level(score: int) -> RiskLevel:
    if score >= 70: return RiskLevel.CRITICAL
    if score >= 40: return RiskLevel.HIGH
    if score >= 20: return RiskLevel.MEDIUM
    return RiskLevel.LOW


def _generate_recommendations(patterns: list[RiskPattern], profile: BehaviorProfile) -> list[str]:
    recs, names = [], {p.pattern_name for p in patterns}
    rec_map = {
        "DATA_EXFILTRATION": "Enable STRICT_ENTERPRISE policy to block external transmissions.",
        "PRIVILEGE_ESCALATION": "Restrict file access scope via policy rules.",
        "SUSPICIOUS_COMMANDS": "Whitelist allowed bash commands. Block rm -rf, curl piping.",
        "MASS_FILE_READ": "Set rate limits on file read operations per session.",
        "RAPID_TOOL_CALLS": "Investigate automated tool usage. May indicate scripted attack.",
    }
    for name, rec in rec_map.items():
        if name in names:
            recs.append(rec)
    if not patterns and profile.total_activities > 0:
        recs.append("No suspicious patterns detected. Session appears normal.")
    if not recs:
        recs.append("Insufficient data. Record more actions for analysis.")
    return recs


# -- Public API ----------------------------------------------------------------
def analyze_basic(session_id: str) -> RiskReport:
    """Free tier: 3 core pattern detectors."""
    records = _load_session_records(session_id) + _load_session_json(session_id)
    patterns: list[RiskPattern] = []
    patterns.extend(_detect_mass_file_read(records))
    patterns.extend(_detect_privilege_escalation(records))
    patterns.extend(_detect_rapid_tool_calls(records))
    profile = _build_behavior_profile(session_id, records)
    score = _compute_risk_score(patterns, profile)
    return RiskReport(session_id=session_id, overall_risk=_score_to_level(score),
                      risk_score=score, patterns=patterns, behavior=profile)


def analyze_full(session_id: str) -> RiskReport:
    """Pro tier: all 5 patterns + behavior profile + recommendations."""
    records = _load_session_records(session_id) + _load_session_json(session_id)
    patterns: list[RiskPattern] = []
    patterns.extend(_detect_mass_file_read(records))
    patterns.extend(_detect_data_exfiltration(records))
    patterns.extend(_detect_privilege_escalation(records))
    patterns.extend(_detect_rapid_tool_calls(records))
    patterns.extend(_detect_suspicious_commands(records))
    profile = _build_behavior_profile(session_id, records)
    score = _compute_risk_score(patterns, profile)
    return RiskReport(session_id=session_id, overall_risk=_score_to_level(score),
                      risk_score=score, patterns=patterns, behavior=profile,
                      recommendations=_generate_recommendations(patterns, profile))


# -- Convenience functions (server.py interface) -------------------------------
def analyze_session_risk(session_id: str) -> dict[str, Any]:
    """Dict interface matching graph_rag.py. Auto-selects tier by license."""
    try:
        from .license import has_feature
        pro = has_feature("advanced_reports")
    except ImportError:
        pro = False
    report = analyze_full(session_id) if pro else analyze_basic(session_id)
    return {
        "session_id": report.session_id,
        "overall_risk": report.overall_risk.value,
        "risk_score": report.risk_score,
        "patterns_detected": len(report.patterns),
        "patterns": [
            {"id": p.pattern_id, "name": p.pattern_name, "risk": p.risk_level.value,
             "confidence": p.confidence, "description": p.description,
             "recommendation": p.recommendation, "evidence": p.evidence}
            for p in report.patterns
        ],
        "behavior_profile": {
            "total_activities": report.behavior.total_activities if report.behavior else 0,
            "avg_action_interval": report.behavior.avg_interval_seconds if report.behavior else 0,
            "anomalies": report.behavior.anomalies if report.behavior else [],
        },
        "recommendations": report.recommendations,
        "tier": "pro" if pro else "free",
        "storage_mode": "sqlite",
    }


def get_behavior_profile(session_id: str) -> dict[str, Any]:
    """Dict interface for server.py get_behavior_profile handler."""
    records = _load_session_records(session_id) + _load_session_json(session_id)
    p = _build_behavior_profile(session_id, records)
    return {
        "session_id": p.session_id, "total_activities": p.total_activities,
        "tool_frequency": p.tool_frequency, "type_frequency": p.type_frequency,
        "avg_interval_seconds": p.avg_interval_seconds,
        "min_interval_seconds": p.min_interval_seconds,
        "first_activity": p.first_activity, "last_activity": p.last_activity,
        "anomalies": p.anomalies,
    }
