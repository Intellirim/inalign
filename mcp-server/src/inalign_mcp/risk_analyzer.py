"""SQLite-Based Risk Analysis with GraphRAG Pattern Detection for InALign.

Reads ~/.inalign/provenance.db + ~/.inalign/sessions/*.json.gz.
Builds in-memory causal graph from provenance records for pattern detection.

Patterns mapped to MITRE ATT&CK and MITRE ATLAS frameworks:
  TA0043 Reconnaissance     - Environment probing, system info gathering
  TA0002 Execution          - Dangerous command execution
  TA0003 Persistence        - Startup file modification, cron jobs
  TA0004 Privilege Esc.     - Credential/key file access, sudo
  TA0005 Defense Evasion    - Log deletion, history clearing, obfuscation
  TA0009 Collection         - Mass file reads, automated collection
  TA0010 Exfiltration       - File read -> external transmission chains
  ATLAS  Prompt Injection   - Instruction injection in tool results
  INALIGN Chain Integrity   - Sequence gaps, hash chain breaks

Tiers: analyze_basic() = Free (5 patterns), analyze_full() = Pro (all 11 + MITRE + causal chains)
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

# ---- MITRE ATT&CK Mapping ---------------------------------------------------
MITRE_MAP = {
    "RECONNAISSANCE":       {"tactic": "TA0043", "techniques": ["T1595.002", "T1592"]},
    "EXECUTION":            {"tactic": "TA0002", "techniques": ["T1059", "T1059.004"]},
    "PERSISTENCE":          {"tactic": "TA0003", "techniques": ["T1053", "T1546"]},
    "PRIVILEGE_ESCALATION": {"tactic": "TA0004", "techniques": ["T1068", "T1548", "T1552"]},
    "DEFENSE_EVASION":      {"tactic": "TA0005", "techniques": ["T1070", "T1027"]},
    "COLLECTION":           {"tactic": "TA0009", "techniques": ["T1005", "T1119"]},
    "EXFILTRATION":         {"tactic": "TA0010", "techniques": ["T1048", "T1567"]},
    "PROMPT_INJECTION":     {"tactic": "ATLAS", "techniques": ["AML.T0051"]},
    "CHAIN_MANIPULATION":   {"tactic": "INTEGRITY", "techniques": ["INALIGN-001"]},
    "SUSPICIOUS_TIMING":    {"tactic": "TA0002", "techniques": ["T1059"]},
}

# ---- Pattern Constants -------------------------------------------------------
SENSITIVE_PATTERNS = [
    ".env", ".ssh", "credentials", "secret", "password", ".key",
    ".pem", "id_rsa", "id_ed25519", ".aws", ".pypirc", ".npmrc", ".netrc",
    "token", ".kube/config", "htpasswd", "shadow",
]

DANGEROUS_COMMANDS = [
    r"rm\s+-rf\s+/", r"curl\s+.*\|.*sh", r"wget\s+.*\|.*sh",
    r"curl\s+-[^\s]*d\s", r"nc\s+-[^\s]*l", r"chmod\s+777",
    r"eval\s*\(", r"base64\s+-d", r"python\s+-c\s", r"powershell\s+-enc",
    r"mkfifo", r"nohup\s+", r"dd\s+if=", r">\s*/dev/sd",
]

EXTERNAL_TOOLS = [
    "curl", "wget", "http", "upload", "send", "post",
    "api_call", "fetch", "request",
]

INJECTION_PATTERNS = [
    r"ignore\s+(all\s+)?previous\s+instructions",
    r"disregard\s+(all\s+)?(above|prior|previous)",
    r"forget\s+(everything|all|your)\s+(instructions|rules|context)",
    r"you\s+are\s+now\s+",
    r"new\s+instructions?\s*:",
    r"\bsystem\s*:\s*you\s+are\b",
    r"\[system\]\s*",
    r"act\s+as\s+(a\s+)?",
    r"pretend\s+(to\s+be|you\s+are)",
    r"\bjailbreak\b",
    r"\bDAN\s+mode\b",
    r"do\s+anything\s+now",
    r"ignore\s+safety",
    r"bypass\s+(filter|restriction|guard)",
]

RECON_PATTERNS = [
    r"\bwhoami\b", r"\bid\b\s", r"\bhostname\b", r"\buname\s",
    r"\benv\b", r"\bprintenv\b",
    r"/etc/passwd", r"/etc/hosts", r"/etc/shadow", r"/etc/group",
    r"/proc/", r"/sys/class",
    r"\bps\s+aux\b", r"\bnetstat\b", r"\bss\s+-",
    r"\bifconfig\b", r"\bip\s+addr\b", r"\bip\s+route\b",
    r"\blsof\b", r"\bfind\s+/\s", r"\bls\s+-la\s+/",
]

PERSISTENCE_PATTERNS = [
    r"\.bashrc", r"\.bash_profile", r"\.zshrc", r"\.profile",
    r"crontab\s+-[el]", r"/etc/cron", r"@reboot",
    r"systemctl\s+enable", r"/etc/systemd/system",
    r"\.ssh/authorized_keys",
    r"/etc/init\.d", r"rc\.local",
    r"launchctl\s+load", r"com\.apple\.launchd",
    r"schtasks\s+/create", r"reg\s+add.*Run",
]

EVASION_PATTERNS = [
    r"history\s+-c", r"unset\s+HISTFILE", r"HISTSIZE=0", r"HISTFILESIZE=0",
    r"shred\s+", r"wipe\s+",
    r"rm\s+.*\.(log|audit|history|bak)",
    r">\s*/dev/null\s+2>&1",
    r"base64\s+-d", r"xxd\s+-r",
    r"openssl\s+enc", r"gpg\s+--decrypt",
    r"chmod\s+[0-7]*\s+.*\.(log|audit)",
    r"truncate\s+-s\s+0",
    r"sed\s+-i.*\.(log|history)",
]


# ---- Data Classes ------------------------------------------------------------
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
    mitre_tactic: str = ""
    mitre_techniques: list[str] = field(default_factory=list)


@dataclass
class CausalChain:
    """A causal chain of actions: input -> reasoning -> action -> result."""
    chain_id: int
    steps: list[dict] = field(default_factory=list)
    risk_indicators: list[str] = field(default_factory=list)


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
    causal_chains: list[CausalChain] = field(default_factory=list)


@dataclass
class RiskReport:
    session_id: str
    overall_risk: RiskLevel
    risk_score: int  # 0-100
    patterns: list[RiskPattern] = field(default_factory=list)
    behavior: Optional[BehaviorProfile] = None
    recommendations: list[str] = field(default_factory=list)
    causal_chains: list[CausalChain] = field(default_factory=list)


# ---- Helpers -----------------------------------------------------------------
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
    """Load session log from json.gz. Falls back to latest if no exact match."""
    if not SESSIONS_DIR.exists():
        return []
    extra: list[dict] = []
    # Try exact session_id match first
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
    # Fallback: load latest session file
    if not extra:
        gz_files = sorted(
            SESSIONS_DIR.glob("*.json.gz"),
            key=lambda f: f.stat().st_mtime, reverse=True,
        )
        if gz_files:
            try:
                with gzip.open(gz_files[0], "rt", encoding="utf-8") as gz:
                    data = json.load(gz)
                    if isinstance(data, dict):
                        extra.extend(data.get("records", []))
                    elif isinstance(data, list):
                        extra.extend(data)
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


def _get_text(record: dict) -> str:
    """Get all searchable text from a record (works for both provenance and session log)."""
    parts = [
        record.get("activity_name", ""),
        record.get("activity_attributes", ""),
        record.get("content", ""),
        record.get("tool_input", ""),
        record.get("tool_output", ""),
    ]
    return " ".join(str(p) for p in parts if p).lower()


def _assign_record_ids(prov_records: list[dict], content_records: list[dict]) -> None:
    """Assign stable numeric IDs to records for cross-referencing with timeline.
    Both prov and content map to timeline indices 0..N (same session, same order).
    """
    for idx, r in enumerate(prov_records):
        r["id"] = str(r.get("sequence_number", idx))
    for idx, r in enumerate(content_records):
        r["id"] = str(idx)


def _with_mitre(pattern_name: str, pat: RiskPattern) -> RiskPattern:
    """Attach MITRE ATT&CK metadata to a pattern."""
    m = MITRE_MAP.get(pattern_name, {})
    pat.mitre_tactic = m.get("tactic", "")
    pat.mitre_techniques = m.get("techniques", [])
    return pat


# ---- Original Pattern Detectors (v0.4) --------------------------------------
def _detect_mass_file_read(records: list[dict], threshold: int = 10) -> list[RiskPattern]:
    reads = [r for r in records if r.get("activity_type") == "file_read"
             or r.get("type") == "tool_call" and "read" in (r.get("tool_name") or "").lower()]
    if len(reads) < threshold:
        return []
    rapid, ids = 0, []
    for i in range(1, len(reads)):
        t1, t2 = _parse_ts(reads[i-1].get("timestamp", "")), _parse_ts(reads[i].get("timestamp", ""))
        if t1 and t2 and (t2 - t1).total_seconds() < 2:
            rapid += 1
            ids.append(reads[i].get("id", ""))
    if rapid >= 5:
        return [_with_mitre("COLLECTION", RiskPattern(
            pattern_id="PAT-MFR", pattern_name="MASS_FILE_READ",
            risk_level=RiskLevel.HIGH, confidence=min(0.95, 0.6 + rapid * 0.03),
            description=f"{len(reads)} file reads, {rapid} rapid (<2s gaps)",
            matched_records=ids[:20],
            recommendation="Review file access patterns. May indicate reconnaissance.",
        ))]
    return []


def _detect_data_exfiltration(records: list[dict]) -> list[RiskPattern]:
    reads = [r for r in records if r.get("activity_type") == "file_read"
             or r.get("type") == "tool_call" and "read" in (r.get("tool_name") or "").lower()]
    externals = []
    for r in records:
        text = _get_text(r)
        # Only flag actual external network tools, NOT llm_request (normal agent behavior)
        if any(e in text for e in EXTERNAL_TOOLS) and r.get("activity_type") != "llm_request":
            externals.append(r)
    pats = []
    for fr in reads:
        ft = _parse_ts(fr.get("timestamp", ""))
        if not ft:
            continue
        for ext in externals:
            et = _parse_ts(ext.get("timestamp", ""))
            if et and 0 < (delta := (et - ft).total_seconds()) < 60:
                pats.append(_with_mitre("EXFILTRATION", RiskPattern(
                    pattern_id="PAT-DEX", pattern_name="DATA_EXFILTRATION",
                    risk_level=RiskLevel.CRITICAL, confidence=0.85,
                    description=f"File read -> external call within {delta:.0f}s",
                    matched_records=[fr.get("id", ""), ext.get("id", "")],
                    evidence={"source": fr.get("activity_name", ""),
                              "target": ext.get("activity_name", ""),
                              "gap_seconds": round(delta, 1)},
                    recommendation="CRITICAL: File content may have been sent externally.",
                )))
                break
    return pats[:3]


def _detect_privilege_escalation(records: list[dict]) -> list[RiskPattern]:
    hits = []
    for r in records:
        text = _get_text(r)
        for pat in SENSITIVE_PATTERNS:
            if pat in text:
                hits.append((r.get("id", ""), r.get("activity_name") or r.get("tool_name", "")))
                break
    if not hits:
        return []
    files = list({h[1] for h in hits})
    return [_with_mitre("PRIVILEGE_ESCALATION", RiskPattern(
        pattern_id="PAT-PEX", pattern_name="PRIVILEGE_ESCALATION",
        risk_level=RiskLevel.CRITICAL if len(hits) >= 3 else RiskLevel.HIGH,
        confidence=0.90,
        description=f"Sensitive file access: {', '.join(files[:5])}",
        matched_records=[h[0] for h in hits][:20],
        evidence={"sensitive_files": files[:10], "count": len(hits)},
        recommendation="Agent accessing credentials/keys. Restrict file access scope.",
    ))]


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
        return [_with_mitre("SUSPICIOUS_TIMING", RiskPattern(
            pattern_id="PAT-RTC", pattern_name="RAPID_TOOL_CALLS",
            risk_level=RiskLevel.MEDIUM, confidence=min(0.90, 0.5 + rapid * 0.04),
            description=f"{rapid} tool calls faster than {threshold_ms}ms apart",
            matched_records=ids[:20],
            recommendation="Unusually rapid activity. May indicate automated probing.",
        ))]
    return []


def _detect_suspicious_commands(records: list[dict]) -> list[RiskPattern]:
    hits = []
    for r in records:
        text = _get_text(r)
        for pat in DANGEROUS_COMMANDS:
            if re.search(pat, text):
                hits.append((r.get("id", ""), r.get("activity_name") or r.get("tool_name", "")))
                break
    if not hits:
        return []
    return [_with_mitre("EXECUTION", RiskPattern(
        pattern_id="PAT-SCM", pattern_name="SUSPICIOUS_COMMANDS",
        risk_level=RiskLevel.CRITICAL if len(hits) >= 2 else RiskLevel.HIGH,
        confidence=0.92, description=f"{len(hits)} suspicious command(s) detected",
        matched_records=[h[0] for h in hits][:20],
        evidence={"commands": [h[1] for h in hits][:10]},
        recommendation="Dangerous commands detected. Review and restrict bash access.",
    ))]


# ---- NEW GraphRAG Pattern Detectors (v0.5.4) --------------------------------

def _detect_prompt_injection(records: list[dict]) -> list[RiskPattern]:
    """Detect prompt injection attempts in tool results (ATLAS AML.T0051)."""
    hits = []
    for r in records:
        # Only check tool results and external inputs
        rtype = r.get("type") or r.get("activity_type", "")
        if rtype not in ("tool_result", "user_input"):
            continue
        text = _get_text(r)
        for pat in INJECTION_PATTERNS:
            if re.search(pat, text):
                hits.append((r.get("id", ""), pat))
                break
    if not hits:
        return []
    return [_with_mitre("PROMPT_INJECTION", RiskPattern(
        pattern_id="PAT-INJ", pattern_name="PROMPT_INJECTION",
        risk_level=RiskLevel.CRITICAL, confidence=0.88,
        description=f"{len(hits)} prompt injection pattern(s) in tool results",
        matched_records=[h[0] for h in hits][:20],
        evidence={"matched_patterns": [h[1] for h in hits][:5], "count": len(hits)},
        recommendation="CRITICAL: Tool result contains instruction injection. May hijack agent behavior.",
    ))]


def _detect_reconnaissance(records: list[dict]) -> list[RiskPattern]:
    """Detect environment probing / system info gathering (TA0043)."""
    hits = []
    for r in records:
        text = _get_text(r)
        for pat in RECON_PATTERNS:
            if re.search(pat, text):
                hits.append((r.get("id", ""), pat))
                break
    if len(hits) < 3:
        return []
    return [_with_mitre("RECONNAISSANCE", RiskPattern(
        pattern_id="PAT-REC", pattern_name="RECONNAISSANCE",
        risk_level=RiskLevel.MEDIUM if len(hits) < 5 else RiskLevel.HIGH,
        confidence=min(0.90, 0.5 + len(hits) * 0.05),
        description=f"{len(hits)} reconnaissance commands detected",
        matched_records=[h[0] for h in hits][:20],
        evidence={"commands": list({h[1] for h in hits})[:10], "count": len(hits)},
        recommendation="Agent probing system environment. Review if this is expected.",
    ))]


def _detect_persistence(records: list[dict]) -> list[RiskPattern]:
    """Detect persistence mechanisms (TA0003) - startup files, cron, services."""
    hits = []
    for r in records:
        # Only flag writes to persistence targets
        rtype = r.get("type") or r.get("activity_type", "")
        text = _get_text(r)
        # Check file writes or edit operations
        is_write = rtype in ("file_write",) or "write" in text or "edit" in text
        for pat in PERSISTENCE_PATTERNS:
            if re.search(pat, text):
                hits.append((r.get("id", ""), pat, is_write))
                break
    # Only critical if actually writing (not just reading)
    write_hits = [h for h in hits if h[2]]
    read_hits = [h for h in hits if not h[2]]
    pats = []
    if write_hits:
        pats.append(_with_mitre("PERSISTENCE", RiskPattern(
            pattern_id="PAT-PER", pattern_name="PERSISTENCE",
            risk_level=RiskLevel.CRITICAL, confidence=0.93,
            description=f"{len(write_hits)} write(s) to persistence targets",
            matched_records=[h[0] for h in write_hits][:20],
            evidence={"targets": list({h[1] for h in write_hits})[:10], "write_count": len(write_hits)},
            recommendation="CRITICAL: Agent modifying startup/persistence files. May establish backdoor.",
        )))
    elif len(read_hits) >= 2:
        pats.append(_with_mitre("PERSISTENCE", RiskPattern(
            pattern_id="PAT-PER-R", pattern_name="PERSISTENCE_RECON",
            risk_level=RiskLevel.MEDIUM, confidence=0.65,
            description=f"{len(read_hits)} read(s) of persistence-related files",
            matched_records=[h[0] for h in read_hits][:20],
            evidence={"targets": list({h[1] for h in read_hits})[:10]},
            recommendation="Agent reading startup files. Monitor for subsequent writes.",
        )))
    return pats


def _detect_defense_evasion(records: list[dict]) -> list[RiskPattern]:
    """Detect log deletion, history clearing, obfuscation (TA0005)."""
    hits = []
    for r in records:
        text = _get_text(r)
        for pat in EVASION_PATTERNS:
            if re.search(pat, text):
                hits.append((r.get("id", ""), pat))
                break
    if not hits:
        return []
    return [_with_mitre("DEFENSE_EVASION", RiskPattern(
        pattern_id="PAT-EVA", pattern_name="DEFENSE_EVASION",
        risk_level=RiskLevel.CRITICAL if len(hits) >= 2 else RiskLevel.HIGH,
        confidence=0.91,
        description=f"{len(hits)} defense evasion technique(s) detected",
        matched_records=[h[0] for h in hits][:20],
        evidence={"techniques": list({h[1] for h in hits})[:10], "count": len(hits)},
        recommendation="Agent attempting to cover tracks. Investigate immediately.",
    ))]


def _detect_chain_manipulation(prov_records: list[dict]) -> list[RiskPattern]:
    """Detect provenance chain integrity violations (sequence gaps, hash breaks)."""
    if len(prov_records) < 2:
        return []
    gaps = []
    hash_breaks = []
    for i in range(1, len(prov_records)):
        prev = prov_records[i - 1]
        curr = prov_records[i]
        # Sequence gap
        prev_seq = prev.get("sequence_number", 0)
        curr_seq = curr.get("sequence_number", 0)
        if curr_seq - prev_seq > 1:
            gaps.append({
                "before": prev_seq, "after": curr_seq,
                "gap": curr_seq - prev_seq - 1,
                "record_id": curr.get("id", ""),
            })
        # Hash chain break
        prev_hash = prev.get("record_hash", "")
        curr_prev_hash = curr.get("previous_hash", "")
        if prev_hash and curr_prev_hash and prev_hash != curr_prev_hash:
            hash_breaks.append({
                "at_sequence": curr_seq,
                "expected": prev_hash[:16],
                "actual": curr_prev_hash[:16],
                "record_id": curr.get("id", ""),
            })
    pats = []
    if gaps:
        pats.append(_with_mitre("CHAIN_MANIPULATION", RiskPattern(
            pattern_id="PAT-GAP", pattern_name="CHAIN_SEQUENCE_GAP",
            risk_level=RiskLevel.HIGH, confidence=0.95,
            description=f"{len(gaps)} sequence gap(s) in provenance chain",
            matched_records=[g["record_id"] for g in gaps][:20],
            evidence={"gaps": gaps[:10]},
            recommendation="Provenance chain has missing records. May indicate tampering.",
        )))
    if hash_breaks:
        pats.append(_with_mitre("CHAIN_MANIPULATION", RiskPattern(
            pattern_id="PAT-BRK", pattern_name="CHAIN_HASH_BREAK",
            risk_level=RiskLevel.CRITICAL, confidence=0.99,
            description=f"{len(hash_breaks)} hash chain break(s) detected",
            matched_records=[h["record_id"] for h in hash_breaks][:20],
            evidence={"breaks": hash_breaks[:10]},
            recommendation="CRITICAL: Hash chain broken. Provenance data has been tampered with.",
        )))
    return pats


# ---- Causal Chain Extraction (GraphRAG Core) ---------------------------------

def _extract_causal_chains(records: list[dict], max_chains: int = 50) -> list[CausalChain]:
    """Extract causal chains: user_input -> thinking -> tool_call -> tool_result -> ...

    This is the 'Graph' part of GraphRAG. Each chain represents a decision path
    through the agent's actions, enabling pattern detection across linked events.
    """
    chains: list[CausalChain] = []
    current_chain: list[dict] = []
    chain_id = 0

    for r in records:
        rtype = r.get("type") or r.get("record_type") or r.get("activity_type", "")
        role = r.get("role", "")

        # New chain starts on user input
        if rtype in ("message", "user_input") and role == "user":
            if current_chain:
                chains.append(_finalize_chain(chain_id, current_chain))
                chain_id += 1
            current_chain = [r]
        else:
            current_chain.append(r)

    # Final chain
    if current_chain:
        chains.append(_finalize_chain(chain_id, current_chain))

    return chains[:max_chains]


def _finalize_chain(chain_id: int, steps: list[dict]) -> CausalChain:
    """Analyze a causal chain for risk indicators."""
    indicators = []
    tool_names = []

    for s in steps:
        text = _get_text(s)
        rtype = s.get("type") or s.get("record_type") or s.get("activity_type", "")
        tool_name = s.get("tool_name") or s.get("activity_name", "")
        if tool_name:
            tool_names.append(tool_name.lower())

        # Check for risky patterns in chain
        if any(re.search(p, text) for p in INJECTION_PATTERNS):
            indicators.append("prompt_injection_in_chain")
        if any(p in text for p in SENSITIVE_PATTERNS):
            indicators.append("sensitive_file_in_chain")
        if any(re.search(p, text) for p in DANGEROUS_COMMANDS):
            indicators.append("dangerous_command_in_chain")

    # Detect suspicious tool sequences
    for i in range(len(tool_names) - 1):
        if "read" in tool_names[i] and any(e in tool_names[i+1] for e in ["bash", "curl", "wget"]):
            indicators.append("read_then_execute_pattern")
        if "bash" in tool_names[i] and "bash" in tool_names[i+1]:
            indicators.append("chained_bash_execution")

    chain_steps = [
        {"type": s.get("type") or s.get("activity_type", ""),
         "name": s.get("tool_name") or s.get("activity_name", ""),
         "role": s.get("role", "")}
        for s in steps[:20]  # Limit step detail
    ]

    return CausalChain(
        chain_id=chain_id,
        steps=chain_steps,
        risk_indicators=list(set(indicators)),
    )


# ---- Behavior Profiling -----------------------------------------------------
def _build_behavior_profile(session_id: str, records: list[dict]) -> BehaviorProfile:
    tool_freq: dict[str, int] = {}
    type_freq: dict[str, int] = {}
    timestamps: list[datetime] = []
    for r in records:
        aname = r.get("activity_name") or r.get("tool_name") or "unknown"
        atype = r.get("activity_type") or r.get("type") or "unknown"
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
    if any(any(p in _get_text(r) for p in SENSITIVE_PATTERNS) for r in records[:50]):
        anomalies.append("Sensitive resource access detected")

    # Extract causal chains
    causal = _extract_causal_chains(records)
    risky_chains = [c for c in causal if c.risk_indicators]
    if risky_chains:
        anomalies.append(f"{len(risky_chains)} causal chain(s) with risk indicators")

    return BehaviorProfile(
        session_id=session_id, total_activities=len(records),
        tool_frequency=dict(sorted(tool_freq.items(), key=lambda x: -x[1])[:15]),
        type_frequency=type_freq,
        avg_interval_seconds=round(avg_iv, 3),
        min_interval_seconds=round(min_iv, 3) if min_iv != float("inf") else 0.0,
        first_activity=timestamps[0].isoformat() if timestamps else "",
        last_activity=timestamps[-1].isoformat() if timestamps else "",
        anomalies=anomalies,
        causal_chains=causal,
    )


# ---- Risk Scoring ------------------------------------------------------------
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
    # Bonus for risky causal chains
    risky_chains = [c for c in profile.causal_chains if c.risk_indicators]
    score += len(risky_chains) * 3
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
        "PROMPT_INJECTION": "Enable input sanitization. Monitor tool results for instruction patterns.",
        "RECONNAISSANCE": "Restrict system command access. Limit agent to project-scoped operations.",
        "PERSISTENCE": "Block write access to startup files (.bashrc, crontab, systemd).",
        "DEFENSE_EVASION": "Enable immutable audit logging. Prevent log deletion by agent.",
        "CHAIN_SEQUENCE_GAP": "Investigate missing provenance records. Enable strict chain mode.",
        "CHAIN_HASH_BREAK": "CRITICAL: Chain tampered. Restore from backup and investigate.",
        "PERSISTENCE_RECON": "Monitor for follow-up write operations to persistence targets.",
    }
    for name, rec in rec_map.items():
        if name in names:
            recs.append(rec)
    if not patterns and profile.total_activities > 0:
        recs.append("No suspicious patterns detected. Session appears normal.")
    if not recs:
        recs.append("Insufficient data. Record more actions for analysis.")
    return recs


# ---- Public API --------------------------------------------------------------
def analyze_basic(session_id: str) -> RiskReport:
    """Free tier: 5 core pattern detectors."""
    prov = _load_session_records(session_id)
    content = _load_session_json(session_id)
    _assign_record_ids(prov, content)
    records = prov + content
    patterns: list[RiskPattern] = []
    patterns.extend(_detect_mass_file_read(records))
    patterns.extend(_detect_privilege_escalation(records))
    patterns.extend(_detect_rapid_tool_calls(records))
    patterns.extend(_detect_prompt_injection(records))
    patterns.extend(_detect_suspicious_commands(records))
    profile = _build_behavior_profile(session_id, records)
    score = _compute_risk_score(patterns, profile)
    return RiskReport(session_id=session_id, overall_risk=_score_to_level(score),
                      risk_score=score, patterns=patterns, behavior=profile)


def analyze_full(session_id: str) -> RiskReport:
    """Pro tier: all 11 patterns + MITRE mapping + causal chains + recommendations."""
    content_records = _load_session_json(session_id)
    prov_records = _load_session_records(session_id)
    _assign_record_ids(prov_records, content_records)
    # Use content records for content-based detection, provenance for structural
    all_records = prov_records + content_records

    patterns: list[RiskPattern] = []
    # Original 5 (content-based)
    patterns.extend(_detect_mass_file_read(all_records))
    patterns.extend(_detect_data_exfiltration(all_records))
    patterns.extend(_detect_privilege_escalation(all_records))
    patterns.extend(_detect_rapid_tool_calls(all_records))
    patterns.extend(_detect_suspicious_commands(all_records))
    # New 6 (GraphRAG v0.5.4)
    patterns.extend(_detect_prompt_injection(all_records))
    patterns.extend(_detect_reconnaissance(all_records))
    patterns.extend(_detect_persistence(all_records))
    patterns.extend(_detect_defense_evasion(all_records))
    patterns.extend(_detect_chain_manipulation(prov_records))

    profile = _build_behavior_profile(session_id, all_records)
    score = _compute_risk_score(patterns, profile)
    causal = profile.causal_chains

    return RiskReport(
        session_id=session_id, overall_risk=_score_to_level(score),
        risk_score=score, patterns=patterns, behavior=profile,
        recommendations=_generate_recommendations(patterns, profile),
        causal_chains=causal,
    )


# ---- Server.py Interface (backward compatible) -------------------------------
def analyze_session_risk(session_id: str) -> dict[str, Any]:
    """Dict interface for server.py analyze_risk handler. Auto-selects tier."""
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
             "recommendation": p.recommendation, "evidence": p.evidence,
             "matched_records": p.matched_records,
             "mitre_tactic": p.mitre_tactic, "mitre_techniques": p.mitre_techniques}
            for p in report.patterns
        ],
        "behavior_profile": {
            "total_activities": report.behavior.total_activities if report.behavior else 0,
            "avg_action_interval": report.behavior.avg_interval_seconds if report.behavior else 0,
            "anomalies": report.behavior.anomalies if report.behavior else [],
        },
        "causal_chains": {
            "total": len(report.causal_chains),
            "risky": len([c for c in report.causal_chains if c.risk_indicators]),
            "chains": [
                {"id": c.chain_id, "steps": len(c.steps),
                 "risk_indicators": c.risk_indicators}
                for c in report.causal_chains if c.risk_indicators
            ][:10],
        },
        "mitre_coverage": list({p.mitre_tactic for p in report.patterns if p.mitre_tactic}),
        "recommendations": report.recommendations,
        "tier": "pro" if pro else "free",
        "engine": "graphrag-sqlite",
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
        "causal_chains": {
            "total": len(p.causal_chains),
            "risky": len([c for c in p.causal_chains if c.risk_indicators]),
        },
    }
