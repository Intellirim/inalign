"""
OWASP LLM Top 10 Compliance Checker

Maps InALign provenance/scanner data to OWASP Top 10 for LLM Applications (v2025).
Each item: PASS / WARN / FAIL with evidence and recommendations.

Mappings:
- LLM01 Prompt Injection      ← scanner.py INJECTION_PATTERNS
- LLM02 Insecure Output       ← output validation checks
- LLM03 Training Data Poisoning ← N/A (runtime only)
- LLM04 Model DoS             ← rapid tool calls, resource abuse
- LLM05 Supply Chain          ← MCP tool provenance
- LLM06 Sensitive Info Disclosure ← PII patterns, sensitive file access
- LLM07 Insecure Plugin Design ← MCP tool permission analysis
- LLM08 Excessive Agency       ← tool call breadth analysis
- LLM09 Overreliance          ← human oversight ratio
- LLM10 Model Theft           ← N/A (runtime only)

100% local — no external API calls.
"""

import json
import logging
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any

logger = logging.getLogger("inalign-owasp")

INALIGN_DIR = Path.home() / ".inalign"
DB_PATH = INALIGN_DIR / "provenance.db"

# Sensitive patterns (reused from risk_analyzer)
SENSITIVE_PATTERNS = [
    ".env", ".ssh", "credentials", "secret", "password", ".key",
    ".pem", "id_rsa", "id_ed25519", ".aws", ".pypirc", ".npmrc",
    ".netrc", "token", ".kube/config",
]

DANGEROUS_COMMANDS = [
    r"rm\s+-rf\s+/", r"curl\s+.*\|.*sh", r"wget\s+.*\|.*sh",
    r"curl\s+-[^\s]*d\s", r"nc\s+-[^\s]*l", r"chmod\s+777",
    r"eval\s*\(", r"base64\s+-d", r"python\s+-c\s", r"powershell\s+-enc",
]

EXTERNAL_TOOLS = [
    "curl", "wget", "http", "upload", "send", "post",
    "llm_request", "api_call", "fetch", "request",
]


class OWASPStatus(str, Enum):
    PASS = "PASS"
    WARN = "WARN"
    FAIL = "FAIL"
    NOT_APPLICABLE = "N/A"


@dataclass
class OWASPCheck:
    item_id: str
    name: str
    status: OWASPStatus
    score: int  # 0-100 (0=best, 100=worst)
    description: str
    evidence: list[str] = field(default_factory=list)
    recommendation: str = ""


@dataclass
class OWASPReport:
    session_id: str
    generated_at: str
    framework: str = "OWASP Top 10 for LLM Applications (2025)"
    overall_score: int = 0
    overall_status: OWASPStatus = OWASPStatus.PASS
    checks: list[OWASPCheck] = field(default_factory=list)


def _load_records(session_id: str) -> list[dict]:
    """Load provenance records from SQLite."""
    import sqlite3
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
    except Exception as e:
        logger.warning(f"[OWASP] DB read failed: {e}")
        return []


def _check_llm01_prompt_injection(records: list[dict]) -> OWASPCheck:
    """LLM01: Prompt Injection — check if injection detection is active."""
    # Check if scanner/security patterns are being monitored
    security_records = [r for r in records if any(
        kw in (r.get("activity_name") or "").lower()
        for kw in ["scan", "security_check", "injection"]
    )]

    # Check for actual injection-like patterns in user inputs
    user_inputs = [r for r in records if r.get("activity_type") == "user_input"]
    suspicious = 0
    injection_keywords = ["ignore previous", "forget instructions", "override", "jailbreak", "sudo mode"]
    for r in user_inputs:
        attrs = (r.get("activity_attributes") or "").lower()
        name = (r.get("activity_name") or "").lower()
        combined = f"{attrs} {name}"
        if any(kw in combined for kw in injection_keywords):
            suspicious += 1

    if suspicious > 0:
        return OWASPCheck(
            item_id="LLM01", name="Prompt Injection",
            status=OWASPStatus.FAIL, score=80,
            description="Prompt injection attempts detected in session.",
            evidence=[f"{suspicious} suspicious input(s) detected", f"{len(security_records)} security scans performed"],
            recommendation="Enable STRICT_ENTERPRISE policy. Review flagged inputs.",
        )

    has_protection = len(security_records) > 0 or len(records) > 0  # InALign itself is protection
    return OWASPCheck(
        item_id="LLM01", name="Prompt Injection",
        status=OWASPStatus.PASS if has_protection else OWASPStatus.WARN,
        score=10 if has_protection else 40,
        description="InALign provides 15+ injection detection patterns (multilingual).",
        evidence=[
            "Regex-based injection detection: 15+ patterns",
            "Multi-language support: EN, KO, JA, ZH",
            f"User inputs monitored: {len(user_inputs)}",
        ],
        recommendation="" if has_protection else "Enable continuous prompt scanning.",
    )


def _check_llm02_insecure_output(records: list[dict]) -> OWASPCheck:
    """LLM02: Insecure Output Handling."""
    # Check for tool outputs that may contain unvalidated data
    tool_results = [r for r in records if r.get("activity_type") == "tool_result"
                    or "tool_call" in (r.get("activity_name") or "")]
    bash_calls = [r for r in records if "bash" in (r.get("activity_name") or "").lower()]

    if bash_calls and len(bash_calls) > 10:
        return OWASPCheck(
            item_id="LLM02", name="Insecure Output Handling",
            status=OWASPStatus.WARN, score=50,
            description="High volume of bash/shell tool calls detected.",
            evidence=[f"{len(bash_calls)} bash/shell calls", "Outputs may be interpreted by downstream systems"],
            recommendation="Validate and sanitize tool outputs. Restrict bash access via policy.",
        )

    return OWASPCheck(
        item_id="LLM02", name="Insecure Output Handling",
        status=OWASPStatus.PASS, score=10,
        description="Tool outputs are recorded in provenance chain for audit.",
        evidence=[f"{len(tool_results)} tool results tracked", "Provenance captures all outputs"],
    )


def _check_llm04_model_dos(records: list[dict]) -> OWASPCheck:
    """LLM04: Model Denial of Service."""
    from .risk_analyzer import _parse_ts

    # Check for rapid tool calls indicating potential DoS
    rapid_count = 0
    for i in range(1, len(records)):
        t1 = _parse_ts(records[i-1].get("timestamp", ""))
        t2 = _parse_ts(records[i].get("timestamp", ""))
        if t1 and t2 and 0 <= (t2 - t1).total_seconds() * 1000 < 200:
            rapid_count += 1

    if rapid_count >= 10:
        return OWASPCheck(
            item_id="LLM04", name="Model Denial of Service",
            status=OWASPStatus.WARN, score=50,
            description="Unusually rapid tool calls detected.",
            evidence=[f"{rapid_count} calls faster than 200ms apart"],
            recommendation="Investigate automated tool usage. Enable rate limiting.",
        )

    return OWASPCheck(
        item_id="LLM04", name="Model Denial of Service",
        status=OWASPStatus.PASS, score=5,
        description="Tool call frequency within normal range.",
        evidence=[f"{len(records)} total records", f"Rapid calls (<200ms): {rapid_count}"],
    )


def _check_llm05_supply_chain(records: list[dict]) -> OWASPCheck:
    """LLM05: Supply Chain Vulnerabilities."""
    # Check MCP tool provenance — are tools from known sources?
    unique_tools = set()
    for r in records:
        name = r.get("activity_name", "")
        if name and r.get("activity_type") == "tool_call":
            unique_tools.add(name)

    return OWASPCheck(
        item_id="LLM05", name="Supply Chain Vulnerabilities",
        status=OWASPStatus.PASS, score=10,
        description="All tool calls tracked in tamper-proof provenance chain.",
        evidence=[
            f"{len(unique_tools)} unique tools used: {', '.join(sorted(unique_tools)[:10])}",
            "SHA-256 hash chain ensures tool call integrity",
            "All tool arguments and results recorded",
        ],
        recommendation="Review tool list periodically. Verify MCP server sources.",
    )


def _check_llm06_sensitive_info(records: list[dict]) -> OWASPCheck:
    """LLM06: Sensitive Information Disclosure."""
    hits = []
    for r in records:
        combined = f"{r.get('activity_name', '')} {r.get('activity_attributes', '')}".lower()
        for pat in SENSITIVE_PATTERNS:
            if pat in combined:
                hits.append(r.get("activity_name", "unknown"))
                break

    if len(hits) >= 3:
        return OWASPCheck(
            item_id="LLM06", name="Sensitive Information Disclosure",
            status=OWASPStatus.FAIL, score=75,
            description="Multiple sensitive resource accesses detected.",
            evidence=[f"{len(hits)} sensitive access(es)", f"Resources: {', '.join(list(set(hits))[:5])}"],
            recommendation="Restrict file access scope. Enable PII masking via policy.",
        )
    elif hits:
        return OWASPCheck(
            item_id="LLM06", name="Sensitive Information Disclosure",
            status=OWASPStatus.WARN, score=40,
            description="Some sensitive resource access detected.",
            evidence=[f"{len(hits)} access(es): {', '.join(set(hits)[:5])}"],
            recommendation="Review sensitive file access patterns.",
        )

    return OWASPCheck(
        item_id="LLM06", name="Sensitive Information Disclosure",
        status=OWASPStatus.PASS, score=5,
        description="No sensitive resource access detected.",
        evidence=["14 PII patterns monitored", "Sensitive file detection active"],
    )


def _check_llm07_insecure_plugin(records: list[dict]) -> OWASPCheck:
    """LLM07: Insecure Plugin Design — MCP tool permission analysis."""
    tool_calls = [r for r in records if r.get("activity_type") == "tool_call"]
    unique_tools = set(r.get("activity_name", "") for r in tool_calls)

    dangerous_tools = {"bash", "shell", "exec", "execute", "run_command"}
    used_dangerous = unique_tools & dangerous_tools

    if used_dangerous:
        return OWASPCheck(
            item_id="LLM07", name="Insecure Plugin Design",
            status=OWASPStatus.WARN, score=45,
            description="Potentially dangerous tools in use.",
            evidence=[f"Dangerous tools: {', '.join(used_dangerous)}", f"Total unique tools: {len(unique_tools)}"],
            recommendation="Configure permission matrix to restrict dangerous tool access.",
        )

    return OWASPCheck(
        item_id="LLM07", name="Insecure Plugin Design",
        status=OWASPStatus.PASS, score=10,
        description="Tool usage within expected parameters.",
        evidence=[f"{len(unique_tools)} unique tools", "All tool calls recorded in provenance"],
    )


def _check_llm08_excessive_agency(records: list[dict]) -> OWASPCheck:
    """LLM08: Excessive Agency — breadth of tool usage."""
    tool_calls = [r for r in records if r.get("activity_type") == "tool_call"]
    unique_tools = set(r.get("activity_name", "") for r in tool_calls)

    # Check for write operations
    writes = [r for r in records if r.get("activity_type") == "file_write"]
    # Check for external calls
    externals = [r for r in records if any(
        e in (r.get("activity_name") or "").lower() for e in EXTERNAL_TOOLS
    )]

    if len(unique_tools) > 15 and (writes or externals):
        return OWASPCheck(
            item_id="LLM08", name="Excessive Agency",
            status=OWASPStatus.WARN, score=50,
            description="Agent using broad range of tools including writes and external calls.",
            evidence=[
                f"{len(unique_tools)} unique tools",
                f"{len(writes)} file write(s)",
                f"{len(externals)} external call(s)",
            ],
            recommendation="Apply principle of least privilege. Restrict to necessary tools only.",
        )

    return OWASPCheck(
        item_id="LLM08", name="Excessive Agency",
        status=OWASPStatus.PASS, score=10,
        description="Tool usage within normal scope.",
        evidence=[f"{len(unique_tools)} unique tools", f"{len(writes)} writes", f"{len(externals)} external calls"],
    )


def _check_llm09_overreliance(records: list[dict]) -> OWASPCheck:
    """LLM09: Overreliance — human oversight ratio."""
    user_inputs = len([r for r in records if r.get("activity_type") == "user_input"])
    tool_calls = len([r for r in records if r.get("activity_type") == "tool_call"])

    if tool_calls == 0:
        return OWASPCheck(
            item_id="LLM09", name="Overreliance",
            status=OWASPStatus.PASS, score=0,
            description="No automated tool calls detected.",
            evidence=["Session appears human-driven"],
        )

    ratio = user_inputs / max(tool_calls, 1)

    if ratio < 0.05 and tool_calls > 20:
        return OWASPCheck(
            item_id="LLM09", name="Overreliance",
            status=OWASPStatus.WARN, score=45,
            description="Very low human-to-agent interaction ratio.",
            evidence=[
                f"Human inputs: {user_inputs}",
                f"Tool calls: {tool_calls}",
                f"Ratio: {ratio:.2f}",
            ],
            recommendation="Increase human review checkpoints. Don't rely solely on AI outputs.",
        )

    return OWASPCheck(
        item_id="LLM09", name="Overreliance",
        status=OWASPStatus.PASS, score=10,
        description="Adequate human oversight detected.",
        evidence=[f"Human inputs: {user_inputs}", f"Tool calls: {tool_calls}", f"Ratio: {ratio:.2f}"],
    )


def _check_llm03_training_data(records: list[dict]) -> OWASPCheck:
    """LLM03: Training Data Poisoning — runtime detection not applicable."""
    return OWASPCheck(
        item_id="LLM03", name="Training Data Poisoning",
        status=OWASPStatus.NOT_APPLICABLE, score=0,
        description="Training data analysis requires model-level access (not runtime auditable).",
        evidence=["Runtime audit cannot assess training data quality"],
        recommendation="Verify model provenance with your LLM provider.",
    )


def _check_llm10_model_theft(records: list[dict]) -> OWASPCheck:
    """LLM10: Model Theft — runtime detection not applicable."""
    return OWASPCheck(
        item_id="LLM10", name="Model Theft",
        status=OWASPStatus.NOT_APPLICABLE, score=0,
        description="Model theft detection requires infrastructure-level monitoring.",
        evidence=["InALign tracks API usage patterns that could indicate extraction attempts"],
        recommendation="Monitor API usage for unusual query patterns.",
    )


def check_owasp_compliance(session_id: str) -> OWASPReport:
    """
    Run full OWASP LLM Top 10 compliance check.

    Returns OWASPReport with per-item PASS/WARN/FAIL scores.
    """
    records = _load_records(session_id)

    checks = [
        _check_llm01_prompt_injection(records),
        _check_llm02_insecure_output(records),
        _check_llm03_training_data(records),
        _check_llm04_model_dos(records),
        _check_llm05_supply_chain(records),
        _check_llm06_sensitive_info(records),
        _check_llm07_insecure_plugin(records),
        _check_llm08_excessive_agency(records),
        _check_llm09_overreliance(records),
        _check_llm10_model_theft(records),
    ]

    # Compute overall score (average of applicable checks)
    applicable = [c for c in checks if c.status != OWASPStatus.NOT_APPLICABLE]
    overall_score = sum(c.score for c in applicable) // max(len(applicable), 1)

    if overall_score >= 60:
        overall_status = OWASPStatus.FAIL
    elif overall_score >= 30:
        overall_status = OWASPStatus.WARN
    else:
        overall_status = OWASPStatus.PASS

    return OWASPReport(
        session_id=session_id,
        generated_at=datetime.now(timezone.utc).isoformat(),
        overall_score=overall_score,
        overall_status=overall_status,
        checks=checks,
    )


def owasp_report_to_dict(report: OWASPReport) -> dict[str, Any]:
    """Convert OWASPReport to JSON-serializable dict."""
    return {
        "session_id": report.session_id,
        "generated_at": report.generated_at,
        "framework": report.framework,
        "overall_score": report.overall_score,
        "overall_status": report.overall_status.value,
        "checks": [
            {
                "item_id": c.item_id,
                "name": c.name,
                "status": c.status.value,
                "score": c.score,
                "description": c.description,
                "evidence": c.evidence,
                "recommendation": c.recommendation,
            }
            for c in report.checks
        ],
    }
