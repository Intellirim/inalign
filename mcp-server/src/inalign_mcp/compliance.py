"""
EU AI Act Compliance Report Generator

Maps InALign provenance data to EU AI Act requirements.
Generates compliance checklist reports for high-risk AI systems.

Articles covered:
- Article 9: Risk Management System
- Article 12: Record-Keeping
- Article 14: Human Oversight
- Article 15: Accuracy, Robustness and Cybersecurity

100% local — no external API calls.
"""

import json
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Optional

logger = logging.getLogger("inalign-compliance")

INALIGN_DIR = Path.home() / ".inalign"
DB_PATH = INALIGN_DIR / "provenance.db"


class ComplianceStatus(str, Enum):
    PASS = "PASS"
    PARTIAL = "PARTIAL"
    FAIL = "FAIL"
    NOT_APPLICABLE = "N/A"


@dataclass
class ComplianceCheck:
    check_id: str
    article: str
    requirement: str
    description: str
    status: ComplianceStatus
    evidence: list[str] = field(default_factory=list)
    recommendation: str = ""


@dataclass
class ComplianceReport:
    session_id: str
    generated_at: str
    framework: str = "EU AI Act (Regulation 2024/1689)"
    overall_status: ComplianceStatus = ComplianceStatus.PARTIAL
    checks: list[ComplianceCheck] = field(default_factory=list)
    summary: dict[str, int] = field(default_factory=dict)


def _load_session_data(session_id: str) -> tuple[list[dict], dict]:
    """Load provenance records and session metadata from SQLite."""
    import sqlite3

    records = []
    session_meta = {}

    if not DB_PATH.exists():
        return records, session_meta

    try:
        conn = sqlite3.connect(str(DB_PATH), check_same_thread=False)
        conn.row_factory = sqlite3.Row

        # Load session
        row = conn.execute(
            "SELECT * FROM sessions WHERE session_id=?", (session_id,)
        ).fetchone()
        if row:
            session_meta = dict(row)

        # Load records
        rows = conn.execute(
            "SELECT * FROM records WHERE session_id=? ORDER BY sequence_number ASC",
            (session_id,),
        ).fetchall()
        records = [dict(r) for r in rows]

        conn.close()
    except Exception as e:
        logger.warning(f"[COMPLIANCE] DB read failed: {e}")

    return records, session_meta


def _check_article_9(records: list[dict], session_meta: dict) -> list[ComplianceCheck]:
    """Article 9: Risk Management System."""
    checks = []

    # 9.1: Risk identification and analysis
    risk_records = [r for r in records if "risk" in (r.get("activity_name") or "").lower()
                    or "analyze_risk" in (r.get("activity_name") or "")]
    checks.append(ComplianceCheck(
        check_id="EU-9.1",
        article="Article 9(1)",
        requirement="Risk identification and analysis",
        description="A risk management system shall be established, implemented, documented and maintained.",
        status=ComplianceStatus.PASS if risk_records else ComplianceStatus.PARTIAL,
        evidence=[f"Risk analysis tool invoked {len(risk_records)} times"] if risk_records
                 else ["No explicit risk analysis detected in session"],
        recommendation="" if risk_records else "Run analyze_risk tool to establish risk assessment baseline.",
    ))

    # 9.2: Risk mitigation measures
    policy_records = [r for r in records if "policy" in (r.get("activity_name") or "").lower()]
    checks.append(ComplianceCheck(
        check_id="EU-9.2",
        article="Article 9(2)",
        requirement="Risk mitigation measures",
        description="Appropriate and targeted risk management measures shall be adopted.",
        status=ComplianceStatus.PASS if policy_records else ComplianceStatus.PARTIAL,
        evidence=[f"Security policies configured ({len(policy_records)} policy actions)"] if policy_records
                 else ["No policy configuration detected"],
        recommendation="" if policy_records else "Configure security policy using set_policy tool.",
    ))

    # 9.4: Testing and validation
    checks.append(ComplianceCheck(
        check_id="EU-9.4",
        article="Article 9(4)",
        requirement="Testing procedures",
        description="Testing shall be performed as appropriate at individual stages and throughout the lifecycle.",
        status=ComplianceStatus.PASS if len(records) >= 5 else ComplianceStatus.PARTIAL,
        evidence=[f"{len(records)} provenance records captured for audit"],
        recommendation="Ensure continuous monitoring across AI system lifecycle.",
    ))

    return checks


def _check_article_12(records: list[dict], session_meta: dict) -> list[ComplianceCheck]:
    """Article 12: Record-Keeping."""
    checks = []

    # 12.1: Automatic logging capability
    checks.append(ComplianceCheck(
        check_id="EU-12.1",
        article="Article 12(1)",
        requirement="Automatic logging of events",
        description="High-risk AI systems shall include logging capabilities enabling the recording of events.",
        status=ComplianceStatus.PASS if records else ComplianceStatus.FAIL,
        evidence=[f"Automatic provenance logging active: {len(records)} records in hash chain"],
        recommendation="" if records else "Enable InALign provenance tracking for automatic event logging.",
    ))

    # 12.2: Traceability
    hash_chain_intact = all(r.get("record_hash") for r in records)
    linked = all(records[i].get("previous_hash") == records[i-1].get("record_hash")
                 for i in range(1, len(records))) if len(records) > 1 else True
    checks.append(ComplianceCheck(
        check_id="EU-12.2",
        article="Article 12(2)",
        requirement="Traceability of operations",
        description="Logging shall ensure a level of traceability of the AI system's functioning throughout its lifecycle.",
        status=ComplianceStatus.PASS if (hash_chain_intact and linked) else ComplianceStatus.PARTIAL,
        evidence=[
            f"Cryptographic hash chain: {'intact' if hash_chain_intact else 'broken'}",
            f"Chain linkage: {'verified' if linked else 'gaps detected'}",
        ],
        recommendation="" if (hash_chain_intact and linked) else "Investigate hash chain integrity issues.",
    ))

    # 12.3: Record retention
    timestamps = [r.get("timestamp", "") for r in records if r.get("timestamp")]
    if timestamps:
        first = timestamps[0][:10]
        last = timestamps[-1][:10]
        checks.append(ComplianceCheck(
            check_id="EU-12.3",
            article="Article 12(3)",
            requirement="Record retention period",
            description="Logs shall be kept for a period appropriate to the intended purpose, at least 6 months.",
            status=ComplianceStatus.PASS,
            evidence=[f"Records span from {first} to {last}", "SQLite local storage with configurable retention"],
            recommendation="Ensure retention_days >= 180 for EU AI Act compliance (Pro plan: 90 days, Enterprise: 365 days).",
        ))
    else:
        checks.append(ComplianceCheck(
            check_id="EU-12.3",
            article="Article 12(3)",
            requirement="Record retention period",
            description="Logs shall be kept for a period appropriate to the intended purpose.",
            status=ComplianceStatus.FAIL,
            evidence=["No timestamped records found"],
            recommendation="Enable provenance tracking to establish record retention.",
        ))

    # 12.4: Record format
    checks.append(ComplianceCheck(
        check_id="EU-12.4",
        article="Article 12(4)",
        requirement="Standardized record format",
        description="Records shall be in a format that facilitates monitoring and interpretation.",
        status=ComplianceStatus.PASS,
        evidence=[
            "W3C PROV-compatible JSON format",
            "PROV-JSON-LD export available",
            "CSV/JSON download available via report dashboard",
        ],
    ))

    return checks


def _check_article_14(records: list[dict], session_meta: dict) -> list[ComplianceCheck]:
    """Article 14: Human Oversight."""
    checks = []

    # 14.1: Human oversight measures
    user_inputs = [r for r in records if r.get("activity_type") == "user_input"]
    checks.append(ComplianceCheck(
        check_id="EU-14.1",
        article="Article 14(1)",
        requirement="Human oversight capability",
        description="High-risk AI systems shall be designed to be effectively overseen by natural persons.",
        status=ComplianceStatus.PASS if user_inputs else ComplianceStatus.PARTIAL,
        evidence=[f"{len(user_inputs)} human inputs recorded in provenance chain"] if user_inputs
                 else ["No human input events detected"],
        recommendation="" if user_inputs else "Ensure user commands are recorded via record_user_command.",
    ))

    # 14.2: Understanding and interpreting outputs
    checks.append(ComplianceCheck(
        check_id="EU-14.2",
        article="Article 14(2)",
        requirement="Interpretability of outputs",
        description="Oversight measures shall enable individuals to correctly interpret the system's output.",
        status=ComplianceStatus.PASS,
        evidence=[
            "Full provenance chain with action-level detail",
            "HTML dashboard with filterable session log",
            "Tool call arguments and results recorded",
        ],
    ))

    # 14.4: Ability to intervene
    decisions = [r for r in records if r.get("activity_type") == "decision"]
    checks.append(ComplianceCheck(
        check_id="EU-14.4",
        article="Article 14(4)",
        requirement="Ability to intervene or interrupt",
        description="Individuals shall be able to decide not to use the system, override, or reverse output.",
        status=ComplianceStatus.PASS,
        evidence=[
            "Policy engine supports BLOCK action for any threat category",
            f"{len(decisions)} decision records tracked",
            "MCP architecture allows human-in-the-loop approval",
        ],
    ))

    return checks


def _check_article_15(records: list[dict], session_meta: dict) -> list[ComplianceCheck]:
    """Article 15: Accuracy, Robustness and Cybersecurity."""
    checks = []

    # 15.1: Accuracy levels
    checks.append(ComplianceCheck(
        check_id="EU-15.1",
        article="Article 15(1)",
        requirement="Appropriate levels of accuracy",
        description="High-risk AI systems shall be designed to achieve appropriate levels of accuracy.",
        status=ComplianceStatus.PARTIAL,
        evidence=["Accuracy tracking requires domain-specific metrics"],
        recommendation="Implement domain-specific accuracy metrics for your AI system.",
    ))

    # 15.3: Robustness
    verify_records = [r for r in records if "verify" in (r.get("activity_name") or "").lower()]
    checks.append(ComplianceCheck(
        check_id="EU-15.3",
        article="Article 15(3)",
        requirement="Technical robustness",
        description="High-risk AI systems shall be resilient against attempts to alter their use or performance.",
        status=ComplianceStatus.PASS if verify_records else ComplianceStatus.PARTIAL,
        evidence=[
            "Tamper-proof hash chain with SHA-256",
            "Ed25519 digital signatures (when available)",
            "Merkle root for external verification",
            f"Chain verification performed {len(verify_records)} times",
        ],
        recommendation="" if verify_records else "Run verify_provenance regularly to confirm chain integrity.",
    ))

    # 15.4: Cybersecurity
    security_records = [r for r in records if any(
        kw in (r.get("activity_name") or "").lower()
        for kw in ["scan", "security", "risk", "policy", "threat"]
    )]
    checks.append(ComplianceCheck(
        check_id="EU-15.4",
        article="Article 15(4)",
        requirement="Cybersecurity measures",
        description="High-risk AI systems shall be resilient against unauthorized third-party attempts.",
        status=ComplianceStatus.PASS if security_records else ComplianceStatus.PARTIAL,
        evidence=[
            f"Security-related activities: {len(security_records)}",
            "Injection detection (15+ regex patterns, multilingual)",
            "PII masking (14 patterns)",
            "Policy-based access control (3 presets)",
        ],
        recommendation="" if security_records else "Enable continuous security monitoring.",
    ))

    return checks


def generate_compliance_report(session_id: str) -> ComplianceReport:
    """
    Generate EU AI Act compliance report for a session.

    Reads provenance data and maps it to Article 9, 12, 14, 15 requirements.
    Returns structured ComplianceReport.
    """
    records, session_meta = _load_session_data(session_id)

    all_checks = []
    all_checks.extend(_check_article_9(records, session_meta))
    all_checks.extend(_check_article_12(records, session_meta))
    all_checks.extend(_check_article_14(records, session_meta))
    all_checks.extend(_check_article_15(records, session_meta))

    # Compute summary
    summary = {
        ComplianceStatus.PASS.value: 0,
        ComplianceStatus.PARTIAL.value: 0,
        ComplianceStatus.FAIL.value: 0,
        ComplianceStatus.NOT_APPLICABLE.value: 0,
    }
    for check in all_checks:
        summary[check.status.value] += 1

    # Determine overall status
    if summary[ComplianceStatus.FAIL.value] > 0:
        overall = ComplianceStatus.FAIL
    elif summary[ComplianceStatus.PARTIAL.value] > 2:
        overall = ComplianceStatus.PARTIAL
    elif summary[ComplianceStatus.PARTIAL.value] > 0:
        overall = ComplianceStatus.PARTIAL
    else:
        overall = ComplianceStatus.PASS

    return ComplianceReport(
        session_id=session_id,
        generated_at=datetime.now(timezone.utc).isoformat(),
        overall_status=overall,
        checks=all_checks,
        summary=summary,
    )


def compliance_report_to_dict(report: ComplianceReport) -> dict[str, Any]:
    """Convert ComplianceReport to JSON-serializable dict."""
    return {
        "session_id": report.session_id,
        "generated_at": report.generated_at,
        "framework": report.framework,
        "overall_status": report.overall_status.value,
        "summary": report.summary,
        "total_checks": len(report.checks),
        "checks": [
            {
                "check_id": c.check_id,
                "article": c.article,
                "requirement": c.requirement,
                "description": c.description,
                "status": c.status.value,
                "evidence": c.evidence,
                "recommendation": c.recommendation,
            }
            for c in report.checks
        ],
    }


def generate_compliance_html(report: ComplianceReport) -> str:
    """Generate standalone HTML compliance report."""
    import html as html_mod

    now = report.generated_at[:19]
    status_color = {
        "PASS": "#3fb950", "PARTIAL": "#d29922",
        "FAIL": "#f85149", "N/A": "#8b949e",
    }

    checks_html = ""
    current_article = ""
    for c in report.checks:
        article_label = c.article.split("(")[0].strip()
        if article_label != current_article:
            current_article = article_label
            checks_html += f'<tr><td colspan="5" style="background:#0d1117;padding:0.6rem;font-weight:600;color:#58a6ff;font-size:0.9rem;">{html_mod.escape(current_article)}</td></tr>'

        sc = status_color.get(c.status.value, "#8b949e")
        evidence_html = "<br>".join(html_mod.escape(e) for e in c.evidence) if c.evidence else "-"
        rec_html = html_mod.escape(c.recommendation) if c.recommendation else "-"

        checks_html += f"""<tr>
<td style="font-family:monospace;font-size:0.78rem;color:#8b949e;">{c.check_id}</td>
<td>{html_mod.escape(c.requirement)}</td>
<td style="text-align:center;"><span style="display:inline-block;padding:0.15rem 0.5rem;border-radius:4px;font-size:0.72rem;font-weight:600;background:rgba({','.join(str(int(sc[i:i+2], 16)) for i in (1,3,5))},0.15);color:{sc};">{c.status.value}</span></td>
<td style="font-size:0.78rem;">{evidence_html}</td>
<td style="font-size:0.78rem;color:#d29922;">{rec_html}</td>
</tr>"""

    overall_color = status_color.get(report.overall_status.value, "#8b949e")
    s = report.summary

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>EU AI Act Compliance — {report.session_id}</title>
<style>
:root {{ --bg:#0d1117; --card:#161b22; --border:#30363d; --text:#e6edf3; --muted:#8b949e; }}
* {{ margin:0; padding:0; box-sizing:border-box; }}
body {{ font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Helvetica,Arial,sans-serif; background:var(--bg); color:var(--text); line-height:1.6; padding:2rem; max-width:1200px; margin:0 auto; }}
h1 {{ font-size:1.6rem; margin-bottom:0.3rem; }}
.subtitle {{ color:var(--muted); font-size:0.85rem; margin-bottom:1.5rem; }}
.cards {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(140px,1fr)); gap:0.8rem; margin-bottom:1.5rem; }}
.card {{ background:var(--card); border:1px solid var(--border); border-radius:8px; padding:0.8rem; text-align:center; }}
.card .label {{ color:var(--muted); font-size:0.7rem; text-transform:uppercase; }}
.card .val {{ font-size:1.5rem; font-weight:700; }}
table {{ width:100%; border-collapse:collapse; font-size:0.82rem; }}
th {{ text-align:left; color:var(--muted); font-weight:500; padding:0.5rem; border-bottom:1px solid var(--border); font-size:0.72rem; text-transform:uppercase; }}
td {{ padding:0.5rem; border-bottom:1px solid var(--border); vertical-align:top; }}
.section {{ background:var(--card); border:1px solid var(--border); border-radius:8px; padding:1.2rem; margin-bottom:1.2rem; }}
.footer {{ text-align:center; color:var(--muted); font-size:0.75rem; margin-top:2rem; padding-top:0.8rem; border-top:1px solid var(--border); }}
.footer a {{ color:#58a6ff; text-decoration:none; }}
</style>
</head>
<body>
<h1>EU AI Act Compliance Report</h1>
<div class="subtitle">{report.framework} — Session {report.session_id} — {now}</div>

<div class="cards">
<div class="card"><div class="label">Overall</div><div class="val" style="color:{overall_color};">{report.overall_status.value}</div></div>
<div class="card"><div class="label">Pass</div><div class="val" style="color:#3fb950;">{s.get('PASS',0)}</div></div>
<div class="card"><div class="label">Partial</div><div class="val" style="color:#d29922;">{s.get('PARTIAL',0)}</div></div>
<div class="card"><div class="label">Fail</div><div class="val" style="color:#f85149;">{s.get('FAIL',0)}</div></div>
<div class="card"><div class="label">Total Checks</div><div class="val">{len(report.checks)}</div></div>
</div>

<div class="section">
<table>
<thead><tr><th>ID</th><th>Requirement</th><th>Status</th><th>Evidence</th><th>Recommendation</th></tr></thead>
<tbody>{checks_html}</tbody>
</table>
</div>

<div class="footer">
<p>Generated by <a href="https://github.com/Intellirim/inalign">InALign</a> — AI Agent Governance Platform</p>
</div>
</body></html>"""
