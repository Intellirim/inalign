"""
Audit Log Export - Simple download for compliance.

Provides:
- JSON export (full detail)
- CSV export (spreadsheet)
- PDF report (optional)
"""

import json
import csv
import io
from datetime import datetime, timezone
from typing import Optional, Any

from .provenance import (
    get_or_create_chain,
    ProvenanceChain,
    ProvenanceRecord,
)


def export_session_json(session_id: str, pretty: bool = True) -> str:
    """
    Export session audit log as JSON.

    Returns complete provenance chain in JSON format.
    """
    chain = get_or_create_chain(session_id)

    data = {
        "export_info": {
            "session_id": session_id,
            "exported_at": datetime.now(timezone.utc).isoformat(),
            "record_count": len(chain.records),
            "chain_valid": chain.verify_chain()[0],
        },
        "agent": {
            "id": chain.agent.id,
            "name": chain.agent.name,
            "type": chain.agent.type,
        } if chain.agent else None,
        "records": [_record_to_dict(r) for r in chain.records],
    }

    if pretty:
        return json.dumps(data, indent=2, ensure_ascii=False)
    return json.dumps(data, ensure_ascii=False)


def export_session_csv(session_id: str) -> str:
    """
    Export session audit log as CSV.

    Flat format for spreadsheet analysis.
    """
    chain = get_or_create_chain(session_id)

    output = io.StringIO()
    writer = csv.writer(output)

    # Header
    writer.writerow([
        "sequence",
        "timestamp",
        "activity_type",
        "activity_name",
        "record_hash",
        "previous_hash",
        "inputs_count",
        "outputs_count",
    ])

    # Records
    for record in chain.records:
        writer.writerow([
            record.sequence_number,
            record.timestamp,
            record.activity_type.value,
            record.activity_name,
            record.record_hash,
            record.previous_hash or "",
            len(record.used_entities),
            len(record.generated_entities),
        ])

    return output.getvalue()


def export_session_summary(session_id: str) -> dict[str, Any]:
    """
    Export session summary for quick review.
    """
    chain = get_or_create_chain(session_id)
    is_valid, error = chain.verify_chain()

    # Count activity types
    activity_counts = {}
    for record in chain.records:
        atype = record.activity_type.value
        activity_counts[atype] = activity_counts.get(atype, 0) + 1

    # Find security decisions
    security_events = []
    for record in chain.records:
        if record.activity_type.value == "decision":
            security_events.append({
                "timestamp": record.timestamp,
                "decision": record.activity_name,
                "attributes": record.activity_attributes,
            })

    return {
        "session_id": session_id,
        "exported_at": datetime.now(timezone.utc).isoformat(),
        "summary": {
            "total_records": len(chain.records),
            "chain_integrity": is_valid,
            "integrity_error": error,
            "activity_breakdown": activity_counts,
            "security_events": len(security_events),
        },
        "security_decisions": security_events,
        "first_activity": chain.records[0].timestamp if chain.records else None,
        "last_activity": chain.records[-1].timestamp if chain.records else None,
    }


def export_multiple_sessions(session_ids: list[str], format: str = "json") -> str:
    """
    Export multiple sessions in one file.
    """
    if format == "json":
        data = {
            "export_info": {
                "exported_at": datetime.now(timezone.utc).isoformat(),
                "session_count": len(session_ids),
            },
            "sessions": {}
        }
        for sid in session_ids:
            chain = get_or_create_chain(sid)
            data["sessions"][sid] = {
                "record_count": len(chain.records),
                "chain_valid": chain.verify_chain()[0],
                "records": [_record_to_dict(r) for r in chain.records],
            }
        return json.dumps(data, indent=2, ensure_ascii=False)

    elif format == "csv":
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow([
            "session_id",
            "sequence",
            "timestamp",
            "activity_type",
            "activity_name",
            "record_hash",
        ])
        for sid in session_ids:
            chain = get_or_create_chain(sid)
            for record in chain.records:
                writer.writerow([
                    sid,
                    record.sequence_number,
                    record.timestamp,
                    record.activity_type.value,
                    record.activity_name,
                    record.record_hash,
                ])
        return output.getvalue()

    return ""


def _record_to_dict(record: ProvenanceRecord) -> dict[str, Any]:
    """Convert record to dictionary."""
    return {
        "id": record.id,
        "sequence": record.sequence_number,
        "timestamp": record.timestamp,
        "activity": {
            "type": record.activity_type.value,
            "name": record.activity_name,
            "attributes": record.activity_attributes,
        },
        "chain": {
            "hash": record.record_hash,
            "previous_hash": record.previous_hash,
        },
        "entities": {
            "used": [
                {"id": e.id, "type": e.type, "hash": e.value_hash}
                for e in record.used_entities
            ],
            "generated": [
                {"id": e.id, "type": e.type, "hash": e.value_hash}
                for e in record.generated_entities
            ],
        },
    }


# ============================================
# CLI Commands
# ============================================

def export_cli(session_id: str, format: str = "json", output: str = None):
    """
    CLI export command.

    Usage:
        python -m inalign_mcp.audit_export SESSION_ID [--format json|csv] [--output file]
    """
    if format == "json":
        content = export_session_json(session_id)
        ext = ".json"
    elif format == "csv":
        content = export_session_csv(session_id)
        ext = ".csv"
    else:
        content = json.dumps(export_session_summary(session_id), indent=2)
        ext = ".json"

    if output:
        filepath = output
    else:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filepath = f"audit_{session_id}_{timestamp}{ext}"

    with open(filepath, "w", encoding="utf-8") as f:
        f.write(content)

    print(f"Exported to: {filepath}")
    return filepath


if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("Usage: python -m inalign_mcp.audit_export SESSION_ID [--format json|csv]")
        sys.exit(1)

    session_id = sys.argv[1]
    format = "json"
    output = None

    for i, arg in enumerate(sys.argv):
        if arg == "--format" and i + 1 < len(sys.argv):
            format = sys.argv[i + 1]
        if arg == "--output" and i + 1 < len(sys.argv):
            output = sys.argv[i + 1]

    export_cli(session_id, format, output)
