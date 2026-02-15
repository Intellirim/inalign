"""
OpenTelemetry Export

Converts InALign provenance data to OpenTelemetry (OTLP) JSON format.
Supports file export (local, 100% offline) and optional OTLP endpoint push.

Span structure:
- Root span: Session
  - Child spans: Tool calls / actions
    - Events: Individual provenance records

100% local by default. OTLP endpoint push is opt-in.
"""

import hashlib
import json
import logging
import os
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

logger = logging.getLogger("inalign-otel")

INALIGN_DIR = Path.home() / ".inalign"
DB_PATH = INALIGN_DIR / "provenance.db"


def _load_session_records(session_id: str) -> tuple[list[dict], dict]:
    """Load records and session metadata."""
    records = []
    session_meta = {}

    if not DB_PATH.exists():
        return records, session_meta

    try:
        conn = sqlite3.connect(str(DB_PATH), check_same_thread=False)
        conn.row_factory = sqlite3.Row

        row = conn.execute(
            "SELECT * FROM sessions WHERE session_id=?", (session_id,)
        ).fetchone()
        if row:
            session_meta = dict(row)

        rows = conn.execute(
            "SELECT * FROM records WHERE session_id=? ORDER BY sequence_number ASC",
            (session_id,),
        ).fetchall()
        records = [dict(r) for r in rows]
        conn.close()
    except Exception as e:
        logger.warning(f"[OTEL] DB read failed: {e}")

    return records, session_meta


def _iso_to_unix_nano(iso_str: str) -> int:
    """Convert ISO 8601 timestamp to Unix nanoseconds."""
    try:
        dt = datetime.fromisoformat(iso_str.replace("Z", "+00:00"))
        return int(dt.timestamp() * 1_000_000_000)
    except Exception:
        return int(datetime.now(timezone.utc).timestamp() * 1_000_000_000)


def _generate_trace_id(session_id: str) -> str:
    """Generate deterministic 32-hex-char trace ID from session."""
    return hashlib.sha256(f"inalign:{session_id}".encode()).hexdigest()[:32]


def _generate_span_id(record_id: str) -> str:
    """Generate deterministic 16-hex-char span ID from record."""
    return hashlib.sha256(f"span:{record_id}".encode()).hexdigest()[:16]


def _record_to_span(record: dict, trace_id: str, parent_span_id: str) -> dict:
    """Convert a provenance record to an OTLP span."""
    span_id = _generate_span_id(record.get("id", ""))
    start_time = _iso_to_unix_nano(record.get("timestamp", ""))
    # Estimate end time as start + 100ms (actual duration unknown)
    end_time = start_time + 100_000_000

    attrs = []
    attrs.append({"key": "inalign.activity_type", "value": {"stringValue": record.get("activity_type", "")}})
    attrs.append({"key": "inalign.activity_name", "value": {"stringValue": record.get("activity_name", "")}})
    attrs.append({"key": "inalign.sequence", "value": {"intValue": str(record.get("sequence_number", 0))}})
    attrs.append({"key": "inalign.record_hash", "value": {"stringValue": record.get("record_hash", "")}})

    if record.get("previous_hash"):
        attrs.append({"key": "inalign.previous_hash", "value": {"stringValue": record["previous_hash"]}})

    # Parse activity attributes
    try:
        act_attrs = json.loads(record.get("activity_attributes", "{}")) if isinstance(
            record.get("activity_attributes"), str
        ) else record.get("activity_attributes", {})
        if act_attrs:
            for k, v in act_attrs.items():
                if k in ("client_id", "command", "tool_name"):
                    attrs.append({"key": f"inalign.{k}", "value": {"stringValue": str(v)[:500]}})
    except Exception:
        pass

    # Map activity_type to OTLP SpanKind
    kind_map = {
        "tool_call": 3,      # CLIENT
        "tool_result": 4,    # SERVER
        "user_input": 3,     # CLIENT
        "decision": 1,       # INTERNAL
        "file_read": 3,      # CLIENT
        "file_write": 3,     # CLIENT
        "llm_request": 3,    # CLIENT
    }
    kind = kind_map.get(record.get("activity_type", ""), 1)

    return {
        "traceId": trace_id,
        "spanId": span_id,
        "parentSpanId": parent_span_id,
        "name": record.get("activity_name", "unknown"),
        "kind": kind,
        "startTimeUnixNano": str(start_time),
        "endTimeUnixNano": str(end_time),
        "attributes": attrs,
        "status": {"code": 1},  # OK
    }


def export_otlp_json(session_id: str) -> dict[str, Any]:
    """
    Export session provenance data as OTLP JSON.

    Returns a complete OTLP TracesData structure.
    """
    records, session_meta = _load_session_records(session_id)
    trace_id = _generate_trace_id(session_id)

    # Root span for the session
    root_span_id = _generate_span_id(f"root:{session_id}")
    first_ts = _iso_to_unix_nano(records[0]["timestamp"]) if records else _iso_to_unix_nano("")
    last_ts = _iso_to_unix_nano(records[-1]["timestamp"]) if records else first_ts

    root_span = {
        "traceId": trace_id,
        "spanId": root_span_id,
        "name": f"inalign.session.{session_id}",
        "kind": 1,  # INTERNAL
        "startTimeUnixNano": str(first_ts),
        "endTimeUnixNano": str(last_ts + 100_000_000),
        "attributes": [
            {"key": "inalign.session_id", "value": {"stringValue": session_id}},
            {"key": "inalign.record_count", "value": {"intValue": str(len(records))}},
            {"key": "inalign.agent_name", "value": {"stringValue": session_meta.get("agent_name", "unknown")}},
        ],
        "status": {"code": 1},
    }

    # Child spans for each record
    child_spans = [_record_to_span(r, trace_id, root_span_id) for r in records]

    # OTLP TracesData structure
    otlp = {
        "resourceSpans": [
            {
                "resource": {
                    "attributes": [
                        {"key": "service.name", "value": {"stringValue": "inalign"}},
                        {"key": "service.version", "value": {"stringValue": "0.5.0"}},
                        {"key": "inalign.session_id", "value": {"stringValue": session_id}},
                    ],
                },
                "scopeSpans": [
                    {
                        "scope": {
                            "name": "inalign.provenance",
                            "version": "0.5.0",
                        },
                        "spans": [root_span] + child_spans,
                    }
                ],
            }
        ],
    }

    return otlp


def _validate_output_path(output_path: str) -> str:
    """Validate output path to prevent path traversal. Must be under ~/.inalign/ or system temp."""
    import tempfile
    resolved = Path(output_path).resolve()
    allowed_parents = [INALIGN_DIR.resolve(), Path(tempfile.gettempdir()).resolve()]
    if not any(str(resolved).startswith(str(p)) for p in allowed_parents):
        raise ValueError(
            f"Output path must be under ~/.inalign/ or system temp dir, got: {resolved}"
        )
    return str(resolved)


def export_to_file(session_id: str, output_path: str = None) -> dict[str, Any]:
    """
    Export OTLP JSON to a file.

    Args:
        session_id: Session to export
        output_path: File path (default: ~/.inalign/exports/otel-{session_id}.json)

    Returns:
        Result dict with file_path and span_count
    """
    otlp = export_otlp_json(session_id)

    if not output_path:
        export_dir = INALIGN_DIR / "exports"
        export_dir.mkdir(parents=True, exist_ok=True)
        output_path = str(export_dir / f"otel-{session_id}.json")
    else:
        output_path = _validate_output_path(output_path)

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(otlp, f, indent=2)

    span_count = len(otlp.get("resourceSpans", [{}])[0].get("scopeSpans", [{}])[0].get("spans", []))

    return {
        "success": True,
        "file_path": output_path,
        "session_id": session_id,
        "span_count": span_count,
        "format": "OTLP JSON (OpenTelemetry Protocol)",
        "message": f"Exported {span_count} spans to {output_path}",
    }


def _validate_endpoint(endpoint: str) -> str:
    """Validate OTLP endpoint URL to prevent SSRF against internal networks."""
    import ipaddress
    import socket
    from urllib.parse import urlparse

    parsed = urlparse(endpoint)
    if parsed.scheme not in ("http", "https"):
        raise ValueError(f"Only http/https schemes allowed, got: {parsed.scheme}")
    if not parsed.hostname:
        raise ValueError("Endpoint must have a hostname")

    # Resolve hostname and check for private IPs
    try:
        for info in socket.getaddrinfo(parsed.hostname, parsed.port or 443):
            addr = info[4][0]
            ip = ipaddress.ip_address(addr)
            if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved:
                raise ValueError(f"Endpoint resolves to private/internal IP: {addr}")
    except socket.gaierror:
        raise ValueError(f"Cannot resolve hostname: {parsed.hostname}")

    return endpoint


def push_to_endpoint(session_id: str, endpoint: str) -> dict[str, Any]:
    """
    Push OTLP data to an OpenTelemetry collector endpoint.

    This is the ONLY function that makes external calls.
    Requires explicit endpoint configuration — not enabled by default.
    """
    try:
        endpoint = _validate_endpoint(endpoint)
    except ValueError as e:
        return {"success": False, "error": str(e), "endpoint": endpoint}

    try:
        import httpx
    except ImportError:
        return {"success": False, "error": "httpx not installed. Run: pip install httpx"}

    otlp = export_otlp_json(session_id)

    try:
        with httpx.Client(timeout=10) as client:
            resp = client.post(
                endpoint.rstrip("/") + "/v1/traces",
                json=otlp,
                headers={"Content-Type": "application/json"},
            )
            return {
                "success": resp.status_code in (200, 202),
                "status_code": resp.status_code,
                "endpoint": endpoint,
                "session_id": session_id,
                "message": f"Pushed to {endpoint} (status: {resp.status_code})",
            }
    except Exception as e:
        return {"success": False, "error": str(e), "endpoint": endpoint}
