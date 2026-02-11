"""
In-A-Lign MCP Server

AI Agent Governance Platform - Provenance & Policy
MCP server for Claude Code, Cursor, and other AI agents.

Features:
- Provenance chain with cryptographic verification (tamper-proof audit trail)
- Policy management for AI agent governance
- GraphRAG pattern detection and risk analysis
- Neo4j graph storage integration
"""

import asyncio
import json
import logging
import os
import tempfile
import uuid
import hashlib
from datetime import datetime, timezone
from typing import Any

from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import (
    Tool,
    TextContent,
    CallToolResult,
)

from .provenance import (
    get_or_create_chain,
    record_tool_call as prov_record_tool,
    record_decision,
    get_chain_summary,
    ActivityType,
    ProvenanceChain,
)

# Usage limiter
try:
    from .usage_limiter import check_and_increment, get_usage_stats as get_limiter_stats
    LIMITER_AVAILABLE = True
except ImportError:
    LIMITER_AVAILABLE = False

# Optional Neo4j and GraphRAG imports (for direct Neo4j mode)
try:
    from .provenance_graph import (
        init_neo4j,
        store_record,
        sync_chain_to_graph,
        is_neo4j_available,
        store_content,
    )
    from .graph_rag import (
        GraphRAGAnalyzer,
        analyze_session_risk,
        get_agent_risk,
        get_user_risk,
        get_all_agents_summary,
    )
    GRAPHRAG_AVAILABLE = True
except ImportError:
    GRAPHRAG_AVAILABLE = False

# API client for HTTP proxy mode (no direct Neo4j needed)
try:
    from .api_client import init_api_client, get_api_client, ApiClient
    API_CLIENT_AVAILABLE = True
except ImportError:
    API_CLIENT_AVAILABLE = False

# SQLite local storage (zero-config persistent storage)
try:
    from .sqlite_storage import (
        init_sqlite,
        store_record as sqlite_store_record,
        store_session as sqlite_store_session,
        load_chain as sqlite_load_chain,
        list_sessions as sqlite_list_sessions,
        get_session_count,
        get_record_count,
        get_db_path,
    )
    SQLITE_AVAILABLE = True
except ImportError:
    SQLITE_AVAILABLE = False

# Policy engine import
try:
    from .policy import (
        PolicyEngine,
        get_policy_engine,
        PolicyAction,
        PRESETS,
        ThreatCategory,
    )
    POLICY_AVAILABLE = True
except ImportError:
    POLICY_AVAILABLE = False
    PolicyEngine = None

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("inalign-mcp")

# Create MCP server
server = Server("inalign")

# Session tracking
SESSION_ID = str(uuid.uuid4())[:12]

# Load ~/.inalign.env for any missing config (Neo4j creds, API key, etc.)
env_file = os.path.expanduser("~/.inalign.env")
if os.path.exists(env_file):
    logger.info(f"[STARTUP] Loading config from {env_file}")
    with open(env_file) as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                key, value = line.split("=", 1)
                key = key.strip()
                # Only set if not already in environment (env vars take precedence)
                if not os.getenv(key):
                    os.environ[key] = value.strip()

# Debug: Log environment variables at startup
logger.info(f"[STARTUP] SESSION_ID: {SESSION_ID}")
logger.info(f"[STARTUP] API_KEY env: {os.getenv('API_KEY', 'NOT SET')[:20] if os.getenv('API_KEY') else 'NOT SET'}...")
logger.info(f"[STARTUP] NEO4J_URI env: {os.getenv('NEO4J_URI', 'NOT SET')}")

# Client ID from API key (for data isolation)
API_KEY = os.getenv("INALIGN_API_KEY") or os.getenv("API_KEY")
CLIENT_ID = None

if API_KEY:
    # Derive client_id from API key prefix
    CLIENT_ID = API_KEY[:12] if API_KEY.startswith("ial_") else hashlib.sha256(API_KEY.encode()).hexdigest()[:12]
    logger.info(f"[CLIENT] Initialized with client_id: {CLIENT_ID}")
else:
    logger.warning(f"[CLIENT] No API_KEY found - client_id will be None")

# Initialize storage: prefer direct Neo4j, fallback to API proxy, then in-memory only
STORAGE_MODE = "memory"  # "neo4j" | "api" | "memory"
NEO4J_URI = os.getenv("NEO4J_URI")
API_URL = os.getenv("INALIGN_API_URL") or os.getenv("API_URL")

if NEO4J_URI and GRAPHRAG_AVAILABLE:
    try:
        neo4j_ok = init_neo4j(
            uri=NEO4J_URI,
            user=os.getenv("NEO4J_USERNAME", "neo4j"),
            password=os.getenv("NEO4J_PASSWORD", "")
        )
        if neo4j_ok:
            STORAGE_MODE = "neo4j"
            logger.info(f"[STORAGE] Direct Neo4j mode → {NEO4J_URI}")
        else:
            logger.warning(f"[NEO4J] Connection failed, trying next backend")
    except Exception as e:
        logger.warning(f"[NEO4J] Failed to connect: {e}")

if STORAGE_MODE != "neo4j" and API_URL and API_KEY and API_CLIENT_AVAILABLE:
    try:
        init_api_client(API_URL, API_KEY)
        STORAGE_MODE = "api"
        logger.info(f"[STORAGE] API proxy mode → {API_URL}")
    except Exception as e:
        logger.warning(f"[API] Failed to init: {e}")

# SQLite local persistent storage (default for --local mode)
if STORAGE_MODE == "memory" and SQLITE_AVAILABLE:
    try:
        if init_sqlite():
            STORAGE_MODE = "sqlite"
            logger.info(f"[STORAGE] SQLite local mode → {get_db_path()}")
    except Exception as e:
        logger.warning(f"[SQLITE] Failed to init: {e}")

if STORAGE_MODE == "memory":
    logger.info("[STORAGE] In-memory only mode (no Neo4j, API, or SQLite)")


def _persist_store(record) -> bool:
    """Store a provenance record to the persistent backend (Neo4j, API, or SQLite)."""
    if STORAGE_MODE == "neo4j":
        try:
            store_record(record)
            return True
        except Exception as e:
            logger.warning(f"[NEO4J] Failed to store: {e}")
            return False
    elif STORAGE_MODE == "api":
        try:
            client = get_api_client()
            if not client:
                return False
            import json as _json
            attrs = _json.dumps(record.activity_attributes) if record.activity_attributes else "{}"
            return client.store_record(
                record_id=record.id,
                timestamp=record.timestamp,
                activity_type=record.activity_type.value,
                activity_name=record.activity_name,
                record_hash=record.record_hash,
                previous_hash=record.previous_hash or "",
                sequence_number=record.sequence_number,
                session_id=record.session_id or "",
                client_id=getattr(record, 'client_id', '') or CLIENT_ID or "",
                agent_id=record.agent.id if record.agent else "",
                agent_name=record.agent.name if record.agent else "",
                agent_type=record.agent.type if record.agent else "",
                activity_attributes=attrs,
            )
        except Exception as e:
            logger.warning(f"[API] Failed to store: {e}")
            return False
    elif STORAGE_MODE == "sqlite":
        try:
            sqlite_store_record(record)
            return True
        except Exception as e:
            logger.warning(f"[SQLITE] Failed to store: {e}")
            return False
    return False


stats = {
    "provenance_records": 0,
    "policy_checks": 0,
    "sessions_tracked": 1,
}


@server.list_tools()
async def list_tools() -> list[Tool]:
    """List available governance tools."""
    tools = [
        # ============================================
        # PROVENANCE TOOLS - Audit Trail
        # ============================================
        Tool(
            name="record_user_command",
            description="Record the user's command/prompt that triggered agent actions. CRITICAL for audit trail - call this at the start of every task with the user's original request.",
            inputSchema={
                "type": "object",
                "properties": {
                    "command": {
                        "type": "string",
                        "description": "The user's command or prompt (what they asked the agent to do)",
                    },
                    "command_hash_only": {
                        "type": "boolean",
                        "description": "If true, only store hash of command (for privacy). Default false.",
                        "default": False,
                    },
                    "user_id": {
                        "type": "string",
                        "description": "Optional user identifier",
                    },
                },
                "required": ["command"],
            },
        ),
        Tool(
            name="record_action",
            description="Record an agent action in the provenance chain. Creates a cryptographically verifiable record of what the agent did.",
            inputSchema={
                "type": "object",
                "properties": {
                    "action_type": {
                        "type": "string",
                        "description": "Type of action",
                        "enum": ["tool_call", "decision", "file_read", "file_write", "llm_request"],
                    },
                    "action_name": {
                        "type": "string",
                        "description": "Name/description of the action",
                    },
                    "inputs": {
                        "type": "object",
                        "description": "Input data used by the action",
                    },
                    "outputs": {
                        "type": "object",
                        "description": "Output data generated by the action",
                    },
                },
                "required": ["action_type", "action_name"],
            },
        ),
        Tool(
            name="get_provenance",
            description="Get the provenance chain summary for this session. Shows all recorded actions with their cryptographic hashes.",
            inputSchema={
                "type": "object",
                "properties": {
                    "format": {
                        "type": "string",
                        "description": "Output format",
                        "enum": ["summary", "full", "prov-jsonld"],
                        "default": "summary",
                    },
                },
            },
        ),
        Tool(
            name="verify_provenance",
            description="Verify the integrity of the provenance chain. Checks that no records have been tampered with.",
            inputSchema={
                "type": "object",
                "properties": {},
            },
        ),
        Tool(
            name="generate_audit_report",
            description="Generate comprehensive audit report with provenance chain, risk analysis, and recommendations.",
            inputSchema={
                "type": "object",
                "properties": {
                    "format": {
                        "type": "string",
                        "description": "Report format",
                        "enum": ["json", "summary", "prov-jsonld"],
                        "default": "summary",
                    },
                },
            },
        ),
        Tool(
            name="verify_third_party",
            description="Generate third-party verifiable proof. Returns all data needed to independently verify the provenance chain on-chain without trusting In-A-Lign.",
            inputSchema={
                "type": "object",
                "properties": {
                    "session_id": {
                        "type": "string",
                        "description": "Session ID to verify (defaults to current session)",
                    },
                },
            },
        ),
        # ============================================
        # RISK ANALYSIS TOOLS
        # ============================================
        Tool(
            name="analyze_risk",
            description="Run GraphRAG pattern detection on the session. Detects data exfiltration, privilege escalation, suspicious tool chains, and other attack patterns.",
            inputSchema={
                "type": "object",
                "properties": {
                    "session_id": {
                        "type": "string",
                        "description": "Session ID to analyze (defaults to current session)",
                    },
                },
            },
        ),
        Tool(
            name="get_behavior_profile",
            description="Get behavioral profile for a session. Shows tool usage patterns, timing analysis, and anomalies.",
            inputSchema={
                "type": "object",
                "properties": {
                    "session_id": {
                        "type": "string",
                        "description": "Session ID to profile (defaults to current session)",
                    },
                },
            },
        ),
        Tool(
            name="get_agent_risk",
            description="Get long-term risk profile for an agent across all sessions. Shows risk trends, common patterns, and tools used.",
            inputSchema={
                "type": "object",
                "properties": {
                    "agent_id": {
                        "type": "string",
                        "description": "Agent ID to profile",
                    },
                },
                "required": ["agent_id"],
            },
        ),
        Tool(
            name="get_user_risk",
            description="Get risk profile for a user/team across all their agents. Aggregates risk data for org-level view.",
            inputSchema={
                "type": "object",
                "properties": {
                    "user_id": {
                        "type": "string",
                        "description": "User or team ID",
                    },
                },
                "required": ["user_id"],
            },
        ),
        Tool(
            name="list_agents_risk",
            description="Get risk summary for all known agents. Useful for org-wide security dashboard.",
            inputSchema={
                "type": "object",
                "properties": {
                    "limit": {
                        "type": "integer",
                        "description": "Maximum number of agents to return",
                        "default": 20,
                    },
                },
            },
        ),
    ]

    # Session history tool (SQLite mode)
    tools.append(
        Tool(
            name="list_sessions",
            description="List past audit sessions stored locally. Shows session history with record counts and timestamps. Works in SQLite storage mode.",
            inputSchema={
                "type": "object",
                "properties": {
                    "limit": {
                        "type": "integer",
                        "description": "Maximum number of sessions to return (default 20)",
                        "default": 20,
                    },
                },
            },
        )
    )

    # Export report tool (works in all modes including memory)
    tools.append(
        Tool(
            name="export_report",
            description="Export a visual HTML audit report that opens in any browser. Works in all storage modes including local memory. The report shows the full provenance chain, verification status, and action timeline.",
            inputSchema={
                "type": "object",
                "properties": {
                    "output_path": {
                        "type": "string",
                        "description": "Optional file path for the HTML report. If not provided, saves to a temp file.",
                    },
                },
            },
        )
    )

    if POLICY_AVAILABLE:
        tools.extend([
            Tool(
                name="get_policy",
                description="Get current security policy settings. Shows active preset and all rule configurations.",
                inputSchema={
                    "type": "object",
                    "properties": {},
                },
            ),
            Tool(
                name="set_policy",
                description="Change security policy preset. Options: STRICT_ENTERPRISE (max security), BALANCED (default), DEV_SANDBOX (permissive).",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "preset": {
                            "type": "string",
                            "description": "Policy preset name",
                            "enum": ["STRICT_ENTERPRISE", "BALANCED", "DEV_SANDBOX"],
                        },
                    },
                    "required": ["preset"],
                },
            ),
            Tool(
                name="list_policies",
                description="List all available policy presets with descriptions.",
                inputSchema={
                    "type": "object",
                    "properties": {},
                },
            ),
            Tool(
                name="simulate_policy",
                description="Simulate a policy against historical events. Shows how many would be blocked/masked/warned.",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "preset": {
                            "type": "string",
                            "description": "Policy preset to simulate",
                            "enum": ["STRICT_ENTERPRISE", "BALANCED", "DEV_SANDBOX"],
                        },
                    },
                    "required": ["preset"],
                },
            ),
        ])

    return tools


@server.call_tool()
async def call_tool(name: str, arguments: dict[str, Any]) -> list[TextContent]:
    """Handle tool calls."""
    global stats

    # === USAGE LIMIT CHECK ===
    if LIMITER_AVAILABLE and CLIENT_ID:
        usage_status = check_and_increment(CLIENT_ID)
        if not usage_status.allowed:
            logger.warning(f"[LIMIT] Client {CLIENT_ID} exceeded limit: {usage_status.message}")
            return [TextContent(
                type="text",
                text=json.dumps({
                    "error": "usage_limit_exceeded",
                    "message": usage_status.message,
                    "current_usage": usage_status.current_count,
                    "limit": usage_status.limit,
                    "plan": usage_status.plan,
                    "upgrade_url": "http://3.36.132.4:8080"
                })
            )]
        logger.info(f"[USAGE] {CLIENT_ID}: {usage_status.current_count}/{usage_status.limit} actions")
    # === END USAGE CHECK ===

    # === AUTO PROVENANCE RECORDING ===
    try:
        # Include client_id for data isolation
        args_with_client = {**arguments, "client_id": CLIENT_ID} if CLIENT_ID else arguments
        # Ensure chain has client_id before recording
        chain = get_or_create_chain(SESSION_ID, "Claude Code", CLIENT_ID or "")
        # Register session in SQLite on first call
        if STORAGE_MODE == "sqlite" and chain._sequence == 0:
            sqlite_store_session(SESSION_ID, chain.agent, CLIENT_ID or "")
        auto_record = prov_record_tool(
            session_id=SESSION_ID,
            tool_name=name,
            arguments=args_with_client,
            agent_name="Claude Code"
        )
        stats["provenance_records"] += 1
        logger.info(f"[PROVENANCE] Recorded: {name} (session: {SESSION_ID})")

        # Store auto-provenance to persistent backend
        if STORAGE_MODE != "memory":
            _persist_store(auto_record)
    except Exception as e:
        logger.warning(f"[PROVENANCE] Failed to record: {e}")
    # === END PROVENANCE RECORDING ===

    # ============================================
    # PROVENANCE HANDLERS
    # ============================================

    if name == "record_user_command":
        command = arguments.get("command", "")
        hash_only = arguments.get("command_hash_only", False)
        user_id = arguments.get("user_id", "unknown")

        chain = get_or_create_chain(SESSION_ID, "claude", CLIENT_ID or "")

        if hash_only:
            command_data = hashlib.sha256(command.encode()).hexdigest()
            storage_note = "hash_only"
        else:
            command_data = command
            storage_note = "full_command"

        record = chain.record_activity(
            activity_type=ActivityType.USER_INPUT,
            activity_name="user_command",
            used=[],
            generated=[({
                "command": command_data,
                "storage_type": storage_note,
                "user_id": user_id,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }, "user_command")],
            attributes={
                "command": command_data,
                "storage_type": storage_note,
                "user_id": user_id,
                "client_id": CLIENT_ID,
            }
        )

        stats["provenance_records"] += 1

        # Store to remote backend
        if STORAGE_MODE != "memory":
            _persist_store(record)
            logger.info(f"[{STORAGE_MODE.upper()}] Stored record {record.id} with client_id={CLIENT_ID}")

            # Store full prompt content (compressed) for legal compliance (Neo4j direct only)
            if STORAGE_MODE == "neo4j" and not hash_only and command:
                try:
                    content_hash = store_content(
                        content=command,
                        content_type="prompt",
                        record_id=record.id,
                        client_id=CLIENT_ID
                    )
                    if content_hash:
                        logger.info(f"[NEO4J] Stored full prompt content: {content_hash[:16]}...")
                except Exception as e:
                    logger.warning(f"[NEO4J] Failed to store content: {e}")

        return [TextContent(
            type="text",
            text=json.dumps({
                "recorded": True,
                "record_id": record.id,
                "record_hash": record.record_hash,
                "sequence": record.sequence_number,
                "storage_type": storage_note,
                "user_id": user_id,
                "message": f"✅ User command recorded (seq #{record.sequence_number})",
            }, indent=2)
        )]

    elif name == "record_action":
        action_type_str = arguments.get("action_type", "tool_call")
        action_name = arguments.get("action_name", "unknown")
        inputs = arguments.get("inputs", {})
        outputs = arguments.get("outputs", {})

        type_map = {
            "tool_call": ActivityType.TOOL_CALL,
            "decision": ActivityType.DECISION,
            "file_read": ActivityType.FILE_READ,
            "file_write": ActivityType.FILE_WRITE,
            "llm_request": ActivityType.LLM_REQUEST,
        }
        activity_type = type_map.get(action_type_str, ActivityType.TOOL_CALL)

        chain = get_or_create_chain(SESSION_ID, "claude", CLIENT_ID or "")

        used = [(inputs, "input")] if inputs else []
        generated = [(outputs, "output")] if outputs else []

        record = chain.record_activity(
            activity_type=activity_type,
            activity_name=action_name,
            used=used,
            generated=generated,
            attributes={"inputs": inputs, "outputs": outputs, "client_id": CLIENT_ID}
        )

        stats["provenance_records"] += 1

        # Store to remote backend
        if STORAGE_MODE != "memory":
            _persist_store(record)
            logger.info(f"[{STORAGE_MODE.upper()}] Stored action record {record.id} with client_id={CLIENT_ID}")

            # Store full content (Neo4j direct mode only)
            if STORAGE_MODE == "neo4j":
                try:
                    if inputs:
                        input_str = json.dumps(inputs, ensure_ascii=False) if isinstance(inputs, dict) else str(inputs)
                        if len(input_str) > 100:
                            store_content(input_str, "input", record.id, CLIENT_ID)
                    if outputs:
                        output_str = json.dumps(outputs, ensure_ascii=False) if isinstance(outputs, dict) else str(outputs)
                        if len(output_str) > 100:
                            store_content(output_str, "output", record.id, CLIENT_ID)
                except Exception as e:
                    logger.warning(f"[NEO4J] Failed to store content: {e}")

        return [TextContent(
            type="text",
            text=json.dumps({
                "recorded": True,
                "record_id": record.id,
                "record_hash": record.record_hash,
                "previous_hash": record.previous_hash,
                "sequence": record.sequence_number,
                "chain_length": len(chain.records),
                "message": f"✅ Action recorded: {action_name} (seq #{record.sequence_number})",
            }, indent=2)
        )]

    elif name == "get_provenance":
        fmt = arguments.get("format", "summary")
        chain = get_or_create_chain(SESSION_ID, "claude", CLIENT_ID or "")

        if fmt == "summary":
            summary = get_chain_summary(SESSION_ID)
            summary["recent_records"] = [
                {
                    "id": r.id,
                    "type": r.activity_type.value,
                    "name": r.activity_name,
                    "hash": r.record_hash[:16] + "...",
                    "timestamp": r.timestamp,
                }
                for r in chain.records[-5:]
            ]
            return [TextContent(type="text", text=json.dumps(summary, indent=2))]

        elif fmt == "full":
            return [TextContent(type="text", text=chain.export_json())]

        elif fmt == "prov-jsonld":
            prov = chain.export_prov_jsonld()
            return [TextContent(type="text", text=json.dumps(prov, indent=2))]

        else:
            return [TextContent(type="text", text=json.dumps({"error": "Unknown format"}))]

    elif name == "verify_provenance":
        chain = get_or_create_chain(SESSION_ID, "claude", CLIENT_ID or "")
        is_valid, error = chain.verify_chain()

        return [TextContent(
            type="text",
            text=json.dumps({
                "valid": is_valid,
                "error": error,
                "record_count": len(chain.records),
                "merkle_root": chain.get_merkle_root(),
                "session_id": SESSION_ID,
                "message": "✅ Chain integrity VERIFIED" if is_valid else f"❌ Chain BROKEN: {error}",
            }, indent=2)
        )]

    elif name == "list_sessions":
        if STORAGE_MODE == "sqlite" and SQLITE_AVAILABLE:
            limit = arguments.get("limit", 20)
            sessions = sqlite_list_sessions(limit=limit, client_id=CLIENT_ID)
            return [TextContent(
                type="text",
                text=json.dumps({
                    "storage_mode": "sqlite",
                    "db_path": get_db_path(),
                    "total_sessions": get_session_count(),
                    "total_records": get_record_count(),
                    "sessions": sessions,
                    "message": f"Found {len(sessions)} sessions in local storage",
                }, indent=2)
            )]
        else:
            return [TextContent(
                type="text",
                text=json.dumps({
                    "storage_mode": STORAGE_MODE,
                    "message": "Session history requires SQLite storage mode. Current mode: " + STORAGE_MODE,
                    "sessions": [],
                }, indent=2)
            )]

    elif name == "export_report":
        from .report import generate_html_report

        chain = get_or_create_chain(SESSION_ID, "claude", CLIENT_ID or "")
        is_valid, error = chain.verify_chain()

        records_data = [
            {
                "sequence": r.sequence_number,
                "type": r.activity_type.value,
                "name": r.activity_name,
                "hash": r.record_hash,
                "previous_hash": r.previous_hash,
                "timestamp": r.timestamp,
            }
            for r in chain.records
        ]

        verification = {
            "valid": is_valid,
            "error": error,
            "merkle_root": chain.get_merkle_root(),
        }

        html = generate_html_report(SESSION_ID, records_data, verification, stats)

        output_path = arguments.get("output_path")
        if not output_path:
            output_path = os.path.join(
                tempfile.gettempdir(),
                f"inalign-report-{SESSION_ID}.html"
            )

        with open(output_path, "w", encoding="utf-8") as f:
            f.write(html)

        return [TextContent(
            type="text",
            text=json.dumps({
                "success": True,
                "file_path": output_path,
                "record_count": len(chain.records),
                "chain_valid": is_valid,
                "message": f"✅ Report exported: {output_path}",
            }, indent=2)
        )]

    elif name == "generate_audit_report":
        fmt = arguments.get("format", "summary")
        chain = get_or_create_chain(SESSION_ID, "claude", CLIENT_ID or "")
        is_valid, error = chain.verify_chain()

        report = {
            "report_id": str(uuid.uuid4())[:8],
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "session_id": SESSION_ID,
            "chain_integrity": {
                "valid": is_valid,
                "error": error,
                "merkle_root": chain.get_merkle_root(),
            },
            "statistics": {
                "total_records": len(chain.records),
                "provenance_records": stats["provenance_records"],
            },
            "records": [
                {
                    "sequence": r.sequence_number,
                    "type": r.activity_type.value,
                    "name": r.activity_name,
                    "hash": r.record_hash,
                    "timestamp": r.timestamp,
                }
                for r in chain.records
            ],
        }

        return [TextContent(type="text", text=json.dumps(report, indent=2))]

    elif name == "verify_third_party":
        session_id = arguments.get("session_id", SESSION_ID)
        chain = get_or_create_chain(session_id, "claude")
        is_valid, error = chain.verify_chain()

        proof = {
            "session_id": session_id,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "chain_valid": is_valid,
            "merkle_root": chain.get_merkle_root(),
            "record_count": len(chain.records),
            "records": [
                {
                    "id": r.id,
                    "sequence": r.sequence_number,
                    "record_hash": r.record_hash,
                    "previous_hash": r.previous_hash,
                    "timestamp": r.timestamp,
                    "activity_type": r.activity_type.value,
                    "activity_name": r.activity_name,
                }
                for r in chain.records
            ],
            "verification_instructions": "To verify: compute SHA-256 of each record's content and check hash chain links.",
        }

        return [TextContent(type="text", text=json.dumps(proof, indent=2))]

    # ============================================
    # RISK ANALYSIS HANDLERS
    # ============================================

    elif name == "analyze_risk":
        session_id = arguments.get("session_id")

        if STORAGE_MODE == "neo4j":
            try:
                from .provenance_graph import _neo4j_driver as driver

                if not driver:
                    return [TextContent(type="text", text=json.dumps({
                        "error": "Neo4j driver is None",
                    }))]

                if not session_id:
                    with driver.session() as neo_session:
                        result = neo_session.run(
                            "MATCH (r:ProvenanceRecord)-[:BELONGS_TO]->(s:Session) "
                            "WHERE r.client_id = $client_id "
                            "RETURN s.session_id as sid, count(r) as cnt "
                            "ORDER BY cnt DESC LIMIT 1",
                            client_id=CLIENT_ID,
                        )
                        row = result.single()
                        session_id = row["sid"] if row else SESSION_ID

                risk = analyze_session_risk(session_id, driver)
                return [TextContent(type="text", text=json.dumps(risk, indent=2))]
            except Exception as e:
                import traceback
                return [TextContent(type="text", text=json.dumps({
                    "error": str(e),
                    "traceback": traceback.format_exc(),
                    "session_id": session_id,
                }))]

        elif STORAGE_MODE == "api":
            try:
                client = get_api_client()
                risk = client.analyze_risk(session_id or "")
                return [TextContent(type="text", text=json.dumps(risk, indent=2))]
            except Exception as e:
                return [TextContent(type="text", text=json.dumps({"error": str(e)}))]

        else:
            # SQLite or memory mode: analyze from in-memory chain
            chain = get_or_create_chain(session_id or SESSION_ID, "claude", CLIENT_ID or "")
            tool_counts = {}
            for r in chain.records:
                tool_counts[r.activity_name] = tool_counts.get(r.activity_name, 0) + 1

            return [TextContent(type="text", text=json.dumps({
                "session_id": session_id or SESSION_ID,
                "storage_mode": STORAGE_MODE,
                "risk_level": "low",
                "total_actions": len(chain.records),
                "tool_usage": tool_counts,
                "patterns_detected": [],
                "message": f"Local analysis ({STORAGE_MODE} mode) - {len(chain.records)} actions recorded",
            }, indent=2))]

    elif name == "get_behavior_profile":
        session_id = arguments.get("session_id", SESSION_ID)
        chain = get_or_create_chain(session_id, "claude")

        tool_counts = {}
        for r in chain.records:
            name_key = r.activity_name
            tool_counts[name_key] = tool_counts.get(name_key, 0) + 1

        profile = {
            "session_id": session_id,
            "total_actions": len(chain.records),
            "tool_usage": tool_counts,
            "first_activity": chain.records[0].timestamp if chain.records else None,
            "last_activity": chain.records[-1].timestamp if chain.records else None,
        }

        return [TextContent(type="text", text=json.dumps(profile, indent=2))]

    elif name == "get_agent_risk":
        agent_id = arguments.get("agent_id", "unknown")

        if STORAGE_MODE == "neo4j":
            try:
                from .provenance_graph import _neo4j_driver
                risk = get_agent_risk(agent_id, _neo4j_driver)
                return [TextContent(type="text", text=json.dumps(risk, indent=2))]
            except Exception as e:
                return [TextContent(type="text", text=json.dumps({"error": str(e)}))]
        elif STORAGE_MODE == "api":
            try:
                client = get_api_client()
                risk = client.get_agent_risk(agent_id)
                return [TextContent(type="text", text=json.dumps(risk, indent=2))]
            except Exception as e:
                return [TextContent(type="text", text=json.dumps({"error": str(e)}))]
        else:
            return [TextContent(type="text", text=json.dumps({
                "agent_id": agent_id,
                "message": "No remote backend configured",
            }))]

    elif name == "get_user_risk":
        user_id = arguments.get("user_id", "unknown")

        if STORAGE_MODE == "neo4j":
            try:
                from .provenance_graph import _neo4j_driver
                risk = get_user_risk(user_id, _neo4j_driver)
                return [TextContent(type="text", text=json.dumps(risk, indent=2))]
            except Exception as e:
                return [TextContent(type="text", text=json.dumps({"error": str(e)}))]
        elif STORAGE_MODE == "api":
            try:
                client = get_api_client()
                risk = client.get_user_risk(user_id)
                return [TextContent(type="text", text=json.dumps(risk, indent=2))]
            except Exception as e:
                return [TextContent(type="text", text=json.dumps({"error": str(e)}))]
        else:
            return [TextContent(type="text", text=json.dumps({
                "user_id": user_id,
                "message": "No remote backend configured",
            }))]

    elif name == "list_agents_risk":
        limit = arguments.get("limit", 20)

        if STORAGE_MODE == "neo4j" and GRAPHRAG_AVAILABLE:
            try:
                agents = get_all_agents_summary(limit)
                return [TextContent(type="text", text=json.dumps(agents, indent=2))]
            except Exception as e:
                return [TextContent(type="text", text=json.dumps({"error": str(e)}))]
        elif STORAGE_MODE == "api":
            try:
                client = get_api_client()
                agents = client.get_all_agents_summary(limit)
                return [TextContent(type="text", text=json.dumps(agents, indent=2))]
            except Exception as e:
                return [TextContent(type="text", text=json.dumps({"error": str(e)}))]
        else:
            return [TextContent(type="text", text=json.dumps({
                "message": "No remote backend configured",
                "agents": [],
            }))]

    # ============================================
    # POLICY HANDLERS
    # ============================================

    elif name == "get_policy" and POLICY_AVAILABLE:
        engine = get_policy_engine()
        policy = engine.get_policy()

        return [TextContent(
            type="text",
            text=json.dumps({
                "preset": policy.get("name", "BALANCED"),
                "rules": policy,
            }, indent=2)
        )]

    elif name == "set_policy" and POLICY_AVAILABLE:
        preset = arguments.get("preset", "BALANCED")
        engine = get_policy_engine()

        if preset in PRESETS:
            engine.set_policy(preset)
            stats["policy_checks"] += 1
            return [TextContent(
                type="text",
                text=json.dumps({
                    "success": True,
                    "preset": preset,
                    "message": f"✅ Policy set to {preset}",
                }, indent=2)
            )]
        else:
            return [TextContent(
                type="text",
                text=json.dumps({
                    "success": False,
                    "error": f"Unknown preset: {preset}",
                    "available": list(PRESETS.keys()),
                }, indent=2)
            )]

    elif name == "list_policies" and POLICY_AVAILABLE:
        engine = get_policy_engine()
        presets = engine.list_presets()

        return [TextContent(
            type="text",
            text=json.dumps({"policies": presets}, indent=2)
        )]

    elif name == "simulate_policy" and POLICY_AVAILABLE:
        preset = arguments.get("preset", "BALANCED")

        # Simulate: replay current session's recorded actions against the target preset
        target_policy = PRESETS.get(preset)
        if not target_policy:
            return [TextContent(type="text", text=json.dumps({"error": f"Unknown preset: {preset}"}))]

        chain = get_or_create_chain(SESSION_ID, "claude")
        blocked = []
        warned = []
        masked = []
        allowed = []

        # Map tool names to threat categories for simulation
        sensitive_patterns = {
            ThreatCategory.SENSITIVE_FILE: [".env", ".key", ".pem", ".ssh", "credentials", "secret"],
            ThreatCategory.COMMAND_INJECTION: ["bash", "exec", "shell", "system"],
            ThreatCategory.EXFILTRATION: ["curl", "wget", "http", "upload", "send"],
        }

        for record in chain.records:
            matched_category = None
            for category, patterns in sensitive_patterns.items():
                if any(p in (record.activity_name or "").lower() for p in patterns):
                    matched_category = category
                    break

            if matched_category:
                action = target_policy.get_action(matched_category, confidence=0.9)
                entry = {"action_name": record.activity_name, "category": matched_category.value, "policy_action": action.value}
                if action == PolicyAction.BLOCK:
                    blocked.append(entry)
                elif action == PolicyAction.WARN:
                    warned.append(entry)
                elif action == PolicyAction.MASK:
                    masked.append(entry)
                else:
                    allowed.append(entry)
            else:
                allowed.append({"action_name": record.activity_name, "category": "none", "policy_action": "allow"})

        return [TextContent(type="text", text=json.dumps({
            "preset": preset,
            "total_events": len(chain.records),
            "would_block": len(blocked),
            "would_warn": len(warned),
            "would_mask": len(masked),
            "would_allow": len(allowed),
            "blocked_details": blocked[:10],
            "warned_details": warned[:10],
            "masked_details": masked[:10],
        }, indent=2))]

    # Unknown tool
    else:
        return [TextContent(
            type="text",
            text=json.dumps({"error": f"Unknown tool: {name}"})
        )]


async def main():
    """Run the MCP server."""
    logger.info(f"Starting InALign MCP Server (session: {SESSION_ID})")
    logger.info("AI Agent Governance Platform - Provenance & Policy")

    async with stdio_server() as (read_stream, write_stream):
        await server.run(
            read_stream,
            write_stream,
            server.create_initialization_options(),
        )


if __name__ == "__main__":
    asyncio.run(main())
