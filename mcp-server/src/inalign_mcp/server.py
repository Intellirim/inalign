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

# Optional Neo4j and GraphRAG imports
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

# Policy engine import
try:
    from .policy import (
        PolicyEngine,
        get_policy_engine,
        PolicyAction,
        PRESETS,
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

# Try to load from .env file if API_KEY not set (Claude Code MCP workaround)
if not os.getenv("API_KEY"):
    env_file = os.path.expanduser("~/.inalign.env")
    if os.path.exists(env_file):
        logger.info(f"[STARTUP] Loading config from {env_file}")
        with open(env_file) as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#") and "=" in line:
                    key, value = line.split("=", 1)
                    os.environ[key.strip()] = value.strip()

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

# Initialize Neo4j connection for provenance storage
NEO4J_URI = os.getenv("NEO4J_URI")
if NEO4J_URI:
    try:
        init_neo4j(
            uri=NEO4J_URI,
            user=os.getenv("NEO4J_USERNAME", "neo4j"),
            password=os.getenv("NEO4J_PASSWORD", "")
        )
        logger.info(f"[NEO4J] Connected to {NEO4J_URI}")
    except Exception as e:
        logger.warning(f"[NEO4J] Failed to connect: {e}")

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

    # Add policy tools if available
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
        prov_record_tool(
            session_id=SESSION_ID,
            tool_name=name,
            arguments=args_with_client,
            agent_name="Claude Code"
        )
        stats["provenance_records"] += 1
        logger.info(f"[PROVENANCE] Recorded: {name} (session: {SESSION_ID})")
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

        # Store to Neo4j for dashboard visibility
        if is_neo4j_available():
            try:
                store_record(record)
                logger.info(f"[NEO4J] Stored record {record.id} with client_id={CLIENT_ID}")

                # Store full prompt content (compressed) for legal compliance
                if not hash_only and command:
                    content_hash = store_content(
                        content=command,
                        content_type="prompt",
                        record_id=record.id,
                        client_id=CLIENT_ID
                    )
                    if content_hash:
                        logger.info(f"[NEO4J] Stored full prompt content: {content_hash[:16]}...")

            except Exception as e:
                logger.warning(f"[NEO4J] Failed to store record: {e}")

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

        # Store to Neo4j for dashboard visibility
        if is_neo4j_available():
            try:
                store_record(record)
                logger.info(f"[NEO4J] Stored action record {record.id} with client_id={CLIENT_ID}")

                # Store full content for inputs/outputs (for legal compliance)
                if inputs:
                    input_str = json.dumps(inputs, ensure_ascii=False) if isinstance(inputs, dict) else str(inputs)
                    if len(input_str) > 100:  # Only store significant content
                        store_content(input_str, "input", record.id, CLIENT_ID)

                if outputs:
                    output_str = json.dumps(outputs, ensure_ascii=False) if isinstance(outputs, dict) else str(outputs)
                    if len(output_str) > 100:  # Only store significant content
                        store_content(output_str, "output", record.id, CLIENT_ID)

            except Exception as e:
                logger.warning(f"[NEO4J] Failed to store action record: {e}")

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
        session_id = arguments.get("session_id", SESSION_ID)

        if GRAPHRAG_AVAILABLE:
            try:
                risk = analyze_session_risk(session_id)
                return [TextContent(type="text", text=json.dumps(risk, indent=2))]
            except Exception as e:
                return [TextContent(type="text", text=json.dumps({
                    "error": str(e),
                    "session_id": session_id,
                }))]
        else:
            return [TextContent(type="text", text=json.dumps({
                "message": "GraphRAG not available",
                "session_id": session_id,
                "risk_level": "unknown",
            }))]

    elif name == "get_behavior_profile":
        session_id = arguments.get("session_id", SESSION_ID)
        chain = get_or_create_chain(session_id, "claude")

        # Basic behavior profile from chain
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

        if GRAPHRAG_AVAILABLE:
            try:
                risk = get_agent_risk(agent_id)
                return [TextContent(type="text", text=json.dumps(risk, indent=2))]
            except Exception as e:
                return [TextContent(type="text", text=json.dumps({"error": str(e)}))]
        else:
            return [TextContent(type="text", text=json.dumps({
                "agent_id": agent_id,
                "message": "GraphRAG not available",
            }))]

    elif name == "get_user_risk":
        user_id = arguments.get("user_id", "unknown")

        if GRAPHRAG_AVAILABLE:
            try:
                risk = get_user_risk(user_id)
                return [TextContent(type="text", text=json.dumps(risk, indent=2))]
            except Exception as e:
                return [TextContent(type="text", text=json.dumps({"error": str(e)}))]
        else:
            return [TextContent(type="text", text=json.dumps({
                "user_id": user_id,
                "message": "GraphRAG not available",
            }))]

    elif name == "list_agents_risk":
        limit = arguments.get("limit", 20)

        if GRAPHRAG_AVAILABLE:
            try:
                agents = get_all_agents_summary(limit)
                return [TextContent(type="text", text=json.dumps(agents, indent=2))]
            except Exception as e:
                return [TextContent(type="text", text=json.dumps({"error": str(e)}))]
        else:
            return [TextContent(type="text", text=json.dumps({
                "message": "GraphRAG not available",
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

        return [TextContent(
            type="text",
            text=json.dumps({
                "preset": preset,
                "simulation": "Not implemented yet",
                "message": "Policy simulation coming soon",
            }, indent=2)
        )]

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
