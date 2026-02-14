"""
Agent Permission Matrix

Per-agent tool access control: allow / deny / audit.
Integrates with policy.py presets for default permissions.
Persists to SQLite (~/.inalign/provenance.db).

100% local — no external API calls.
"""

import json
import logging
import sqlite3
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Optional

logger = logging.getLogger("inalign-permissions")

INALIGN_DIR = Path.home() / ".inalign"
DB_PATH = INALIGN_DIR / "provenance.db"


class PermissionLevel(str, Enum):
    ALLOW = "allow"
    DENY = "deny"
    AUDIT = "audit"  # Allow but log every usage


@dataclass
class ToolPermission:
    tool_name: str
    permission: PermissionLevel
    reason: str = ""
    set_by: str = "system"
    set_at: str = ""


@dataclass
class AgentPermissions:
    agent_id: str
    agent_name: str = ""
    default_permission: PermissionLevel = PermissionLevel.ALLOW
    tool_permissions: dict[str, ToolPermission] = field(default_factory=dict)
    created_at: str = ""
    updated_at: str = ""


# Default dangerous tools that should be audited/denied
DANGEROUS_TOOLS = {
    "bash", "shell", "exec", "execute", "run_command",
    "write_file", "delete_file", "rm", "curl", "wget",
}

AUDIT_TOOLS = {
    "file_write", "file_read", "llm_request",
}


def _ensure_table():
    """Create permissions table if it doesn't exist."""
    if not DB_PATH.exists():
        return
    try:
        conn = sqlite3.connect(str(DB_PATH), check_same_thread=False)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS agent_permissions (
                agent_id TEXT NOT NULL,
                tool_name TEXT NOT NULL,
                permission TEXT NOT NULL DEFAULT 'allow',
                reason TEXT DEFAULT '',
                set_by TEXT DEFAULT 'system',
                set_at TEXT NOT NULL,
                PRIMARY KEY (agent_id, tool_name)
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS agent_defaults (
                agent_id TEXT PRIMARY KEY,
                agent_name TEXT DEFAULT '',
                default_permission TEXT NOT NULL DEFAULT 'allow',
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
        """)
        conn.commit()
        conn.close()
    except Exception as e:
        logger.warning(f"[PERMISSIONS] Table creation failed: {e}")


def get_permission_matrix(agent_id: str = None) -> dict[str, Any]:
    """
    Get permission matrix for an agent or all agents.

    Returns dict with agent_id → tool permissions mapping.
    """
    _ensure_table()
    if not DB_PATH.exists():
        return {"agents": {}, "message": "No permissions configured (using defaults)"}

    try:
        conn = sqlite3.connect(str(DB_PATH), check_same_thread=False)
        conn.row_factory = sqlite3.Row

        result = {"agents": {}}

        if agent_id:
            # Get specific agent
            default_row = conn.execute(
                "SELECT * FROM agent_defaults WHERE agent_id=?", (agent_id,)
            ).fetchone()

            perm_rows = conn.execute(
                "SELECT * FROM agent_permissions WHERE agent_id=?", (agent_id,)
            ).fetchall()

            result["agents"][agent_id] = {
                "agent_name": default_row["agent_name"] if default_row else "",
                "default_permission": default_row["default_permission"] if default_row else "allow",
                "tools": {
                    r["tool_name"]: {
                        "permission": r["permission"],
                        "reason": r["reason"],
                        "set_by": r["set_by"],
                    }
                    for r in perm_rows
                },
            }
        else:
            # Get all agents
            default_rows = conn.execute("SELECT * FROM agent_defaults").fetchall()
            for dr in default_rows:
                aid = dr["agent_id"]
                perm_rows = conn.execute(
                    "SELECT * FROM agent_permissions WHERE agent_id=?", (aid,)
                ).fetchall()
                result["agents"][aid] = {
                    "agent_name": dr["agent_name"],
                    "default_permission": dr["default_permission"],
                    "tools": {
                        r["tool_name"]: {
                            "permission": r["permission"],
                            "reason": r["reason"],
                            "set_by": r["set_by"],
                        }
                        for r in perm_rows
                    },
                }

        conn.close()
        return result

    except Exception as e:
        logger.warning(f"[PERMISSIONS] Read failed: {e}")
        return {"agents": {}, "error": str(e)}


def set_agent_permissions(
    agent_id: str,
    permissions: dict[str, str],
    default_permission: str = None,
    agent_name: str = "",
) -> dict[str, Any]:
    """
    Set permissions for an agent.

    Args:
        agent_id: Agent identifier
        permissions: Dict of tool_name → "allow"/"deny"/"audit"
        default_permission: Default permission for unlisted tools
        agent_name: Human-readable agent name

    Returns:
        Result dict with updated permissions
    """
    _ensure_table()
    if not DB_PATH.exists():
        INALIGN_DIR.mkdir(parents=True, exist_ok=True)

    now = datetime.now(timezone.utc).isoformat()

    try:
        conn = sqlite3.connect(str(DB_PATH), check_same_thread=False)

        # Set or update default
        dp = default_permission or "allow"
        conn.execute(
            """INSERT INTO agent_defaults (agent_id, agent_name, default_permission, created_at, updated_at)
               VALUES (?, ?, ?, ?, ?)
               ON CONFLICT(agent_id) DO UPDATE SET
                   agent_name=COALESCE(NULLIF(?, ''), agent_name),
                   default_permission=?, updated_at=?""",
            (agent_id, agent_name, dp, now, now, agent_name, dp, now),
        )

        # Set tool permissions
        updated = []
        for tool_name, perm in permissions.items():
            if perm not in ("allow", "deny", "audit"):
                continue
            conn.execute(
                """INSERT INTO agent_permissions (agent_id, tool_name, permission, set_by, set_at)
                   VALUES (?, ?, ?, 'user', ?)
                   ON CONFLICT(agent_id, tool_name) DO UPDATE SET
                       permission=?, set_by='user', set_at=?""",
                (agent_id, tool_name, perm, now, perm, now),
            )
            updated.append({"tool": tool_name, "permission": perm})

        conn.commit()
        conn.close()

        return {
            "success": True,
            "agent_id": agent_id,
            "default_permission": dp,
            "updated": updated,
            "message": f"Updated {len(updated)} tool permission(s) for {agent_id}",
        }

    except Exception as e:
        logger.warning(f"[PERMISSIONS] Write failed: {e}")
        return {"success": False, "error": str(e)}


def check_permission(agent_id: str, tool_name: str) -> dict[str, Any]:
    """
    Check if an agent has permission to use a tool.

    Returns:
        Dict with 'allowed' bool, 'permission' level, 'audit' bool
    """
    _ensure_table()
    if not DB_PATH.exists():
        return {"allowed": True, "permission": "allow", "audit": False, "source": "default"}

    try:
        conn = sqlite3.connect(str(DB_PATH), check_same_thread=False)
        conn.row_factory = sqlite3.Row

        # Check specific tool permission
        row = conn.execute(
            "SELECT * FROM agent_permissions WHERE agent_id=? AND tool_name=?",
            (agent_id, tool_name),
        ).fetchone()

        if row:
            perm = row["permission"]
            conn.close()
            return {
                "allowed": perm != "deny",
                "permission": perm,
                "audit": perm == "audit",
                "source": "explicit",
            }

        # Check default
        default_row = conn.execute(
            "SELECT default_permission FROM agent_defaults WHERE agent_id=?",
            (agent_id,),
        ).fetchone()

        conn.close()

        if default_row:
            dp = default_row["default_permission"]
            return {
                "allowed": dp != "deny",
                "permission": dp,
                "audit": dp == "audit",
                "source": "agent_default",
            }

        return {"allowed": True, "permission": "allow", "audit": False, "source": "system_default"}

    except Exception as e:
        logger.warning(f"[PERMISSIONS] Check failed: {e}")
        return {"allowed": True, "permission": "allow", "audit": False, "source": "error_fallback"}


def apply_policy_defaults(agent_id: str, policy_preset: str = "BALANCED") -> dict[str, Any]:
    """
    Apply default permissions based on policy preset.

    STRICT_ENTERPRISE: deny dangerous, audit everything else
    BALANCED: audit dangerous, allow rest
    DEV_SANDBOX: allow everything
    """
    if policy_preset == "STRICT_ENTERPRISE":
        perms = {t: "deny" for t in DANGEROUS_TOOLS}
        perms.update({t: "audit" for t in AUDIT_TOOLS})
        default = "audit"
    elif policy_preset == "BALANCED":
        perms = {t: "audit" for t in DANGEROUS_TOOLS}
        default = "allow"
    else:  # DEV_SANDBOX
        perms = {}
        default = "allow"

    return set_agent_permissions(
        agent_id=agent_id,
        permissions=perms,
        default_permission=default,
        agent_name=f"auto-{policy_preset.lower()}",
    )
