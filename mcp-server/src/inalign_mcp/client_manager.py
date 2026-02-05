"""
Client & API Key Management System.

Provides:
- API Key generation and validation
- Client registration and tracking
- Usage metering per client
- Session management
"""

import os
import json
import secrets
import hashlib
import logging
from datetime import datetime, timezone, timedelta
from typing import Optional, Any
from dataclasses import dataclass, field, asdict
from enum import Enum
from pathlib import Path

logger = logging.getLogger("inalign-client")


class PlanType(str, Enum):
    """Subscription plans."""
    FREE = "free"
    PRO = "pro"
    ENTERPRISE = "enterprise"


@dataclass
class UsageStats:
    """Usage statistics for a client."""
    scan_count: int = 0
    action_count: int = 0
    session_count: int = 0
    blocked_threats: int = 0
    pii_detected: int = 0
    last_activity: Optional[str] = None

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class Client:
    """Registered client."""
    client_id: str
    name: str
    email: str
    plan: PlanType = PlanType.FREE
    created_at: str = ""
    api_key_hash: str = ""  # Hashed API key
    api_key_prefix: str = ""  # First 8 chars for display

    # Limits based on plan
    monthly_scan_limit: int = 1000
    session_retention_days: int = 7

    # Usage tracking
    usage: UsageStats = field(default_factory=UsageStats)

    # Settings
    policy_preset: str = "BALANCED"
    webhook_url: Optional[str] = None

    # Status
    active: bool = True

    def __post_init__(self):
        if not self.created_at:
            self.created_at = datetime.now(timezone.utc).isoformat()

    def to_dict(self) -> dict:
        return {
            "client_id": self.client_id,
            "name": self.name,
            "email": self.email,
            "plan": self.plan.value,
            "created_at": self.created_at,
            "api_key_prefix": self.api_key_prefix,
            "monthly_scan_limit": self.monthly_scan_limit,
            "session_retention_days": self.session_retention_days,
            "usage": self.usage.to_dict(),
            "policy_preset": self.policy_preset,
            "active": self.active,
        }


@dataclass
class Session:
    """Client session."""
    session_id: str
    client_id: str
    agent_id: str = "unknown"
    agent_name: str = "Unknown Agent"
    created_at: str = ""
    last_activity: str = ""
    record_count: int = 0
    threats_blocked: int = 0
    status: str = "active"  # active, completed, expired

    def __post_init__(self):
        if not self.created_at:
            self.created_at = datetime.now(timezone.utc).isoformat()
        if not self.last_activity:
            self.last_activity = self.created_at

    def to_dict(self) -> dict:
        return asdict(self)


class ClientManager:
    """
    Manages clients, API keys, and usage tracking.

    Storage: JSON file (can be replaced with database)
    """

    PLAN_LIMITS = {
        PlanType.FREE: {
            "monthly_scan_limit": 1000,
            "session_retention_days": 7,
            "features": ["basic_scan", "pii_detection"],
        },
        PlanType.PRO: {
            "monthly_scan_limit": 50000,
            "session_retention_days": 30,
            "features": ["basic_scan", "pii_detection", "ml_scan", "audit_export"],
        },
        PlanType.ENTERPRISE: {
            "monthly_scan_limit": -1,  # Unlimited
            "session_retention_days": 365,
            "features": ["basic_scan", "pii_detection", "ml_scan", "audit_export",
                        "graph_visualization", "blockchain_anchor", "custom_policy"],
        },
    }

    def __init__(self, storage_path: str = None):
        """Initialize client manager with storage path."""
        self.storage_path = storage_path or os.getenv(
            "INALIGN_CLIENT_DB",
            str(Path.home() / ".inalign" / "clients.json")
        )
        self._clients: dict[str, Client] = {}
        self._sessions: dict[str, Session] = {}
        self._api_key_map: dict[str, str] = {}  # key_hash -> client_id
        self._load()

    def _load(self):
        """Load clients from storage."""
        try:
            if os.path.exists(self.storage_path):
                with open(self.storage_path, "r") as f:
                    data = json.load(f)
                    for cid, cdata in data.get("clients", {}).items():
                        cdata["plan"] = PlanType(cdata["plan"])
                        cdata["usage"] = UsageStats(**cdata.get("usage", {}))
                        self._clients[cid] = Client(**cdata)
                        if cdata.get("api_key_hash"):
                            self._api_key_map[cdata["api_key_hash"]] = cid
                    for sid, sdata in data.get("sessions", {}).items():
                        self._sessions[sid] = Session(**sdata)
                logger.info(f"Loaded {len(self._clients)} clients, {len(self._sessions)} sessions")
        except Exception as e:
            logger.warning(f"Failed to load client data: {e}")

    def _save(self):
        """Save clients to storage."""
        try:
            os.makedirs(os.path.dirname(self.storage_path), exist_ok=True)
            data = {
                "clients": {cid: {**c.to_dict(), "api_key_hash": c.api_key_hash}
                           for cid, c in self._clients.items()},
                "sessions": {sid: s.to_dict() for sid, s in self._sessions.items()},
            }
            with open(self.storage_path, "w") as f:
                json.dump(data, f, indent=2)
        except Exception as e:
            logger.error(f"Failed to save client data: {e}")

    # ============================================
    # Client Management
    # ============================================

    def register_client(
        self,
        name: str,
        email: str,
        plan: PlanType = PlanType.FREE,
    ) -> tuple[Client, str]:
        """
        Register a new client and generate API key.

        Returns (Client, api_key)
        """
        import uuid

        client_id = f"client-{uuid.uuid4().hex[:12]}"
        api_key = f"ial_{secrets.token_urlsafe(32)}"
        api_key_hash = hashlib.sha256(api_key.encode()).hexdigest()

        limits = self.PLAN_LIMITS[plan]

        client = Client(
            client_id=client_id,
            name=name,
            email=email,
            plan=plan,
            api_key_hash=api_key_hash,
            api_key_prefix=api_key[:12],
            monthly_scan_limit=limits["monthly_scan_limit"],
            session_retention_days=limits["session_retention_days"],
        )

        self._clients[client_id] = client
        self._api_key_map[api_key_hash] = client_id
        self._save()

        logger.info(f"Registered client: {name} ({email}) - {plan.value}")
        return client, api_key

    def get_client(self, client_id: str) -> Optional[Client]:
        """Get client by ID."""
        return self._clients.get(client_id)

    def get_client_by_api_key(self, api_key: str) -> Optional[Client]:
        """Get client by API key."""
        key_hash = hashlib.sha256(api_key.encode()).hexdigest()
        client_id = self._api_key_map.get(key_hash)
        if client_id:
            return self._clients.get(client_id)
        return None

    def validate_api_key(self, api_key: str) -> tuple[bool, Optional[Client], str]:
        """
        Validate API key and check limits.

        Returns (valid, client, error_message)
        """
        client = self.get_client_by_api_key(api_key)

        if not client:
            return False, None, "Invalid API key"

        if not client.active:
            return False, client, "Client account is inactive"

        # Check monthly limit
        if client.monthly_scan_limit > 0:
            if client.usage.scan_count >= client.monthly_scan_limit:
                return False, client, "Monthly scan limit exceeded"

        return True, client, ""

    def update_plan(self, client_id: str, plan: PlanType) -> bool:
        """Update client's subscription plan."""
        client = self._clients.get(client_id)
        if not client:
            return False

        limits = self.PLAN_LIMITS[plan]
        client.plan = plan
        client.monthly_scan_limit = limits["monthly_scan_limit"]
        client.session_retention_days = limits["session_retention_days"]
        self._save()
        return True

    def regenerate_api_key(self, client_id: str) -> Optional[str]:
        """Regenerate API key for a client."""
        client = self._clients.get(client_id)
        if not client:
            return None

        # Remove old key mapping
        if client.api_key_hash in self._api_key_map:
            del self._api_key_map[client.api_key_hash]

        # Generate new key
        api_key = f"ial_{secrets.token_urlsafe(32)}"
        api_key_hash = hashlib.sha256(api_key.encode()).hexdigest()

        client.api_key_hash = api_key_hash
        client.api_key_prefix = api_key[:12]
        self._api_key_map[api_key_hash] = client_id
        self._save()

        return api_key

    def list_clients(self) -> list[dict]:
        """List all clients."""
        return [c.to_dict() for c in self._clients.values()]

    # ============================================
    # Session Management
    # ============================================

    def create_session(
        self,
        client_id: str,
        session_id: str = None,
        agent_id: str = "unknown",
        agent_name: str = "Unknown Agent",
    ) -> Optional[Session]:
        """Create a new session for a client."""
        client = self._clients.get(client_id)
        if not client:
            return None

        import uuid
        if not session_id:
            session_id = f"sess-{uuid.uuid4().hex[:12]}"

        session = Session(
            session_id=session_id,
            client_id=client_id,
            agent_id=agent_id,
            agent_name=agent_name,
        )

        self._sessions[session_id] = session
        client.usage.session_count += 1
        self._save()

        return session

    def get_session(self, session_id: str) -> Optional[Session]:
        """Get session by ID."""
        return self._sessions.get(session_id)

    def get_client_sessions(self, client_id: str) -> list[Session]:
        """Get all sessions for a client."""
        return [s for s in self._sessions.values() if s.client_id == client_id]

    def update_session_activity(
        self,
        session_id: str,
        record_count_delta: int = 0,
        threats_blocked_delta: int = 0,
    ):
        """Update session activity stats."""
        session = self._sessions.get(session_id)
        if session:
            session.last_activity = datetime.now(timezone.utc).isoformat()
            session.record_count += record_count_delta
            session.threats_blocked += threats_blocked_delta

            # Update client usage
            client = self._clients.get(session.client_id)
            if client:
                client.usage.action_count += record_count_delta
                client.usage.blocked_threats += threats_blocked_delta
                client.usage.last_activity = session.last_activity

            self._save()

    # ============================================
    # Usage Tracking
    # ============================================

    def record_scan(self, client_id: str, blocked: bool = False, pii_found: bool = False):
        """Record a scan for usage tracking."""
        client = self._clients.get(client_id)
        if client:
            client.usage.scan_count += 1
            if blocked:
                client.usage.blocked_threats += 1
            if pii_found:
                client.usage.pii_detected += 1
            client.usage.last_activity = datetime.now(timezone.utc).isoformat()
            self._save()

    def get_usage_stats(self, client_id: str) -> Optional[dict]:
        """Get usage statistics for a client."""
        client = self._clients.get(client_id)
        if client:
            return {
                **client.usage.to_dict(),
                "plan": client.plan.value,
                "monthly_limit": client.monthly_scan_limit,
                "remaining": max(0, client.monthly_scan_limit - client.usage.scan_count)
                            if client.monthly_scan_limit > 0 else "unlimited",
            }
        return None

    def reset_monthly_usage(self):
        """Reset monthly usage counters (call on billing cycle)."""
        for client in self._clients.values():
            client.usage.scan_count = 0
        self._save()
        logger.info(f"Reset monthly usage for {len(self._clients)} clients")

    # ============================================
    # Cleanup
    # ============================================

    def cleanup_expired_sessions(self) -> int:
        """Remove expired sessions based on retention policy."""
        now = datetime.now(timezone.utc)
        removed = 0

        for session_id, session in list(self._sessions.items()):
            client = self._clients.get(session.client_id)
            if not client:
                del self._sessions[session_id]
                removed += 1
                continue

            last_activity = datetime.fromisoformat(session.last_activity.replace("Z", "+00:00"))
            age = now - last_activity

            if age.days > client.session_retention_days:
                del self._sessions[session_id]
                removed += 1

        if removed:
            self._save()
            logger.info(f"Cleaned up {removed} expired sessions")

        return removed


# ============================================
# Singleton Instance
# ============================================

_manager: Optional[ClientManager] = None


def get_client_manager() -> ClientManager:
    """Get or create the client manager singleton."""
    global _manager
    if _manager is None:
        _manager = ClientManager()
    return _manager


# ============================================
# Convenience Functions
# ============================================

def register_client(name: str, email: str, plan: str = "free") -> tuple[dict, str]:
    """Register a new client. Returns (client_info, api_key)."""
    manager = get_client_manager()
    plan_type = PlanType(plan)
    client, api_key = manager.register_client(name, email, plan_type)
    return client.to_dict(), api_key


def validate_request(api_key: str) -> tuple[bool, Optional[str], str]:
    """Validate an API request. Returns (valid, client_id, error)."""
    manager = get_client_manager()
    valid, client, error = manager.validate_api_key(api_key)
    return valid, client.client_id if client else None, error


def track_scan(api_key: str, blocked: bool = False, pii_found: bool = False):
    """Track a scan for the client."""
    manager = get_client_manager()
    client = manager.get_client_by_api_key(api_key)
    if client:
        manager.record_scan(client.client_id, blocked, pii_found)


# ============================================
# CLI
# ============================================

def main():
    """CLI for client management."""
    import sys

    if len(sys.argv) < 2:
        print("""
InALign Client Manager

Usage:
    inalign-clients register <name> <email> [plan]   Register new client
    inalign-clients list                             List all clients
    inalign-clients usage <client_id>                Show usage stats
    inalign-clients upgrade <client_id> <plan>       Upgrade plan
    inalign-clients regenerate <client_id>           Regenerate API key
        """)
        sys.exit(0)

    manager = get_client_manager()
    command = sys.argv[1]

    if command == "register":
        if len(sys.argv) < 4:
            print("Usage: inalign-clients register <name> <email> [plan]")
            sys.exit(1)
        name = sys.argv[2]
        email = sys.argv[3]
        plan = PlanType(sys.argv[4]) if len(sys.argv) > 4 else PlanType.FREE

        client, api_key = manager.register_client(name, email, plan)
        print(f"\nClient registered successfully!")
        print(f"  Client ID: {client.client_id}")
        print(f"  Name: {client.name}")
        print(f"  Plan: {client.plan.value}")
        print(f"\n  API Key: {api_key}")
        print(f"\n  (Save this key - it won't be shown again)")

    elif command == "list":
        clients = manager.list_clients()
        print(f"\nRegistered Clients ({len(clients)}):")
        print("-" * 60)
        for c in clients:
            print(f"  {c['client_id']}: {c['name']} ({c['email']})")
            print(f"    Plan: {c['plan']}, Scans: {c['usage']['scan_count']}/{c['monthly_scan_limit']}")

    elif command == "usage":
        if len(sys.argv) < 3:
            print("Usage: inalign-clients usage <client_id>")
            sys.exit(1)
        client_id = sys.argv[2]
        stats = manager.get_usage_stats(client_id)
        if stats:
            print(f"\nUsage for {client_id}:")
            print(json.dumps(stats, indent=2))
        else:
            print(f"Client not found: {client_id}")

    elif command == "upgrade":
        if len(sys.argv) < 4:
            print("Usage: inalign-clients upgrade <client_id> <plan>")
            sys.exit(1)
        client_id = sys.argv[2]
        plan = PlanType(sys.argv[3])
        if manager.update_plan(client_id, plan):
            print(f"Upgraded {client_id} to {plan.value}")
        else:
            print(f"Client not found: {client_id}")

    elif command == "regenerate":
        if len(sys.argv) < 3:
            print("Usage: inalign-clients regenerate <client_id>")
            sys.exit(1)
        client_id = sys.argv[2]
        new_key = manager.regenerate_api_key(client_id)
        if new_key:
            print(f"\nNew API Key: {new_key}")
            print("(Save this key - it won't be shown again)")
        else:
            print(f"Client not found: {client_id}")

    else:
        print(f"Unknown command: {command}")
        sys.exit(1)


if __name__ == "__main__":
    main()
