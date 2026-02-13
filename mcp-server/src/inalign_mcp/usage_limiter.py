"""
InALign Usage Limiter

Tracks and enforces usage limits per client based on their plan.
Persists usage data to ~/.inalign/usage.json to survive server restarts.
"""

import os
import json
import threading
from datetime import datetime, timezone
from pathlib import Path
from dataclasses import dataclass

# Import plan limits from license module
try:
    from .license import PLAN_FEATURES, get_current_plan
    PLAN_LIMITS = {
        plan: {
            "actions_per_month": info["actions_per_month"],
            "retention_days": info["retention_days"],
            "max_agents": info["max_agents"],
        }
        for plan, info in PLAN_FEATURES.items()
    }
    LICENSE_AVAILABLE = True
except ImportError:
    LICENSE_AVAILABLE = False
    PLAN_LIMITS = {
        "free": {
            "actions_per_month": 1000,
            "retention_days": 7,
            "max_agents": 1,
        },
        "pro": {
            "actions_per_month": 50000,
            "retention_days": 90,
            "max_agents": 10,
        },
        "enterprise": {
            "actions_per_month": float('inf'),
            "retention_days": 365,
            "max_agents": float('inf'),
        }
    }

# Persistent usage file
_USAGE_FILE = str(Path.home() / ".inalign" / "usage.json")
_save_lock = threading.Lock()
_save_counter = 0  # Save every N increments to reduce disk I/O
_SAVE_INTERVAL = 10  # Save to disk every 10 actions


@dataclass
class UsageStatus:
    allowed: bool
    current_count: int
    limit: int
    remaining: int
    plan: str
    message: str


def get_current_month() -> str:
    """Get current month as YYYY-MM string."""
    return datetime.now(timezone.utc).strftime("%Y-%m")


def _load_usage() -> dict:
    """Load usage data from disk."""
    try:
        if os.path.exists(_USAGE_FILE):
            with open(_USAGE_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
                # Convert inf back from string
                for cid, info in data.items():
                    if info.get("plan") == "enterprise":
                        pass  # limits handled by PLAN_LIMITS
                return data
    except Exception as e:
        print(f"[USAGE] Error loading {_USAGE_FILE}: {e}")
    return {}


def _save_usage():
    """Save usage data to disk (thread-safe)."""
    with _save_lock:
        try:
            os.makedirs(os.path.dirname(_USAGE_FILE), exist_ok=True)
            with open(_USAGE_FILE, "w", encoding="utf-8") as f:
                json.dump(USAGE_CACHE, f, indent=2)
        except Exception as e:
            print(f"[USAGE] Error saving {_USAGE_FILE}: {e}")


def _maybe_save():
    """Save periodically to reduce disk writes."""
    global _save_counter
    _save_counter += 1
    if _save_counter >= _SAVE_INTERVAL:
        _save_counter = 0
        _save_usage()


# Load persisted usage on module import
USAGE_CACHE = _load_usage()


def get_usage(client_id: str) -> dict:
    """Get current usage for a client."""
    if client_id not in USAGE_CACHE:
        USAGE_CACHE[client_id] = {
            "month": get_current_month(),
            "count": 0,
            "plan": "starter"
        }

    # Reset if new month
    current_month = get_current_month()
    if USAGE_CACHE[client_id]["month"] != current_month:
        USAGE_CACHE[client_id]["month"] = current_month
        USAGE_CACHE[client_id]["count"] = 0
        _save_usage()  # Save on month reset

    return USAGE_CACHE[client_id]


def set_plan(client_id: str, plan: str):
    """Set the plan for a client."""
    usage = get_usage(client_id)
    if usage["plan"] != plan:
        usage["plan"] = plan
        _save_usage()


def check_and_increment(client_id: str, plan: str = None) -> UsageStatus:
    """
    Check if client can perform action and increment counter.
    Returns UsageStatus with allowed=True/False.
    """
    usage = get_usage(client_id)

    # Update plan if provided
    if plan and usage.get("plan") != plan:
        usage["plan"] = plan

    # Use license-based plan if available
    if LICENSE_AVAILABLE:
        current_plan = get_current_plan()
    else:
        current_plan = usage.get("plan", "free")
    limits = PLAN_LIMITS.get(current_plan, PLAN_LIMITS["free"])
    limit = limits["actions_per_month"]

    current_count = usage["count"]

    # Check if over limit
    if current_count >= limit:
        return UsageStatus(
            allowed=False,
            current_count=current_count,
            limit=int(limit) if limit != float('inf') else -1,
            remaining=0,
            plan=current_plan,
            message=f"Monthly limit reached ({int(limit)} actions). Upgrade to Pro for more."
        )

    # Increment and allow
    usage["count"] = current_count + 1
    remaining = int(limit - usage["count"]) if limit != float('inf') else -1

    # Periodic save to disk
    _maybe_save()

    return UsageStatus(
        allowed=True,
        current_count=usage["count"],
        limit=int(limit) if limit != float('inf') else -1,
        remaining=remaining,
        plan=current_plan,
        message="OK"
    )


def get_usage_stats(client_id: str) -> dict:
    """Get usage statistics for a client."""
    usage = get_usage(client_id)
    plan = usage.get("plan", "starter")
    limits = PLAN_LIMITS.get(plan, PLAN_LIMITS["free"])
    limit = limits["actions_per_month"]

    return {
        "client_id": client_id,
        "plan": plan,
        "month": usage["month"],
        "actions_used": usage["count"],
        "actions_limit": int(limit) if limit != float('inf') else "unlimited",
        "actions_remaining": int(limit - usage["count"]) if limit != float('inf') else "unlimited",
        "retention_days": limits["retention_days"],
        "max_agents": int(limits["max_agents"]) if limits["max_agents"] != float('inf') else "unlimited",
    }


# Integration with payments.py - sync customer plans
def sync_from_payments():
    """Sync plans from payments module."""
    try:
        from .payments import CUSTOMERS
        for email, data in CUSTOMERS.items():
            client_id = data.get("client_id")
            plan = data.get("plan", "starter")
            if client_id:
                set_plan(client_id, plan)
    except ImportError:
        pass
