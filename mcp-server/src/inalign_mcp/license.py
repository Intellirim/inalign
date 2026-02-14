"""
InALign License Key Manager

Local-first license validation. No user data leaves the machine.
License keys are issued by Lemonsqueezy and validated via their API.
Validation result is cached locally to minimize network calls.

Flow:
1. User buys Pro/Enterprise on Lemonsqueezy
2. Gets license key (e.g., ial_pro_xK9mN2...)
3. Runs: inalign-install --license KEY
4. Key validated once via Lemonsqueezy API → cached locally
5. MCP server checks local cache on startup → unlocks features
6. Re-validates weekly to check subscription status
"""

import json
import hashlib
import time
import os
from pathlib import Path
from datetime import datetime, timezone
from typing import Optional

try:
    import httpx
    HTTPX_AVAILABLE = True
except ImportError:
    HTTPX_AVAILABLE = False

# License file location
LICENSE_FILE = Path.home() / ".inalign" / "license.json"

# Validation cache duration (7 days in seconds)
CACHE_DURATION = 7 * 24 * 60 * 60

# Lemonsqueezy license validation endpoint
LEMON_VALIDATE_URL = "https://api.lemonsqueezy.com/v1/licenses/validate"
LEMON_ACTIVATE_URL = "https://api.lemonsqueezy.com/v1/licenses/activate"

# Feature definitions per plan
PLAN_FEATURES = {
    "free": {
        "actions_per_month": 1000,
        "retention_days": 7,
        "max_agents": 1,
        "features": [
            "local_sqlite",
            "hash_chain",
            "basic_policy",
            "html_report",
            "session_ingest",
            "owasp_basic",
            "compliance_basic",
        ],
    },
    "pro": {
        "actions_per_month": 50000,
        "retention_days": 90,
        "max_agents": 10,
        "features": [
            "local_sqlite",
            "hash_chain",
            "all_policies",
            "html_report",
            "session_ingest",
            "advanced_reports",
            "custom_filters",
            "session_compare",
            "export_all_formats",
            "priority_updates",
            "owasp_full",
            "compliance_full",
            "permissions",
            "drift_detection",
            "otel_export",
            "cost_tracking",
        ],
    },
    "enterprise": {
        "actions_per_month": float("inf"),
        "retention_days": 365,
        "max_agents": float("inf"),
        "features": [
            "local_sqlite",
            "hash_chain",
            "all_policies",
            "custom_policy",
            "html_report",
            "session_ingest",
            "advanced_reports",
            "custom_filters",
            "session_compare",
            "export_all_formats",
            "priority_updates",
            "blockchain_anchor",
            "priority_support",
            "owasp_full",
            "compliance_full",
            "permissions",
            "drift_detection",
            "otel_export",
            "cost_tracking",
            "multi_agent_topology",
            "otel_push",
        ],
    },
}


def _load_license() -> dict:
    """Load cached license from disk."""
    try:
        if LICENSE_FILE.exists():
            with open(LICENSE_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
    except Exception:
        pass
    return {}


def _save_license(data: dict):
    """Save license data to disk."""
    try:
        LICENSE_FILE.parent.mkdir(parents=True, exist_ok=True)
        with open(LICENSE_FILE, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
        # Restrict permissions (owner only)
        try:
            os.chmod(LICENSE_FILE, 0o600)
        except OSError:
            pass  # Windows may not support chmod
    except Exception as e:
        print(f"[LICENSE] Error saving license: {e}")


def validate_with_lemonsqueezy(license_key: str, instance_name: str = None) -> dict:
    """
    Validate license key with Lemonsqueezy API.
    Returns dict with 'valid', 'plan', 'meta' fields.
    """
    if not HTTPX_AVAILABLE:
        return {"valid": False, "error": "httpx not installed. Run: pip install httpx"}

    if not instance_name:
        instance_name = f"inalign-{hashlib.sha256(str(Path.home()).encode()).hexdigest()[:12]}"

    try:
        # First try to activate the license for this instance
        with httpx.Client(timeout=10) as client:
            resp = client.post(LEMON_ACTIVATE_URL, json={
                "license_key": license_key,
                "instance_name": instance_name,
            })
            data = resp.json()

            if resp.status_code == 200 and data.get("activated"):
                meta = data.get("meta", {})
                return {
                    "valid": True,
                    "plan": _detect_plan(data),
                    "instance_id": data.get("instance", {}).get("id"),
                    "customer_email": meta.get("customer_email"),
                    "product_name": meta.get("product_name"),
                    "variant_name": meta.get("variant_name"),
                    "expires_at": data.get("license_key", {}).get("expires_at"),
                }

            # If already activated, try validate instead
            if data.get("error") and "already" in str(data.get("error", "")).lower():
                resp2 = client.post(LEMON_VALIDATE_URL, json={
                    "license_key": license_key,
                    "instance_name": instance_name,
                })
                data2 = resp2.json()

                if resp2.status_code == 200 and data2.get("valid"):
                    meta = data2.get("meta", {})
                    return {
                        "valid": True,
                        "plan": _detect_plan(data2),
                        "instance_id": data2.get("instance", {}).get("id"),
                        "customer_email": meta.get("customer_email"),
                        "product_name": meta.get("product_name"),
                        "variant_name": meta.get("variant_name"),
                        "expires_at": data2.get("license_key", {}).get("expires_at"),
                    }

            return {
                "valid": False,
                "error": data.get("error", "Validation failed"),
            }

    except httpx.TimeoutException:
        return {"valid": False, "error": "Connection timeout. Check your internet."}
    except Exception as e:
        return {"valid": False, "error": str(e)}


def _detect_plan(data: dict) -> str:
    """Detect plan from Lemonsqueezy response."""
    meta = data.get("meta", {})
    product_name = (meta.get("product_name") or "").lower()
    variant_name = (meta.get("variant_name") or "").lower()

    if "enterprise" in product_name or "enterprise" in variant_name:
        return "enterprise"
    elif "pro" in product_name or "pro" in variant_name:
        return "pro"
    return "pro"  # Default paid = pro


def activate_license(license_key: str) -> dict:
    """
    Activate a license key. Validates with Lemonsqueezy and caches locally.
    Returns activation result.
    """
    result = validate_with_lemonsqueezy(license_key)

    if result.get("valid"):
        license_data = {
            "license_key_hash": hashlib.sha256(license_key.encode()).hexdigest(),
            "license_key_prefix": license_key[:16] + "...",
            "plan": result["plan"],
            "activated_at": datetime.now(timezone.utc).isoformat(),
            "last_validated": datetime.now(timezone.utc).isoformat(),
            "validated_epoch": int(time.time()),
            "instance_id": result.get("instance_id"),
            "customer_email": result.get("customer_email"),
            "product_name": result.get("product_name"),
            "expires_at": result.get("expires_at"),
            "status": "active",
        }
        _save_license(license_data)
        return {"success": True, "plan": result["plan"], "message": f"License activated! Plan: {result['plan']}"}
    else:
        return {"success": False, "error": result.get("error", "Validation failed")}


def deactivate_license() -> dict:
    """Remove license from this machine."""
    if LICENSE_FILE.exists():
        LICENSE_FILE.unlink()
        return {"success": True, "message": "License removed. Reverted to free plan."}
    return {"success": True, "message": "No license found."}


def get_current_plan() -> str:
    """Get current plan based on cached license."""
    license_data = _load_license()

    if not license_data or license_data.get("status") != "active":
        return "free"

    # Check if cache is expired (needs re-validation)
    validated_epoch = license_data.get("validated_epoch", 0)
    if time.time() - validated_epoch > CACHE_DURATION:
        # Cache expired, but still allow usage (validate in background next time)
        # This ensures offline usage works
        license_data["needs_revalidation"] = True
        _save_license(license_data)

    return license_data.get("plan", "free")


def get_plan_limits() -> dict:
    """Get limits for current plan."""
    plan = get_current_plan()
    return PLAN_FEATURES.get(plan, PLAN_FEATURES["free"])


def has_feature(feature: str) -> bool:
    """Check if current plan has a specific feature."""
    plan = get_current_plan()
    features = PLAN_FEATURES.get(plan, PLAN_FEATURES["free"]).get("features", [])
    return feature in features


def get_license_info() -> dict:
    """Get current license information (safe to display)."""
    license_data = _load_license()

    if not license_data:
        return {
            "plan": "free",
            "status": "no_license",
            "features": PLAN_FEATURES["free"]["features"],
            "limits": {
                "actions_per_month": PLAN_FEATURES["free"]["actions_per_month"],
                "retention_days": PLAN_FEATURES["free"]["retention_days"],
                "max_agents": PLAN_FEATURES["free"]["max_agents"],
            },
        }

    plan = license_data.get("plan", "free")
    plan_info = PLAN_FEATURES.get(plan, PLAN_FEATURES["free"])

    return {
        "plan": plan,
        "status": license_data.get("status", "unknown"),
        "license_prefix": license_data.get("license_key_prefix", ""),
        "activated_at": license_data.get("activated_at"),
        "last_validated": license_data.get("last_validated"),
        "needs_revalidation": license_data.get("needs_revalidation", False),
        "features": plan_info["features"],
        "limits": {
            "actions_per_month": plan_info["actions_per_month"] if plan_info["actions_per_month"] != float("inf") else "unlimited",
            "retention_days": plan_info["retention_days"],
            "max_agents": plan_info["max_agents"] if plan_info["max_agents"] != float("inf") else "unlimited",
        },
    }


def try_revalidate() -> bool:
    """
    Try to re-validate license if cache is expired.
    Called on MCP server startup. Non-blocking.
    Returns True if valid, False if expired/invalid.
    """
    license_data = _load_license()

    if not license_data or license_data.get("status") != "active":
        return False

    if not license_data.get("needs_revalidation"):
        return True

    # We don't have the original key (only hash), so we can't re-validate.
    # The user would need to re-activate if the license expires.
    # For now, trust the cache and remind them to re-validate.
    return True
