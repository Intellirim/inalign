"""
InALign Payment System - Lemonsqueezy Integration

Handles:
- Lemonsqueezy Checkout for Pro ($29/mo) and Enterprise ($99/mo) plans
- Webhook for payment confirmation (HMAC-SHA256 verified)
- Auto API key generation after payment
- Plan upgrade/downgrade on subscription events
"""

import os
import hmac
import secrets
import hashlib
import json
import threading
from pathlib import Path
from datetime import datetime, timezone
from typing import Optional, Tuple

try:
    import bcrypt
except ImportError:
    bcrypt = None

try:
    from fastapi import APIRouter, Request, HTTPException, Header
    from fastapi.responses import RedirectResponse, JSONResponse
    FASTAPI_AVAILABLE = True
except ImportError:
    FASTAPI_AVAILABLE = False

# Lemonsqueezy config
LEMONSQUEEZY_WEBHOOK_SECRET = os.getenv("LEMONSQUEEZY_WEBHOOK_SECRET", "")
LEMONSQUEEZY_STORE_ID = os.getenv("LEMONSQUEEZY_STORE_ID", "")
BASE_URL = os.getenv("BASE_URL", "http://localhost:8080")

# Checkout URLs (set after creating products in Lemonsqueezy dashboard)
CHECKOUT_URLS = {
    "pro": os.getenv("LEMONSQUEEZY_PRO_URL", ""),
    "enterprise": os.getenv("LEMONSQUEEZY_ENTERPRISE_URL", ""),
}

# Map Lemonsqueezy variant/product IDs to plans
# Set these after creating products: LEMONSQUEEZY_PRO_VARIANT_ID, LEMONSQUEEZY_ENTERPRISE_VARIANT_ID
VARIANT_TO_PLAN = {}
_pro_vid = os.getenv("LEMONSQUEEZY_PRO_VARIANT_ID", "")
_ent_vid = os.getenv("LEMONSQUEEZY_ENTERPRISE_VARIANT_ID", "")
if _pro_vid:
    VARIANT_TO_PLAN[_pro_vid] = "pro"
if _ent_vid:
    VARIANT_TO_PLAN[_ent_vid] = "enterprise"

if FASTAPI_AVAILABLE:
    router = APIRouter()
else:
    router = None

# ============================================
# Persistent Customer Storage (JSON file)
# ============================================

_CUSTOMERS_FILE = os.getenv(
    "CUSTOMERS_FILE",
    str(Path(__file__).parent.parent.parent / "customers.json")
)
_save_lock = threading.Lock()

# Default test user (hashed)
_DEFAULT_CUSTOMERS = {
    "test@inalign.ai": {
        "api_key_hash": "cf75cd3fa6c7b6c0c7c1b7652fa86ef34fc976578b22b517be0e115214c6502c",
        "api_key_prefix": "ial_EBSo",
        "client_id": "ial_EBSooXgF",
        "plan": "starter",
        "created_at": "2026-02-05"
    }
}


def _hash_api_key(api_key: str) -> str:
    """Hash an API key with SHA-256."""
    return hashlib.sha256(api_key.encode()).hexdigest()


def hash_password(password: str) -> str:
    """Hash password with bcrypt."""
    if bcrypt is None:
        return hashlib.sha256(password.encode()).hexdigest()
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")


def verify_password(password: str, hashed: str) -> bool:
    """Verify password against bcrypt hash."""
    if bcrypt is None:
        return hmac.compare_digest(hashlib.sha256(password.encode()).hexdigest(), hashed)
    try:
        return bcrypt.checkpw(password.encode("utf-8"), hashed.encode("utf-8"))
    except (ValueError, TypeError):
        return False


def find_customer_by_email(email: str) -> Optional[dict]:
    """Find customer by email. Returns customer data or None."""
    return CUSTOMERS.get(email)


def _verify_key(api_key: str, stored_hash: str) -> bool:
    """Constant-time comparison of API key against stored hash."""
    return hmac.compare_digest(_hash_api_key(api_key), stored_hash)


def find_customer_by_key(api_key: str) -> Tuple[Optional[str], Optional[dict]]:
    """Find customer by API key (hash comparison). Returns (email, data) or (None, None)."""
    key_hash = _hash_api_key(api_key)
    for email, data in CUSTOMERS.items():
        stored = data.get("api_key_hash", "")
        if stored and hmac.compare_digest(key_hash, stored):
            return email, data
    return None, None


def _migrate_plaintext_keys(data: dict) -> bool:
    """Migrate any plaintext api_key fields to api_key_hash. Returns True if migrated."""
    migrated = False
    for email, info in data.items():
        if "api_key" in info and "api_key_hash" not in info:
            plain_key = info["api_key"]
            info["api_key_hash"] = _hash_api_key(plain_key)
            info["api_key_prefix"] = plain_key[:8]
            if not info.get("client_id"):
                info["client_id"] = get_client_id(plain_key)
            del info["api_key"]
            migrated = True
            print(f"[CUSTOMERS] Migrated {email} to hashed key")
    return migrated


def _load_customers() -> dict:
    """Load customers from JSON file, falling back to defaults."""
    try:
        if os.path.exists(_CUSTOMERS_FILE):
            with open(_CUSTOMERS_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
                print(f"[CUSTOMERS] Loaded {len(data)} customers from {_CUSTOMERS_FILE}")
                for email, info in _DEFAULT_CUSTOMERS.items():
                    if email not in data:
                        data[email] = dict(info)
                if _migrate_plaintext_keys(data):
                    _save_customers_data(data)
                return data
    except Exception as e:
        print(f"[CUSTOMERS] Error loading {_CUSTOMERS_FILE}: {e}")

    print(f"[CUSTOMERS] Using defaults ({len(_DEFAULT_CUSTOMERS)} customers)")
    return {k: dict(v) for k, v in _DEFAULT_CUSTOMERS.items()}


def _save_customers_data(data: dict):
    """Save customer data to JSON file (no lock, for internal use during load)."""
    try:
        os.makedirs(os.path.dirname(_CUSTOMERS_FILE) or ".", exist_ok=True)
        with open(_CUSTOMERS_FILE, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        try:
            os.chmod(_CUSTOMERS_FILE, 0o600)
        except (OSError, AttributeError):
            pass
        print(f"[CUSTOMERS] Saved {len(data)} customers to {_CUSTOMERS_FILE}")
    except Exception as e:
        print(f"[CUSTOMERS] Error saving: {e}")


def _save_customers():
    """Save customers to JSON file (thread-safe)."""
    with _save_lock:
        _save_customers_data(CUSTOMERS)


CUSTOMERS = _load_customers()

# Pricing
PLANS = {
    "starter": {
        "name": "Starter",
        "price": 0,
        "actions_per_month": 1000,
        "retention_days": 7,
        "agents": 1,
        "features": ["local_sqlite", "hash_chain", "policy_engine", "html_report", "session_ingest"],
    },
    "pro": {
        "name": "Pro",
        "price": 2900,  # $29/mo
        "actions_per_month": 50000,
        "retention_days": 30,
        "agents": 10,
        "features": ["local_sqlite", "hash_chain", "policy_engine", "html_report", "session_ingest",
                     "cloud_neo4j", "web_dashboard", "team_management", "auto_collection", "api_access"],
    },
    "enterprise": {
        "name": "Enterprise",
        "price": 9900,  # $99/mo
        "actions_per_month": None,  # Unlimited
        "retention_days": 365,
        "agents": None,  # Unlimited
        "features": ["local_sqlite", "hash_chain", "policy_engine", "html_report", "session_ingest",
                     "cloud_neo4j", "web_dashboard", "team_management", "auto_collection", "api_access",
                     "blockchain_anchor", "custom_policy", "priority_support", "sla"],
    }
}


def generate_api_key() -> Tuple[str, str, str]:
    """Generate a secure API key. Returns (plaintext_key, key_hash, key_prefix)."""
    key = f"ial_{secrets.token_urlsafe(32)}"
    key_hash = _hash_api_key(key)
    key_prefix = key[:8]
    return key, key_hash, key_prefix


def get_client_id(api_key: str) -> str:
    """Derive client_id from API key."""
    if api_key.startswith("ial_"):
        return api_key[:12]
    return hashlib.sha256(api_key.encode()).hexdigest()[:12]


def sync_usage_limiter(client_id: str, plan: str):
    """Sync plan to usage limiter."""
    try:
        from .usage_limiter import set_plan
        set_plan(client_id, plan)
    except ImportError:
        pass


def has_feature(email_or_plan: str, feature: str) -> bool:
    """Check if a customer/plan has access to a feature."""
    plan_name = email_or_plan
    if "@" in email_or_plan:
        customer = CUSTOMERS.get(email_or_plan)
        if not customer:
            plan_name = "starter"
        else:
            plan_name = customer.get("plan", "starter")

    plan = PLANS.get(plan_name, PLANS["starter"])
    return feature in plan.get("features", [])


def get_checkout_url(plan: str, email: str = "") -> str:
    """Get Lemonsqueezy checkout URL for a plan."""
    url = CHECKOUT_URLS.get(plan, "")
    if url and email:
        # Pre-fill email in checkout
        separator = "&" if "?" in url else "?"
        url = f"{url}{separator}checkout[email]={email}"
    return url


def _verify_lemonsqueezy_signature(payload: bytes, signature: str) -> bool:
    """Verify Lemonsqueezy webhook signature (HMAC-SHA256)."""
    if not LEMONSQUEEZY_WEBHOOK_SECRET:
        return False
    expected = hmac.new(
        LEMONSQUEEZY_WEBHOOK_SECRET.encode("utf-8"),
        payload,
        hashlib.sha256,
    ).hexdigest()
    return hmac.compare_digest(expected, signature)


# ============================================
# FastAPI Routes (only if fastapi is installed)
# ============================================

if FASTAPI_AVAILABLE and router is not None:

    @router.post("/api/signup/starter")
    async def signup_starter(request: Request):
        """Sign up for free Starter plan."""
        try:
            from .dashboard import rate_limit_or_429
            rate_limit_or_429(request, max_req=3, window=60, prefix="signup")
        except ImportError:
            pass
        try:
            data = await request.json()
            email = data.get("email")
            password = data.get("password", "")
            company_name = data.get("company_name", "")
            contact_name = data.get("contact_name", "")
            use_case = data.get("use_case", "")
            team_size = data.get("team_size", "")

            if not email:
                raise HTTPException(status_code=400, detail="Email required")

            if not password or len(password) < 8:
                raise HTTPException(status_code=400, detail="Password must be at least 8 characters")

            if not company_name:
                company_name = email.split("@")[1].split(".")[0].title() if "@" in email else "Unknown"

            if email in CUSTOMERS:
                return JSONResponse({
                    "success": False,
                    "error": "Email already registered. Use your email and password to log in.",
                })

            api_key, key_hash, key_prefix = generate_api_key()

            client_id = get_client_id(api_key)
            CUSTOMERS[email] = {
                "api_key_hash": key_hash,
                "api_key_prefix": key_prefix,
                "password_hash": hash_password(password),
                "client_id": client_id,
                "plan": "starter",
                "created_at": datetime.now(timezone.utc).isoformat(),
                "lemonsqueezy_customer_id": None,
                "company_name": company_name,
                "contact_name": contact_name,
                "use_case": use_case,
                "team_size": team_size,
            }

            sync_usage_limiter(client_id, "starter")
            _save_customers()

            return JSONResponse({
                "success": True,
                "api_key": api_key,
                "plan": "starter",
                "company": company_name,
                "message": "Save this API key now! It will not be shown again."
            })

        except HTTPException:
            raise
        except Exception as e:
            print(f"[SIGNUP ERROR] {e}")
            raise HTTPException(status_code=500, detail="Internal server error")

    @router.post("/api/checkout/pro")
    async def create_pro_checkout(request: Request):
        """Get Lemonsqueezy checkout URL for Pro plan."""
        try:
            data = await request.json()
            email = data.get("email", "")
        except Exception:
            email = ""

        url = get_checkout_url("pro", email)
        if not url:
            return JSONResponse({
                "success": False,
                "error": "Pro checkout not configured. Contact hello@in-a-lign.com",
                "fallback_email": "hello@in-a-lign.com",
            }, status_code=503)

        return JSONResponse({
            "success": True,
            "checkout_url": url,
        })

    @router.post("/api/checkout/enterprise")
    async def create_enterprise_checkout(request: Request):
        """Get Lemonsqueezy checkout URL for Enterprise plan."""
        try:
            data = await request.json()
            email = data.get("email", "")
        except Exception:
            email = ""

        url = get_checkout_url("enterprise", email)
        if not url:
            return JSONResponse({
                "success": False,
                "error": "Enterprise checkout not configured. Contact hello@in-a-lign.com",
                "fallback_email": "hello@in-a-lign.com",
            }, status_code=503)

        return JSONResponse({
            "success": True,
            "checkout_url": url,
        })

    @router.get("/payment/success")
    async def payment_success(request: Request):
        """Handle successful payment redirect from Lemonsqueezy."""
        return RedirectResponse(url="/dashboard?payment=success")

    @router.get("/payment/cancel")
    async def payment_cancel():
        """Handle cancelled payment."""
        return RedirectResponse(url="/?cancelled=true")

    @router.post("/webhook/lemonsqueezy")
    async def lemonsqueezy_webhook(request: Request):
        """
        Handle Lemonsqueezy webhooks for subscription events.

        Events handled:
        - order_created: New purchase
        - subscription_created: New subscription started
        - subscription_updated: Plan changed
        - subscription_cancelled: Subscription ended
        - subscription_expired: Subscription expired
        """
        payload = await request.body()
        signature = request.headers.get("x-signature", "")

        # Verify signature (skip if secret not configured — dev mode)
        if LEMONSQUEEZY_WEBHOOK_SECRET and not _verify_lemonsqueezy_signature(payload, signature):
            print("[WEBHOOK] Invalid signature")
            raise HTTPException(status_code=403, detail="Invalid signature")

        try:
            event = json.loads(payload)
        except json.JSONDecodeError:
            raise HTTPException(status_code=400, detail="Invalid JSON")

        meta = event.get("meta", {})
        event_name = meta.get("event_name", "")
        data = event.get("data", {})
        attrs = data.get("attributes", {})

        print(f"[WEBHOOK] Event: {event_name}")

        # Extract customer email
        email = (
            attrs.get("user_email")
            or attrs.get("customer_email")
            or meta.get("custom_data", {}).get("email", "")
        )

        # Determine plan from variant ID
        variant_id = str(attrs.get("variant_id", "") or attrs.get("first_order_item", {}).get("variant_id", ""))
        plan = VARIANT_TO_PLAN.get(variant_id, "pro")

        if event_name in ("order_created", "subscription_created"):
            if not email:
                print(f"[WEBHOOK] No email in {event_name}")
                return JSONResponse({"received": True, "warning": "no_email"})

            if email in CUSTOMERS:
                # Upgrade existing customer
                CUSTOMERS[email]["plan"] = plan
                CUSTOMERS[email]["lemonsqueezy_customer_id"] = str(attrs.get("customer_id", ""))
                CUSTOMERS[email]["subscription_id"] = str(data.get("id", ""))
                client_id = CUSTOMERS[email].get("client_id", "")
                if client_id:
                    sync_usage_limiter(client_id, plan)
                print(f"[WEBHOOK] Upgraded {email} to {plan}")
            else:
                # New customer — create account + API key
                api_key, key_hash, key_prefix = generate_api_key()
                client_id = get_client_id(api_key)
                CUSTOMERS[email] = {
                    "api_key_hash": key_hash,
                    "api_key_prefix": key_prefix,
                    "client_id": client_id,
                    "plan": plan,
                    "created_at": datetime.now(timezone.utc).isoformat(),
                    "lemonsqueezy_customer_id": str(attrs.get("customer_id", "")),
                    "subscription_id": str(data.get("id", "")),
                }
                sync_usage_limiter(client_id, plan)
                print(f"[WEBHOOK] New customer {email} ({plan}) — key: {key_prefix}...")
                # NOTE: API key is stored hashed. Customer will need to log in
                # to the dashboard to see their key, or we email it via Lemonsqueezy.

            _save_customers()

        elif event_name == "subscription_updated":
            # Plan change (upgrade/downgrade)
            new_variant = str(attrs.get("variant_id", ""))
            new_plan = VARIANT_TO_PLAN.get(new_variant, "")

            if email and email in CUSTOMERS and new_plan:
                old_plan = CUSTOMERS[email].get("plan", "starter")
                CUSTOMERS[email]["plan"] = new_plan
                client_id = CUSTOMERS[email].get("client_id", "")
                if client_id:
                    sync_usage_limiter(client_id, new_plan)
                _save_customers()
                print(f"[WEBHOOK] Plan change {email}: {old_plan} -> {new_plan}")

        elif event_name in ("subscription_cancelled", "subscription_expired"):
            # Downgrade to starter
            if email and email in CUSTOMERS:
                CUSTOMERS[email]["plan"] = "starter"
                CUSTOMERS[email].pop("subscription_id", None)
                client_id = CUSTOMERS[email].get("client_id", "")
                if client_id:
                    sync_usage_limiter(client_id, "starter")
                _save_customers()
                print(f"[WEBHOOK] Downgraded {email} to starter (subscription ended)")

        return JSONResponse({"received": True, "event": event_name})

    # Keep Stripe webhook endpoint for backward compatibility (returns 410 Gone)
    @router.post("/webhook/stripe")
    async def stripe_webhook_deprecated(request: Request):
        """Stripe webhooks are no longer supported. Use Lemonsqueezy."""
        return JSONResponse(
            {"error": "Stripe integration deprecated. Use /webhook/lemonsqueezy"},
            status_code=410,
        )

    @router.get("/api/customer/{email}")
    async def get_customer(email: str, request: Request):
        """Get customer info by email (requires valid session)."""
        session_email = request.session.get("email")
        if not session_email or session_email != email:
            raise HTTPException(status_code=403, detail="Forbidden")

        if email not in CUSTOMERS:
            raise HTTPException(status_code=404, detail="Customer not found")

        customer = CUSTOMERS[email]
        plan_info = PLANS.get(customer["plan"], PLANS["starter"])
        return JSONResponse({
            "email": email,
            "plan": customer["plan"],
            "plan_name": plan_info["name"],
            "features": plan_info.get("features", []),
            "created_at": customer.get("created_at", ""),
        })

    @router.post("/api/verify-key")
    async def verify_api_key_endpoint(request: Request):
        """Verify if API key is valid and get plan info."""
        data = await request.json()
        api_key = data.get("api_key", "")

        _email, cust = find_customer_by_key(api_key)
        if cust:
            plan_name = cust.get("plan", "starter")
            plan = PLANS.get(plan_name, PLANS["starter"])
            return JSONResponse({
                "valid": True,
                "plan": plan_name,
                "actions_per_month": plan["actions_per_month"],
                "features": plan.get("features", []),
            })

        raise HTTPException(status_code=401, detail="Unauthorized")

    @router.get("/api/usage")
    async def get_usage(request: Request, x_api_key: str = Header(None)):
        """Get usage statistics (requires API key in header or session)."""
        api_key = x_api_key
        if not api_key:
            client_id = request.session.get("client_id")
            if client_id:
                for _e, d in CUSTOMERS.items():
                    if d.get("client_id") == client_id:
                        customer = d
                        break
                else:
                    customer = None
                if customer:
                    plan = PLANS.get(customer["plan"], PLANS["starter"])
                    return JSONResponse({
                        "plan": customer["plan"],
                        "actions_limit": plan["actions_per_month"],
                        "features": plan.get("features", []),
                    })
            raise HTTPException(status_code=401, detail="Unauthorized")

        _email, customer = find_customer_by_key(api_key)
        if not customer:
            raise HTTPException(status_code=401, detail="Unauthorized")

        try:
            from .usage_limiter import get_usage_stats
            stats = get_usage_stats(customer["client_id"])
            plan = PLANS.get(customer["plan"], PLANS["starter"])
            stats["features"] = plan.get("features", [])
            return JSONResponse(stats)
        except ImportError:
            plan = PLANS.get(customer["plan"], PLANS["starter"])
            return JSONResponse({
                "plan": customer["plan"],
                "actions_limit": plan["actions_per_month"],
                "features": plan.get("features", []),
            })

    @router.get("/api/plans")
    async def get_plans():
        """Get available plans and pricing."""
        result = {}
        for plan_id, plan in PLANS.items():
            result[plan_id] = {
                "name": plan["name"],
                "price_cents": plan["price"],
                "price_display": f"${plan['price'] // 100}/mo" if plan["price"] else "Free" if plan["price"] == 0 else "Custom",
                "actions_per_month": plan["actions_per_month"] or "Unlimited",
                "retention_days": plan["retention_days"],
                "agents": plan["agents"] or "Unlimited",
                "features": plan.get("features", []),
                "checkout_url": CHECKOUT_URLS.get(plan_id, ""),
            }
        return JSONResponse(result)

    @router.post("/api/regenerate-key")
    async def regenerate_api_key_endpoint(request: Request):
        """Regenerate API key for authenticated user. Old key is immediately invalidated."""
        try:
            from .dashboard import rate_limit_or_429
            rate_limit_or_429(request, max_req=3, window=300, prefix="regen")
        except ImportError:
            pass

        email = request.session.get("email")
        if not email or email not in CUSTOMERS:
            raise HTTPException(status_code=401, detail="Login required")

        customer = CUSTOMERS[email]
        if customer.get("password_hash"):
            try:
                data = await request.json()
                password = data.get("password", "")
            except Exception:
                password = ""
            if not password or not verify_password(password, customer["password_hash"]):
                return JSONResponse({"success": False, "error": "Password confirmation required"}, status_code=403)

        new_key, key_hash, key_prefix = generate_api_key()
        new_client_id = get_client_id(new_key)

        old_client_id = customer.get("client_id", "")

        customer["api_key_hash"] = key_hash
        customer["api_key_prefix"] = key_prefix
        customer["client_id"] = new_client_id

        _save_customers()

        return JSONResponse({
            "success": True,
            "api_key": new_key,
            "client_id": new_client_id,
            "old_client_id": old_client_id,
            "message": "Save this API key now! The old key has been invalidated.",
        })

    @router.post("/api/change-password")
    async def change_password(request: Request):
        """Change password for authenticated user."""
        try:
            from .dashboard import rate_limit_or_429
            rate_limit_or_429(request, max_req=5, window=300, prefix="chpw")
        except ImportError:
            pass

        email = request.session.get("email")
        if not email or email not in CUSTOMERS:
            raise HTTPException(status_code=401, detail="Login required")

        customer = CUSTOMERS[email]

        try:
            data = await request.json()
            current_password = data.get("current_password", "")
            new_password = data.get("new_password", "")
        except Exception:
            raise HTTPException(status_code=400, detail="Invalid request")

        if customer.get("password_hash"):
            if not current_password or not verify_password(current_password, customer["password_hash"]):
                return JSONResponse({"success": False, "error": "Current password is incorrect"}, status_code=403)

        if not new_password or len(new_password) < 8:
            return JSONResponse({"success": False, "error": "New password must be at least 8 characters"}, status_code=400)

        customer["password_hash"] = hash_password(new_password)
        _save_customers()

        return JSONResponse({
            "success": True,
            "message": "Password changed successfully",
        })
