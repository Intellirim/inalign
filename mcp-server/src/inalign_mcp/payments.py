"""
InALign Payment System - Stripe Integration

Handles:
- Stripe Checkout for Pro plan ($49/mo)
- Webhook for payment confirmation
- Auto API key generation after payment
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

import bcrypt
import stripe
from fastapi import APIRouter, Request, HTTPException, Header
from fastapi.responses import RedirectResponse, JSONResponse

# Initialize Stripe
stripe.api_key = os.getenv("STRIPE_SECRET_KEY")
STRIPE_WEBHOOK_SECRET = os.getenv("STRIPE_WEBHOOK_SECRET")
BASE_URL = os.getenv("BASE_URL", "http://localhost:8080")

router = APIRouter()

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
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")


def verify_password(password: str, hashed: str) -> bool:
    """Verify password against bcrypt hash."""
    return bcrypt.checkpw(password.encode("utf-8"), hashed.encode("utf-8"))


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
                # Ensure default test user exists
                for email, info in _DEFAULT_CUSTOMERS.items():
                    if email not in data:
                        data[email] = dict(info)
                # Auto-migrate plaintext keys
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
        # Restrict file permissions (owner-only on Unix)
        try:
            os.chmod(_CUSTOMERS_FILE, 0o600)
        except (OSError, AttributeError):
            pass  # Windows doesn't support Unix permissions
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
    },
    "pro": {
        "name": "Pro",
        "price": 4900,  # cents
        "price_id": os.getenv("STRIPE_PRO_PRICE_ID"),  # Set in Stripe dashboard
        "actions_per_month": 50000,
        "retention_days": 30,
        "agents": 10,
    },
    "enterprise": {
        "name": "Enterprise",
        "price": None,  # Custom
        "actions_per_month": None,  # Unlimited
        "retention_days": 365,
        "agents": None,  # Unlimited
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


@router.post("/api/signup/starter")
async def signup_starter(request: Request):
    """Sign up for free Starter plan."""
    # Rate limit: 3 signups per minute per IP
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
            # Auto-generate from email domain
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
            "stripe_customer_id": None,
            "company_name": company_name,
            "contact_name": contact_name,
            "use_case": use_case,
            "team_size": team_size,
        }

        # Sync to usage limiter
        sync_usage_limiter(client_id, "starter")

        # Persist to disk (hash only)
        _save_customers()

        # Return plaintext key ONCE (never stored)
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
    """Create Stripe Checkout session for Pro plan."""
    try:
        data = await request.json()
        email = data.get("email")

        if not email:
            raise HTTPException(status_code=400, detail="Email required")

        if not stripe.api_key:
            raise HTTPException(status_code=500, detail="Stripe not configured")

        # Create Stripe Checkout session
        session = stripe.checkout.Session.create(
            payment_method_types=["card"],
            line_items=[{
                "price_data": {
                    "currency": "usd",
                    "product_data": {
                        "name": "InALign Pro",
                        "description": "50,000 actions/month, 30-day retention, 10 agents",
                    },
                    "unit_amount": 4900,  # $49.00
                    "recurring": {"interval": "month"},
                },
                "quantity": 1,
            }],
            mode="subscription",
            customer_email=email,
            success_url=f"{BASE_URL}/payment/success?session_id={{CHECKOUT_SESSION_ID}}",
            cancel_url=f"{BASE_URL}/payment/cancel",
            metadata={"email": email},
        )

        return JSONResponse({
            "success": True,
            "checkout_url": session.url,
            "session_id": session.id,
        })

    except stripe.error.StripeError as e:
        print(f"[STRIPE ERROR] {e}")
        raise HTTPException(status_code=400, detail="Payment processing error")
    except Exception as e:
        print(f"[CHECKOUT ERROR] {e}")
        raise HTTPException(status_code=500, detail="Internal server error")


@router.get("/payment/success")
async def payment_success(session_id: str):
    """Handle successful payment - redirect to dashboard with API key."""
    try:
        if not stripe.api_key:
            # Stripe not configured, show generic success
            return RedirectResponse(url="/dashboard?payment=success")

        session = stripe.checkout.Session.retrieve(session_id)
        email = session.metadata.get("email") or session.customer_email

        if not email:
            return RedirectResponse(url="/dashboard?error=no_email")

        # Generate API key if not exists
        if email not in CUSTOMERS:
            api_key, key_hash, key_prefix = generate_api_key()
            CUSTOMERS[email] = {
                "api_key_hash": key_hash,
                "api_key_prefix": key_prefix,
                "client_id": get_client_id(api_key),
                "plan": "pro",
                "created_at": datetime.now(timezone.utc).isoformat(),
                "stripe_customer_id": session.customer,
                "subscription_id": session.subscription,
            }
            _save_customers()
            # Show key once after payment
            return RedirectResponse(url=f"/dashboard?api_key={api_key}&plan=pro")
        else:
            # Upgrade existing customer
            CUSTOMERS[email]["plan"] = "pro"
            CUSTOMERS[email]["stripe_customer_id"] = session.customer
            CUSTOMERS[email]["subscription_id"] = session.subscription
            _save_customers()
            return RedirectResponse(url="/dashboard?plan=pro&upgraded=true")

    except Exception as e:
        return RedirectResponse(url=f"/dashboard?error={str(e)}")


@router.get("/payment/cancel")
async def payment_cancel():
    """Handle cancelled payment."""
    return RedirectResponse(url="/?cancelled=true")


@router.post("/webhook/stripe")
async def stripe_webhook(request: Request):
    """Handle Stripe webhooks for subscription events."""
    payload = await request.body()
    sig_header = request.headers.get("stripe-signature")

    if not STRIPE_WEBHOOK_SECRET:
        # Webhook not configured, just acknowledge
        return JSONResponse({"received": True})

    try:
        event = stripe.Webhook.construct_event(
            payload, sig_header, STRIPE_WEBHOOK_SECRET
        )
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid payload")
    except stripe.error.SignatureVerificationError:
        raise HTTPException(status_code=400, detail="Invalid signature")

    # Handle events
    if event["type"] == "checkout.session.completed":
        session = event["data"]["object"]
        email = session.get("customer_email")

        if email and email not in CUSTOMERS:
            api_key, key_hash, key_prefix = generate_api_key()
            CUSTOMERS[email] = {
                "api_key_hash": key_hash,
                "api_key_prefix": key_prefix,
                "client_id": get_client_id(api_key),
                "plan": "pro",
                "created_at": datetime.now(timezone.utc).isoformat(),
                "stripe_customer_id": session.get("customer"),
                "subscription_id": session.get("subscription"),
            }

    elif event["type"] == "customer.subscription.deleted":
        # Downgrade to starter on cancellation
        subscription = event["data"]["object"]
        customer_id = subscription.get("customer")

        for email, data in CUSTOMERS.items():
            if data.get("stripe_customer_id") == customer_id:
                data["plan"] = "starter"
                _save_customers()
                break

    # Save after webhook checkout too
    if event["type"] == "checkout.session.completed":
        _save_customers()

    return JSONResponse({"received": True})


@router.get("/api/customer/{email}")
async def get_customer(email: str, request: Request):
    """Get customer info by email (requires valid session)."""
    # Auth: only logged-in users can query, and only their own email
    session_email = request.session.get("email")
    if not session_email or session_email != email:
        raise HTTPException(status_code=403, detail="Forbidden")

    if email not in CUSTOMERS:
        raise HTTPException(status_code=404, detail="Customer not found")

    customer = CUSTOMERS[email]
    return JSONResponse({
        "email": email,
        "plan": customer["plan"],
        "created_at": customer.get("created_at", ""),
    })


@router.post("/api/verify-key")
async def verify_api_key_endpoint(request: Request):
    """Verify if API key is valid and get plan info."""
    data = await request.json()
    api_key = data.get("api_key", "")

    _email, cust = find_customer_by_key(api_key)
    if cust:
        plan = PLANS.get(cust["plan"], PLANS["starter"])
        return JSONResponse({
            "valid": True,
            "plan": cust["plan"],
            "actions_per_month": plan["actions_per_month"],
        })

    raise HTTPException(status_code=401, detail="Unauthorized")


@router.get("/api/usage")
async def get_usage(request: Request, x_api_key: str = Header(None)):
    """Get usage statistics (requires API key in header or session)."""
    api_key = x_api_key
    if not api_key:
        # Fallback: find by client_id in session
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
                return JSONResponse({"plan": customer["plan"], "actions_limit": plan["actions_per_month"]})
        raise HTTPException(status_code=401, detail="Unauthorized")

    # Find customer by API key hash
    _email, customer = find_customer_by_key(api_key)
    if not customer:
        raise HTTPException(status_code=401, detail="Unauthorized")

    # Get usage from limiter
    try:
        from .usage_limiter import get_usage_stats
        stats = get_usage_stats(customer["client_id"])
        return JSONResponse(stats)
    except ImportError:
        plan = PLANS.get(customer["plan"], PLANS["starter"])
        return JSONResponse({
            "plan": customer["plan"],
            "actions_limit": plan["actions_per_month"],
        })


@router.post("/api/regenerate-key")
async def regenerate_api_key(request: Request):
    """Regenerate API key for authenticated user. Old key is immediately invalidated."""
    try:
        from .dashboard import rate_limit_or_429
        rate_limit_or_429(request, max_req=3, window=300, prefix="regen")
    except ImportError:
        pass

    # Must be logged in (session auth)
    email = request.session.get("email")
    if not email or email not in CUSTOMERS:
        raise HTTPException(status_code=401, detail="Login required")

    # Require password confirmation if account has password
    customer = CUSTOMERS[email]
    if customer.get("password_hash"):
        try:
            data = await request.json()
            password = data.get("password", "")
        except Exception:
            password = ""
        if not password or not verify_password(password, customer["password_hash"]):
            return JSONResponse({"success": False, "error": "Password confirmation required"}, status_code=403)

    # Generate new key, invalidate old
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

    # Must be logged in
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

    # Verify current password
    if customer.get("password_hash"):
        if not current_password or not verify_password(current_password, customer["password_hash"]):
            return JSONResponse({"success": False, "error": "Current password is incorrect"}, status_code=403)
    else:
        # No password set yet — allow setting one without current password
        pass

    # Validate new password
    if not new_password or len(new_password) < 8:
        return JSONResponse({"success": False, "error": "New password must be at least 8 characters"}, status_code=400)

    # Update password
    customer["password_hash"] = hash_password(new_password)
    _save_customers()

    return JSONResponse({
        "success": True,
        "message": "Password changed successfully",
    })
