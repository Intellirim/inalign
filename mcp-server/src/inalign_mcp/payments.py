"""
InALign Payment System - Stripe Integration

Handles:
- Stripe Checkout for Pro plan ($49/mo)
- Webhook for payment confirmation
- Auto API key generation after payment
"""

import os
import secrets
import hashlib
import json
from datetime import datetime, timezone
from typing import Optional

import stripe
from fastapi import APIRouter, Request, HTTPException
from fastapi.responses import RedirectResponse, JSONResponse

# Initialize Stripe
stripe.api_key = os.getenv("STRIPE_SECRET_KEY")
STRIPE_WEBHOOK_SECRET = os.getenv("STRIPE_WEBHOOK_SECRET")
BASE_URL = os.getenv("BASE_URL", "http://localhost:8080")

router = APIRouter()

# In-memory storage (replace with database in production)
# Format: {email: {api_key, plan, created_at, stripe_customer_id}}
CUSTOMERS = {}

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


def generate_api_key() -> str:
    """Generate a secure API key."""
    random_bytes = secrets.token_bytes(32)
    key = f"ial_{secrets.token_urlsafe(32)}"
    return key


def get_client_id(api_key: str) -> str:
    """Derive client_id from API key."""
    if api_key.startswith("ial_"):
        return api_key[:12]
    return hashlib.sha256(api_key.encode()).hexdigest()[:12]


@router.post("/api/signup/starter")
async def signup_starter(request: Request):
    """Sign up for free Starter plan."""
    try:
        data = await request.json()
        email = data.get("email")

        if not email:
            raise HTTPException(status_code=400, detail="Email required")

        if email in CUSTOMERS:
            return JSONResponse({
                "success": False,
                "error": "Email already registered",
                "api_key": CUSTOMERS[email]["api_key"]
            })

        api_key = generate_api_key()

        CUSTOMERS[email] = {
            "api_key": api_key,
            "client_id": get_client_id(api_key),
            "plan": "starter",
            "created_at": datetime.now(timezone.utc).isoformat(),
            "stripe_customer_id": None,
        }

        return JSONResponse({
            "success": True,
            "api_key": api_key,
            "plan": "starter",
            "message": "Welcome to InALign! Add this to your Claude Code settings."
        })

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


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
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


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
            api_key = generate_api_key()
            CUSTOMERS[email] = {
                "api_key": api_key,
                "client_id": get_client_id(api_key),
                "plan": "pro",
                "created_at": datetime.now(timezone.utc).isoformat(),
                "stripe_customer_id": session.customer,
                "subscription_id": session.subscription,
            }
        else:
            # Upgrade existing customer
            CUSTOMERS[email]["plan"] = "pro"
            CUSTOMERS[email]["stripe_customer_id"] = session.customer
            CUSTOMERS[email]["subscription_id"] = session.subscription

        api_key = CUSTOMERS[email]["api_key"]

        # Redirect to dashboard with API key shown
        return RedirectResponse(url=f"/dashboard?api_key={api_key}&plan=pro")

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
            api_key = generate_api_key()
            CUSTOMERS[email] = {
                "api_key": api_key,
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
                break

    return JSONResponse({"received": True})


@router.get("/api/customer/{email}")
async def get_customer(email: str):
    """Get customer info by email."""
    if email not in CUSTOMERS:
        raise HTTPException(status_code=404, detail="Customer not found")

    customer = CUSTOMERS[email]
    return JSONResponse({
        "email": email,
        "plan": customer["plan"],
        "api_key": customer["api_key"][:20] + "...",  # Partial for security
        "created_at": customer["created_at"],
    })


@router.get("/api/verify-key/{api_key}")
async def verify_api_key(api_key: str):
    """Verify if API key is valid and get plan info."""
    for email, data in CUSTOMERS.items():
        if data["api_key"] == api_key:
            plan = PLANS.get(data["plan"], PLANS["starter"])
            return JSONResponse({
                "valid": True,
                "plan": data["plan"],
                "actions_per_month": plan["actions_per_month"],
                "retention_days": plan["retention_days"],
            })

    raise HTTPException(status_code=404, detail="Invalid API key")
