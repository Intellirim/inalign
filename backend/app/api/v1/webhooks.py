"""
Webhook management endpoints.

CRUD operations for outbound webhook subscriptions and a test-fire
endpoint to verify connectivity.
"""

from __future__ import annotations

import logging
import secrets
from uuid import uuid4

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.dependencies import CurrentUser, DBSession
from app.models.webhook import Webhook
from app.schemas.common import SuccessResponse

logger = logging.getLogger("inalign.api.webhooks")

router = APIRouter()


# --------------------------------------------------------------------------
# Request / Response models (webhook-specific)
# --------------------------------------------------------------------------


class WebhookCreateRequest(BaseModel):
    """Payload for creating a new webhook subscription."""

    name: str = Field(..., min_length=1, max_length=255, description="Webhook label")
    url: str = Field(..., min_length=1, max_length=2048, description="Destination URL (HTTPS)")
    events: list[str] = Field(
        default_factory=lambda: ["alert.critical", "alert.high"],
        description="Event types to subscribe to",
    )
    is_active: bool = Field(default=True)


class WebhookUpdateRequest(BaseModel):
    """Payload for updating an existing webhook."""

    name: str | None = Field(default=None, max_length=255)
    url: str | None = Field(default=None, max_length=2048)
    events: list[str] | None = None
    is_active: bool | None = None


class WebhookResponse(BaseModel):
    """Webhook subscription returned by the API."""

    id: str
    name: str
    url: str
    events: list[str]
    is_active: bool
    secret: str = Field(description="HMAC-SHA256 shared secret for payload verification")
    last_triggered_at: str | None = None
    created_at: str | None = None


class WebhookTestResponse(BaseModel):
    """Result of a test webhook delivery."""

    success: bool
    status_code: int | None = None
    message: str = ""


# --------------------------------------------------------------------------
# POST /
# --------------------------------------------------------------------------


@router.post(
    "/",
    response_model=WebhookResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create webhook",
    description="Register a new outbound webhook subscription for the authenticated user.",
)
async def create_webhook(
    body: WebhookCreateRequest,
    current_user: CurrentUser,
    db: DBSession,
) -> WebhookResponse:
    """Create a new webhook subscription."""
    logger.info(
        "POST /webhooks  user=%s  name=%s  url=%s",
        current_user["user_id"],
        body.name,
        body.url,
    )

    webhook = Webhook(
        id=uuid4(),
        user_id=current_user["user_id"],
        name=body.name,
        url=body.url,
        events=body.events,
        secret=secrets.token_urlsafe(32),
        is_active=body.is_active,
    )

    db.add(webhook)
    await db.flush()
    await db.refresh(webhook)

    logger.info("Webhook %s created for user %s", webhook.id, current_user["user_id"])

    return _webhook_to_response(webhook)


# --------------------------------------------------------------------------
# GET /
# --------------------------------------------------------------------------


@router.get(
    "/",
    response_model=list[WebhookResponse],
    status_code=status.HTTP_200_OK,
    summary="List webhooks",
    description="Return all webhook subscriptions for the authenticated user.",
)
async def list_webhooks(
    current_user: CurrentUser,
    db: DBSession,
) -> list[WebhookResponse]:
    """List all webhooks owned by the current user."""
    logger.info("GET /webhooks  user=%s", current_user["user_id"])

    result = await db.execute(
        select(Webhook)
        .where(Webhook.user_id == current_user["user_id"])
        .order_by(Webhook.created_at.desc())
    )
    webhooks = result.scalars().all()

    return [_webhook_to_response(w) for w in webhooks]


# --------------------------------------------------------------------------
# PUT /{webhook_id}
# --------------------------------------------------------------------------


@router.put(
    "/{webhook_id}",
    response_model=WebhookResponse,
    status_code=status.HTTP_200_OK,
    summary="Update webhook",
    description="Update properties of an existing webhook subscription.",
)
async def update_webhook(
    webhook_id: str,
    body: WebhookUpdateRequest,
    current_user: CurrentUser,
    db: DBSession,
) -> WebhookResponse:
    """Update a webhook subscription."""
    logger.info(
        "PUT /webhooks/%s  user=%s",
        webhook_id,
        current_user["user_id"],
    )

    result = await db.execute(
        select(Webhook).where(
            Webhook.id == webhook_id,
            Webhook.user_id == current_user["user_id"],
        )
    )
    webhook = result.scalar_one_or_none()

    if webhook is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Webhook '{webhook_id}' not found",
        )

    if body.name is not None:
        webhook.name = body.name
    if body.url is not None:
        webhook.url = body.url
    if body.events is not None:
        webhook.events = body.events
    if body.is_active is not None:
        webhook.is_active = body.is_active

    await db.flush()
    await db.refresh(webhook)

    logger.info("Webhook %s updated", webhook_id)

    return _webhook_to_response(webhook)


# --------------------------------------------------------------------------
# DELETE /{webhook_id}
# --------------------------------------------------------------------------


@router.delete(
    "/{webhook_id}",
    response_model=SuccessResponse,
    status_code=status.HTTP_200_OK,
    summary="Delete webhook",
    description="Permanently delete a webhook subscription.",
)
async def delete_webhook(
    webhook_id: str,
    current_user: CurrentUser,
    db: DBSession,
) -> SuccessResponse:
    """Delete a webhook subscription."""
    logger.info(
        "DELETE /webhooks/%s  user=%s",
        webhook_id,
        current_user["user_id"],
    )

    result = await db.execute(
        select(Webhook).where(
            Webhook.id == webhook_id,
            Webhook.user_id == current_user["user_id"],
        )
    )
    webhook = result.scalar_one_or_none()

    if webhook is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Webhook '{webhook_id}' not found",
        )

    await db.delete(webhook)
    await db.flush()

    logger.info("Webhook %s deleted", webhook_id)

    return SuccessResponse(message=f"Webhook '{webhook_id}' deleted")


# --------------------------------------------------------------------------
# POST /{webhook_id}/test
# --------------------------------------------------------------------------


@router.post(
    "/{webhook_id}/test",
    response_model=WebhookTestResponse,
    status_code=status.HTTP_200_OK,
    summary="Test webhook",
    description=(
        "Send a test notification payload to the webhook URL to verify "
        "connectivity and configuration."
    ),
)
async def test_webhook(
    webhook_id: str,
    current_user: CurrentUser,
    db: DBSession,
) -> WebhookTestResponse:
    """Fire a test payload to the registered webhook URL."""
    logger.info(
        "POST /webhooks/%s/test  user=%s",
        webhook_id,
        current_user["user_id"],
    )

    result = await db.execute(
        select(Webhook).where(
            Webhook.id == webhook_id,
            Webhook.user_id == current_user["user_id"],
        )
    )
    webhook = result.scalar_one_or_none()

    if webhook is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Webhook '{webhook_id}' not found",
        )

    # Attempt delivery via httpx
    import json
    from datetime import datetime, timezone

    from app.core.security import sign_webhook_payload

    payload = json.dumps({
        "event": "test",
        "webhook_id": str(webhook.id),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "message": "This is a test notification from InALign.",
    }).encode()

    signature = sign_webhook_payload(payload, webhook.secret)

    try:
        import httpx

        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.post(
                webhook.url,
                content=payload,
                headers={
                    "Content-Type": "application/json",
                    "X-InALign-Signature": signature,
                    "X-InALign-Event": "test",
                },
            )

        success = 200 <= resp.status_code < 300
        logger.info(
            "Webhook %s test delivery: status=%d  success=%s",
            webhook_id,
            resp.status_code,
            success,
        )

        return WebhookTestResponse(
            success=success,
            status_code=resp.status_code,
            message="Test notification delivered" if success else f"Endpoint returned {resp.status_code}",
        )

    except ImportError:
        logger.warning("httpx not installed -- cannot send test webhook")
        return WebhookTestResponse(
            success=False,
            message="httpx library not available for outbound HTTP calls",
        )
    except Exception as exc:
        logger.exception("Webhook test delivery failed for %s", webhook_id)
        return WebhookTestResponse(
            success=False,
            message=f"Delivery failed: {exc}",
        )


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------


def _webhook_to_response(webhook: Webhook) -> WebhookResponse:
    """Convert an ORM :class:`Webhook` to the API response schema."""
    return WebhookResponse(
        id=str(webhook.id),
        name=webhook.name,
        url=webhook.url,
        events=webhook.events,
        is_active=webhook.is_active,
        secret=webhook.secret,
        last_triggered_at=webhook.last_triggered_at.isoformat() if webhook.last_triggered_at else None,
        created_at=webhook.created_at.isoformat() if webhook.created_at else None,
    )
