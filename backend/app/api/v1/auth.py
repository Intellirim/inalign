"""
Authentication endpoints.

Handles user login, registration, and API key lifecycle management.
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from uuid import uuid4

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import get_settings
from app.core.security import (
    create_access_token,
    generate_api_key,
    get_api_key_prefix,
    hash_api_key,
    hash_password,
    verify_password,
)
from app.dependencies import CurrentUser, DBSession
from app.models.api_key import APIKey
from app.models.user import User, UserRole
from app.schemas.auth import (
    APIKeyCreateRequest,
    APIKeyResponse,
    LoginRequest,
    RegisterRequest,
    TokenResponse,
    UserResponse,
)
from app.schemas.common import SuccessResponse

logger = logging.getLogger("agentshield.api.auth")

router = APIRouter()


# --------------------------------------------------------------------------
# POST /login
# --------------------------------------------------------------------------


@router.post(
    "/login",
    response_model=TokenResponse,
    status_code=status.HTTP_200_OK,
    summary="Authenticate user",
    description="Validate email and password and return a signed JWT access token.",
)
async def login(
    body: LoginRequest,
    db: DBSession,
) -> TokenResponse:
    """Authenticate a user with email/password and issue a JWT."""
    logger.info("login attempt for %s", body.email)

    result = await db.execute(
        select(User).where(User.email == body.email)
    )
    user = result.scalar_one_or_none()

    if user is None or not verify_password(body.password, user.hashed_password):
        logger.warning("Login failed for %s", body.email)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password",
        )

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Account is disabled",
        )

    settings = get_settings()
    token = create_access_token(
        data={"sub": str(user.id), "email": user.email, "role": user.role.value},
    )

    logger.info("User %s logged in successfully", user.id)

    return TokenResponse(
        access_token=token,
        token_type="bearer",
        expires_in=settings.jwt_access_token_expire_minutes * 60,
    )


# --------------------------------------------------------------------------
# POST /register
# --------------------------------------------------------------------------


@router.post(
    "/register",
    response_model=UserResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Register new user",
    description="Create a new user account. Returns the created user profile.",
)
async def register(
    body: RegisterRequest,
    db: DBSession,
) -> UserResponse:
    """Register a new user account."""
    logger.info("register attempt for %s", body.email)

    # Check for duplicate email
    existing = await db.execute(
        select(User).where(User.email == body.email)
    )
    if existing.scalar_one_or_none() is not None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Email already registered",
        )

    user = User(
        id=uuid4(),
        email=body.email,
        name=body.name,
        hashed_password=hash_password(body.password),
        role=UserRole.USER,
        is_active=True,
    )
    db.add(user)
    await db.flush()
    await db.refresh(user)

    logger.info("User %s registered (email=%s)", user.id, user.email)

    return UserResponse(
        id=str(user.id),
        email=user.email,
        name=user.name,
        role=user.role.value,
        is_active=user.is_active,
        created_at=user.created_at,
    )


# --------------------------------------------------------------------------
# POST /api-keys
# --------------------------------------------------------------------------


@router.post(
    "/api-keys",
    response_model=APIKeyResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create API key",
    description=(
        "Generate a new API key for the authenticated user. "
        "The full key is shown **only once** in this response."
    ),
)
async def create_api_key(
    body: APIKeyCreateRequest,
    current_user: CurrentUser,
    db: DBSession,
) -> APIKeyResponse:
    """Create a new API key for the authenticated user."""
    raw_key = generate_api_key()
    key_hash = hash_api_key(raw_key)
    key_prefix = get_api_key_prefix(raw_key)

    expires_at = None
    if body.expires_in_days:
        expires_at = datetime.now(timezone.utc) + timedelta(days=body.expires_in_days)

    api_key = APIKey(
        id=uuid4(),
        user_id=current_user["user_id"],
        key_hash=key_hash,
        key_prefix=key_prefix,
        name=body.name,
        permissions=body.permissions,
        is_active=True,
        expires_at=expires_at,
    )

    db.add(api_key)
    await db.flush()
    await db.refresh(api_key)

    logger.info(
        "API key created  id=%s  user=%s  name=%s",
        api_key.id,
        current_user["user_id"],
        body.name,
    )

    return APIKeyResponse(
        id=str(api_key.id),
        name=api_key.name,
        key_prefix=api_key.key_prefix,
        permissions=api_key.permissions,
        is_active=api_key.is_active,
        last_used_at=api_key.last_used_at,
        expires_at=api_key.expires_at,
        created_at=api_key.created_at,
        key=raw_key,  # shown only once
    )


# --------------------------------------------------------------------------
# GET /api-keys
# --------------------------------------------------------------------------


@router.get(
    "/api-keys",
    response_model=list[APIKeyResponse],
    status_code=status.HTTP_200_OK,
    summary="List API keys",
    description="Return all API keys belonging to the authenticated user.",
)
async def list_api_keys(
    current_user: CurrentUser,
    db: DBSession,
) -> list[APIKeyResponse]:
    """List all API keys for the current user."""
    result = await db.execute(
        select(APIKey)
        .where(APIKey.user_id == current_user["user_id"])
        .order_by(APIKey.created_at.desc())
    )
    keys = result.scalars().all()

    return [
        APIKeyResponse(
            id=str(k.id),
            name=k.name,
            key_prefix=k.key_prefix,
            permissions=k.permissions,
            is_active=k.is_active,
            last_used_at=k.last_used_at,
            expires_at=k.expires_at,
            created_at=k.created_at,
            key=None,  # never expose the full key after creation
        )
        for k in keys
    ]


# --------------------------------------------------------------------------
# DELETE /api-keys/{key_id}
# --------------------------------------------------------------------------


@router.delete(
    "/api-keys/{key_id}",
    response_model=SuccessResponse,
    status_code=status.HTTP_200_OK,
    summary="Revoke API key",
    description="Deactivate (revoke) an API key. The key can no longer be used for authentication.",
)
async def delete_api_key(
    key_id: str,
    current_user: CurrentUser,
    db: DBSession,
) -> SuccessResponse:
    """Revoke an API key by setting ``is_active = False``."""
    result = await db.execute(
        select(APIKey).where(
            APIKey.id == key_id,
            APIKey.user_id == current_user["user_id"],
        )
    )
    api_key = result.scalar_one_or_none()

    if api_key is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"API key '{key_id}' not found",
        )

    api_key.is_active = False
    await db.flush()

    logger.info("API key %s revoked by user %s", key_id, current_user["user_id"])

    return SuccessResponse(message=f"API key '{key_id}' revoked")
