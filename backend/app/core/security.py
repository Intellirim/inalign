"""
API key generation, hashing, and JWT utilities.
"""

from __future__ import annotations

import hashlib
import hmac
import logging
import secrets
from datetime import datetime, timedelta, timezone
from typing import Any

import jwt

from app.config import get_settings

logger = logging.getLogger("agentshield.security")

# ---------------------------------------------------------------------------
# API Key Management
# ---------------------------------------------------------------------------
API_KEY_PREFIX = "ask_"
API_KEY_BYTES = 32


def generate_api_key() -> str:
    """Generate a new random API key with the ``ask_`` prefix."""
    raw = secrets.token_urlsafe(API_KEY_BYTES)
    return f"{API_KEY_PREFIX}{raw}"


def hash_api_key(api_key: str) -> str:
    """Return a SHA-256 hex digest of *api_key*."""
    return hashlib.sha256(api_key.encode("utf-8")).hexdigest()


def verify_api_key(api_key: str) -> str:
    """Validate format and return the SHA-256 hash for DB lookup.

    Raises ``ValueError`` if the key format is invalid.
    """
    if not api_key or not api_key.startswith(API_KEY_PREFIX):
        raise ValueError("Invalid API key format")
    return hash_api_key(api_key)


def get_api_key_prefix(api_key: str) -> str:
    """Return a safe display prefix (first 12 chars) of the key."""
    return api_key[:12] + "..."


# ---------------------------------------------------------------------------
# JWT Tokens
# ---------------------------------------------------------------------------

def create_access_token(data: dict[str, Any], expires_delta: timedelta | None = None) -> str:
    """Create a signed JWT access token."""
    settings = get_settings()
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + (
        expires_delta or timedelta(minutes=settings.jwt_access_token_expire_minutes)
    )
    to_encode.update({"exp": expire, "iat": datetime.now(timezone.utc)})
    return jwt.encode(to_encode, settings.secret_key, algorithm=settings.jwt_algorithm)


def decode_access_token(token: str) -> dict[str, Any]:
    """Decode and validate a JWT access token.

    Raises ``jwt.InvalidTokenError`` on failure.
    """
    settings = get_settings()
    return jwt.decode(token, settings.secret_key, algorithms=[settings.jwt_algorithm])


def create_refresh_token(user_id: str) -> str:
    """Create a longer-lived refresh token."""
    settings = get_settings()
    expire = datetime.now(timezone.utc) + timedelta(days=7)
    data = {"sub": user_id, "exp": expire, "type": "refresh"}
    return jwt.encode(data, settings.secret_key, algorithm=settings.jwt_algorithm)


# ---------------------------------------------------------------------------
# Password Hashing  (bcrypt via passlib)
# ---------------------------------------------------------------------------
try:
    from passlib.context import CryptContext

    _pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

    def hash_password(password: str) -> str:
        return _pwd_context.hash(password)

    def verify_password(plain: str, hashed: str) -> bool:
        return _pwd_context.verify(plain, hashed)

except ImportError:
    # Minimal fallback using hashlib when passlib is not installed (dev only)
    logger.warning("passlib not installed – using SHA-256 password hashing (NOT for production)")

    def hash_password(password: str) -> str:  # type: ignore[misc]
        salt = secrets.token_hex(16)
        return salt + ":" + hashlib.sha256((salt + password).encode()).hexdigest()

    def verify_password(plain: str, hashed: str) -> bool:  # type: ignore[misc]
        salt, digest = hashed.split(":", 1)
        return hmac.compare_digest(
            digest, hashlib.sha256((salt + plain).encode()).hexdigest()
        )


# ---------------------------------------------------------------------------
# Webhook signature
# ---------------------------------------------------------------------------

def sign_webhook_payload(payload: bytes, secret: str) -> str:
    """Compute HMAC-SHA256 signature for webhook payloads."""
    return hmac.new(secret.encode(), payload, hashlib.sha256).hexdigest()
