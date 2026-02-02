"""Authentication schemas."""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, EmailStr, Field

__all__ = [
    "LoginRequest", "RegisterRequest", "TokenResponse",
    "APIKeyCreateRequest", "APIKeyResponse", "UserResponse",
]


class LoginRequest(BaseModel):
    email: EmailStr
    password: str = Field(..., min_length=8)


class RegisterRequest(BaseModel):
    email: EmailStr
    password: str = Field(..., min_length=8)
    name: str = Field(..., min_length=1, max_length=100)


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int


class APIKeyCreateRequest(BaseModel):
    name: str = Field(..., min_length=1, max_length=100, description="Human-readable key name")
    permissions: list[str] = Field(
        default=["scan:read", "scan:write", "logs:write", "sessions:read"],
        description="Granted permission scopes",
    )
    expires_in_days: int | None = Field(default=None, ge=1, le=365)


class APIKeyResponse(BaseModel):
    id: str
    name: str
    key_prefix: str
    permissions: list[str]
    is_active: bool
    last_used_at: datetime | None = None
    expires_at: datetime | None = None
    created_at: datetime | None = None
    key: str | None = Field(default=None, description="Full key, shown only on creation")


class UserResponse(BaseModel):
    id: str
    email: str
    name: str
    role: str
    is_active: bool
    created_at: datetime | None = None
