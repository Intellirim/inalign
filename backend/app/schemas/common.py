"""Common schemas shared across the API."""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any, Generic, TypeVar
from uuid import UUID

from pydantic import BaseModel, Field

__all__ = [
    "RiskLevel", "Severity", "ErrorResponse", "SuccessResponse",
    "PaginatedResponse", "PaginationMeta",
]


class RiskLevel(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    NONE = "none"


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class ErrorResponse(BaseModel):
    error: bool = True
    message: str
    status_code: int
    details: Any = None


class SuccessResponse(BaseModel):
    success: bool = True
    message: str = "OK"


class PaginationMeta(BaseModel):
    page: int = Field(ge=1)
    size: int = Field(ge=1, le=100)
    total: int = Field(ge=0)
    total_pages: int = Field(ge=0)


T = TypeVar("T")


class PaginatedResponse(BaseModel, Generic[T]):
    items: list[T]
    meta: PaginationMeta
