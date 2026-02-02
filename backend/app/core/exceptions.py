"""
Custom exception hierarchy and FastAPI exception handlers.
"""

from __future__ import annotations

import logging
from typing import Any

from fastapi import FastAPI, Request, status
from fastapi.responses import JSONResponse

logger = logging.getLogger("agentshield.exceptions")


# ---------------------------------------------------------------------------
# Exception hierarchy
# ---------------------------------------------------------------------------

class AgentShieldError(Exception):
    """Base exception for all AgentShield errors."""

    def __init__(self, message: str = "An unexpected error occurred", details: Any = None):
        self.message = message
        self.details = details
        super().__init__(message)


class AuthenticationError(AgentShieldError):
    """Invalid or missing credentials."""

    def __init__(self, message: str = "Authentication failed", details: Any = None):
        super().__init__(message, details)


class AuthorizationError(AgentShieldError):
    """Insufficient permissions."""

    def __init__(self, message: str = "Insufficient permissions", details: Any = None):
        super().__init__(message, details)


class RateLimitError(AgentShieldError):
    """Rate limit exceeded."""

    def __init__(self, message: str = "Rate limit exceeded", retry_after: int = 60):
        self.retry_after = retry_after
        super().__init__(message)


class ValidationError(AgentShieldError):
    """Request validation failed."""

    def __init__(self, message: str = "Validation error", details: Any = None):
        super().__init__(message, details)


class NotFoundError(AgentShieldError):
    """Requested resource not found."""

    def __init__(self, resource: str = "Resource", resource_id: str = ""):
        msg = f"{resource} not found"
        if resource_id:
            msg = f"{resource} '{resource_id}' not found"
        super().__init__(msg)


class ScanError(AgentShieldError):
    """Error during input/output scanning."""

    def __init__(self, message: str = "Scan processing failed", details: Any = None):
        super().__init__(message, details)


class GraphError(AgentShieldError):
    """Error in Neo4j graph operations."""

    def __init__(self, message: str = "Graph operation failed", details: Any = None):
        super().__init__(message, details)


class ReportGenerationError(AgentShieldError):
    """Error generating a security report."""

    def __init__(self, message: str = "Report generation failed", details: Any = None):
        super().__init__(message, details)


class ExternalServiceError(AgentShieldError):
    """Error communicating with an external service."""

    def __init__(self, service: str, message: str = ""):
        super().__init__(f"External service error ({service}): {message}")


# ---------------------------------------------------------------------------
# FastAPI exception handlers
# ---------------------------------------------------------------------------

_STATUS_MAP: dict[type[AgentShieldError], int] = {
    AuthenticationError: status.HTTP_401_UNAUTHORIZED,
    AuthorizationError: status.HTTP_403_FORBIDDEN,
    RateLimitError: status.HTTP_429_TOO_MANY_REQUESTS,
    ValidationError: status.HTTP_422_UNPROCESSABLE_ENTITY,
    NotFoundError: status.HTTP_404_NOT_FOUND,
    ScanError: status.HTTP_500_INTERNAL_SERVER_ERROR,
    GraphError: status.HTTP_502_BAD_GATEWAY,
    ReportGenerationError: status.HTTP_500_INTERNAL_SERVER_ERROR,
    ExternalServiceError: status.HTTP_502_BAD_GATEWAY,
}


def _error_response(request: Request, status_code: int, message: str, details: Any = None) -> JSONResponse:
    body: dict[str, Any] = {
        "error": True,
        "message": message,
        "status_code": status_code,
    }
    if details is not None:
        body["details"] = details
    return JSONResponse(status_code=status_code, content=body)


async def agentshield_exception_handler(request: Request, exc: AgentShieldError) -> JSONResponse:
    status_code = _STATUS_MAP.get(type(exc), status.HTTP_500_INTERNAL_SERVER_ERROR)
    logger.error("AgentShieldError [%d]: %s", status_code, exc.message, exc_info=exc)
    headers = {}
    if isinstance(exc, RateLimitError):
        headers["Retry-After"] = str(exc.retry_after)
    return JSONResponse(
        status_code=status_code,
        content={"error": True, "message": exc.message, "details": exc.details},
        headers=headers,
    )


async def generic_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    logger.exception("Unhandled exception on %s %s", request.method, request.url.path)
    return _error_response(request, status.HTTP_500_INTERNAL_SERVER_ERROR, "Internal server error")


def register_exception_handlers(app: FastAPI) -> None:
    """Register all custom exception handlers on the FastAPI app."""
    app.add_exception_handler(AgentShieldError, agentshield_exception_handler)  # type: ignore[arg-type]
    app.add_exception_handler(Exception, generic_exception_handler)
