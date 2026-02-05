"""
FastAPI application entry point for InALign.

Creates the FastAPI app with lifespan context management, registers all
middleware, exception handlers, routers, and configures OpenAPI with
Bearer authentication.
"""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager
from typing import AsyncGenerator

from fastapi import FastAPI
from fastapi.openapi.utils import get_openapi

from app.config import configure_logging, get_settings
from app.core.exceptions import register_exception_handlers
from app.core.middleware import register_middleware
from app.dependencies import (
    init_db,
    init_neo4j,
    init_redis,
    shutdown_db,
    shutdown_neo4j,
    shutdown_redis,
)

logger = logging.getLogger("inalign.main")


# ---------------------------------------------------------------------------
# Lifespan context manager
# ---------------------------------------------------------------------------
@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """Manage application startup and shutdown lifecycle.

    On startup:
      - Configure logging
      - Initialise PostgreSQL async engine
      - Initialise Neo4j async driver
      - Initialise Redis connection pool

    On shutdown:
      - Dispose of all connection pools and drivers gracefully
    """
    settings = get_settings()
    configure_logging(settings)

    logger.info(
        "InALign starting up (env=%s, debug=%s)",
        settings.api_env.value,
        settings.debug,
    )

    # --- Startup -----------------------------------------------------------
    try:
        await init_db(settings)
        logger.info("PostgreSQL initialised.")
    except Exception:
        logger.exception("Failed to initialise PostgreSQL.")

    try:
        await init_neo4j(settings)
        logger.info("Neo4j initialised.")
    except Exception:
        logger.exception("Failed to initialise Neo4j.")

    try:
        await init_redis(settings)
        logger.info("Redis initialised.")
    except Exception:
        logger.exception("Failed to initialise Redis.")

    logger.info("InALign startup complete.")

    yield

    # --- Shutdown ----------------------------------------------------------
    logger.info("InALign shutting down...")

    await shutdown_redis()
    await shutdown_neo4j()
    await shutdown_db()

    logger.info("InALign shutdown complete.")


# ---------------------------------------------------------------------------
# Application factory
# ---------------------------------------------------------------------------
def create_app() -> FastAPI:
    """Create and configure the FastAPI application instance."""
    settings = get_settings()

    app = FastAPI(
        title="InALign API",
        version="1.0.0",
        description=(
            "AI Agent security monitoring and threat detection platform. "
            "Provides real-time scanning, session tracking, anomaly detection, "
            "and GraphRAG-powered security analysis reports."
        ),
        lifespan=lifespan,
        docs_url="/docs" if not settings.is_production else None,
        redoc_url="/redoc" if not settings.is_production else None,
        openapi_url="/openapi.json" if not settings.is_production else None,
    )

    # --- Middleware ---------------------------------------------------------
    register_middleware(app)

    # --- Exception handlers ------------------------------------------------
    register_exception_handlers(app)

    # --- Routers -----------------------------------------------------------
    _register_routers(app)

    # --- Custom OpenAPI schema ---------------------------------------------
    app.openapi = lambda: _custom_openapi(app)  # type: ignore[assignment]

    return app


# ---------------------------------------------------------------------------
# Router registration
# ---------------------------------------------------------------------------
def _register_routers(app: FastAPI) -> None:
    """Register all API routers on the application.

    Health check router is mounted at ``/`` and the versioned API
    router is mounted at ``/api``.
    """
    from app.api.health import router as health_router
    from app.api.v1.router import v1_router

    app.include_router(health_router)
    app.include_router(v1_router, prefix="/api")


# ---------------------------------------------------------------------------
# Custom OpenAPI with Bearer auth
# ---------------------------------------------------------------------------
def _custom_openapi(app: FastAPI) -> dict:
    """Generate a custom OpenAPI schema with Bearer token security scheme."""
    if app.openapi_schema:
        return app.openapi_schema

    openapi_schema = get_openapi(
        title="InALign API",
        version="1.0.0",
        description=(
            "AI Agent security monitoring and threat detection platform.\n\n"
            "## Authentication\n\n"
            "All endpoints (except health checks) require an API key passed "
            "via the `X-API-Key` header or a Bearer JWT token in the "
            "`Authorization` header.\n\n"
            "## Rate Limiting\n\n"
            "API calls are rate-limited per API key. Check response headers "
            "`X-RateLimit-Limit` and `X-RateLimit-Remaining`."
        ),
        routes=app.routes,
    )

    # Add Bearer security scheme
    openapi_schema["components"] = openapi_schema.get("components", {})
    openapi_schema["components"]["securitySchemes"] = {
        "BearerAuth": {
            "type": "http",
            "scheme": "bearer",
            "bearerFormat": "JWT",
            "description": "JWT access token obtained from /api/v1/auth/login",
        },
        "APIKeyAuth": {
            "type": "apiKey",
            "in": "header",
            "name": "X-API-Key",
            "description": "API key with `ask_` prefix",
        },
    }

    # Apply security globally
    openapi_schema["security"] = [
        {"BearerAuth": []},
        {"APIKeyAuth": []},
    ]

    app.openapi_schema = openapi_schema
    return app.openapi_schema


# ---------------------------------------------------------------------------
# Module-level app instance
# ---------------------------------------------------------------------------
app = create_app()
