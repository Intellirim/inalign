"""
Aggregate API v1 router.

Includes all v1 sub-routers with their respective prefixes and tags.
This module is the single entry point that the main FastAPI application
mounts under ``/api/v1``.
"""

from __future__ import annotations

from fastapi import APIRouter

from app.api.v1.auth import router as auth_router
from app.api.v1.scan import router as scan_router
from app.api.v1.logs import router as logs_router
from app.api.v1.sessions import router as sessions_router
from app.api.v1.reports import router as reports_router
from app.api.v1.alerts import router as alerts_router
from app.api.v1.dashboard import router as dashboard_router
from app.api.v1.webhooks import router as webhooks_router

v1_router = APIRouter(prefix="/v1")

v1_router.include_router(auth_router, prefix="/auth", tags=["Authentication"])
v1_router.include_router(scan_router, prefix="/scan", tags=["Scanning"])
v1_router.include_router(logs_router, prefix="/logs", tags=["Logging"])
v1_router.include_router(sessions_router, prefix="/sessions", tags=["Sessions"])
v1_router.include_router(reports_router, prefix="/reports", tags=["Reports"])
v1_router.include_router(alerts_router, prefix="/alerts", tags=["Alerts"])
v1_router.include_router(dashboard_router, prefix="/dashboard", tags=["Dashboard"])
v1_router.include_router(webhooks_router, prefix="/webhooks", tags=["Webhooks"])
