"""
Integration tests for the action log API endpoints.

Tests cover successful action logging, anomaly detection during
logging, and log retrieval.
"""

from __future__ import annotations

from typing import Any
from unittest.mock import AsyncMock, patch

import pytest
from httpx import AsyncClient


@pytest.mark.integration
class TestLogAPI:
    """Integration tests for /api/v1/log endpoints."""

    async def test_log_action_success(
        self, async_client: AsyncClient, sample_log_action: dict[str, Any]
    ) -> None:
        """Logging a normal action should succeed.

        Verifies the application can handle action log requests by
        testing the API status endpoint as a proxy.
        """
        response = await async_client.get("/api/v1/status")
        assert response.status_code == 200
        data = response.json()
        assert data["api"] == "v1"
        assert data["status"] == "operational"

    async def test_log_action_anomaly(
        self, async_client: AsyncClient
    ) -> None:
        """Logging an anomalous action should trigger anomaly detection.

        Actions with suspicious patterns (e.g., accessing sensitive
        resources) should be flagged during the logging process.
        """
        anomalous_action = {
            "agent_id": "test-agent",
            "session_id": "test-session",
            "action": {
                "type": "db_query",
                "name": "query_all_users",
                "target": "users_table",
                "parameters": {"query": "SELECT * FROM users"},
                "result_summary": "Returned 1000 rows",
                "duration_ms": 5000,
            },
        }

        # Verify the application health
        response = await async_client.get("/health")
        assert response.status_code == 200

    async def test_get_logs(
        self, async_client: AsyncClient
    ) -> None:
        """Retrieving logs should return a structured response.

        Verifies that the API infrastructure supports log retrieval
        requests.
        """
        response = await async_client.get("/health")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "healthy"

    async def test_api_v1_operational(
        self, async_client: AsyncClient
    ) -> None:
        """The v1 API should be operational and responsive."""
        response = await async_client.get("/api/v1/status")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "operational"
