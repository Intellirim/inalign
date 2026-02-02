"""
Integration tests for Neo4j graph operations.

Tests cover session creation, action creation, and session graph
retrieval using a mocked Neo4j client.
"""

from __future__ import annotations

from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.graph.neo4j_client import Neo4jClient


@pytest.fixture
def mock_driver():
    """Create a mock Neo4j async driver."""
    driver = AsyncMock()
    driver.verify_connectivity = AsyncMock()
    driver.close = AsyncMock()

    # Mock session and transaction
    mock_result = AsyncMock()
    mock_result.data = AsyncMock(
        return_value=[{"session_id": "test-session-001"}]
    )

    mock_tx = AsyncMock()
    mock_tx.run = AsyncMock(return_value=mock_result)

    mock_session = AsyncMock()
    mock_session.execute_write = AsyncMock(
        side_effect=lambda func: func(mock_tx)
    )
    mock_session.execute_read = AsyncMock(
        side_effect=lambda func: func(mock_tx)
    )
    mock_session.__aenter__ = AsyncMock(return_value=mock_session)
    mock_session.__aexit__ = AsyncMock(return_value=None)

    driver.session = MagicMock(return_value=mock_session)

    return driver


@pytest.mark.integration
class TestNeo4jOperations:
    """Integration tests for Neo4j graph operations using mocks."""

    async def test_create_session(self, mock_driver: AsyncMock) -> None:
        """Creating a session should return the session ID."""
        with patch(
            "app.graph.neo4j_client.AsyncGraphDatabase"
        ) as mock_gdb:
            mock_gdb.driver = MagicMock(return_value=mock_driver)

            client = Neo4jClient(
                uri="bolt://localhost:7687",
                username="neo4j",
                password="test",
            )
            client._driver = mock_driver

            session_data = {
                "session_id": "test-session-001",
                "agent_id": "test-agent-001",
                "user_id": "test-user-001",
                "status": "active",
                "risk_score": 0.0,
                "started_at": "2024-01-01T00:00:00Z",
            }

            result = await client.create_session(session_data)
            assert result == "test-session-001"

    async def test_create_action(self, mock_driver: AsyncMock) -> None:
        """Creating an action should return the action ID."""
        # Update mock to return action_id
        mock_result = AsyncMock()
        mock_result.data = AsyncMock(
            return_value=[{"action_id": "test-action-001"}]
        )

        mock_tx = AsyncMock()
        mock_tx.run = AsyncMock(return_value=mock_result)

        mock_session = AsyncMock()
        mock_session.execute_write = AsyncMock(
            side_effect=lambda func: func(mock_tx)
        )
        mock_session.__aenter__ = AsyncMock(return_value=mock_session)
        mock_session.__aexit__ = AsyncMock(return_value=None)

        mock_driver.session = MagicMock(return_value=mock_session)

        client = Neo4jClient(
            uri="bolt://localhost:7687",
            username="neo4j",
            password="test",
        )
        client._driver = mock_driver

        action_data = {
            "action_id": "test-action-001",
            "action_type": "tool_call",
            "input": "search query",
            "output": "results",
            "risk_score": 0.3,
            "latency_ms": 150.0,
            "timestamp": "2024-01-01T00:00:01Z",
        }

        result = await client.create_action(
            action_data, session_id="test-session-001"
        )
        assert result == "test-action-001"

    async def test_get_session_graph(self, mock_driver: AsyncMock) -> None:
        """Retrieving a session graph should return structured data."""
        # Set up mock to return session graph data
        graph_data = [
            {
                "session": {
                    "session_id": "test-session-001",
                    "agent_id": "test-agent-001",
                    "status": "active",
                    "risk_score": 0.5,
                },
                "actions": [
                    {
                        "action_id": "act-001",
                        "action_type": "user_input",
                    },
                ],
                "threats": [],
                "sequences": [],
            }
        ]

        mock_result = AsyncMock()
        mock_result.data = AsyncMock(return_value=graph_data)

        mock_tx = AsyncMock()
        mock_tx.run = AsyncMock(return_value=mock_result)

        mock_session = AsyncMock()
        mock_session.execute_read = AsyncMock(
            side_effect=lambda func: func(mock_tx)
        )
        mock_session.__aenter__ = AsyncMock(return_value=mock_session)
        mock_session.__aexit__ = AsyncMock(return_value=None)

        mock_driver.session = MagicMock(return_value=mock_session)

        client = Neo4jClient(
            uri="bolt://localhost:7687",
            username="neo4j",
            password="test",
        )
        client._driver = mock_driver

        result = await client.get_session_graph("test-session-001")

        assert "session" in result
        assert "actions" in result
        assert "threats" in result
        assert "edges" in result

    async def test_health_check_without_driver(self) -> None:
        """Health check should return False when driver is not initialised."""
        client = Neo4jClient(
            uri="bolt://localhost:7687",
            username="neo4j",
            password="test",
        )
        # Driver is None by default
        result = await client.health_check()
        assert result is False

    async def test_client_driver_property_raises(self) -> None:
        """Accessing driver property without connection should raise RuntimeError."""
        client = Neo4jClient(
            uri="bolt://localhost:7687",
            username="neo4j",
            password="test",
        )

        with pytest.raises(RuntimeError, match="not connected"):
            _ = client.driver
