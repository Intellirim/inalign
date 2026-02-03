"""
Real-time monitoring WebSocket endpoint.

Provides live streaming of agent activities, threats, and metrics.
"""

from __future__ import annotations

import asyncio
import json
import logging
from datetime import datetime, timezone
from typing import Any, Optional

from fastapi import APIRouter, Depends, WebSocket, WebSocketDisconnect, Query
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.dependencies import get_db
from app.models import Agent, Activity
from app.core.security import verify_api_key

router = APIRouter()
logger = logging.getLogger(__name__)


class ConnectionManager:
    """Manages WebSocket connections for real-time monitoring."""

    def __init__(self):
        # Map of user_id -> list of active connections
        self.active_connections: dict[str, list[WebSocket]] = {}
        # Map of user_id -> set of subscribed agent_ids
        self.subscriptions: dict[str, set[str]] = {}

    async def connect(
        self,
        websocket: WebSocket,
        user_id: str,
        agent_ids: list[str] | None = None,
    ) -> None:
        """Accept a new WebSocket connection."""
        await websocket.accept()

        if user_id not in self.active_connections:
            self.active_connections[user_id] = []
            self.subscriptions[user_id] = set()

        self.active_connections[user_id].append(websocket)

        # Subscribe to specific agents or all
        if agent_ids:
            self.subscriptions[user_id].update(agent_ids)

        logger.info(f"WebSocket connected for user {user_id}, agents: {agent_ids}")

    def disconnect(self, websocket: WebSocket, user_id: str) -> None:
        """Remove a WebSocket connection."""
        if user_id in self.active_connections:
            if websocket in self.active_connections[user_id]:
                self.active_connections[user_id].remove(websocket)
            if not self.active_connections[user_id]:
                del self.active_connections[user_id]
                if user_id in self.subscriptions:
                    del self.subscriptions[user_id]

        logger.info(f"WebSocket disconnected for user {user_id}")

    async def broadcast_to_user(
        self,
        user_id: str,
        agent_id: str,
        message: dict[str, Any],
    ) -> None:
        """Send a message to all connections of a user."""
        if user_id not in self.active_connections:
            return

        # Check subscription
        subscriptions = self.subscriptions.get(user_id, set())
        if subscriptions and agent_id not in subscriptions:
            return

        message_json = json.dumps(message, default=str)
        disconnected = []

        for connection in self.active_connections[user_id]:
            try:
                await connection.send_text(message_json)
            except Exception:
                disconnected.append(connection)

        # Clean up disconnected
        for conn in disconnected:
            self.disconnect(conn, user_id)


# Global connection manager
manager = ConnectionManager()


@router.websocket("/stream")
async def activity_stream(
    websocket: WebSocket,
    api_key: str = Query(..., description="API key for authentication"),
    agent_ids: Optional[str] = Query(
        default=None,
        description="Comma-separated agent IDs to monitor (empty = all)",
    ),
):
    """WebSocket endpoint for real-time activity streaming.

    Connect with:
    ws://localhost:8000/api/v1/monitor/stream?api_key=xxx&agent_ids=agent1,agent2

    Messages received:
    - activity: New agent action
    - threat: Threat detected
    - policy_violation: Policy violation occurred
    - metric: Periodic metrics update
    - heartbeat: Keep-alive ping

    Send messages:
    - {"type": "subscribe", "agent_ids": ["agent1", "agent2"]}
    - {"type": "unsubscribe", "agent_ids": ["agent1"]}
    - {"type": "ping"}
    """
    # Authenticate
    async for db in get_db_for_ws():
        user = await verify_api_key_for_ws(api_key, db)
        if not user:
            await websocket.close(code=4001, reason="Invalid API key")
            return

        user_id = str(user.id)
        agent_list = agent_ids.split(",") if agent_ids else None

        # Verify user owns these agents
        if agent_list:
            result = await db.execute(
                select(Agent.agent_id).where(
                    Agent.user_id == user.id,
                    Agent.agent_id.in_(agent_list),
                )
            )
            valid_agents = [r[0] for r in result.all()]
            if not valid_agents:
                await websocket.close(code=4003, reason="No valid agents")
                return
            agent_list = valid_agents
        break

    # Connect
    await manager.connect(websocket, user_id, agent_list)

    try:
        # Start heartbeat task
        heartbeat_task = asyncio.create_task(
            send_heartbeat(websocket, user_id)
        )

        # Listen for client messages
        while True:
            try:
                data = await websocket.receive_text()
                message = json.loads(data)

                if message.get("type") == "ping":
                    await websocket.send_json({
                        "event_type": "pong",
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                    })
                elif message.get("type") == "subscribe":
                    new_agents = message.get("agent_ids", [])
                    if new_agents:
                        manager.subscriptions[user_id].update(new_agents)
                elif message.get("type") == "unsubscribe":
                    remove_agents = message.get("agent_ids", [])
                    manager.subscriptions[user_id].difference_update(remove_agents)

            except json.JSONDecodeError:
                pass  # Ignore invalid JSON

    except WebSocketDisconnect:
        manager.disconnect(websocket, user_id)
        heartbeat_task.cancel()
    except Exception as e:
        logger.error(f"WebSocket error: {e}")
        manager.disconnect(websocket, user_id)
        heartbeat_task.cancel()


async def send_heartbeat(websocket: WebSocket, user_id: str) -> None:
    """Send periodic heartbeat to keep connection alive."""
    while True:
        try:
            await asyncio.sleep(30)
            await websocket.send_json({
                "event_type": "heartbeat",
                "timestamp": datetime.now(timezone.utc).isoformat(),
            })
        except Exception:
            break


async def get_db_for_ws():
    """Get database session for WebSocket handlers."""
    from app.models.database import async_session_factory

    async with async_session_factory() as session:
        yield session


async def verify_api_key_for_ws(api_key: str, db: AsyncSession):
    """Verify API key and return user."""
    from app.models import APIKey, User
    from app.core.security import hash_api_key

    if not api_key.startswith("ask_"):
        return None

    key_hash = hash_api_key(api_key)
    result = await db.execute(
        select(APIKey).where(APIKey.key_hash == key_hash)
    )
    api_key_record = result.scalar_one_or_none()

    if not api_key_record:
        return None

    user_result = await db.execute(
        select(User).where(User.id == api_key_record.user_id)
    )
    return user_result.scalar_one_or_none()


# Event broadcast functions (called from other services)

async def broadcast_activity(
    user_id: str,
    agent_id: str,
    activity_data: dict[str, Any],
) -> None:
    """Broadcast a new activity event."""
    await manager.broadcast_to_user(
        user_id=user_id,
        agent_id=agent_id,
        message={
            "event_type": "activity",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "agent_id": agent_id,
            "data": activity_data,
        },
    )


async def broadcast_threat(
    user_id: str,
    agent_id: str,
    threat_data: dict[str, Any],
) -> None:
    """Broadcast a threat detection event."""
    await manager.broadcast_to_user(
        user_id=user_id,
        agent_id=agent_id,
        message={
            "event_type": "threat",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "agent_id": agent_id,
            "data": threat_data,
        },
    )


async def broadcast_policy_violation(
    user_id: str,
    agent_id: str,
    violation_data: dict[str, Any],
) -> None:
    """Broadcast a policy violation event."""
    await manager.broadcast_to_user(
        user_id=user_id,
        agent_id=agent_id,
        message={
            "event_type": "policy_violation",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "agent_id": agent_id,
            "data": violation_data,
        },
    )


async def broadcast_metric(
    user_id: str,
    agent_id: str,
    metric_data: dict[str, Any],
) -> None:
    """Broadcast a metrics update."""
    await manager.broadcast_to_user(
        user_id=user_id,
        agent_id=agent_id,
        message={
            "event_type": "metric",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "agent_id": agent_id,
            "data": metric_data,
        },
    )
