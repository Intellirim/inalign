"""
Living Agent API & WebSocket endpoints.

Provides:
- Agent lifecycle management (start/stop)
- Real-time WebSocket for live dashboard
- Event history and subscription
"""
from __future__ import annotations

import logging
from typing import Any, Optional
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, WebSocket, WebSocketDisconnect
from pydantic import BaseModel

from app.api.v1.auth import get_api_key
from app.cost_guard.living_agent import (
    get_living_agent, start_living_agent, stop_living_agent,
    LivingAgent, EventType
)

logger = logging.getLogger(__name__)
router = APIRouter()


# =============================================================================
# Request/Response Models
# =============================================================================

class ProcessRequest(BaseModel):
    """Request to process through Living Agent."""
    user_message: str
    system_prompt: str = ""
    model: str = "gpt-4o-mini"
    agent_id: str = "default"
    session_id: str = "default"
    user_id: Optional[str] = None
    org_id: Optional[str] = None


class AgentConfigRequest(BaseModel):
    """Agent configuration update request."""
    auto_heal: bool = True
    health_check_interval: int = 30
    metrics_interval: int = 5
    enable_learning: bool = True


# =============================================================================
# REST Endpoints
# =============================================================================

@router.get("/status")
async def get_agent_status(_api_key: str = Depends(get_api_key)):
    """Get Living Agent status and metrics."""
    agent = get_living_agent()
    return agent.get_status()


@router.post("/start")
async def start_agent(_api_key: str = Depends(get_api_key)):
    """Start the Living Agent."""
    try:
        agent = await start_living_agent()
        return {
            "status": "ok",
            "message": "Living Agent started",
            "state": agent.state.value,
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/stop")
async def stop_agent(_api_key: str = Depends(get_api_key)):
    """Stop the Living Agent."""
    try:
        await stop_living_agent()
        return {
            "status": "ok",
            "message": "Living Agent stopped",
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/process")
async def process_request(
    request: ProcessRequest,
    _api_key: str = Depends(get_api_key),
):
    """
    Process a request through the Living Agent.

    This is the main endpoint for all LLM requests going through
    the protection layer.
    """
    agent = get_living_agent()

    if not agent.is_running:
        # Auto-start if not running
        await agent.start()

    try:
        result = await agent.process(
            user_message=request.user_message,
            system_prompt=request.system_prompt,
            model=request.model,
            agent_id=request.agent_id,
            session_id=request.session_id,
            user_id=request.user_id,
            org_id=request.org_id,
        )
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/events")
async def get_event_history(
    event_type: Optional[str] = None,
    limit: int = 100,
    _api_key: str = Depends(get_api_key),
):
    """Get event history."""
    agent = get_living_agent()

    etype = None
    if event_type:
        try:
            etype = EventType(event_type)
        except ValueError:
            raise HTTPException(
                status_code=400,
                detail=f"Invalid event type: {event_type}"
            )

    events = agent.events.get_history(event_type=etype, limit=limit)

    return {
        "count": len(events),
        "events": [
            {
                "type": e.type.value,
                "timestamp": e.timestamp.isoformat(),
                "severity": e.severity,
                "data": e.data,
            }
            for e in events
        ],
    }


@router.get("/metrics")
async def get_metrics(_api_key: str = Depends(get_api_key)):
    """Get current agent metrics."""
    agent = get_living_agent()
    metrics = agent.metrics

    return {
        "uptime_seconds": metrics.uptime_seconds,
        "requests_processed": metrics.requests_processed,
        "threats_blocked": metrics.threats_blocked,
        "tokens_saved": metrics.tokens_saved,
        "cache_hits": metrics.cache_hits,
        "cache_misses": metrics.cache_misses,
        "cache_hit_rate": (
            metrics.cache_hits /
            max(metrics.cache_hits + metrics.cache_misses, 1)
        ),
        "avg_latency_ms": round(metrics.avg_latency_ms, 2),
        "errors": metrics.errors,
        "last_threat_time": (
            metrics.last_threat_time.isoformat()
            if metrics.last_threat_time else None
        ),
        "last_error_time": (
            metrics.last_error_time.isoformat()
            if metrics.last_error_time else None
        ),
    }


@router.get("/health")
async def health_check():
    """
    Health check endpoint (no auth required).

    Used for liveness/readiness probes.
    """
    agent = get_living_agent()

    return {
        "status": "healthy" if agent.is_running else "stopped",
        "state": agent.state.value,
        "uptime_seconds": agent.metrics.uptime_seconds,
    }


# =============================================================================
# WebSocket Endpoint for Real-time Updates
# =============================================================================

@router.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    """
    WebSocket endpoint for real-time Living Agent events.

    Connect to receive live updates:
    - Threat detections
    - Metrics updates
    - Budget alerts
    - System health events

    Usage (JavaScript):
        const ws = new WebSocket('ws://localhost:8000/api/v1/living-agent/ws');
        ws.onmessage = (event) => {
            const data = JSON.parse(event.data);
            console.log('Event:', data.type, data.data);
        };
    """
    await websocket.accept()

    agent = get_living_agent()
    agent.register_websocket(websocket)

    # Send initial status
    await websocket.send_json({
        "type": "connected",
        "timestamp": datetime.utcnow().isoformat(),
        "data": {
            "agent_state": agent.state.value,
            "is_running": agent.is_running,
        },
    })

    try:
        # Keep connection alive and handle incoming messages
        while True:
            try:
                # Wait for messages (ping/pong, commands, etc.)
                data = await websocket.receive_text()

                # Handle commands
                if data == "ping":
                    await websocket.send_text("pong")
                elif data == "status":
                    await websocket.send_json({
                        "type": "status",
                        "timestamp": datetime.utcnow().isoformat(),
                        "data": agent.get_status(),
                    })
                elif data == "metrics":
                    metrics = agent.metrics
                    await websocket.send_json({
                        "type": "metrics",
                        "timestamp": datetime.utcnow().isoformat(),
                        "data": {
                            "requests_processed": metrics.requests_processed,
                            "threats_blocked": metrics.threats_blocked,
                            "tokens_saved": metrics.tokens_saved,
                            "cache_hit_rate": (
                                metrics.cache_hits /
                                max(metrics.cache_hits + metrics.cache_misses, 1)
                            ),
                        },
                    })

            except WebSocketDisconnect:
                break

    finally:
        agent.unregister_websocket(websocket)
        logger.debug("WebSocket disconnected")
