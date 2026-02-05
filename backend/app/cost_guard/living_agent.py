"""
Living Agent - Always-running intelligent guardian.

Runs as a background service that:
- Monitors all LLM traffic in real-time
- Auto-responds to threats and budget alerts
- Self-heals and maintains health
- Pushes real-time updates via WebSocket
- Learns and adapts from patterns

Think of it as an AI security guard that never sleeps.
"""
from __future__ import annotations

import asyncio
import logging
import signal
import sys
import time
import threading
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import Any, Callable, Optional
from collections import deque
import json

logger = logging.getLogger("inalign.living_agent")


class AgentState(str, Enum):
    """Living Agent states."""
    STARTING = "starting"
    RUNNING = "running"
    PAUSED = "paused"
    HEALING = "healing"
    STOPPING = "stopping"
    STOPPED = "stopped"


class EventType(str, Enum):
    """Event types the agent can emit."""
    # Security events
    THREAT_DETECTED = "threat_detected"
    THREAT_BLOCKED = "threat_blocked"
    ATTACK_PATTERN = "attack_pattern"

    # Cost events
    BUDGET_WARNING = "budget_warning"
    BUDGET_EXCEEDED = "budget_exceeded"
    MODEL_DOWNGRADED = "model_downgraded"
    CACHE_HIT = "cache_hit"
    TOKENS_SAVED = "tokens_saved"

    # System events
    AGENT_STARTED = "agent_started"
    AGENT_STOPPED = "agent_stopped"
    HEALTH_CHECK = "health_check"
    SELF_HEAL = "self_heal"
    CONFIG_CHANGED = "config_changed"

    # Metrics events
    METRICS_UPDATE = "metrics_update"
    ANOMALY_DETECTED = "anomaly_detected"


@dataclass
class Event:
    """Event data structure."""
    type: EventType
    timestamp: datetime
    data: dict[str, Any]
    severity: str = "info"  # info, warning, critical
    agent_id: str = "living-agent"


@dataclass
class AgentMetrics:
    """Real-time agent metrics."""
    uptime_seconds: float = 0.0
    requests_processed: int = 0
    threats_blocked: int = 0
    tokens_saved: int = 0
    cost_saved_usd: float = 0.0
    cache_hits: int = 0
    cache_misses: int = 0
    avg_latency_ms: float = 0.0
    errors: int = 0
    last_threat_time: Optional[datetime] = None
    last_error_time: Optional[datetime] = None


class EventBus:
    """
    In-memory event bus for real-time communication.

    Supports:
    - Pub/sub pattern
    - Event history
    - Multiple subscribers per event type
    """

    def __init__(self, max_history: int = 1000):
        self._subscribers: dict[EventType, list[Callable]] = {}
        self._all_subscribers: list[Callable] = []
        self._history: deque[Event] = deque(maxlen=max_history)
        self._lock = threading.Lock()

    def subscribe(
        self,
        event_type: Optional[EventType],
        callback: Callable[[Event], None],
    ) -> None:
        """
        Subscribe to events.

        If event_type is None, subscribes to ALL events.
        """
        with self._lock:
            if event_type is None:
                self._all_subscribers.append(callback)
            else:
                if event_type not in self._subscribers:
                    self._subscribers[event_type] = []
                self._subscribers[event_type].append(callback)

    def unsubscribe(
        self,
        event_type: Optional[EventType],
        callback: Callable[[Event], None],
    ) -> None:
        """Unsubscribe from events."""
        with self._lock:
            if event_type is None:
                if callback in self._all_subscribers:
                    self._all_subscribers.remove(callback)
            elif event_type in self._subscribers:
                if callback in self._subscribers[event_type]:
                    self._subscribers[event_type].remove(callback)

    def publish(self, event: Event) -> None:
        """Publish an event to all subscribers."""
        with self._lock:
            self._history.append(event)

            # Notify type-specific subscribers
            if event.type in self._subscribers:
                for callback in self._subscribers[event.type]:
                    try:
                        callback(event)
                    except Exception as e:
                        logger.error(f"Event callback error: {e}")

            # Notify all-events subscribers
            for callback in self._all_subscribers:
                try:
                    callback(event)
                except Exception as e:
                    logger.error(f"Event callback error: {e}")

    def get_history(
        self,
        event_type: Optional[EventType] = None,
        since: Optional[datetime] = None,
        limit: int = 100,
    ) -> list[Event]:
        """Get event history."""
        with self._lock:
            events = list(self._history)

        if event_type:
            events = [e for e in events if e.type == event_type]

        if since:
            events = [e for e in events if e.timestamp >= since]

        return events[-limit:]


class LivingAgent:
    """
    The Living Agent - An always-running intelligent guardian.

    Features:
    - Continuous monitoring
    - Real-time event emission
    - Self-healing capabilities
    - Adaptive learning (pattern detection)
    - WebSocket support for live dashboard

    Usage:
        agent = LivingAgent()
        await agent.start()

        # Agent is now running in background
        # Subscribe to events
        agent.on_event(EventType.THREAT_DETECTED, my_handler)

        # Process requests through the agent
        result = await agent.process(user_message, ...)

        # Stop when done
        await agent.stop()
    """

    def __init__(
        self,
        auto_heal: bool = True,
        health_check_interval: int = 30,
        metrics_interval: int = 5,
        enable_learning: bool = True,
    ):
        """
        Initialize the Living Agent.

        Parameters
        ----------
        auto_heal : bool
            Automatically recover from errors.
        health_check_interval : int
            Seconds between health checks.
        metrics_interval : int
            Seconds between metrics updates.
        enable_learning : bool
            Enable pattern learning/adaptation.
        """
        self.auto_heal = auto_heal
        self.health_check_interval = health_check_interval
        self.metrics_interval = metrics_interval
        self.enable_learning = enable_learning

        # State
        self._state = AgentState.STOPPED
        self._start_time: Optional[datetime] = None
        self._metrics = AgentMetrics()

        # Event bus
        self.events = EventBus()

        # Runtime Guard (lazy loaded)
        self._guard = None

        # Background tasks
        self._tasks: list[asyncio.Task] = []
        self._stop_event = asyncio.Event()

        # Pattern learning
        self._attack_patterns: dict[str, int] = {}
        self._request_patterns: deque = deque(maxlen=1000)

        # WebSocket connections
        self._ws_connections: list[Any] = []

        logger.info("LivingAgent initialized")

    @property
    def state(self) -> AgentState:
        return self._state

    @property
    def metrics(self) -> AgentMetrics:
        return self._metrics

    @property
    def is_running(self) -> bool:
        return self._state == AgentState.RUNNING

    def _get_guard(self):
        """Lazy load Runtime Guard."""
        if self._guard is None:
            from app.cost_guard.runtime_guard import RuntimeGuard
            self._guard = RuntimeGuard(
                enable_security=True,
                enable_cache=True,
                enable_compression=True,
                enable_routing=True,
                enable_policy=True,
            )
        return self._guard

    async def start(self) -> None:
        """Start the Living Agent."""
        if self._state == AgentState.RUNNING:
            logger.warning("Agent is already running")
            return

        self._state = AgentState.STARTING
        self._start_time = datetime.utcnow()
        self._stop_event.clear()

        logger.info("Starting Living Agent...")

        # Initialize Runtime Guard
        self._get_guard()

        # Start background tasks
        self._tasks = [
            asyncio.create_task(self._health_check_loop()),
            asyncio.create_task(self._metrics_loop()),
        ]

        if self.enable_learning:
            self._tasks.append(asyncio.create_task(self._learning_loop()))

        self._state = AgentState.RUNNING

        # Emit started event
        self._emit(EventType.AGENT_STARTED, {
            "timestamp": self._start_time.isoformat(),
            "config": {
                "auto_heal": self.auto_heal,
                "health_check_interval": self.health_check_interval,
                "metrics_interval": self.metrics_interval,
                "enable_learning": self.enable_learning,
            }
        })

        logger.info("Living Agent started successfully")

    async def stop(self) -> None:
        """Stop the Living Agent."""
        if self._state == AgentState.STOPPED:
            return

        self._state = AgentState.STOPPING
        logger.info("Stopping Living Agent...")

        # Signal stop
        self._stop_event.set()

        # Cancel background tasks
        for task in self._tasks:
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass

        self._tasks.clear()

        # Calculate uptime
        uptime = 0.0
        if self._start_time:
            uptime = (datetime.utcnow() - self._start_time).total_seconds()

        self._state = AgentState.STOPPED

        # Emit stopped event
        self._emit(EventType.AGENT_STOPPED, {
            "uptime_seconds": uptime,
            "total_requests": self._metrics.requests_processed,
            "total_threats_blocked": self._metrics.threats_blocked,
        })

        logger.info(f"Living Agent stopped (uptime: {uptime:.0f}s)")

    async def process(
        self,
        user_message: str,
        system_prompt: str = "",
        model: str = "gpt-4o-mini",
        agent_id: str = "default",
        session_id: str = "default",
        user_id: Optional[str] = None,
        org_id: Optional[str] = None,
    ) -> dict[str, Any]:
        """
        Process a request through the Living Agent.

        This is the main entry point for all LLM requests.
        """
        if not self.is_running:
            raise RuntimeError("Agent is not running. Call start() first.")

        start_time = time.time()
        guard = self._get_guard()

        try:
            # Process through Runtime Guard
            result = await guard.before_request(
                user_message=user_message,
                system_prompt=system_prompt,
                model=model,
                agent_id=agent_id,
                session_id=session_id,
                user_id=user_id,
                org_id=org_id,
            )

            latency_ms = (time.time() - start_time) * 1000
            self._metrics.requests_processed += 1

            # Update running average latency
            n = self._metrics.requests_processed
            self._metrics.avg_latency_ms = (
                (self._metrics.avg_latency_ms * (n - 1) + latency_ms) / n
            )

            # Emit events based on result
            if not result.allowed:
                if result.action.value == "block_security":
                    self._metrics.threats_blocked += 1
                    self._metrics.last_threat_time = datetime.utcnow()

                    # Learn from attack pattern
                    if self.enable_learning:
                        self._learn_attack_pattern(user_message, result.security_threats)

                    self._emit(EventType.THREAT_BLOCKED, {
                        "risk_score": result.security_risk_score,
                        "threats": [t.get("pattern_id") for t in result.security_threats[:5]],
                        "user_message_preview": user_message[:100],
                    }, severity="critical")

                elif result.action.value == "block_budget":
                    self._emit(EventType.BUDGET_EXCEEDED, {
                        "reason": result.reason,
                    }, severity="warning")

            else:
                # Successful processing
                if result.cache_hit:
                    self._metrics.cache_hits += 1
                    self._metrics.tokens_saved += result.tokens_saved
                    self._emit(EventType.CACHE_HIT, {
                        "tokens_saved": result.tokens_saved,
                    })
                else:
                    self._metrics.cache_misses += 1

                if result.model_downgraded:
                    self._emit(EventType.MODEL_DOWNGRADED, {
                        "from": result.original_model,
                        "to": result.selected_model,
                        "reason": result.reason,
                    })

                if result.tokens_saved > 0:
                    self._metrics.tokens_saved += result.tokens_saved

            # Store request pattern for learning
            if self.enable_learning:
                self._request_patterns.append({
                    "timestamp": datetime.utcnow(),
                    "message_length": len(user_message),
                    "model": result.selected_model,
                    "blocked": not result.allowed,
                    "latency_ms": latency_ms,
                })

            return {
                "allowed": result.allowed,
                "action": result.action.value,
                "model": result.selected_model,
                "cache_hit": result.cache_hit,
                "cached_response": result.cached_response,
                "security_safe": result.security_safe,
                "risk_score": result.security_risk_score,
                "threats": result.security_threats,
                "tokens_saved": result.tokens_saved,
                "latency_ms": latency_ms,
                "reason": result.reason,
            }

        except Exception as e:
            self._metrics.errors += 1
            self._metrics.last_error_time = datetime.utcnow()
            logger.error(f"Error processing request: {e}")

            if self.auto_heal:
                await self._heal()

            raise

    def on_event(
        self,
        event_type: Optional[EventType],
        callback: Callable[[Event], None],
    ) -> None:
        """
        Subscribe to agent events.

        Parameters
        ----------
        event_type : EventType or None
            Type of event to subscribe to. None = all events.
        callback : callable
            Function to call when event occurs.
        """
        self.events.subscribe(event_type, callback)

    def off_event(
        self,
        event_type: Optional[EventType],
        callback: Callable[[Event], None],
    ) -> None:
        """Unsubscribe from events."""
        self.events.unsubscribe(event_type, callback)

    def _emit(
        self,
        event_type: EventType,
        data: dict[str, Any],
        severity: str = "info",
    ) -> None:
        """Emit an event."""
        event = Event(
            type=event_type,
            timestamp=datetime.utcnow(),
            data=data,
            severity=severity,
        )
        self.events.publish(event)

        # Also push to WebSocket connections
        self._broadcast_ws(event)

    def _broadcast_ws(self, event: Event) -> None:
        """Broadcast event to WebSocket connections."""
        if not self._ws_connections:
            return

        message = json.dumps({
            "type": event.type.value,
            "timestamp": event.timestamp.isoformat(),
            "severity": event.severity,
            "data": event.data,
        })

        # Non-blocking broadcast
        for ws in self._ws_connections:
            try:
                asyncio.create_task(ws.send_text(message))
            except Exception:
                pass

    def register_websocket(self, ws: Any) -> None:
        """Register a WebSocket connection for real-time updates."""
        self._ws_connections.append(ws)
        logger.debug(f"WebSocket registered (total: {len(self._ws_connections)})")

    def unregister_websocket(self, ws: Any) -> None:
        """Unregister a WebSocket connection."""
        if ws in self._ws_connections:
            self._ws_connections.remove(ws)

    async def _health_check_loop(self) -> None:
        """Periodic health check."""
        while not self._stop_event.is_set():
            try:
                await asyncio.sleep(self.health_check_interval)

                if self._stop_event.is_set():
                    break

                # Perform health check
                health = await self._check_health()

                self._emit(EventType.HEALTH_CHECK, health)

                if not health["healthy"] and self.auto_heal:
                    await self._heal()

            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Health check error: {e}")

    async def _metrics_loop(self) -> None:
        """Periodic metrics update."""
        while not self._stop_event.is_set():
            try:
                await asyncio.sleep(self.metrics_interval)

                if self._stop_event.is_set():
                    break

                # Calculate uptime
                uptime = 0.0
                if self._start_time:
                    uptime = (datetime.utcnow() - self._start_time).total_seconds()
                self._metrics.uptime_seconds = uptime

                # Emit metrics update
                self._emit(EventType.METRICS_UPDATE, {
                    "uptime_seconds": uptime,
                    "requests_processed": self._metrics.requests_processed,
                    "threats_blocked": self._metrics.threats_blocked,
                    "tokens_saved": self._metrics.tokens_saved,
                    "cache_hit_rate": (
                        self._metrics.cache_hits /
                        max(self._metrics.cache_hits + self._metrics.cache_misses, 1)
                    ),
                    "avg_latency_ms": self._metrics.avg_latency_ms,
                    "errors": self._metrics.errors,
                })

            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Metrics loop error: {e}")

    async def _learning_loop(self) -> None:
        """Pattern learning and adaptation."""
        while not self._stop_event.is_set():
            try:
                await asyncio.sleep(60)  # Learn every minute

                if self._stop_event.is_set():
                    break

                # Analyze patterns
                if len(self._request_patterns) > 100:
                    anomalies = self._detect_anomalies()
                    if anomalies:
                        self._emit(EventType.ANOMALY_DETECTED, {
                            "anomalies": anomalies,
                        }, severity="warning")

            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Learning loop error: {e}")

    async def _check_health(self) -> dict[str, Any]:
        """Check agent health."""
        healthy = True
        issues = []

        # Check state
        if self._state != AgentState.RUNNING:
            healthy = False
            issues.append(f"State is {self._state.value}")

        # Check error rate
        if self._metrics.requests_processed > 0:
            error_rate = self._metrics.errors / self._metrics.requests_processed
            if error_rate > 0.1:  # > 10% error rate
                healthy = False
                issues.append(f"High error rate: {error_rate:.1%}")

        # Check Runtime Guard
        try:
            guard = self._get_guard()
            if guard is None:
                healthy = False
                issues.append("Runtime Guard not available")
        except Exception as e:
            healthy = False
            issues.append(f"Runtime Guard error: {e}")

        return {
            "healthy": healthy,
            "state": self._state.value,
            "issues": issues,
            "uptime_seconds": self._metrics.uptime_seconds,
        }

    async def _heal(self) -> None:
        """Attempt to heal the agent."""
        logger.warning("Attempting self-heal...")
        self._state = AgentState.HEALING

        self._emit(EventType.SELF_HEAL, {
            "reason": "Auto-heal triggered",
        }, severity="warning")

        try:
            # Reset Runtime Guard
            self._guard = None
            self._get_guard()

            self._state = AgentState.RUNNING
            logger.info("Self-heal successful")

        except Exception as e:
            logger.error(f"Self-heal failed: {e}")
            self._state = AgentState.RUNNING  # Keep running anyway

    def _learn_attack_pattern(
        self,
        message: str,
        threats: list[dict[str, Any]],
    ) -> None:
        """Learn from detected attack patterns."""
        for threat in threats:
            pattern_id = threat.get("pattern_id", "unknown")
            self._attack_patterns[pattern_id] = (
                self._attack_patterns.get(pattern_id, 0) + 1
            )

        # Log top attack patterns
        if sum(self._attack_patterns.values()) % 10 == 0:
            top = sorted(
                self._attack_patterns.items(),
                key=lambda x: x[1],
                reverse=True
            )[:5]
            logger.info(f"Top attack patterns: {top}")

    def _detect_anomalies(self) -> list[str]:
        """Detect anomalies in request patterns."""
        anomalies = []
        patterns = list(self._request_patterns)

        if not patterns:
            return anomalies

        # Check for sudden spike in blocked requests
        recent = [p for p in patterns if p["timestamp"] > datetime.utcnow() - timedelta(minutes=5)]
        if len(recent) > 10:
            block_rate = sum(1 for p in recent if p["blocked"]) / len(recent)
            if block_rate > 0.5:
                anomalies.append(f"High block rate in last 5 min: {block_rate:.1%}")

        # Check for unusual latency
        latencies = [p["latency_ms"] for p in recent if "latency_ms" in p]
        if latencies:
            avg_latency = sum(latencies) / len(latencies)
            if avg_latency > 1000:
                anomalies.append(f"High average latency: {avg_latency:.0f}ms")

        return anomalies

    def get_status(self) -> dict[str, Any]:
        """Get comprehensive agent status."""
        return {
            "state": self._state.value,
            "is_running": self.is_running,
            "start_time": self._start_time.isoformat() if self._start_time else None,
            "metrics": {
                "uptime_seconds": self._metrics.uptime_seconds,
                "requests_processed": self._metrics.requests_processed,
                "threats_blocked": self._metrics.threats_blocked,
                "tokens_saved": self._metrics.tokens_saved,
                "cache_hits": self._metrics.cache_hits,
                "cache_misses": self._metrics.cache_misses,
                "cache_hit_rate": (
                    self._metrics.cache_hits /
                    max(self._metrics.cache_hits + self._metrics.cache_misses, 1)
                ),
                "avg_latency_ms": self._metrics.avg_latency_ms,
                "errors": self._metrics.errors,
            },
            "config": {
                "auto_heal": self.auto_heal,
                "health_check_interval": self.health_check_interval,
                "metrics_interval": self.metrics_interval,
                "enable_learning": self.enable_learning,
            },
            "websocket_connections": len(self._ws_connections),
            "top_attack_patterns": dict(
                sorted(self._attack_patterns.items(), key=lambda x: x[1], reverse=True)[:10]
            ),
        }


# Global singleton instance
_living_agent: Optional[LivingAgent] = None


def get_living_agent() -> LivingAgent:
    """Get or create the global Living Agent instance."""
    global _living_agent
    if _living_agent is None:
        _living_agent = LivingAgent()
    return _living_agent


async def start_living_agent() -> LivingAgent:
    """Start the global Living Agent."""
    agent = get_living_agent()
    if not agent.is_running:
        await agent.start()
    return agent


async def stop_living_agent() -> None:
    """Stop the global Living Agent."""
    global _living_agent
    if _living_agent and _living_agent.is_running:
        await _living_agent.stop()
