"""
In-A-Lign Guard - Core protection class.

The Guard is the main entry point for protecting AI agents.
It can be used standalone or integrated with frameworks.
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass, field
from typing import Any, Optional, Callable
from enum import Enum

logger = logging.getLogger("inalign.guard")


class ThreatLevel(str, Enum):
    """Threat severity levels."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    NONE = "none"


@dataclass
class GuardResult:
    """Result of a Guard check."""
    safe: bool
    risk_score: float = 0.0
    threat_level: ThreatLevel = ThreatLevel.NONE
    threats: list[dict[str, Any]] = field(default_factory=list)
    blocked: bool = False
    cached: bool = False
    latency_ms: float = 0.0

    # For debugging
    details: dict[str, Any] = field(default_factory=dict)

    def __bool__(self) -> bool:
        """Allow using result directly in if statements."""
        return self.safe


@dataclass
class GuardConfig:
    """Configuration for Guard."""
    # Detection settings
    block_threshold: float = 0.5  # Block if risk_score >= this
    use_ml: bool = True  # Use ML classifier
    use_rules: bool = True  # Use rule-based detection
    use_graphrag: bool = False  # Use GraphRAG (requires Neo4j)

    # Performance settings
    enable_cache: bool = True
    cache_ttl_seconds: int = 3600

    # Logging
    log_blocked: bool = True
    log_allowed: bool = False

    # Callbacks
    on_block: Optional[Callable[[GuardResult], None]] = None
    on_threat: Optional[Callable[[GuardResult], None]] = None


class Guard:
    """
    Main protection class for AI agents.

    Usage:
        # Basic usage
        guard = Guard()
        result = guard.check("user input")
        if result.safe:
            response = llm.generate(user_input)

        # Async usage
        result = await guard.check_async("user input")

        # With custom config
        guard = Guard(config=GuardConfig(block_threshold=0.7))

        # As decorator
        @guard.protect
        def my_agent(user_input: str) -> str:
            return llm.generate(user_input)
    """

    def __init__(
        self,
        config: Optional[GuardConfig] = None,
        api_key: Optional[str] = None,
    ):
        """
        Initialize the Guard.

        Parameters
        ----------
        config : GuardConfig, optional
            Configuration settings. Uses defaults if not provided.
        api_key : str, optional
            API key for cloud features (GraphRAG, advanced ML).
        """
        self.config = config or GuardConfig()
        self.api_key = api_key
        self._detector = None
        self._initialized = False

    def _ensure_initialized(self):
        """Lazy initialization of detector."""
        if self._initialized:
            return

        try:
            from app.detectors.injection.detector import InjectionDetector
            self._detector = InjectionDetector(
                use_local_ml=self.config.use_ml,
                use_graphrag=self.config.use_graphrag,
                use_intent_classifier=True,
            )
            self._initialized = True
            logger.info("Guard initialized with local detector")
        except ImportError:
            # Fallback to lightweight detection
            from inalign.lite_detector import LiteDetector
            self._detector = LiteDetector()
            self._initialized = True
            logger.info("Guard initialized with lite detector")

    def check(self, text: str) -> GuardResult:
        """
        Check if input is safe (synchronous).

        Parameters
        ----------
        text : str
            User input to check.

        Returns
        -------
        GuardResult
            Result with safe/blocked status and threat details.
        """
        import time
        start = time.time()

        self._ensure_initialized()

        # Run async detection in sync context
        try:
            loop = asyncio.get_event_loop()
            if loop.is_running():
                # Already in async context, run directly
                import concurrent.futures
                with concurrent.futures.ThreadPoolExecutor() as pool:
                    future = pool.submit(asyncio.run, self._check_async(text))
                    result = future.result()
            else:
                result = loop.run_until_complete(self._check_async(text))
        except RuntimeError:
            # No event loop, create one
            result = asyncio.run(self._check_async(text))

        result.latency_ms = (time.time() - start) * 1000

        # Callbacks
        if result.blocked and self.config.on_block:
            self.config.on_block(result)
        elif result.threats and self.config.on_threat:
            self.config.on_threat(result)

        # Logging
        if result.blocked and self.config.log_blocked:
            logger.warning(f"Blocked input: {text[:50]}... | threats={len(result.threats)}")
        elif self.config.log_allowed:
            logger.debug(f"Allowed input: {text[:50]}...")

        return result

    async def check_async(self, text: str) -> GuardResult:
        """
        Check if input is safe (asynchronous).

        Parameters
        ----------
        text : str
            User input to check.

        Returns
        -------
        GuardResult
            Result with safe/blocked status and threat details.
        """
        import time
        start = time.time()

        self._ensure_initialized()
        result = await self._check_async(text)
        result.latency_ms = (time.time() - start) * 1000

        return result

    async def _check_async(self, text: str) -> GuardResult:
        """Internal async check."""
        if not text or not text.strip():
            return GuardResult(safe=True, risk_score=0.0, threat_level=ThreatLevel.NONE)

        # Run detection
        detection = await self._detector.detect(text)

        risk_score = detection.get("risk_score", 0.0)
        threats = detection.get("threats", [])

        # Determine threat level
        if risk_score >= 0.8:
            threat_level = ThreatLevel.CRITICAL
        elif risk_score >= 0.6:
            threat_level = ThreatLevel.HIGH
        elif risk_score >= 0.35:
            threat_level = ThreatLevel.MEDIUM
        elif risk_score >= 0.1:
            threat_level = ThreatLevel.LOW
        else:
            threat_level = ThreatLevel.NONE

        # Determine if blocked
        blocked = risk_score >= self.config.block_threshold
        safe = not blocked

        return GuardResult(
            safe=safe,
            risk_score=risk_score,
            threat_level=threat_level,
            threats=threats,
            blocked=blocked,
            details={
                "risk_level": detection.get("risk_level", "unknown"),
                "intent_bypass": detection.get("intent_bypass", False),
            }
        )

    def protect(self, func: Callable) -> Callable:
        """
        Decorator to protect a function.

        Usage:
            @guard.protect
            def my_agent(user_input: str) -> str:
                return llm.generate(user_input)

        The decorated function will raise SecurityError if input is blocked.
        """
        import functools

        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            # Find the input text (first string argument)
            text = None
            for arg in args:
                if isinstance(arg, str):
                    text = arg
                    break
            if text is None:
                for v in kwargs.values():
                    if isinstance(v, str):
                        text = v
                        break

            if text:
                result = self.check(text)
                if result.blocked:
                    raise SecurityError(
                        f"Input blocked by In-A-Lign Guard: {result.threat_level.value} risk",
                        result=result
                    )

            return func(*args, **kwargs)

        return wrapper

    def protect_async(self, func: Callable) -> Callable:
        """Async version of protect decorator."""
        import functools

        @functools.wraps(func)
        async def wrapper(*args, **kwargs):
            text = None
            for arg in args:
                if isinstance(arg, str):
                    text = arg
                    break
            if text is None:
                for v in kwargs.values():
                    if isinstance(v, str):
                        text = v
                        break

            if text:
                result = await self.check_async(text)
                if result.blocked:
                    raise SecurityError(
                        f"Input blocked by In-A-Lign Guard: {result.threat_level.value} risk",
                        result=result
                    )

            return await func(*args, **kwargs)

        return wrapper


class SecurityError(Exception):
    """Raised when Guard blocks an input."""

    def __init__(self, message: str, result: GuardResult):
        super().__init__(message)
        self.result = result
