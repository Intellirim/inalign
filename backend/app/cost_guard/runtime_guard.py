"""
Runtime Guard - Unified Security + Cost Optimization Layer.

This is the "living system" that combines:
- Injection detection (security)
- Token usage optimization (cost)
- Smart model routing
- Response caching
- Real-time policy enforcement

Think of it as a "living firewall" that protects both security AND budget.
"""
from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from typing import Any, Optional
from enum import Enum

from app.cost_guard.tracker import TokenTracker
from app.cost_guard.compressor import PromptCompressor
from app.cost_guard.cache import ResponseCache
from app.cost_guard.router import ModelRouter, RoutingStrategy
from app.cost_guard.policy import PolicyEngine, BudgetStatus
from app.cost_guard.models import (
    ModelTier, RequestType, CacheStatus, PolicyDecision
)

# Graph integration for auto-labeling and similarity lookup
_graph_labeler = None
_graph_cache = None  # In-memory cache for graph similarity results

logger = logging.getLogger("inalign.runtime_guard")


class GuardAction(str, Enum):
    """Actions the Runtime Guard can take."""
    ALLOW = "allow"                     # Pass through unchanged
    ALLOW_CACHED = "allow_cached"       # Serve from cache
    ALLOW_COMPRESSED = "allow_compressed"  # Allow with compressed prompt
    ALLOW_DOWNGRADED = "allow_downgraded"  # Allow with cheaper model
    BLOCK_SECURITY = "block_security"   # Blocked for security reasons
    BLOCK_BUDGET = "block_budget"       # Blocked for budget reasons
    REQUIRE_APPROVAL = "require_approval"  # Needs approval to proceed


@dataclass
class GuardResult:
    """Result of Runtime Guard evaluation."""
    action: GuardAction
    allowed: bool

    # Security results
    security_safe: bool = True
    security_threats: list[dict[str, Any]] = field(default_factory=list)
    security_risk_score: float = 0.0

    # Cost optimization results
    original_model: Optional[str] = None
    selected_model: Optional[str] = None
    model_downgraded: bool = False
    prompt_compressed: bool = False
    tokens_saved: int = 0

    # Cache results
    cache_hit: bool = False
    cached_response: Optional[str] = None

    # Cost estimates
    estimated_cost_usd: float = 0.0
    estimated_tokens: int = 0

    # Timing
    guard_latency_ms: float = 0.0

    # Messages
    reason: str = ""
    warnings: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)


class RuntimeGuard:
    """
    Unified Runtime Guard - The "living system" for agent security and efficiency.

    Flow:
    1. Security Check (Injection Detection)
    2. Cache Lookup (Skip API if cached)
    3. Policy Evaluation (Budget/limits check)
    4. Model Routing (Cheap → Expensive)
    5. Prompt Compression (If needed)
    6. Track Usage (After response)

    Usage:
        guard = RuntimeGuard()

        # Before LLM call
        result = await guard.before_request(
            user_message="What is 2+2?",
            system_prompt="You are a math tutor.",
            model="gpt-4o",
            agent_id="math-agent",
            session_id="session-123",
        )

        if result.allowed:
            if result.cache_hit:
                response = result.cached_response
            else:
                # Make actual LLM call with result.selected_model
                response = await llm_call(result.selected_model, ...)

                # After LLM call
                guard.after_response(
                    result=result,
                    response=response,
                    prompt_tokens=...,
                    completion_tokens=...,
                )
    """

    def __init__(
        self,
        # Security
        enable_security: bool = True,
        security_detector: Optional[Any] = None,  # InjectionDetector

        # Cost optimization
        enable_cache: bool = True,
        enable_compression: bool = True,
        enable_routing: bool = True,
        enable_policy: bool = True,

        # Configuration
        routing_strategy: RoutingStrategy = RoutingStrategy.BALANCED,
        cache_ttl_seconds: int = 3600,
        compression_aggressive: bool = False,
    ):
        """
        Initialize the Runtime Guard.

        Parameters
        ----------
        enable_security : bool
            Enable injection detection.
        security_detector : InjectionDetector, optional
            Custom security detector. If None, creates default.
        enable_cache : bool
            Enable response caching.
        enable_compression : bool
            Enable prompt compression.
        enable_routing : bool
            Enable smart model routing.
        enable_policy : bool
            Enable cost policy enforcement.
        routing_strategy : RoutingStrategy
            Model routing strategy.
        cache_ttl_seconds : int
            Cache entry TTL.
        compression_aggressive : bool
            Use aggressive compression.
        """
        self.enable_security = enable_security
        self.enable_cache = enable_cache
        self.enable_compression = enable_compression
        self.enable_routing = enable_routing
        self.enable_policy = enable_policy

        # Initialize components
        self.tracker = TokenTracker()

        if enable_cache:
            self.cache = ResponseCache(default_ttl_seconds=cache_ttl_seconds)
        else:
            self.cache = None

        if enable_compression:
            self.compressor = PromptCompressor(aggressive=compression_aggressive)
        else:
            self.compressor = None

        if enable_routing:
            self.router = ModelRouter(strategy=routing_strategy)
        else:
            self.router = None

        if enable_policy:
            self.policy_engine = PolicyEngine(tracker=self.tracker)
        else:
            self.policy_engine = None

        # Security detector (lazy load to avoid circular imports)
        self._security_detector = security_detector
        self._security_detector_loaded = security_detector is not None

        # Graph integration for auto-labeling and cost optimization
        self._graph_labeler = None
        self._graph_labeler_loaded = False
        self.enable_graph = enable_security  # Enable graph if security is enabled

        logger.info(
            f"RuntimeGuard initialized | security={enable_security} cache={enable_cache} "
            f"compression={enable_compression} routing={enable_routing} policy={enable_policy}"
        )

    def _get_security_detector(self):
        """Lazy load security detector."""
        if not self._security_detector_loaded:
            try:
                from app.detectors.injection.detector import InjectionDetector
                self._security_detector = InjectionDetector(
                    use_local_ml=True,
                    use_graphrag=True,
                    use_intent_classifier=True,
                )
                self._security_detector_loaded = True
            except Exception as e:
                logger.error(f"Failed to load security detector: {e}")
                self._security_detector = None
                self._security_detector_loaded = True

        return self._security_detector

    async def _get_graph_labeler(self):
        """Lazy load graph labeler for auto-labeling detection results."""
        if not self._graph_labeler_loaded:
            try:
                from app.services.graph_labeler import get_graph_labeler
                self._graph_labeler = await get_graph_labeler()
                self._graph_labeler_loaded = True
                logger.info("Graph labeler connected for auto-labeling")
            except Exception as e:
                logger.debug(f"Graph labeler not available: {e}")
                self._graph_labeler = None
                self._graph_labeler_loaded = True

        return self._graph_labeler

    async def _check_graph_cache(self, text: str) -> Optional[dict[str, Any]]:
        """
        Check graph for similar known attacks using semantic similarity.

        If a very similar attack exists in graph with high confidence,
        we can skip expensive detection and return cached result.

        This uses embedding-based similarity search, not just exact match.
        """
        if not self.enable_graph:
            return None

        try:
            labeler = await self._get_graph_labeler()
            if not labeler or not labeler._driver:
                return None

            # Step 1: Check for exact match first (fastest)
            async with labeler._driver.session() as session:
                result = await session.run("""
                    MATCH (a:AttackSample)
                    WHERE a.confidence >= 0.95
                    AND a.text = $text
                    RETURN a.category as category, a.confidence as confidence,
                           'exact_match' as match_type
                    LIMIT 1
                """, {"text": text})
                record = await result.single()

                if record:
                    logger.info(f"Graph cache hit (exact): {text[:30]}...")
                    return {
                        "is_attack": True,
                        "confidence": record["confidence"],
                        "category": record["category"],
                        "source": "graph_cache",
                        "match_type": "exact",
                    }

            # Step 2: Semantic similarity search using embeddings
            embedder = labeler._get_embedder()
            if not embedder:
                return None

            # Get embedding for input text
            input_embedding = embedder.encode([text], convert_to_numpy=True)[0]

            # Get high-confidence attacks with embeddings from graph
            async with labeler._driver.session() as session:
                result = await session.run("""
                    MATCH (a:AttackSample)
                    WHERE a.confidence >= 0.90 AND a.embedding IS NOT NULL
                    RETURN a.text as text, a.category as category,
                           a.confidence as confidence, a.embedding as embedding
                    ORDER BY a.created_at DESC
                    LIMIT 100
                """)
                samples = await result.data()

            if not samples:
                return None

            # Calculate similarities
            import numpy as np
            best_match = None
            best_similarity = 0.0

            for sample in samples:
                stored_embedding = np.array(sample["embedding"])
                similarity = float(np.dot(input_embedding, stored_embedding) / (
                    np.linalg.norm(input_embedding) * np.linalg.norm(stored_embedding)
                ))

                if similarity > best_similarity:
                    best_similarity = similarity
                    best_match = sample

            # Require very high similarity (>0.92) for cache hit
            if best_match and best_similarity >= 0.92:
                logger.info(
                    f"Graph cache hit (semantic, sim={best_similarity:.3f}): {text[:30]}..."
                )
                return {
                    "is_attack": True,
                    "confidence": best_match["confidence"] * best_similarity,
                    "category": best_match["category"],
                    "source": "graph_cache",
                    "match_type": "semantic",
                    "similarity": best_similarity,
                    "similar_text": best_match["text"][:50],
                }

            return None

        except Exception as e:
            logger.debug(f"Graph cache check failed: {e}")
            return None

    async def _auto_label_result(
        self,
        text: str,
        security_safe: bool,
        threats: list[dict],
        confidence: float,
    ):
        """Auto-label detection result to graph if high-confidence."""
        if not self.enable_graph:
            return

        try:
            labeler = await self._get_graph_labeler()
            if not labeler:
                return

            if not security_safe and confidence >= 0.85:
                # Store attack sample
                await labeler.store_attack(
                    text=text,
                    threats=threats,
                    confidence=confidence,
                    source="runtime_guard",
                )
            elif security_safe and confidence >= 0.9:
                # Store benign sample (very high confidence only)
                await labeler.store_benign(
                    text=text,
                    confidence=confidence,
                    source="runtime_guard",
                )

        except Exception as e:
            logger.debug(f"Auto-labeling failed: {e}")

    async def before_request(
        self,
        user_message: str,
        system_prompt: str = "",
        model: str = "gpt-4o-mini",
        agent_id: str = "default",
        session_id: str = "default",
        user_id: Optional[str] = None,
        org_id: Optional[str] = None,
        skip_security: bool = False,
        skip_cache: bool = False,
        force_model: Optional[str] = None,
    ) -> GuardResult:
        """
        Evaluate request before making LLM call.

        This is the main entry point for the Runtime Guard.
        """
        start_time = time.time()

        result = GuardResult(
            action=GuardAction.ALLOW,
            allowed=True,
            original_model=model,
            selected_model=model,
        )

        warnings: list[str] = []

        # ===== Step 1: Security Check =====
        if self.enable_security and not skip_security:
            # Step 1a: Check graph cache first (cost optimization)
            graph_result = await self._check_graph_cache(user_message)
            if graph_result and graph_result.get("is_attack"):
                # Known attack from graph - skip expensive detection
                result.security_safe = False
                result.security_threats = [{
                    "type": "known_attack",
                    "category": graph_result.get("category", "unknown"),
                    "confidence": graph_result.get("confidence", 0.95),
                    "source": "graph_cache",
                }]
                result.security_risk_score = graph_result.get("confidence", 0.95)
                result.action = GuardAction.BLOCK_SECURITY
                result.allowed = False
                result.reason = f"Blocked: Known attack pattern (graph cache, conf={result.security_risk_score:.2f})"
                result.metadata["graph_cache_hit"] = True
                result.guard_latency_ms = (time.time() - start_time) * 1000
                return result

            # Step 1b: Full security detection
            security_result = await self._check_security(user_message)

            result.security_safe = security_result.get("safe", True)
            result.security_threats = security_result.get("threats", [])
            result.security_risk_score = security_result.get("risk_score", 0.0)

            # Auto-label to graph for future lookups
            await self._auto_label_result(
                text=user_message,
                security_safe=result.security_safe,
                threats=result.security_threats,
                confidence=1.0 - result.security_risk_score if result.security_safe else result.security_risk_score,
            )

            if not result.security_safe:
                result.action = GuardAction.BLOCK_SECURITY
                result.allowed = False
                result.reason = f"Blocked: Security threat detected (risk={result.security_risk_score:.2f})"
                result.guard_latency_ms = (time.time() - start_time) * 1000
                return result

        # ===== Step 2: Cache Lookup =====
        if self.enable_cache and self.cache and not skip_cache:
            cache_result = self.cache.get(system_prompt, user_message, model)

            if cache_result.hit:
                result.action = GuardAction.ALLOW_CACHED
                result.cache_hit = True
                result.cached_response = cache_result.response
                result.tokens_saved = cache_result.tokens_saved
                result.reason = f"Cache hit (age={cache_result.age_seconds:.0f}s)"
                result.guard_latency_ms = (time.time() - start_time) * 1000
                return result

        # ===== Step 3: Estimate Tokens =====
        estimated_prompt_tokens = self.tracker.estimate_token_count(
            system_prompt + user_message
        )
        result.estimated_tokens = estimated_prompt_tokens

        # ===== Step 4: Policy Evaluation =====
        if self.enable_policy and self.policy_engine:
            # Classify request type
            request_type = RequestType.MODERATE
            if self.router:
                request_type = self.router.classify_request(
                    user_message, system_prompt, estimated_prompt_tokens
                )

            policy_decision = self.policy_engine.evaluate(
                user_message=user_message,
                model=model,
                estimated_prompt_tokens=estimated_prompt_tokens,
                request_type=request_type,
                org_id=org_id,
                user_id=user_id,
                session_id=session_id,
            )

            if not policy_decision.allowed:
                if policy_decision.action == "block":
                    result.action = GuardAction.BLOCK_BUDGET
                    result.allowed = False
                    result.reason = policy_decision.reason
                    result.guard_latency_ms = (time.time() - start_time) * 1000
                    return result

                elif policy_decision.action == "require_approval":
                    result.action = GuardAction.REQUIRE_APPROVAL
                    result.allowed = False
                    result.reason = policy_decision.reason
                    result.metadata["approval_key"] = policy_decision.metadata.get("approval_key")
                    result.guard_latency_ms = (time.time() - start_time) * 1000
                    return result

            # Apply policy suggestions
            if policy_decision.suggested_model and not force_model:
                result.selected_model = policy_decision.suggested_model
                result.model_downgraded = True
                warnings.append(f"Model downgraded: {model} → {policy_decision.suggested_model}")

            if policy_decision.compress_prompt:
                result.metadata["should_compress"] = True

            result.estimated_cost_usd = policy_decision.metadata.get("estimated_cost_usd", 0)

        # ===== Step 5: Model Routing =====
        if self.enable_routing and self.router and not force_model and not result.model_downgraded:
            routing_decision = self.router.route(
                user_message=user_message,
                system_prompt=system_prompt,
                context_tokens=estimated_prompt_tokens,
                preferred_model=model,
            )

            if routing_decision.selected_model != model:
                result.selected_model = routing_decision.selected_model
                result.model_downgraded = routing_decision.downgraded
                if routing_decision.downgraded:
                    warnings.append(f"Routed to cheaper model: {routing_decision.reason}")

            result.estimated_cost_usd = routing_decision.estimated_cost_usd

        # ===== Step 6: Prompt Compression =====
        if self.enable_compression and self.compressor:
            should_compress = (
                result.metadata.get("should_compress", False) or
                estimated_prompt_tokens > 3000
            )

            if should_compress:
                # Store compression info for later use
                result.metadata["compress_prompt"] = True
                result.prompt_compressed = True
                warnings.append("Prompt will be compressed before sending")

        # Force model override
        if force_model:
            result.selected_model = force_model
            result.model_downgraded = False

        # Set final action
        if result.model_downgraded:
            result.action = GuardAction.ALLOW_DOWNGRADED
        elif result.prompt_compressed:
            result.action = GuardAction.ALLOW_COMPRESSED
        else:
            result.action = GuardAction.ALLOW

        result.warnings = warnings
        result.reason = f"Allowed: model={result.selected_model}"
        result.guard_latency_ms = (time.time() - start_time) * 1000

        return result

    async def _check_security(self, text: str) -> dict[str, Any]:
        """Run security detection."""
        detector = self._get_security_detector()
        if not detector:
            return {"safe": True, "threats": [], "risk_score": 0.0}

        try:
            result = await detector.detect(text)
            is_safe = len(result.get("threats", [])) == 0
            return {
                "safe": is_safe,
                "threats": result.get("threats", []),
                "risk_score": result.get("risk_score", 0.0),
            }
        except Exception as e:
            logger.error(f"Security check failed: {e}")
            return {"safe": True, "threats": [], "risk_score": 0.0}

    def compress_prompt(
        self,
        system_prompt: str,
        user_message: str,
    ) -> tuple[str, str, int]:
        """
        Compress prompts if compression is enabled.

        Returns (compressed_system, compressed_user, tokens_saved).
        """
        if not self.compressor:
            return system_prompt, user_message, 0

        total_saved = 0

        # Compress system prompt
        sys_result = self.compressor.compress(system_prompt, "system_prompt")
        total_saved += sys_result.tokens_saved

        # Compress user message
        user_result = self.compressor.compress(user_message, "general")
        total_saved += user_result.tokens_saved

        return sys_result.compressed_text, user_result.compressed_text, total_saved

    def after_response(
        self,
        result: GuardResult,
        response: str,
        prompt_tokens: int,
        completion_tokens: int,
        latency_ms: float,
        user_id: Optional[str] = None,
        org_id: Optional[str] = None,
        agent_id: str = "default",
        session_id: str = "default",
        system_prompt: str = "",
        user_message: str = "",
    ) -> None:
        """
        Record usage after LLM response.

        Call this after receiving the LLM response to:
        1. Track token usage
        2. Cache the response
        """
        # Track usage
        self.tracker.record(
            agent_id=agent_id,
            session_id=session_id,
            model=result.selected_model or result.original_model,
            prompt_tokens=prompt_tokens,
            completion_tokens=completion_tokens,
            latency_ms=latency_ms,
            user_id=user_id,
            org_id=org_id,
            cache_status=CacheStatus.HIT if result.cache_hit else CacheStatus.MISS,
            compressed=result.prompt_compressed,
            original_prompt_tokens=result.estimated_tokens,
        )

        # Cache the response
        if self.cache and not result.cache_hit and system_prompt and user_message:
            self.cache.set(
                system_prompt=system_prompt,
                user_message=user_message,
                model=result.selected_model or result.original_model,
                response=response,
                tokens_used=prompt_tokens + completion_tokens,
            )

    def get_status(
        self,
        org_id: Optional[str] = None,
        user_id: Optional[str] = None,
    ) -> dict[str, Any]:
        """Get comprehensive status of the Runtime Guard."""
        status = {
            "components": {
                "security": self.enable_security,
                "cache": self.enable_cache,
                "compression": self.enable_compression,
                "routing": self.enable_routing,
                "policy": self.enable_policy,
                "graph": self.enable_graph,
            },
        }

        # Usage stats (last 24 hours)
        usage_stats = self.tracker.get_stats(period_hours=24)
        status["usage_24h"] = {
            "requests": usage_stats.total_requests,
            "tokens": usage_stats.total_tokens,
            "cost_usd": round(usage_stats.total_cost_usd, 4),
            "tokens_saved": usage_stats.tokens_saved_by_compression + usage_stats.tokens_saved_by_cache,
            "cost_saved_usd": round(usage_stats.cost_saved_usd, 4),
            "cache_hit_rate": round(usage_stats.cache_hit_rate, 4),
        }

        # Cache stats
        if self.cache:
            status["cache"] = self.cache.get_stats()

        # Budget status
        if self.policy_engine:
            status["budget"] = self.policy_engine.get_policy_summary(org_id, user_id)["budget"]

        return status

    def get_dashboard_data(
        self,
        period_hours: int = 24,
        org_id: Optional[str] = None,
        user_id: Optional[str] = None,
    ) -> dict[str, Any]:
        """Get data for dashboard visualization."""
        stats = self.tracker.get_stats(period_hours=period_hours)

        return {
            "period_hours": period_hours,
            "summary": {
                "total_requests": stats.total_requests,
                "total_tokens": stats.total_tokens,
                "total_cost_usd": round(stats.total_cost_usd, 4),
                "avg_tokens_per_request": round(stats.avg_prompt_tokens + stats.avg_completion_tokens, 1),
                "avg_latency_ms": round(stats.avg_latency_ms, 1),
            },
            "savings": {
                "tokens_saved_compression": stats.tokens_saved_by_compression,
                "tokens_saved_cache": stats.tokens_saved_by_cache,
                "total_tokens_saved": stats.tokens_saved_by_compression + stats.tokens_saved_by_cache,
                "cost_saved_usd": round(stats.cost_saved_usd, 4),
                "cache_hit_rate": round(stats.cache_hit_rate * 100, 1),
                "compression_ratio": round(stats.compression_ratio * 100, 1),
            },
            "breakdown": {
                "by_model": stats.by_model,
                "by_agent": stats.by_agent,
                "by_tier": stats.by_tier,
            },
            "budget": self.policy_engine.get_policy_summary(org_id, user_id)["budget"] if self.policy_engine else None,
        }
