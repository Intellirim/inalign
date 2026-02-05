"""
In-A-Lign Efficiency Engine.

Provides cost optimization features:
- Smart model routing (complexity-based)
- Response caching (semantic + exact)
- Token optimization
- Cost tracking & analytics
"""

import hashlib
import json
import logging
import re
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any, Callable, Optional

logger = logging.getLogger("inalign.efficiency")


# ============================================================================
# Cost Configuration
# ============================================================================

MODEL_COSTS = {
    # OpenAI (per 1K tokens)
    "gpt-4": {"input": 0.03, "output": 0.06},
    "gpt-4-turbo": {"input": 0.01, "output": 0.03},
    "gpt-4o": {"input": 0.005, "output": 0.015},
    "gpt-4o-mini": {"input": 0.00015, "output": 0.0006},
    "gpt-3.5-turbo": {"input": 0.0005, "output": 0.0015},
    # Anthropic (per 1K tokens)
    "claude-3-opus": {"input": 0.015, "output": 0.075},
    "claude-3-sonnet": {"input": 0.003, "output": 0.015},
    "claude-3-haiku": {"input": 0.00025, "output": 0.00125},
    "claude-3-5-sonnet": {"input": 0.003, "output": 0.015},
}

# Complexity thresholds for routing
COMPLEXITY_THRESHOLDS = {
    "simple": 0.3,
    "medium": 0.6,
    "complex": 1.0,
}


@dataclass
class UsageStats:
    """Track usage statistics."""

    total_requests: int = 0
    cached_requests: int = 0
    tokens_input: int = 0
    tokens_output: int = 0
    cost_actual: float = 0.0
    cost_without_optimization: float = 0.0
    requests_by_model: dict = field(default_factory=dict)
    requests_by_hour: dict = field(default_factory=dict)

    @property
    def cost_saved(self) -> float:
        return self.cost_without_optimization - self.cost_actual

    @property
    def cache_hit_rate(self) -> float:
        if self.total_requests == 0:
            return 0.0
        return self.cached_requests / self.total_requests

    def to_dict(self) -> dict:
        return {
            "total_requests": self.total_requests,
            "cached_requests": self.cached_requests,
            "cache_hit_rate": f"{self.cache_hit_rate:.1%}",
            "tokens": {
                "input": self.tokens_input,
                "output": self.tokens_output,
                "total": self.tokens_input + self.tokens_output,
            },
            "cost": {
                "actual": f"${self.cost_actual:.4f}",
                "without_optimization": f"${self.cost_without_optimization:.4f}",
                "saved": f"${self.cost_saved:.4f}",
                "savings_percent": f"{(self.cost_saved / max(self.cost_without_optimization, 0.001)) * 100:.1f}%",
            },
            "requests_by_model": self.requests_by_model,
        }


@dataclass
class CacheEntry:
    """A cached response."""

    response: str
    model: str
    tokens: int
    created_at: datetime
    ttl_hours: int
    hits: int = 0

    def is_expired(self) -> bool:
        return datetime.now() > self.created_at + timedelta(hours=self.ttl_hours)


class ResponseCache:
    """
    Intelligent response caching with multiple strategies.
    """

    def __init__(self, max_size: int = 10000, default_ttl_hours: int = 24):
        self.max_size = max_size
        self.default_ttl_hours = default_ttl_hours
        self._exact_cache: dict[str, CacheEntry] = {}
        self._semantic_cache: dict[str, CacheEntry] = {}  # Would need embeddings

    def _hash_query(self, query: str, system_prompt: Optional[str] = None) -> str:
        """Create hash for exact matching."""
        content = f"{system_prompt or ''}::{query}".lower().strip()
        return hashlib.sha256(content.encode()).hexdigest()

    def get(self, query: str, system_prompt: Optional[str] = None) -> Optional[CacheEntry]:
        """Get cached response if available."""
        key = self._hash_query(query, system_prompt)

        if key in self._exact_cache:
            entry = self._exact_cache[key]
            if not entry.is_expired():
                entry.hits += 1
                return entry
            else:
                del self._exact_cache[key]

        return None

    def set(
        self,
        query: str,
        response: str,
        model: str,
        tokens: int,
        system_prompt: Optional[str] = None,
        ttl_hours: Optional[int] = None,
    ) -> None:
        """Cache a response."""
        # Evict if at capacity
        if len(self._exact_cache) >= self.max_size:
            self._evict_oldest()

        key = self._hash_query(query, system_prompt)
        self._exact_cache[key] = CacheEntry(
            response=response,
            model=model,
            tokens=tokens,
            created_at=datetime.now(),
            ttl_hours=ttl_hours or self.default_ttl_hours,
        )

    def _evict_oldest(self) -> None:
        """Remove oldest entries."""
        if not self._exact_cache:
            return

        # Sort by created_at and remove oldest 10%
        sorted_keys = sorted(
            self._exact_cache.keys(),
            key=lambda k: self._exact_cache[k].created_at,
        )
        for key in sorted_keys[: len(sorted_keys) // 10]:
            del self._exact_cache[key]

    def clear(self) -> None:
        """Clear all caches."""
        self._exact_cache.clear()
        self._semantic_cache.clear()

    def stats(self) -> dict:
        """Get cache statistics."""
        total_hits = sum(e.hits for e in self._exact_cache.values())
        return {
            "size": len(self._exact_cache),
            "max_size": self.max_size,
            "total_hits": total_hits,
        }


class ComplexityAnalyzer:
    """
    Analyzes query complexity to determine optimal model.
    """

    # Indicators of complex queries
    COMPLEX_INDICATORS = [
        r"\b(analyze|explain|compare|evaluate|synthesize)\b",
        r"\b(step by step|detailed|comprehensive|thorough)\b",
        r"\b(code|program|implement|debug|optimize)\b",
        r"\b(math|calculation|equation|formula)\b",
        r"\b(research|study|investigate|explore)\b",
        r"\?.*\?",  # Multiple questions
    ]

    # Indicators of simple queries
    SIMPLE_INDICATORS = [
        r"^(what is|who is|when|where|yes or no)\b",
        r"^(translate|convert|summarize briefly)\b",
        r"\b(simple|quick|short|brief)\b",
    ]

    def analyze(self, query: str) -> dict:
        """
        Analyze query complexity.

        Returns:
            Dict with complexity score and recommended tier
        """
        query_lower = query.lower()
        score = 0.5  # Base score

        # Check for complex indicators
        for pattern in self.COMPLEX_INDICATORS:
            if re.search(pattern, query_lower):
                score += 0.1

        # Check for simple indicators
        for pattern in self.SIMPLE_INDICATORS:
            if re.search(pattern, query_lower):
                score -= 0.15

        # Length factor
        word_count = len(query.split())
        if word_count > 100:
            score += 0.15
        elif word_count < 20:
            score -= 0.1

        # Clamp score
        score = max(0.0, min(1.0, score))

        # Determine tier
        if score < COMPLEXITY_THRESHOLDS["simple"]:
            tier = "simple"
        elif score < COMPLEXITY_THRESHOLDS["medium"]:
            tier = "medium"
        else:
            tier = "complex"

        return {
            "score": round(score, 3),
            "tier": tier,
            "word_count": word_count,
        }


class SmartRouter:
    """
    Routes queries to optimal models based on complexity and cost.
    """

    DEFAULT_ROUTING = {
        "simple": "gpt-4o-mini",
        "medium": "gpt-4o",
        "complex": "gpt-4-turbo",
    }

    def __init__(self, routing_config: Optional[dict] = None):
        self.routing = routing_config or self.DEFAULT_ROUTING
        self.analyzer = ComplexityAnalyzer()

    def route(self, query: str, force_model: Optional[str] = None) -> dict:
        """
        Determine optimal model for query.

        Args:
            query: The user query
            force_model: Override automatic routing

        Returns:
            Dict with selected model and analysis
        """
        if force_model:
            return {
                "model": force_model,
                "reason": "forced",
                "analysis": None,
            }

        analysis = self.analyzer.analyze(query)
        tier = analysis["tier"]
        model = self.routing.get(tier, self.routing["medium"])

        return {
            "model": model,
            "reason": f"complexity_{tier}",
            "analysis": analysis,
        }

    def estimate_cost(self, model: str, input_tokens: int, output_tokens: int) -> float:
        """Estimate cost for a request."""
        if model not in MODEL_COSTS:
            return 0.0

        costs = MODEL_COSTS[model]
        input_cost = (input_tokens / 1000) * costs["input"]
        output_cost = (output_tokens / 1000) * costs["output"]
        return input_cost + output_cost


class EfficiencyEngine:
    """
    Main efficiency engine combining all optimization features.

    Usage:
        engine = EfficiencyEngine()

        # Before calling LLM
        result = engine.optimize_request(query, system_prompt)
        if result["cached"]:
            return result["response"]

        # Call LLM with result["model"]
        response = call_llm(result["model"], query)

        # After getting response
        engine.record_response(query, response, model, tokens)
    """

    def __init__(
        self,
        enable_caching: bool = True,
        enable_routing: bool = True,
        routing_config: Optional[dict] = None,
        cache_ttl_hours: int = 24,
    ):
        self.enable_caching = enable_caching
        self.enable_routing = enable_routing

        self.cache = ResponseCache(default_ttl_hours=cache_ttl_hours)
        self.router = SmartRouter(routing_config)
        self.stats = UsageStats()

    def optimize_request(
        self,
        query: str,
        system_prompt: Optional[str] = None,
        force_model: Optional[str] = None,
        skip_cache: bool = False,
    ) -> dict:
        """
        Optimize an LLM request.

        Args:
            query: User query
            system_prompt: System prompt (for cache key)
            force_model: Force a specific model
            skip_cache: Skip cache lookup

        Returns:
            Dict with optimization results
        """
        self.stats.total_requests += 1
        hour_key = datetime.now().strftime("%Y-%m-%d-%H")
        self.stats.requests_by_hour[hour_key] = self.stats.requests_by_hour.get(hour_key, 0) + 1

        result = {
            "cached": False,
            "response": None,
            "model": None,
            "analysis": None,
        }

        # Check cache first
        if self.enable_caching and not skip_cache:
            cached = self.cache.get(query, system_prompt)
            if cached:
                self.stats.cached_requests += 1
                result["cached"] = True
                result["response"] = cached.response
                result["model"] = cached.model
                return result

        # Route to optimal model
        if self.enable_routing:
            routing = self.router.route(query, force_model)
            result["model"] = routing["model"]
            result["analysis"] = routing["analysis"]
        else:
            result["model"] = force_model or "gpt-4o"

        return result

    def record_response(
        self,
        query: str,
        response: str,
        model: str,
        input_tokens: int,
        output_tokens: int,
        system_prompt: Optional[str] = None,
        cache_response: bool = True,
    ) -> dict:
        """
        Record a response and update statistics.

        Args:
            query: Original query
            response: LLM response
            model: Model used
            input_tokens: Input token count
            output_tokens: Output token count
            system_prompt: System prompt used
            cache_response: Whether to cache this response

        Returns:
            Dict with cost information
        """
        # Calculate costs
        actual_cost = self.router.estimate_cost(model, input_tokens, output_tokens)

        # What would it cost with GPT-4?
        baseline_cost = self.router.estimate_cost("gpt-4", input_tokens, output_tokens)

        # Update stats
        self.stats.total_requests += 1
        self.stats.tokens_input += input_tokens
        self.stats.tokens_output += output_tokens
        self.stats.cost_actual += actual_cost
        self.stats.cost_without_optimization += baseline_cost
        self.stats.requests_by_model[model] = self.stats.requests_by_model.get(model, 0) + 1

        # Cache response
        if self.enable_caching and cache_response:
            self.cache.set(
                query=query,
                response=response,
                model=model,
                tokens=input_tokens + output_tokens,
                system_prompt=system_prompt,
            )

        return {
            "cost": actual_cost,
            "baseline_cost": baseline_cost,
            "saved": baseline_cost - actual_cost,
        }

    def get_stats(self) -> dict:
        """Get current usage statistics."""
        return {
            "usage": self.stats.to_dict(),
            "cache": self.cache.stats(),
        }

    def reset_stats(self) -> None:
        """Reset usage statistics."""
        self.stats = UsageStats()


# ============================================================================
# Convenience Functions
# ============================================================================

# Global engine instance
_default_engine: Optional[EfficiencyEngine] = None


def get_engine() -> EfficiencyEngine:
    """Get or create default engine."""
    global _default_engine
    if _default_engine is None:
        _default_engine = EfficiencyEngine()
    return _default_engine


def optimize(query: str, **kwargs) -> dict:
    """Optimize a request using default engine."""
    return get_engine().optimize_request(query, **kwargs)


def record(query: str, response: str, model: str, input_tokens: int, output_tokens: int, **kwargs) -> dict:
    """Record a response using default engine."""
    return get_engine().record_response(query, response, model, input_tokens, output_tokens, **kwargs)


def stats() -> dict:
    """Get stats from default engine."""
    return get_engine().get_stats()
