"""
Data models for Cost Guard module.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Optional


class ModelTier(str, Enum):
    """Model tier classification by cost/capability."""
    CHEAP = "cheap"           # e.g., gpt-3.5-turbo, claude-3-haiku
    STANDARD = "standard"     # e.g., gpt-4o-mini, claude-3-sonnet
    EXPENSIVE = "expensive"   # e.g., gpt-4, claude-3-opus


class RequestType(str, Enum):
    """Request type classification for routing."""
    SIMPLE = "simple"         # Simple queries, classification
    MODERATE = "moderate"     # Code generation, analysis
    COMPLEX = "complex"       # Multi-step reasoning, long context


class CacheStatus(str, Enum):
    """Cache lookup result status."""
    HIT = "hit"
    MISS = "miss"
    EXPIRED = "expired"
    BYPASSED = "bypassed"


@dataclass
class TokenCount:
    """Token count breakdown."""
    prompt_tokens: int = 0
    completion_tokens: int = 0
    total_tokens: int = 0
    cached_tokens: int = 0  # Tokens served from cache (saved)

    def __post_init__(self):
        if self.total_tokens == 0:
            self.total_tokens = self.prompt_tokens + self.completion_tokens


@dataclass
class UsageRecord:
    """Single usage record for tracking."""
    timestamp: datetime
    agent_id: str
    session_id: str
    user_id: Optional[str]
    org_id: Optional[str]
    model: str
    model_tier: ModelTier
    request_type: RequestType
    tokens: TokenCount
    cost_usd: float
    cache_status: CacheStatus
    latency_ms: float
    compressed: bool = False
    original_prompt_tokens: int = 0  # Before compression
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class UsageStats:
    """Aggregated usage statistics."""
    period_start: datetime
    period_end: datetime

    # Totals
    total_requests: int = 0
    total_tokens: int = 0
    total_prompt_tokens: int = 0
    total_completion_tokens: int = 0
    total_cost_usd: float = 0.0

    # Savings
    cached_requests: int = 0
    cached_tokens: int = 0
    tokens_saved_by_compression: int = 0
    tokens_saved_by_cache: int = 0
    cost_saved_usd: float = 0.0

    # Breakdowns
    by_model: dict[str, dict[str, Any]] = field(default_factory=dict)
    by_agent: dict[str, dict[str, Any]] = field(default_factory=dict)
    by_user: dict[str, dict[str, Any]] = field(default_factory=dict)
    by_org: dict[str, dict[str, Any]] = field(default_factory=dict)
    by_tier: dict[str, dict[str, Any]] = field(default_factory=dict)

    # Averages
    avg_prompt_tokens: float = 0.0
    avg_completion_tokens: float = 0.0
    avg_latency_ms: float = 0.0
    cache_hit_rate: float = 0.0
    compression_ratio: float = 0.0


@dataclass
class CostPolicy:
    """Cost policy configuration."""
    policy_id: str
    name: str
    enabled: bool = True

    # Budget limits
    daily_budget_usd: Optional[float] = None
    monthly_budget_usd: Optional[float] = None
    per_request_limit_tokens: Optional[int] = None
    per_request_limit_usd: Optional[float] = None

    # Auto-actions
    auto_compress_threshold_tokens: int = 2000  # Compress if > N tokens
    auto_downgrade_threshold_usd: float = 0.10  # Downgrade model if > $0.10
    auto_cache_enabled: bool = True

    # Model preferences
    default_tier: ModelTier = ModelTier.STANDARD
    allow_expensive_tier: bool = True
    require_approval_for_expensive: bool = False

    # Routing rules
    force_cheap_for_types: list[RequestType] = field(
        default_factory=lambda: [RequestType.SIMPLE]
    )

    # Alerts
    alert_at_budget_percent: float = 80.0  # Alert when 80% consumed

    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class PolicyDecision:
    """Result of policy evaluation."""
    allowed: bool
    action: str  # "allow", "downgrade", "compress", "cache", "block", "require_approval"
    reason: str
    suggested_model: Optional[str] = None
    suggested_tier: Optional[ModelTier] = None
    compress_prompt: bool = False
    use_cache: bool = True
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class ModelConfig:
    """Model configuration with pricing."""
    model_id: str
    provider: str  # "openai", "anthropic", "local"
    tier: ModelTier

    # Pricing (per 1M tokens, USD)
    input_price_per_million: float
    output_price_per_million: float

    # Capabilities
    max_context_tokens: int
    supports_tools: bool = True
    supports_vision: bool = False

    # Performance
    avg_latency_ms: float = 500.0

    def calculate_cost(self, prompt_tokens: int, completion_tokens: int) -> float:
        """Calculate cost for given token counts."""
        input_cost = (prompt_tokens / 1_000_000) * self.input_price_per_million
        output_cost = (completion_tokens / 1_000_000) * self.output_price_per_million
        return input_cost + output_cost


# Default model configurations
DEFAULT_MODEL_CONFIGS: dict[str, ModelConfig] = {
    # OpenAI
    "gpt-4o": ModelConfig(
        model_id="gpt-4o",
        provider="openai",
        tier=ModelTier.STANDARD,
        input_price_per_million=2.50,
        output_price_per_million=10.00,
        max_context_tokens=128000,
        supports_vision=True,
    ),
    "gpt-4o-mini": ModelConfig(
        model_id="gpt-4o-mini",
        provider="openai",
        tier=ModelTier.CHEAP,
        input_price_per_million=0.15,
        output_price_per_million=0.60,
        max_context_tokens=128000,
        supports_vision=True,
    ),
    "gpt-4-turbo": ModelConfig(
        model_id="gpt-4-turbo",
        provider="openai",
        tier=ModelTier.EXPENSIVE,
        input_price_per_million=10.00,
        output_price_per_million=30.00,
        max_context_tokens=128000,
        supports_vision=True,
    ),
    # Anthropic
    "claude-3-5-sonnet-20241022": ModelConfig(
        model_id="claude-3-5-sonnet-20241022",
        provider="anthropic",
        tier=ModelTier.STANDARD,
        input_price_per_million=3.00,
        output_price_per_million=15.00,
        max_context_tokens=200000,
        supports_vision=True,
    ),
    "claude-3-haiku-20240307": ModelConfig(
        model_id="claude-3-haiku-20240307",
        provider="anthropic",
        tier=ModelTier.CHEAP,
        input_price_per_million=0.25,
        output_price_per_million=1.25,
        max_context_tokens=200000,
        supports_vision=True,
    ),
    "claude-3-opus-20240229": ModelConfig(
        model_id="claude-3-opus-20240229",
        provider="anthropic",
        tier=ModelTier.EXPENSIVE,
        input_price_per_million=15.00,
        output_price_per_million=75.00,
        max_context_tokens=200000,
        supports_vision=True,
    ),
}
