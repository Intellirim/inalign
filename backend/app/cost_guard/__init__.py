"""
Cost Guard Module - Token Cost Optimization for LLM Operations.

This module provides:
- Token usage tracking and analytics
- Prompt compression and optimization
- Response caching (hash-based deduplication)
- Cheap → Expensive model routing
- Cost guardrails and budget policies
- Unified Runtime Guard (Security + Cost)
- Living Agent (Always-running intelligent guardian)
"""

from app.cost_guard.tracker import TokenTracker
from app.cost_guard.compressor import PromptCompressor
from app.cost_guard.cache import ResponseCache
from app.cost_guard.router import ModelRouter, RoutingStrategy
from app.cost_guard.policy import PolicyEngine
from app.cost_guard.runtime_guard import RuntimeGuard, GuardAction, GuardResult
from app.cost_guard.living_agent import (
    LivingAgent, get_living_agent, start_living_agent, stop_living_agent,
    EventType, Event, AgentState
)
from app.cost_guard.models import (
    ModelTier, RequestType, CacheStatus,
    TokenCount, UsageRecord, UsageStats, CostPolicy, ModelConfig
)

__all__ = [
    # Main entry points
    "RuntimeGuard",
    "GuardAction",
    "GuardResult",
    # Living Agent
    "LivingAgent",
    "get_living_agent",
    "start_living_agent",
    "stop_living_agent",
    "EventType",
    "Event",
    "AgentState",
    # Components
    "TokenTracker",
    "PromptCompressor",
    "ResponseCache",
    "ModelRouter",
    "RoutingStrategy",
    "PolicyEngine",
    # Models
    "ModelTier",
    "RequestType",
    "CacheStatus",
    "TokenCount",
    "UsageRecord",
    "UsageStats",
    "CostPolicy",
    "ModelConfig",
]
