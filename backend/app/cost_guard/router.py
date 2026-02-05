"""
Model Router - Intelligent model selection and routing.

Features:
- Cheap → Expensive model hierarchy
- Request type classification
- Cost-aware model selection
- Automatic downgrade/upgrade based on context
"""
from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from typing import Any, Optional
from enum import Enum

from app.cost_guard.models import (
    ModelTier, RequestType, ModelConfig, DEFAULT_MODEL_CONFIGS
)

logger = logging.getLogger("inalign.cost_guard.router")


class RoutingStrategy(str, Enum):
    """Model routing strategy."""
    COST_OPTIMIZED = "cost_optimized"      # Always use cheapest viable model
    BALANCED = "balanced"                   # Balance cost and quality
    QUALITY_FIRST = "quality_first"         # Prefer higher quality models
    FIXED = "fixed"                         # Always use specified model


@dataclass
class RoutingDecision:
    """Result of model routing decision."""
    selected_model: str
    selected_tier: ModelTier
    original_request_type: RequestType
    upgraded: bool = False      # Was upgraded to better model
    downgraded: bool = False    # Was downgraded to cheaper model
    reason: str = ""
    estimated_cost_usd: float = 0.0
    alternative_models: list[str] = None

    def __post_init__(self):
        if self.alternative_models is None:
            self.alternative_models = []


class ModelRouter:
    """
    Routes requests to appropriate models based on:
    - Request complexity
    - Cost constraints
    - Quality requirements
    - Available models
    """

    # Keywords indicating simple requests (can use cheap model)
    SIMPLE_KEYWORDS = [
        "yes or no", "true or false", "classify", "categorize",
        "label", "extract", "parse", "format", "convert",
        "translate", "summarize briefly", "list", "count",
    ]

    # Keywords indicating complex requests (need expensive model)
    COMPLEX_KEYWORDS = [
        "analyze in detail", "comprehensive", "step by step",
        "explain thoroughly", "creative writing", "code review",
        "debug", "architect", "design", "plan", "strategy",
        "multi-step", "reasoning", "compare and contrast",
    ]

    # Task patterns for classification
    TASK_PATTERNS = {
        RequestType.SIMPLE: [
            r"(?i)^(yes|no|true|false)\??$",
            r"(?i)^(classify|categorize|label|tag)\s",
            r"(?i)^(extract|parse|format)\s",
            r"(?i)^translate\s.*\sto\s",
            r"(?i)^(list|count|enumerate)\s",
        ],
        RequestType.COMPLEX: [
            r"(?i)(analyze|examine|investigate)\s.*\s(detail|depth|thorough)",
            r"(?i)(explain|describe)\s.*\s(step.?by.?step|comprehensive)",
            r"(?i)(write|create|generate)\s.*(code|program|script|function)",
            r"(?i)(review|audit|evaluate)\s.*(code|architecture|design)",
            r"(?i)(plan|design|architect|strategy)\s",
        ],
    }

    def __init__(
        self,
        strategy: RoutingStrategy = RoutingStrategy.BALANCED,
        default_model: str = "gpt-4o-mini",
        cheap_models: Optional[list[str]] = None,
        standard_models: Optional[list[str]] = None,
        expensive_models: Optional[list[str]] = None,
        model_configs: Optional[dict[str, ModelConfig]] = None,
    ):
        """
        Initialize the router.

        Parameters
        ----------
        strategy : RoutingStrategy
            Default routing strategy.
        default_model : str
            Default model when no specific routing applies.
        cheap_models : list[str]
            Models in the cheap tier.
        standard_models : list[str]
            Models in the standard tier.
        expensive_models : list[str]
            Models in the expensive tier.
        """
        self.strategy = strategy
        self.default_model = default_model

        # Model tiers
        self.cheap_models = cheap_models or [
            "gpt-4o-mini", "claude-3-haiku-20240307"
        ]
        self.standard_models = standard_models or [
            "gpt-4o", "claude-3-5-sonnet-20241022"
        ]
        self.expensive_models = expensive_models or [
            "gpt-4-turbo", "claude-3-opus-20240229"
        ]

        # Model configurations
        self.model_configs = model_configs or DEFAULT_MODEL_CONFIGS

        # Compile task patterns
        self._task_patterns = {
            rtype: [re.compile(p) for p in patterns]
            for rtype, patterns in self.TASK_PATTERNS.items()
        }

        logger.info(
            f"ModelRouter initialized (strategy={strategy.value}, "
            f"default={default_model})"
        )

    def classify_request(
        self,
        user_message: str,
        system_prompt: Optional[str] = None,
        context_tokens: int = 0,
    ) -> RequestType:
        """
        Classify request complexity.

        Returns RequestType (SIMPLE, MODERATE, COMPLEX).
        """
        text = f"{system_prompt or ''} {user_message}".lower()

        # Check explicit patterns
        for rtype, patterns in self._task_patterns.items():
            for pattern in patterns:
                if pattern.search(text):
                    return rtype

        # Check keywords
        simple_score = sum(1 for kw in self.SIMPLE_KEYWORDS if kw in text)
        complex_score = sum(1 for kw in self.COMPLEX_KEYWORDS if kw in text)

        # Consider context length
        if context_tokens > 50000:
            complex_score += 2
        elif context_tokens > 10000:
            complex_score += 1

        # Consider message length
        if len(user_message) > 2000:
            complex_score += 1
        elif len(user_message) < 100:
            simple_score += 1

        # Decide
        if simple_score > complex_score + 1:
            return RequestType.SIMPLE
        elif complex_score > simple_score + 1:
            return RequestType.COMPLEX
        else:
            return RequestType.MODERATE

    def route(
        self,
        user_message: str,
        system_prompt: Optional[str] = None,
        context_tokens: int = 0,
        preferred_model: Optional[str] = None,
        max_cost_usd: Optional[float] = None,
        force_tier: Optional[ModelTier] = None,
        strategy_override: Optional[RoutingStrategy] = None,
    ) -> RoutingDecision:
        """
        Route request to appropriate model.

        Parameters
        ----------
        user_message : str
            The user's message/query.
        system_prompt : str, optional
            System prompt (for context classification).
        context_tokens : int
            Current context size in tokens.
        preferred_model : str, optional
            User's preferred model (will try to honor if viable).
        max_cost_usd : float, optional
            Maximum acceptable cost per request.
        force_tier : ModelTier, optional
            Force a specific model tier.
        strategy_override : RoutingStrategy, optional
            Override default strategy for this request.

        Returns
        -------
        RoutingDecision
        """
        strategy = strategy_override or self.strategy

        # Classify the request
        request_type = self.classify_request(
            user_message, system_prompt, context_tokens
        )

        # Determine target tier based on strategy and request type
        if force_tier:
            target_tier = force_tier
        elif strategy == RoutingStrategy.FIXED and preferred_model:
            config = self.model_configs.get(preferred_model)
            target_tier = config.tier if config else ModelTier.STANDARD
        elif strategy == RoutingStrategy.COST_OPTIMIZED:
            # Always start with cheap, upgrade only if necessary
            target_tier = ModelTier.CHEAP
            if request_type == RequestType.COMPLEX:
                target_tier = ModelTier.STANDARD
        elif strategy == RoutingStrategy.QUALITY_FIRST:
            # Start with expensive, downgrade only if cost constrained
            target_tier = ModelTier.EXPENSIVE
            if request_type == RequestType.SIMPLE:
                target_tier = ModelTier.STANDARD
        else:  # BALANCED
            target_tier = {
                RequestType.SIMPLE: ModelTier.CHEAP,
                RequestType.MODERATE: ModelTier.STANDARD,
                RequestType.COMPLEX: ModelTier.EXPENSIVE,
            }.get(request_type, ModelTier.STANDARD)

        # Get models for target tier
        tier_models = self._get_models_for_tier(target_tier)

        # If preferred model is in the tier, use it
        if preferred_model and preferred_model in tier_models:
            selected_model = preferred_model
        else:
            # Select first available model in tier
            selected_model = tier_models[0] if tier_models else self.default_model

        # Check cost constraint
        downgraded = False
        if max_cost_usd:
            config = self.model_configs.get(selected_model)
            if config:
                # Estimate cost (assume ~1000 tokens output)
                estimated_prompt_tokens = context_tokens + len(user_message) // 4
                estimated_cost = config.calculate_cost(estimated_prompt_tokens, 1000)

                if estimated_cost > max_cost_usd:
                    # Try to downgrade
                    cheaper_model, cheaper_tier = self._find_cheaper_model(
                        max_cost_usd, estimated_prompt_tokens
                    )
                    if cheaper_model:
                        selected_model = cheaper_model
                        target_tier = cheaper_tier
                        downgraded = True

        # Get final config
        final_config = self.model_configs.get(selected_model)
        estimated_cost = 0.0
        if final_config:
            estimated_prompt_tokens = context_tokens + len(user_message) // 4
            estimated_cost = final_config.calculate_cost(estimated_prompt_tokens, 1000)

        # Determine alternatives
        alternatives = self._get_alternatives(selected_model, target_tier)

        reason = self._build_reason(
            request_type, target_tier, strategy, downgraded, max_cost_usd
        )

        return RoutingDecision(
            selected_model=selected_model,
            selected_tier=target_tier,
            original_request_type=request_type,
            downgraded=downgraded,
            reason=reason,
            estimated_cost_usd=estimated_cost,
            alternative_models=alternatives,
        )

    def _get_models_for_tier(self, tier: ModelTier) -> list[str]:
        """Get available models for a tier."""
        if tier == ModelTier.CHEAP:
            return self.cheap_models
        elif tier == ModelTier.STANDARD:
            return self.standard_models
        else:
            return self.expensive_models

    def _find_cheaper_model(
        self,
        max_cost_usd: float,
        estimated_prompt_tokens: int,
    ) -> tuple[Optional[str], Optional[ModelTier]]:
        """Find a model that fits within cost constraint."""
        # Try tiers from cheap to standard
        for tier, models in [
            (ModelTier.CHEAP, self.cheap_models),
            (ModelTier.STANDARD, self.standard_models),
        ]:
            for model in models:
                config = self.model_configs.get(model)
                if config:
                    cost = config.calculate_cost(estimated_prompt_tokens, 1000)
                    if cost <= max_cost_usd:
                        return model, tier

        return None, None

    def _get_alternatives(
        self,
        selected_model: str,
        tier: ModelTier,
    ) -> list[str]:
        """Get alternative models."""
        tier_models = self._get_models_for_tier(tier)
        return [m for m in tier_models if m != selected_model][:3]

    def _build_reason(
        self,
        request_type: RequestType,
        tier: ModelTier,
        strategy: RoutingStrategy,
        downgraded: bool,
        max_cost: Optional[float],
    ) -> str:
        """Build explanation for routing decision."""
        parts = []

        parts.append(f"Request classified as {request_type.value}")
        parts.append(f"Strategy: {strategy.value}")

        if downgraded:
            parts.append(f"Downgraded due to cost limit (${max_cost:.2f})")
        else:
            parts.append(f"Selected {tier.value} tier")

        return " | ".join(parts)

    def suggest_upgrade(
        self,
        current_model: str,
        quality_score: float,  # 0-1, lower = worse quality
        threshold: float = 0.6,
    ) -> Optional[str]:
        """
        Suggest model upgrade if quality is poor.

        Returns suggested model or None.
        """
        if quality_score >= threshold:
            return None

        config = self.model_configs.get(current_model)
        if not config:
            return None

        # Suggest upgrade based on current tier
        if config.tier == ModelTier.CHEAP:
            return self.standard_models[0] if self.standard_models else None
        elif config.tier == ModelTier.STANDARD:
            return self.expensive_models[0] if self.expensive_models else None

        return None

    def get_tier_for_model(self, model: str) -> ModelTier:
        """Get tier for a specific model."""
        config = self.model_configs.get(model)
        if config:
            return config.tier

        # Fallback: check lists
        if model in self.cheap_models:
            return ModelTier.CHEAP
        elif model in self.expensive_models:
            return ModelTier.EXPENSIVE
        else:
            return ModelTier.STANDARD
