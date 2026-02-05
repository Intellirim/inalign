"""
AI Model Database with benchmarks and pricing.

Updated: 2026-02 based on latest benchmarks and pricing.
Sources:
- https://artificialanalysis.ai/leaderboards/models
- https://llm-stats.com/
- https://intuitionlabs.ai/articles/llm-api-pricing-comparison-2025
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional


@dataclass
class ModelInfo:
    """Information about an AI model."""

    id: str
    provider: str
    name: str

    # Pricing per 1M tokens (USD)
    input_price: float
    output_price: float
    cached_input_price: Optional[float] = None

    # Capabilities (0-100 score)
    coding: int = 50
    reasoning: int = 50
    creativity: int = 50
    translation: int = 50
    summarization: int = 50
    conversation: int = 50
    math: int = 50

    # Technical specs
    context_window: int = 128000
    max_output: int = 4096
    supports_vision: bool = False
    supports_function_calling: bool = True

    # Speed (tokens per second, approximate)
    speed_tps: int = 50

    # Best for
    best_for: list[str] = None

    def __post_init__(self):
        if self.best_for is None:
            self.best_for = []


# =============================================================================
# Model Database (2026-02)
# =============================================================================

MODELS: dict[str, ModelInfo] = {
    # =========================================================================
    # OpenAI Models
    # =========================================================================
    "gpt-4o": ModelInfo(
        id="gpt-4o",
        provider="openai",
        name="GPT-4o",
        input_price=5.00,
        output_price=15.00,
        cached_input_price=2.50,
        coding=88,
        reasoning=90,
        creativity=92,
        translation=88,
        summarization=85,
        conversation=95,
        math=85,
        context_window=128000,
        max_output=16384,
        supports_vision=True,
        speed_tps=80,
        best_for=["general", "conversation", "creativity", "vision"],
    ),
    "gpt-4o-mini": ModelInfo(
        id="gpt-4o-mini",
        provider="openai",
        name="GPT-4o Mini",
        input_price=0.15,
        output_price=0.60,
        cached_input_price=0.075,
        coding=75,
        reasoning=78,
        creativity=80,
        translation=82,
        summarization=80,
        conversation=85,
        math=70,
        context_window=128000,
        max_output=16384,
        supports_vision=True,
        speed_tps=150,
        best_for=["budget", "simple_tasks", "high_volume"],
    ),
    "gpt-4-turbo": ModelInfo(
        id="gpt-4-turbo",
        provider="openai",
        name="GPT-4 Turbo",
        input_price=10.00,
        output_price=30.00,
        coding=85,
        reasoning=88,
        creativity=90,
        translation=85,
        summarization=85,
        conversation=90,
        math=82,
        context_window=128000,
        max_output=4096,
        supports_vision=True,
        speed_tps=60,
        best_for=["complex_reasoning", "long_context"],
    ),
    "o1": ModelInfo(
        id="o1",
        provider="openai",
        name="o1 (Reasoning)",
        input_price=15.00,
        output_price=60.00,
        coding=95,
        reasoning=98,
        creativity=70,
        translation=75,
        summarization=80,
        conversation=75,
        math=98,
        context_window=200000,
        max_output=100000,
        supports_vision=True,
        speed_tps=20,
        best_for=["math", "coding", "complex_reasoning", "science"],
    ),
    "o3-mini": ModelInfo(
        id="o3-mini",
        provider="openai",
        name="o3-mini",
        input_price=1.10,
        output_price=4.40,
        coding=90,
        reasoning=92,
        creativity=65,
        translation=70,
        summarization=75,
        conversation=70,
        math=95,
        context_window=200000,
        max_output=100000,
        speed_tps=40,
        best_for=["math", "coding", "logic"],
    ),

    # =========================================================================
    # Anthropic Models
    # =========================================================================
    "claude-opus-4": ModelInfo(
        id="claude-opus-4",
        provider="anthropic",
        name="Claude Opus 4",
        input_price=15.00,
        output_price=75.00,
        coding=95,
        reasoning=95,
        creativity=90,
        translation=88,
        summarization=92,
        conversation=90,
        math=90,
        context_window=200000,
        max_output=32000,
        supports_vision=True,
        speed_tps=30,
        best_for=["coding", "complex_analysis", "safety_critical"],
    ),
    "claude-sonnet-4": ModelInfo(
        id="claude-sonnet-4",
        provider="anthropic",
        name="Claude Sonnet 4",
        input_price=3.00,
        output_price=15.00,
        coding=92,
        reasoning=90,
        creativity=88,
        translation=85,
        summarization=90,
        conversation=88,
        math=85,
        context_window=200000,
        max_output=16000,
        supports_vision=True,
        speed_tps=60,
        best_for=["coding", "balanced", "enterprise"],
    ),
    "claude-3.5-sonnet": ModelInfo(
        id="claude-3.5-sonnet",
        provider="anthropic",
        name="Claude 3.5 Sonnet",
        input_price=3.00,
        output_price=15.00,
        cached_input_price=0.30,
        coding=92,
        reasoning=88,
        creativity=85,
        translation=85,
        summarization=88,
        conversation=88,
        math=82,
        context_window=200000,
        max_output=8192,
        supports_vision=True,
        speed_tps=70,
        best_for=["coding", "analysis", "long_documents"],
    ),
    "claude-3.5-haiku": ModelInfo(
        id="claude-3.5-haiku",
        provider="anthropic",
        name="Claude 3.5 Haiku",
        input_price=1.00,
        output_price=5.00,
        cached_input_price=0.10,
        coding=80,
        reasoning=78,
        creativity=75,
        translation=80,
        summarization=82,
        conversation=85,
        math=70,
        context_window=200000,
        max_output=8192,
        supports_vision=True,
        speed_tps=150,
        best_for=["budget", "fast", "simple_tasks"],
    ),

    # =========================================================================
    # Google Models
    # =========================================================================
    "gemini-2.5-pro": ModelInfo(
        id="gemini-2.5-pro",
        provider="google",
        name="Gemini 2.5 Pro",
        input_price=1.25,
        output_price=10.00,
        coding=90,
        reasoning=92,
        creativity=85,
        translation=90,
        summarization=88,
        conversation=85,
        math=88,
        context_window=1000000,
        max_output=8192,
        supports_vision=True,
        speed_tps=80,
        best_for=["long_context", "multimodal", "translation"],
    ),
    "gemini-2.5-flash": ModelInfo(
        id="gemini-2.5-flash",
        provider="google",
        name="Gemini 2.5 Flash",
        input_price=0.15,
        output_price=0.60,
        coding=82,
        reasoning=80,
        creativity=78,
        translation=85,
        summarization=85,
        conversation=82,
        math=75,
        context_window=1000000,
        max_output=8192,
        supports_vision=True,
        speed_tps=200,
        best_for=["budget", "fast", "high_volume", "long_context"],
    ),
    "gemini-3-flash": ModelInfo(
        id="gemini-3-flash",
        provider="google",
        name="Gemini 3 Flash",
        input_price=0.50,
        output_price=2.00,
        coding=85,
        reasoning=85,
        creativity=80,
        translation=88,
        summarization=88,
        conversation=85,
        math=80,
        context_window=1000000,
        max_output=16384,
        supports_vision=True,
        speed_tps=180,
        best_for=["balanced", "fast", "multimodal"],
    ),

    # =========================================================================
    # Other Models
    # =========================================================================
    "deepseek-v3": ModelInfo(
        id="deepseek-v3",
        provider="deepseek",
        name="DeepSeek V3",
        input_price=0.27,
        output_price=1.10,
        cached_input_price=0.07,
        coding=92,
        reasoning=88,
        creativity=75,
        translation=80,
        summarization=82,
        conversation=78,
        math=90,
        context_window=64000,
        max_output=8192,
        speed_tps=100,
        best_for=["coding", "math", "budget"],
    ),
    "mistral-large": ModelInfo(
        id="mistral-large",
        provider="mistral",
        name="Mistral Large",
        input_price=2.00,
        output_price=6.00,
        coding=85,
        reasoning=85,
        creativity=82,
        translation=88,
        summarization=85,
        conversation=85,
        math=80,
        context_window=128000,
        max_output=8192,
        supports_function_calling=True,
        speed_tps=90,
        best_for=["european_languages", "balanced", "enterprise"],
    ),
    "llama-4-maverick": ModelInfo(
        id="llama-4-maverick",
        provider="meta",
        name="Llama 4 Maverick",
        input_price=0.20,
        output_price=0.80,
        coding=88,
        reasoning=85,
        creativity=80,
        translation=85,
        summarization=85,
        conversation=82,
        math=82,
        context_window=128000,
        max_output=8192,
        speed_tps=120,
        best_for=["open_source", "self_hosted", "budget"],
    ),
}


# =============================================================================
# Task-Model Mapping
# =============================================================================

TASK_MODEL_RECOMMENDATIONS: dict[str, dict] = {
    "coding": {
        "description": "Code generation, debugging, and review",
        "best": ["claude-sonnet-4", "claude-opus-4", "o1"],
        "budget": ["deepseek-v3", "claude-3.5-haiku", "gpt-4o-mini"],
        "key_metric": "coding",
        "why": "Claude excels at code understanding and generation. DeepSeek offers best value for coding tasks.",
    },
    "customer_service": {
        "description": "Customer support chatbots and assistance",
        "best": ["gpt-4o", "claude-sonnet-4"],
        "budget": ["gpt-4o-mini", "gemini-2.5-flash", "claude-3.5-haiku"],
        "key_metric": "conversation",
        "why": "GPT-4o has the most natural conversational style. Mini versions handle most support queries well.",
    },
    "translation": {
        "description": "Language translation and localization",
        "best": ["gemini-2.5-pro", "gpt-4o"],
        "budget": ["gemini-2.5-flash", "gpt-4o-mini"],
        "key_metric": "translation",
        "why": "Gemini excels at multilingual tasks. Google's training data advantage for less common languages.",
    },
    "summarization": {
        "description": "Document summarization and content condensation",
        "best": ["claude-3.5-sonnet", "gemini-2.5-pro"],
        "budget": ["gemini-2.5-flash", "claude-3.5-haiku"],
        "key_metric": "summarization",
        "why": "Claude's long context handling and accuracy make it ideal. Gemini's 1M context for very long docs.",
    },
    "creative_writing": {
        "description": "Stories, marketing copy, creative content",
        "best": ["gpt-4o", "claude-opus-4"],
        "budget": ["gpt-4o-mini", "claude-3.5-haiku"],
        "key_metric": "creativity",
        "why": "GPT-4o leads in creative, engaging writing. Claude Opus for nuanced, literary content.",
    },
    "data_analysis": {
        "description": "Data analysis, insights, and interpretation",
        "best": ["claude-sonnet-4", "o1"],
        "budget": ["deepseek-v3", "gemini-2.5-flash"],
        "key_metric": "reasoning",
        "why": "Claude's analytical precision. o1 for complex statistical reasoning.",
    },
    "math": {
        "description": "Mathematical problem solving and proofs",
        "best": ["o1", "o3-mini"],
        "budget": ["deepseek-v3", "gemini-2.5-flash"],
        "key_metric": "math",
        "why": "o1/o3 series designed specifically for mathematical reasoning.",
    },
    "qa_rag": {
        "description": "Question answering and RAG applications",
        "best": ["claude-3.5-sonnet", "gemini-2.5-pro"],
        "budget": ["gemini-2.5-flash", "claude-3.5-haiku"],
        "key_metric": "summarization",
        "why": "Long context windows crucial for RAG. Claude's citation accuracy.",
    },
    "image_analysis": {
        "description": "Image understanding and description",
        "best": ["gpt-4o", "gemini-2.5-pro"],
        "budget": ["gemini-2.5-flash", "gpt-4o-mini"],
        "key_metric": None,
        "why": "GPT-4o and Gemini lead in vision capabilities.",
    },
    "general": {
        "description": "General purpose tasks",
        "best": ["gpt-4o", "claude-sonnet-4"],
        "budget": ["gpt-4o-mini", "gemini-2.5-flash"],
        "key_metric": "reasoning",
        "why": "Balanced performance across all tasks.",
    },
}


def get_model(model_id: str) -> Optional[ModelInfo]:
    """Get model info by ID."""
    return MODELS.get(model_id)


def get_models_by_provider(provider: str) -> list[ModelInfo]:
    """Get all models from a provider."""
    return [m for m in MODELS.values() if m.provider == provider]


def get_cheapest_models(limit: int = 5) -> list[ModelInfo]:
    """Get cheapest models by input price."""
    return sorted(MODELS.values(), key=lambda m: m.input_price)[:limit]


def get_best_for_task(task: str, budget: bool = False) -> list[str]:
    """Get recommended models for a task."""
    task_info = TASK_MODEL_RECOMMENDATIONS.get(task, TASK_MODEL_RECOMMENDATIONS["general"])
    return task_info["budget"] if budget else task_info["best"]
