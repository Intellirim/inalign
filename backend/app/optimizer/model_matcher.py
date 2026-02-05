"""
Model Matcher - Recommends optimal AI models based on task requirements.

Considers task type, budget, performance requirements, and special features.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from app.optimizer.models_data import (
    MODELS,
    TASK_MODEL_RECOMMENDATIONS,
    ModelInfo,
    get_model,
)
from app.optimizer.task_analyzer import TaskClassification


@dataclass
class ModelRecommendation:
    """A model recommendation with reasoning."""

    model_id: str
    model_name: str
    provider: str
    score: float  # 0-100
    reasoning: str
    estimated_cost_per_1k_requests: float
    pros: list[str]
    cons: list[str]


@dataclass
class ModelMatchResult:
    """Result of model matching."""

    task_type: str
    complexity: str
    recommendations: list[ModelRecommendation]
    best_performance: ModelRecommendation
    best_value: ModelRecommendation
    best_budget: ModelRecommendation
    comparison_table: list[dict]
    savings_potential: dict


class ModelMatcher:
    """Matches tasks to optimal AI models."""

    def __init__(self):
        self.models = MODELS
        self.task_recommendations = TASK_MODEL_RECOMMENDATIONS

    def match(
        self,
        task_classification: TaskClassification,
        budget_mode: bool = False,
        max_price_per_1m_input: Optional[float] = None,
        preferred_providers: Optional[list[str]] = None,
        required_features: Optional[dict] = None,
    ) -> ModelMatchResult:
        """
        Find optimal models for a task.

        Args:
            task_classification: Result from TaskAnalyzer.
            budget_mode: If True, prioritize cost over performance.
            max_price_per_1m_input: Maximum acceptable input price.
            preferred_providers: List of preferred providers (openai, anthropic, google).
            required_features: Required features like vision, function_calling.

        Returns:
            ModelMatchResult with ranked recommendations.
        """
        task_type = task_classification.primary_task
        complexity = task_classification.complexity
        requires_vision = task_classification.requires_vision

        # Get task-specific recommendations
        task_info = self.task_recommendations.get(
            task_type, self.task_recommendations["general"]
        )

        # Score all models
        scored_models: list[tuple[ModelInfo, float, str]] = []

        for model_id, model in self.models.items():
            # Filter by requirements
            if requires_vision and not model.supports_vision:
                continue
            if max_price_per_1m_input and model.input_price > max_price_per_1m_input:
                continue
            if preferred_providers and model.provider not in preferred_providers:
                continue
            if required_features:
                if required_features.get("vision") and not model.supports_vision:
                    continue
                if required_features.get("function_calling") and not model.supports_function_calling:
                    continue

            # Calculate score
            score, reasoning = self._calculate_score(
                model, task_type, complexity, task_info, budget_mode
            )
            scored_models.append((model, score, reasoning))

        # Sort by score
        scored_models.sort(key=lambda x: x[1], reverse=True)

        # Create recommendations
        recommendations = []
        for model, score, reasoning in scored_models[:10]:
            rec = self._create_recommendation(model, score, reasoning, task_type)
            recommendations.append(rec)

        # Find best in each category
        best_performance = self._find_best_performance(scored_models)
        best_value = self._find_best_value(scored_models)
        best_budget = self._find_cheapest(scored_models)

        # Create comparison table
        comparison_table = self._create_comparison_table(recommendations[:5])

        # Calculate savings potential
        savings_potential = self._calculate_savings(best_performance, best_budget)

        return ModelMatchResult(
            task_type=task_type,
            complexity=complexity,
            recommendations=recommendations,
            best_performance=best_performance,
            best_value=best_value,
            best_budget=best_budget,
            comparison_table=comparison_table,
            savings_potential=savings_potential,
        )

    def _calculate_score(
        self,
        model: ModelInfo,
        task_type: str,
        complexity: str,
        task_info: dict,
        budget_mode: bool,
    ) -> tuple[float, str]:
        """Calculate model score for a task."""
        score = 0.0
        reasons = []

        # Get the key metric for this task
        key_metric = task_info.get("key_metric")
        if key_metric:
            metric_value = getattr(model, key_metric, 50)
            score += metric_value * 0.4
            if metric_value >= 90:
                reasons.append(f"Excellent {key_metric} ({metric_value})")
            elif metric_value >= 80:
                reasons.append(f"Good {key_metric} ({metric_value})")

        # Check if model is in recommended list
        if model.id in task_info.get("best", []):
            score += 20
            reasons.append("Recommended for this task")
        elif model.id in task_info.get("budget", []):
            score += 15
            reasons.append("Good budget option")

        # Adjust for complexity
        if complexity == "complex":
            # Favor more capable models
            score += (model.reasoning + model.coding) / 10
            if model.reasoning >= 90:
                reasons.append("Strong reasoning for complex tasks")
        elif complexity == "simple":
            # Favor faster, cheaper models
            score += model.speed_tps / 10
            reasons.append("Fast for simple tasks")

        # Cost factor
        if budget_mode:
            # Strongly favor cheaper models
            cost_score = max(0, 50 - model.input_price * 2)
            score += cost_score
            if model.input_price < 1.0:
                reasons.append(f"Very affordable (${model.input_price}/1M)")
        else:
            # Mild cost consideration
            cost_score = max(0, 20 - model.input_price)
            score += cost_score

        # Speed bonus
        if model.speed_tps >= 100:
            score += 5
            reasons.append("High throughput")

        # Context window bonus for summarization/RAG
        if task_type in ["summarization", "qa_rag"] and model.context_window >= 200000:
            score += 10
            reasons.append(f"Large context ({model.context_window // 1000}K)")

        reasoning = "; ".join(reasons[:3]) if reasons else "General purpose model"
        return score, reasoning

    def _create_recommendation(
        self,
        model: ModelInfo,
        score: float,
        reasoning: str,
        task_type: str,
    ) -> ModelRecommendation:
        """Create a recommendation object."""
        # Calculate cost per 1K requests (assuming 500 input + 200 output tokens avg)
        avg_input_tokens = 500
        avg_output_tokens = 200
        cost_per_1k = (
            (model.input_price * avg_input_tokens / 1_000_000) +
            (model.output_price * avg_output_tokens / 1_000_000)
        ) * 1000

        # Generate pros/cons
        pros = []
        cons = []

        if model.coding >= 90:
            pros.append("Excellent for coding")
        if model.reasoning >= 90:
            pros.append("Strong reasoning")
        if model.speed_tps >= 100:
            pros.append("Very fast")
        if model.input_price < 1.0:
            pros.append("Very affordable")
        if model.context_window >= 200000:
            pros.append("Large context window")
        if model.supports_vision:
            pros.append("Vision capable")

        if model.input_price > 10:
            cons.append("Premium pricing")
        if model.speed_tps < 50:
            cons.append("Slower generation")
        if model.context_window < 32000:
            cons.append("Limited context")
        if not model.supports_vision:
            cons.append("No vision support")

        return ModelRecommendation(
            model_id=model.id,
            model_name=model.name,
            provider=model.provider,
            score=round(score, 1),
            reasoning=reasoning,
            estimated_cost_per_1k_requests=round(cost_per_1k, 4),
            pros=pros[:4],
            cons=cons[:3],
        )

    def _find_best_performance(
        self, scored_models: list[tuple[ModelInfo, float, str]]
    ) -> ModelRecommendation:
        """Find the best performing model regardless of cost."""
        # Sort by raw capability scores
        by_capability = sorted(
            scored_models,
            key=lambda x: (x[0].reasoning + x[0].coding + x[0].creativity) / 3,
            reverse=True,
        )
        model, score, reasoning = by_capability[0]
        return self._create_recommendation(model, score, reasoning, "general")

    def _find_best_value(
        self, scored_models: list[tuple[ModelInfo, float, str]]
    ) -> ModelRecommendation:
        """Find the best value (performance/price ratio)."""
        # Calculate value score
        value_scores = []
        for model, score, reasoning in scored_models:
            capability = (model.reasoning + model.coding + model.creativity) / 3
            cost = model.input_price + model.output_price / 10
            value = capability / (cost + 0.1)  # Avoid division by zero
            value_scores.append((model, score, reasoning, value))

        value_scores.sort(key=lambda x: x[3], reverse=True)
        model, score, reasoning, _ = value_scores[0]
        return self._create_recommendation(model, score, reasoning + "; Best value", "general")

    def _find_cheapest(
        self, scored_models: list[tuple[ModelInfo, float, str]]
    ) -> ModelRecommendation:
        """Find the cheapest acceptable model."""
        # Filter to models with score > 50 and sort by price
        acceptable = [
            (m, s, r) for m, s, r in scored_models
            if s > 50
        ]
        if not acceptable:
            acceptable = scored_models

        by_price = sorted(acceptable, key=lambda x: x[0].input_price)
        model, score, reasoning = by_price[0]
        return self._create_recommendation(model, score, reasoning + "; Most affordable", "general")

    def _create_comparison_table(
        self, recommendations: list[ModelRecommendation]
    ) -> list[dict]:
        """Create a comparison table for top models."""
        table = []
        for rec in recommendations:
            model = get_model(rec.model_id)
            if model:
                table.append({
                    "model": rec.model_name,
                    "provider": rec.provider,
                    "score": rec.score,
                    "input_price": f"${model.input_price}",
                    "output_price": f"${model.output_price}",
                    "cost_per_1k": f"${rec.estimated_cost_per_1k_requests:.4f}",
                    "speed": f"{model.speed_tps} tps",
                    "context": f"{model.context_window // 1000}K",
                })
        return table

    def _calculate_savings(
        self,
        best_performance: ModelRecommendation,
        best_budget: ModelRecommendation,
    ) -> dict:
        """Calculate potential savings from switching models."""
        perf_cost = best_performance.estimated_cost_per_1k_requests
        budget_cost = best_budget.estimated_cost_per_1k_requests

        savings_per_1k = perf_cost - budget_cost
        savings_percent = (savings_per_1k / perf_cost * 100) if perf_cost > 0 else 0

        return {
            "performance_model": best_performance.model_name,
            "budget_model": best_budget.model_name,
            "cost_difference_per_1k": round(savings_per_1k, 4),
            "savings_percent": round(savings_percent, 1),
            "monthly_savings_at_100k_requests": round(savings_per_1k * 100, 2),
            "recommendation": (
                f"Switching from {best_performance.model_name} to {best_budget.model_name} "
                f"could save {savings_percent:.0f}% (${savings_per_1k * 100:.2f}/month at 100K requests)"
            ),
        }

    def quick_recommend(
        self,
        task_type: str,
        budget: bool = False,
    ) -> str:
        """Quick recommendation without full analysis."""
        task_info = self.task_recommendations.get(
            task_type, self.task_recommendations["general"]
        )
        models = task_info["budget"] if budget else task_info["best"]
        return models[0] if models else "gpt-4o-mini"

    def compare_models(
        self,
        model_ids: list[str],
    ) -> dict:
        """Compare specific models head-to-head."""
        models = [get_model(mid) for mid in model_ids if get_model(mid)]

        if not models:
            return {"error": "No valid models found"}

        comparison = {
            "models": [],
            "winner_by_category": {},
        }

        for model in models:
            comparison["models"].append({
                "id": model.id,
                "name": model.name,
                "provider": model.provider,
                "coding": model.coding,
                "reasoning": model.reasoning,
                "creativity": model.creativity,
                "speed": model.speed_tps,
                "input_price": model.input_price,
                "output_price": model.output_price,
            })

        # Find winners
        comparison["winner_by_category"] = {
            "coding": max(models, key=lambda m: m.coding).name,
            "reasoning": max(models, key=lambda m: m.reasoning).name,
            "creativity": max(models, key=lambda m: m.creativity).name,
            "speed": max(models, key=lambda m: m.speed_tps).name,
            "cheapest": min(models, key=lambda m: m.input_price).name,
        }

        return comparison
