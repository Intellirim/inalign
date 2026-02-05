"""
Cost Simulator - Predicts and compares AI costs across configurations.

Helps users understand cost implications of different model/prompt choices.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from app.optimizer.models_data import MODELS, get_model, ModelInfo


@dataclass
class CostEstimate:
    """Estimated cost for a configuration."""

    model_id: str
    model_name: str
    input_tokens: int
    output_tokens: int
    requests_per_day: int
    cost_per_request: float
    daily_cost: float
    monthly_cost: float
    yearly_cost: float
    with_caching: Optional[float] = None
    cache_savings: Optional[float] = None


@dataclass
class CostComparison:
    """Comparison of costs across multiple models."""

    estimates: list[CostEstimate]
    cheapest: CostEstimate
    most_expensive: CostEstimate
    recommended: CostEstimate
    savings_summary: dict


@dataclass
class UsageProjection:
    """Projected costs based on usage growth."""

    current_monthly: float
    month_3: float
    month_6: float
    month_12: float
    growth_rate: float
    breakeven_self_hosted: Optional[int] = None


class CostSimulator:
    """Simulates and compares AI API costs."""

    def __init__(self):
        self.models = MODELS

    def estimate(
        self,
        model_id: str,
        avg_input_tokens: int = 500,
        avg_output_tokens: int = 200,
        requests_per_day: int = 1000,
        cache_hit_rate: float = 0.0,
    ) -> CostEstimate:
        """
        Estimate costs for a specific configuration.

        Args:
            model_id: The model to estimate for.
            avg_input_tokens: Average input tokens per request.
            avg_output_tokens: Average output tokens per request.
            requests_per_day: Expected daily request volume.
            cache_hit_rate: Expected cache hit rate (0-1).

        Returns:
            CostEstimate with detailed cost breakdown.
        """
        model = get_model(model_id)
        if not model:
            # Default to gpt-4o-mini if model not found
            model = get_model("gpt-4o-mini")

        # Calculate per-request cost
        input_cost = (model.input_price / 1_000_000) * avg_input_tokens
        output_cost = (model.output_price / 1_000_000) * avg_output_tokens
        cost_per_request = input_cost + output_cost

        # Calculate totals
        daily_cost = cost_per_request * requests_per_day
        monthly_cost = daily_cost * 30
        yearly_cost = daily_cost * 365

        # Calculate with caching
        with_caching = None
        cache_savings = None

        if cache_hit_rate > 0 and model.cached_input_price:
            cached_input_cost = (model.cached_input_price / 1_000_000) * avg_input_tokens
            non_cached_input_cost = input_cost

            effective_input_cost = (
                cached_input_cost * cache_hit_rate +
                non_cached_input_cost * (1 - cache_hit_rate)
            )

            cached_cost_per_request = effective_input_cost + output_cost
            with_caching = cached_cost_per_request * requests_per_day * 30
            cache_savings = monthly_cost - with_caching

        return CostEstimate(
            model_id=model.id,
            model_name=model.name,
            input_tokens=avg_input_tokens,
            output_tokens=avg_output_tokens,
            requests_per_day=requests_per_day,
            cost_per_request=round(cost_per_request, 6),
            daily_cost=round(daily_cost, 2),
            monthly_cost=round(monthly_cost, 2),
            yearly_cost=round(yearly_cost, 2),
            with_caching=round(with_caching, 2) if with_caching else None,
            cache_savings=round(cache_savings, 2) if cache_savings else None,
        )

    def compare(
        self,
        model_ids: list[str],
        avg_input_tokens: int = 500,
        avg_output_tokens: int = 200,
        requests_per_day: int = 1000,
    ) -> CostComparison:
        """
        Compare costs across multiple models.

        Args:
            model_ids: List of models to compare.
            avg_input_tokens: Average input tokens per request.
            avg_output_tokens: Average output tokens per request.
            requests_per_day: Expected daily request volume.

        Returns:
            CostComparison with all estimates and analysis.
        """
        estimates = []

        for model_id in model_ids:
            estimate = self.estimate(
                model_id=model_id,
                avg_input_tokens=avg_input_tokens,
                avg_output_tokens=avg_output_tokens,
                requests_per_day=requests_per_day,
            )
            estimates.append(estimate)

        # Sort by monthly cost
        estimates.sort(key=lambda e: e.monthly_cost)

        cheapest = estimates[0]
        most_expensive = estimates[-1]

        # Recommended = best value (middle ground)
        # Simple heuristic: pick the one with best cost/capability ratio
        model_scores = []
        for est in estimates:
            model = get_model(est.model_id)
            if model:
                capability = (model.reasoning + model.coding + model.creativity) / 3
                value_score = capability / (est.monthly_cost + 1)  # +1 to avoid div by 0
                model_scores.append((est, value_score))

        model_scores.sort(key=lambda x: x[1], reverse=True)
        recommended = model_scores[0][0] if model_scores else cheapest

        # Calculate savings summary
        max_savings = most_expensive.monthly_cost - cheapest.monthly_cost
        savings_percent = (max_savings / most_expensive.monthly_cost * 100) if most_expensive.monthly_cost > 0 else 0

        savings_summary = {
            "max_monthly_savings": round(max_savings, 2),
            "savings_percent": round(savings_percent, 1),
            "cheapest_model": cheapest.model_name,
            "most_expensive_model": most_expensive.model_name,
            "recommended_model": recommended.model_name,
            "yearly_savings_potential": round(max_savings * 12, 2),
        }

        return CostComparison(
            estimates=estimates,
            cheapest=cheapest,
            most_expensive=most_expensive,
            recommended=recommended,
            savings_summary=savings_summary,
        )

    def compare_all_providers(
        self,
        avg_input_tokens: int = 500,
        avg_output_tokens: int = 200,
        requests_per_day: int = 1000,
        tier: str = "all",  # "budget", "mid", "premium", "all"
    ) -> CostComparison:
        """
        Compare costs across all available models.

        Args:
            avg_input_tokens: Average input tokens per request.
            avg_output_tokens: Average output tokens per request.
            requests_per_day: Expected daily request volume.
            tier: Filter by tier.

        Returns:
            CostComparison for all models.
        """
        model_ids = []

        for model_id, model in self.models.items():
            if tier == "all":
                model_ids.append(model_id)
            elif tier == "budget" and model.input_price < 1.0:
                model_ids.append(model_id)
            elif tier == "mid" and 1.0 <= model.input_price <= 5.0:
                model_ids.append(model_id)
            elif tier == "premium" and model.input_price > 5.0:
                model_ids.append(model_id)

        return self.compare(
            model_ids=model_ids,
            avg_input_tokens=avg_input_tokens,
            avg_output_tokens=avg_output_tokens,
            requests_per_day=requests_per_day,
        )

    def project_growth(
        self,
        current_requests_per_day: int,
        growth_rate_monthly: float,
        model_id: str,
        avg_input_tokens: int = 500,
        avg_output_tokens: int = 200,
    ) -> UsageProjection:
        """
        Project costs with expected growth.

        Args:
            current_requests_per_day: Current daily volume.
            growth_rate_monthly: Monthly growth rate (e.g., 0.2 for 20%).
            model_id: The model being used.
            avg_input_tokens: Average input tokens.
            avg_output_tokens: Average output tokens.

        Returns:
            UsageProjection with cost forecasts.
        """
        # Current cost
        current = self.estimate(
            model_id=model_id,
            avg_input_tokens=avg_input_tokens,
            avg_output_tokens=avg_output_tokens,
            requests_per_day=current_requests_per_day,
        )

        # Project future volumes
        requests_month_3 = int(current_requests_per_day * (1 + growth_rate_monthly) ** 3)
        requests_month_6 = int(current_requests_per_day * (1 + growth_rate_monthly) ** 6)
        requests_month_12 = int(current_requests_per_day * (1 + growth_rate_monthly) ** 12)

        # Calculate costs
        month_3 = self.estimate(
            model_id=model_id,
            avg_input_tokens=avg_input_tokens,
            avg_output_tokens=avg_output_tokens,
            requests_per_day=requests_month_3,
        ).monthly_cost

        month_6 = self.estimate(
            model_id=model_id,
            avg_input_tokens=avg_input_tokens,
            avg_output_tokens=avg_output_tokens,
            requests_per_day=requests_month_6,
        ).monthly_cost

        month_12 = self.estimate(
            model_id=model_id,
            avg_input_tokens=avg_input_tokens,
            avg_output_tokens=avg_output_tokens,
            requests_per_day=requests_month_12,
        ).monthly_cost

        # Calculate breakeven for self-hosting
        # Assume self-hosted costs $2000/month fixed for decent GPU
        # This is a rough approximation
        self_hosted_monthly = 2000
        breakeven = None

        if month_12 > self_hosted_monthly:
            # Find month where API cost exceeds self-hosting
            for month in range(1, 13):
                requests = int(current_requests_per_day * (1 + growth_rate_monthly) ** month)
                cost = self.estimate(
                    model_id=model_id,
                    avg_input_tokens=avg_input_tokens,
                    avg_output_tokens=avg_output_tokens,
                    requests_per_day=requests,
                ).monthly_cost

                if cost >= self_hosted_monthly:
                    breakeven = month
                    break

        return UsageProjection(
            current_monthly=current.monthly_cost,
            month_3=month_3,
            month_6=month_6,
            month_12=month_12,
            growth_rate=growth_rate_monthly,
            breakeven_self_hosted=breakeven,
        )

    def calculate_roi(
        self,
        current_model_id: str,
        optimized_model_id: str,
        avg_input_tokens: int,
        optimized_input_tokens: int,
        avg_output_tokens: int,
        requests_per_day: int,
    ) -> dict:
        """
        Calculate ROI of switching to optimized configuration.

        Args:
            current_model_id: Current model being used.
            optimized_model_id: Proposed optimized model.
            avg_input_tokens: Current average input tokens.
            optimized_input_tokens: Optimized input tokens (after prompt optimization).
            avg_output_tokens: Average output tokens.
            requests_per_day: Daily request volume.

        Returns:
            ROI analysis with savings breakdown.
        """
        # Current costs
        current = self.estimate(
            model_id=current_model_id,
            avg_input_tokens=avg_input_tokens,
            avg_output_tokens=avg_output_tokens,
            requests_per_day=requests_per_day,
        )

        # Optimized costs
        optimized = self.estimate(
            model_id=optimized_model_id,
            avg_input_tokens=optimized_input_tokens,
            avg_output_tokens=avg_output_tokens,
            requests_per_day=requests_per_day,
        )

        # Savings breakdown
        token_savings = avg_input_tokens - optimized_input_tokens
        token_savings_percent = (token_savings / avg_input_tokens * 100) if avg_input_tokens > 0 else 0

        monthly_savings = current.monthly_cost - optimized.monthly_cost
        savings_percent = (monthly_savings / current.monthly_cost * 100) if current.monthly_cost > 0 else 0

        return {
            "current_config": {
                "model": current.model_name,
                "input_tokens": avg_input_tokens,
                "monthly_cost": current.monthly_cost,
            },
            "optimized_config": {
                "model": optimized.model_name,
                "input_tokens": optimized_input_tokens,
                "monthly_cost": optimized.monthly_cost,
            },
            "savings": {
                "token_reduction": token_savings,
                "token_reduction_percent": round(token_savings_percent, 1),
                "monthly_savings": round(monthly_savings, 2),
                "savings_percent": round(savings_percent, 1),
                "yearly_savings": round(monthly_savings * 12, 2),
            },
            "recommendation": (
                f"Switching from {current.model_name} to {optimized.model_name} "
                f"with optimized prompts saves ${monthly_savings:.2f}/month ({savings_percent:.0f}%)"
            ),
        }

    def get_budget_recommendation(
        self,
        monthly_budget: float,
        avg_input_tokens: int = 500,
        avg_output_tokens: int = 200,
    ) -> dict:
        """
        Recommend configuration based on budget.

        Args:
            monthly_budget: Maximum monthly budget in USD.
            avg_input_tokens: Average input tokens.
            avg_output_tokens: Average output tokens.

        Returns:
            Recommended configuration within budget.
        """
        recommendations = []

        for model_id, model in self.models.items():
            # Calculate max requests per day within budget
            cost_per_request = (
                (model.input_price / 1_000_000) * avg_input_tokens +
                (model.output_price / 1_000_000) * avg_output_tokens
            )

            if cost_per_request > 0:
                max_daily = int((monthly_budget / 30) / cost_per_request)

                if max_daily >= 100:  # Minimum viable usage
                    recommendations.append({
                        "model_id": model_id,
                        "model_name": model.name,
                        "provider": model.provider,
                        "max_requests_per_day": max_daily,
                        "max_requests_per_month": max_daily * 30,
                        "cost_per_request": round(cost_per_request, 6),
                        "capability_score": (model.reasoning + model.coding + model.creativity) / 3,
                    })

        # Sort by capability
        recommendations.sort(key=lambda r: r["capability_score"], reverse=True)

        return {
            "budget": monthly_budget,
            "recommendations": recommendations[:5],
            "best_capability": recommendations[0] if recommendations else None,
            "highest_volume": max(recommendations, key=lambda r: r["max_requests_per_day"]) if recommendations else None,
        }
