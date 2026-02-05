"""
AI Advisor - Main interface for AI optimization recommendations.

Combines task analysis, model matching, prompt optimization, and cost simulation
to provide comprehensive AI usage recommendations.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Optional

from app.optimizer.task_analyzer import TaskAnalyzer, TaskClassification
from app.optimizer.model_matcher import ModelMatcher, ModelMatchResult
from app.optimizer.prompt_optimizer import PromptOptimizer, PromptAnalysis, OptimizedPrompt
from app.optimizer.cost_simulator import CostSimulator, CostComparison


@dataclass
class ProjectRecommendation:
    """Complete recommendation for a project."""

    project_name: str
    task_analysis: dict
    model_recommendation: dict
    prompt_suggestions: list[str]
    cost_analysis: dict
    optimization_potential: dict
    action_items: list[str]


@dataclass
class QuickAnalysis:
    """Quick analysis result for a single prompt."""

    task_type: str
    recommended_model: str
    budget_model: str
    estimated_tokens: int
    optimization_tips: list[str]
    estimated_cost_per_1k: float


class AIAdvisor:
    """
    Main AI optimization advisor.

    Provides intelligent recommendations for:
    - Task classification
    - Model selection
    - Prompt optimization
    - Cost optimization
    """

    def __init__(self):
        self.task_analyzer = TaskAnalyzer()
        self.model_matcher = ModelMatcher()
        self.prompt_optimizer = PromptOptimizer()
        self.cost_simulator = CostSimulator()

    def analyze_prompt(self, prompt: str) -> QuickAnalysis:
        """
        Quick analysis of a single prompt.

        Args:
            prompt: The prompt to analyze.

        Returns:
            QuickAnalysis with recommendations.
        """
        # Analyze task
        task = self.task_analyzer.analyze(prompt)

        # Get model recommendations
        match = self.model_matcher.match(task)

        # Get prompt optimization tips
        prompt_analysis = self.prompt_optimizer.analyze(prompt)

        # Calculate estimated cost
        model = match.best_value
        cost_per_1k = model.estimated_cost_per_1k_requests if model else 0.01

        return QuickAnalysis(
            task_type=task.primary_task,
            recommended_model=match.best_value.model_id if match.best_value else "gpt-4o-mini",
            budget_model=match.best_budget.model_id if match.best_budget else "gpt-4o-mini",
            estimated_tokens=task.estimated_tokens,
            optimization_tips=prompt_analysis.suggestions[:3],
            estimated_cost_per_1k=cost_per_1k,
        )

    def analyze_project(
        self,
        project_name: str,
        project_description: str,
        sample_prompts: Optional[list[str]] = None,
        current_model: Optional[str] = None,
        monthly_budget: Optional[float] = None,
        requests_per_day: int = 1000,
    ) -> ProjectRecommendation:
        """
        Comprehensive analysis of a project.

        Args:
            project_name: Name of the project.
            project_description: What the project does.
            sample_prompts: Optional sample prompts from the project.
            current_model: Current model being used (if any).
            monthly_budget: Monthly budget constraint.
            requests_per_day: Expected daily request volume.

        Returns:
            ProjectRecommendation with complete analysis.
        """
        # Analyze project
        project_analysis = self.task_analyzer.analyze_project(
            project_name=project_name,
            project_description=project_description,
            sample_prompts=sample_prompts,
        )

        # Get task classification for description
        main_task = self.task_analyzer.analyze(project_description)

        # Get model recommendations
        model_match = self.model_matcher.match(main_task, budget_mode=monthly_budget is not None and monthly_budget < 100)

        # Analyze prompts for optimization
        prompt_suggestions = []
        total_potential_savings = 0

        if sample_prompts:
            for prompt in sample_prompts[:5]:  # Analyze up to 5 samples
                analysis = self.prompt_optimizer.analyze(prompt)
                prompt_suggestions.extend(analysis.suggestions)
                total_potential_savings += analysis.total_potential_savings

            # Deduplicate suggestions
            prompt_suggestions = list(dict.fromkeys(prompt_suggestions))[:5]

        # Cost analysis
        recommended_model = model_match.best_value.model_id if model_match.best_value else "gpt-4o-mini"
        budget_model = model_match.best_budget.model_id if model_match.best_budget else "gpt-4o-mini"

        cost_comparison = self.cost_simulator.compare(
            model_ids=[recommended_model, budget_model],
            avg_input_tokens=project_analysis.get("average_tokens", 500),
            avg_output_tokens=200,
            requests_per_day=requests_per_day,
        )

        # Calculate optimization potential
        current_cost = None
        if current_model:
            current_estimate = self.cost_simulator.estimate(
                model_id=current_model,
                avg_input_tokens=project_analysis.get("average_tokens", 500),
                avg_output_tokens=200,
                requests_per_day=requests_per_day,
            )
            current_cost = current_estimate.monthly_cost

        optimization_potential = {
            "current_monthly_cost": current_cost,
            "optimized_monthly_cost": cost_comparison.cheapest.monthly_cost,
            "potential_savings": (
                round(current_cost - cost_comparison.cheapest.monthly_cost, 2)
                if current_cost else None
            ),
            "prompt_token_savings": total_potential_savings,
        }

        # Generate action items
        action_items = self._generate_action_items(
            project_analysis=project_analysis,
            model_match=model_match,
            prompt_suggestions=prompt_suggestions,
            optimization_potential=optimization_potential,
            current_model=current_model,
        )

        return ProjectRecommendation(
            project_name=project_name,
            task_analysis={
                "primary_task": project_analysis["primary_task"],
                "confidence": project_analysis["confidence"],
                "detected_features": project_analysis["detected_features"],
                "complexity_distribution": project_analysis.get("complexity_distribution", {}),
                "requires_vision": project_analysis.get("requires_vision", False),
            },
            model_recommendation={
                "recommended": {
                    "model": model_match.best_value.model_name if model_match.best_value else None,
                    "reasoning": model_match.best_value.reasoning if model_match.best_value else None,
                    "cost_per_1k": model_match.best_value.estimated_cost_per_1k_requests if model_match.best_value else None,
                },
                "budget_option": {
                    "model": model_match.best_budget.model_name if model_match.best_budget else None,
                    "reasoning": model_match.best_budget.reasoning if model_match.best_budget else None,
                    "cost_per_1k": model_match.best_budget.estimated_cost_per_1k_requests if model_match.best_budget else None,
                },
                "comparison": model_match.comparison_table[:3],
                "savings_potential": model_match.savings_potential,
            },
            prompt_suggestions=prompt_suggestions,
            cost_analysis={
                "recommended_monthly": cost_comparison.recommended.monthly_cost,
                "budget_monthly": cost_comparison.cheapest.monthly_cost,
                "savings_summary": cost_comparison.savings_summary,
            },
            optimization_potential=optimization_potential,
            action_items=action_items,
        )

    def optimize_prompt(
        self,
        prompt: str,
        task_type: Optional[str] = None,
        aggressive: bool = False,
    ) -> dict:
        """
        Optimize a prompt and provide recommendations.

        Args:
            prompt: The prompt to optimize.
            task_type: Optional task type override.
            aggressive: Whether to apply aggressive optimizations.

        Returns:
            Dictionary with optimized prompt and analysis.
        """
        # Analyze first if task type not provided
        if not task_type:
            task = self.task_analyzer.analyze(prompt)
            task_type = task.primary_task

        # Analyze original
        analysis = self.prompt_optimizer.analyze(prompt)

        # Optimize
        optimized = self.prompt_optimizer.optimize(prompt, aggressive=aggressive)

        # Get system prompt suggestion
        system_prompt = self.prompt_optimizer.suggest_system_prompt(task_type)

        return {
            "original": {
                "text": prompt,
                "tokens": analysis.original_tokens,
                "quality_score": analysis.quality_score,
                "efficiency_score": analysis.efficiency_score,
            },
            "optimized": {
                "text": optimized.optimized,
                "tokens": optimized.optimized_tokens,
                "tokens_saved": optimized.tokens_saved,
                "savings_percent": optimized.savings_percent,
                "changes": optimized.changes_made,
                "quality_preserved": optimized.quality_preserved,
            },
            "issues_found": [
                {
                    "type": issue.issue_type,
                    "severity": issue.severity,
                    "description": issue.description,
                    "suggestion": issue.suggestion,
                }
                for issue in analysis.issues
            ],
            "suggestions": analysis.suggestions,
            "recommended_system_prompt": system_prompt,
        }

    def compare_models(
        self,
        model_ids: list[str],
        requests_per_day: int = 1000,
        avg_input_tokens: int = 500,
        avg_output_tokens: int = 200,
    ) -> dict:
        """
        Compare specific models head-to-head.

        Args:
            model_ids: List of models to compare.
            requests_per_day: Expected daily volume.
            avg_input_tokens: Average input tokens.
            avg_output_tokens: Average output tokens.

        Returns:
            Detailed comparison.
        """
        # Capability comparison
        capability_comparison = self.model_matcher.compare_models(model_ids)

        # Cost comparison
        cost_comparison = self.cost_simulator.compare(
            model_ids=model_ids,
            avg_input_tokens=avg_input_tokens,
            avg_output_tokens=avg_output_tokens,
            requests_per_day=requests_per_day,
        )

        return {
            "capabilities": capability_comparison,
            "costs": {
                "estimates": [
                    {
                        "model": e.model_name,
                        "cost_per_request": e.cost_per_request,
                        "daily_cost": e.daily_cost,
                        "monthly_cost": e.monthly_cost,
                    }
                    for e in cost_comparison.estimates
                ],
                "cheapest": cost_comparison.cheapest.model_name,
                "most_expensive": cost_comparison.most_expensive.model_name,
                "savings_summary": cost_comparison.savings_summary,
            },
            "recommendation": cost_comparison.recommended.model_name,
        }

    def get_optimization_report(
        self,
        current_model: str,
        current_avg_tokens: int,
        requests_per_day: int,
        sample_prompt: Optional[str] = None,
    ) -> dict:
        """
        Generate a comprehensive optimization report.

        Args:
            current_model: Current model being used.
            current_avg_tokens: Current average tokens per request.
            requests_per_day: Current daily volume.
            sample_prompt: Optional sample prompt for analysis.

        Returns:
            Comprehensive optimization report.
        """
        report = {
            "current_state": {},
            "recommendations": [],
            "potential_savings": {},
            "action_plan": [],
        }

        # Current state
        current_estimate = self.cost_simulator.estimate(
            model_id=current_model,
            avg_input_tokens=current_avg_tokens,
            avg_output_tokens=200,
            requests_per_day=requests_per_day,
        )

        report["current_state"] = {
            "model": current_estimate.model_name,
            "avg_tokens": current_avg_tokens,
            "daily_requests": requests_per_day,
            "monthly_cost": current_estimate.monthly_cost,
        }

        # Analyze prompt if provided
        optimized_tokens = current_avg_tokens
        if sample_prompt:
            optimized = self.prompt_optimizer.optimize(sample_prompt, aggressive=True)
            if optimized.tokens_saved > 0:
                savings_ratio = optimized.tokens_saved / optimized.original_tokens
                optimized_tokens = int(current_avg_tokens * (1 - savings_ratio))

                report["recommendations"].append({
                    "type": "prompt_optimization",
                    "description": f"Optimize prompts to reduce tokens by {optimized.savings_percent:.0f}%",
                    "impact": f"Save ~{optimized.tokens_saved} tokens per request",
                    "changes": optimized.changes_made,
                })

        # Model recommendations
        task = self.task_analyzer.analyze(sample_prompt or "general assistant")
        model_match = self.model_matcher.match(task, budget_mode=True)

        if model_match.best_budget.model_id != current_model:
            report["recommendations"].append({
                "type": "model_switch",
                "description": f"Switch from {current_model} to {model_match.best_budget.model_id}",
                "reasoning": model_match.best_budget.reasoning,
                "impact": f"Reduce cost per request",
            })

        # Calculate potential savings
        optimized_estimate = self.cost_simulator.estimate(
            model_id=model_match.best_budget.model_id,
            avg_input_tokens=optimized_tokens,
            avg_output_tokens=200,
            requests_per_day=requests_per_day,
        )

        monthly_savings = current_estimate.monthly_cost - optimized_estimate.monthly_cost
        savings_percent = (monthly_savings / current_estimate.monthly_cost * 100) if current_estimate.monthly_cost > 0 else 0

        report["potential_savings"] = {
            "current_monthly": current_estimate.monthly_cost,
            "optimized_monthly": optimized_estimate.monthly_cost,
            "monthly_savings": round(monthly_savings, 2),
            "savings_percent": round(savings_percent, 1),
            "yearly_savings": round(monthly_savings * 12, 2),
        }

        # Action plan
        report["action_plan"] = [
            f"1. Review and optimize prompts (save ~{(current_avg_tokens - optimized_tokens)} tokens/request)",
            f"2. Consider switching to {model_match.best_budget.model_name}",
            f"3. Enable response caching for repeated queries",
            f"4. Monitor usage to identify further optimization opportunities",
        ]

        return report

    def _generate_action_items(
        self,
        project_analysis: dict,
        model_match: ModelMatchResult,
        prompt_suggestions: list[str],
        optimization_potential: dict,
        current_model: Optional[str],
    ) -> list[str]:
        """Generate actionable items from analysis."""
        items = []

        # Model recommendation
        if current_model and model_match.best_value:
            if model_match.best_value.model_id != current_model:
                items.append(
                    f"Consider switching from {current_model} to {model_match.best_value.model_name} "
                    f"for better value"
                )

        # Prompt optimization
        if optimization_potential.get("prompt_token_savings", 0) > 0:
            items.append(
                f"Optimize prompts to save ~{optimization_potential['prompt_token_savings']} tokens per request"
            )

        # Specific suggestions
        if prompt_suggestions:
            items.append(f"Prompt improvement: {prompt_suggestions[0]}")

        # Caching recommendation
        items.append("Enable response caching for frequently asked questions")

        # Task-specific recommendations
        task = project_analysis.get("primary_task", "general")
        if task == "customer_service":
            items.append("Set up FAQ cache to reduce repeat queries")
        elif task == "coding":
            items.append("Use code-specific models like Claude or DeepSeek for better results")
        elif task == "translation":
            items.append("Consider specialized translation APIs for high volume")

        return items[:5]  # Top 5 action items
