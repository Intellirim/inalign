"""
Efficiency Service - Analyzes agent behavior for optimization opportunities.

Identifies inefficiencies like redundant calls, excessive retries,
and suggests improvements.
"""

from __future__ import annotations

from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy import func, select, and_
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import Activity
from app.schemas.activity import EfficiencyReport, EfficiencySuggestion


class EfficiencyService:
    """Analyzes agent activities for efficiency optimization."""

    def __init__(self, db: AsyncSession):
        self.db = db

    async def analyze_agent(
        self,
        agent_id: str,
        days: int = 7,
    ) -> EfficiencyReport:
        """Analyze an agent's efficiency over a time period.

        Args:
            agent_id: The agent to analyze.
            days: Number of days to analyze.

        Returns:
            EfficiencyReport with scores and suggestions.
        """
        end_time = datetime.now(timezone.utc)
        start_time = end_time - timedelta(days=days)

        # Fetch activities
        result = await self.db.execute(
            select(Activity).where(
                Activity.agent_id == agent_id,
                Activity.timestamp >= start_time,
                Activity.timestamp <= end_time,
            ).order_by(Activity.timestamp.asc())
        )
        activities = list(result.scalars().all())

        if not activities:
            return self._empty_report(agent_id, days)

        # Calculate metrics
        total_actions = len(activities)
        total_cost = sum(a.cost_usd for a in activities)
        total_duration = sum(a.duration_ms for a in activities)
        successful = [a for a in activities if a.status == "success"]
        failed = [a for a in activities if a.status == "failure"]
        blocked = [a for a in activities if a.status == "blocked"]

        # Identify patterns
        redundant_calls = self._find_redundant_calls(activities)
        failed_retries = self._find_failed_retries(activities)
        expensive_ops = self._find_expensive_operations(activities)

        # Generate suggestions
        suggestions = self._generate_suggestions(
            activities, redundant_calls, failed_retries, expensive_ops
        )

        # Calculate scores
        success_rate = len(successful) / total_actions * 100 if total_actions > 0 else 0
        cost_efficiency = self._calculate_cost_efficiency(activities)
        time_efficiency = self._calculate_time_efficiency(activities)
        security_score = self._calculate_security_score(activities)
        overall_score = (success_rate + cost_efficiency + time_efficiency + security_score) / 4

        # Top consumers
        top_cost = self._get_top_consumers(activities, "cost_usd")
        top_time = self._get_top_consumers(activities, "duration_ms")
        top_failures = self._get_top_failures(activities)

        return EfficiencyReport(
            agent_id=agent_id,
            analysis_period=f"{days} days",
            generated_at=datetime.now(timezone.utc),
            overall_score=round(overall_score, 1),
            cost_efficiency=round(cost_efficiency, 1),
            time_efficiency=round(time_efficiency, 1),
            success_rate=round(success_rate, 1),
            security_score=round(security_score, 1),
            total_actions=total_actions,
            total_cost_usd=round(total_cost, 4),
            total_duration_ms=total_duration,
            avg_action_duration_ms=total_duration / total_actions if total_actions > 0 else 0,
            redundant_calls=len(redundant_calls),
            failed_retries=len(failed_retries),
            expensive_operations=len(expensive_ops),
            suggestions=suggestions,
            top_cost_actions=top_cost,
            top_time_actions=top_time,
            top_failure_actions=top_failures,
        )

    def _empty_report(self, agent_id: str, days: int) -> EfficiencyReport:
        """Return an empty report when no data is available."""
        return EfficiencyReport(
            agent_id=agent_id,
            analysis_period=f"{days} days",
            generated_at=datetime.now(timezone.utc),
            overall_score=0.0,
            cost_efficiency=0.0,
            time_efficiency=0.0,
            success_rate=0.0,
            security_score=100.0,
            total_actions=0,
            total_cost_usd=0.0,
            total_duration_ms=0,
            avg_action_duration_ms=0.0,
            redundant_calls=0,
            failed_retries=0,
            expensive_operations=0,
            suggestions=[],
            top_cost_actions=[],
            top_time_actions=[],
            top_failure_actions=[],
        )

    def _find_redundant_calls(
        self,
        activities: list[Activity],
    ) -> list[dict[str, Any]]:
        """Find potentially redundant consecutive calls."""
        redundant = []
        prev_activity = None

        for activity in activities:
            if prev_activity:
                # Same action within 5 seconds with same parameters
                time_diff = (activity.timestamp - prev_activity.timestamp).total_seconds()
                if (
                    time_diff < 5
                    and activity.name == prev_activity.name
                    and activity.target == prev_activity.target
                    and activity.activity_type == prev_activity.activity_type
                ):
                    redundant.append({
                        "action_id": activity.action_id,
                        "name": activity.name,
                        "time_since_previous": time_diff,
                    })

            prev_activity = activity

        return redundant

    def _find_failed_retries(
        self,
        activities: list[Activity],
    ) -> list[dict[str, Any]]:
        """Find failed actions that were retried without changes."""
        failed_retries = []
        session_failures: dict[str, list[Activity]] = defaultdict(list)

        # Group failures by session
        for activity in activities:
            if activity.status == "failure":
                session_failures[activity.session_id].append(activity)

        # Look for repeated failures with same signature
        for session_id, failures in session_failures.items():
            failure_signatures = Counter()
            for f in failures:
                sig = f"{f.name}:{f.target}"
                failure_signatures[sig] += 1

            for sig, count in failure_signatures.items():
                if count > 2:  # Same failure 3+ times
                    failed_retries.append({
                        "session_id": session_id,
                        "signature": sig,
                        "retry_count": count,
                    })

        return failed_retries

    def _find_expensive_operations(
        self,
        activities: list[Activity],
    ) -> list[dict[str, Any]]:
        """Find unusually expensive operations."""
        expensive = []

        # Calculate average cost for LLM calls
        llm_costs = [a.cost_usd for a in activities if a.activity_type == "llm_call" and a.cost_usd > 0]
        avg_cost = sum(llm_costs) / len(llm_costs) if llm_costs else 0

        for activity in activities:
            # Flag if cost is 3x average
            if activity.cost_usd > avg_cost * 3 and activity.cost_usd > 0.01:
                expensive.append({
                    "action_id": activity.action_id,
                    "name": activity.name,
                    "cost_usd": activity.cost_usd,
                    "avg_cost": avg_cost,
                    "multiplier": activity.cost_usd / avg_cost if avg_cost > 0 else 0,
                })

        return sorted(expensive, key=lambda x: x["cost_usd"], reverse=True)[:10]

    def _generate_suggestions(
        self,
        activities: list[Activity],
        redundant: list[dict],
        failed_retries: list[dict],
        expensive: list[dict],
    ) -> list[EfficiencySuggestion]:
        """Generate optimization suggestions based on analysis."""
        suggestions = []

        # Redundancy suggestions
        if redundant:
            suggestions.append(EfficiencySuggestion(
                suggestion_type="redundancy",
                severity="warning" if len(redundant) > 10 else "info",
                title="Redundant API calls detected",
                description=f"Found {len(redundant)} potentially redundant consecutive calls to the same endpoints.",
                impact=f"Could reduce API calls by up to {len(redundant)} requests",
                affected_actions=[r["action_id"] for r in redundant[:5]],
                recommendation="Consider implementing caching or deduplication for frequently repeated calls within short time windows.",
            ))

        # Failed retry suggestions
        if failed_retries:
            total_retries = sum(r["retry_count"] for r in failed_retries)
            suggestions.append(EfficiencySuggestion(
                suggestion_type="error_retry",
                severity="warning",
                title="Ineffective retry patterns",
                description=f"Found {len(failed_retries)} operations that failed repeatedly ({total_retries} total retries) without changes.",
                impact=f"Could save {total_retries} failed calls by implementing better error handling",
                affected_actions=[],
                recommendation="Implement exponential backoff and check error types before retrying. Some errors (auth, not found) should not be retried.",
            ))

        # Cost suggestions
        if expensive:
            total_expensive_cost = sum(e["cost_usd"] for e in expensive)
            suggestions.append(EfficiencySuggestion(
                suggestion_type="cost",
                severity="critical" if total_expensive_cost > 1.0 else "info",
                title="High-cost LLM operations identified",
                description=f"Found {len(expensive)} operations costing significantly more than average (${total_expensive_cost:.4f} total).",
                impact=f"Review these calls to potentially save ${total_expensive_cost * 0.5:.4f}",
                affected_actions=[e["action_id"] for e in expensive[:5]],
                recommendation="Consider using smaller models for simple tasks, implementing prompt caching, or batching similar requests.",
            ))

        # General efficiency suggestions based on patterns
        api_calls = [a for a in activities if a.activity_type == "api_call"]
        if api_calls:
            api_types = Counter(a.name for a in api_calls)
            most_common_api = api_types.most_common(1)
            if most_common_api and most_common_api[0][1] > len(api_calls) * 0.3:
                api_name, count = most_common_api[0]
                suggestions.append(EfficiencySuggestion(
                    suggestion_type="batching",
                    severity="info",
                    title=f"Frequent calls to {api_name}",
                    description=f"'{api_name}' was called {count} times ({count/len(api_calls)*100:.0f}% of all API calls).",
                    impact="Batching could reduce latency and rate limit usage",
                    affected_actions=[],
                    recommendation="If this API supports batching, consider grouping multiple requests together.",
                ))

        return suggestions

    def _calculate_cost_efficiency(self, activities: list[Activity]) -> float:
        """Calculate cost efficiency score (0-100)."""
        llm_activities = [a for a in activities if a.activity_type == "llm_call"]
        if not llm_activities:
            return 100.0

        # Score based on cost per successful action
        successful = [a for a in llm_activities if a.status == "success"]
        if not successful:
            return 0.0

        total_cost = sum(a.cost_usd for a in llm_activities)
        wasted_cost = sum(a.cost_usd for a in llm_activities if a.status != "success")

        efficiency = (1 - wasted_cost / total_cost) * 100 if total_cost > 0 else 100
        return max(0, min(100, efficiency))

    def _calculate_time_efficiency(self, activities: list[Activity]) -> float:
        """Calculate time efficiency score (0-100)."""
        if not activities:
            return 100.0

        durations = [a.duration_ms for a in activities if a.duration_ms > 0]
        if not durations:
            return 100.0

        # Score based on consistency and timeout ratio
        avg_duration = sum(durations) / len(durations)
        timeout_count = sum(1 for a in activities if a.status == "timeout")
        timeout_ratio = timeout_count / len(activities)

        # Penalize high variance and timeouts
        variance_penalty = min(50, sum(abs(d - avg_duration) for d in durations) / len(durations) / 100)
        timeout_penalty = timeout_ratio * 50

        return max(0, 100 - variance_penalty - timeout_penalty)

    def _calculate_security_score(self, activities: list[Activity]) -> float:
        """Calculate security score based on risk and violations."""
        if not activities:
            return 100.0

        blocked = sum(1 for a in activities if a.status == "blocked")
        high_risk = sum(1 for a in activities if a.risk_score >= 0.7)
        total = len(activities)

        blocked_penalty = (blocked / total) * 30 if total > 0 else 0
        risk_penalty = (high_risk / total) * 20 if total > 0 else 0

        return max(0, 100 - blocked_penalty - risk_penalty)

    def _get_top_consumers(
        self,
        activities: list[Activity],
        field: str,
        limit: int = 5,
    ) -> list[dict[str, Any]]:
        """Get top consuming actions by a field."""
        aggregated: dict[str, dict] = defaultdict(lambda: {"count": 0, "total": 0})

        for activity in activities:
            value = getattr(activity, field, 0)
            key = f"{activity.activity_type}:{activity.name}"
            aggregated[key]["count"] += 1
            aggregated[key]["total"] += value
            aggregated[key]["name"] = activity.name
            aggregated[key]["type"] = activity.activity_type

        sorted_items = sorted(
            aggregated.items(),
            key=lambda x: x[1]["total"],
            reverse=True,
        )[:limit]

        return [
            {
                "name": v["name"],
                "type": v["type"],
                "count": v["count"],
                "total": round(v["total"], 4) if field == "cost_usd" else v["total"],
            }
            for _, v in sorted_items
        ]

    def _get_top_failures(
        self,
        activities: list[Activity],
        limit: int = 5,
    ) -> list[dict[str, Any]]:
        """Get actions with highest failure rates."""
        action_stats: dict[str, dict] = defaultdict(lambda: {"success": 0, "failure": 0})

        for activity in activities:
            key = f"{activity.activity_type}:{activity.name}"
            if activity.status == "success":
                action_stats[key]["success"] += 1
            elif activity.status == "failure":
                action_stats[key]["failure"] += 1
            action_stats[key]["name"] = activity.name
            action_stats[key]["type"] = activity.activity_type

        # Calculate failure rates
        failure_rates = []
        for key, stats in action_stats.items():
            total = stats["success"] + stats["failure"]
            if total >= 3 and stats["failure"] > 0:  # Minimum 3 attempts
                rate = stats["failure"] / total
                failure_rates.append({
                    "name": stats["name"],
                    "type": stats["type"],
                    "failure_rate": round(rate * 100, 1),
                    "failures": stats["failure"],
                    "total": total,
                })

        return sorted(failure_rates, key=lambda x: x["failure_rate"], reverse=True)[:limit]
