"""
Token Usage Tracker - Tracks and analyzes token usage across all operations.

Provides:
- Real-time usage tracking
- Per-agent, per-model, per-user statistics
- Cost calculation and forecasting
- Usage alerts and budget monitoring
"""
from __future__ import annotations

import logging
from collections import defaultdict
from datetime import datetime, timedelta
from typing import Any, Optional
import threading
import json

from app.cost_guard.models import (
    TokenCount, UsageRecord, UsageStats, ModelTier,
    RequestType, CacheStatus, ModelConfig, DEFAULT_MODEL_CONFIGS
)

logger = logging.getLogger("inalign.cost_guard.tracker")


class TokenTracker:
    """
    Tracks token usage across all LLM operations.

    Thread-safe singleton for global usage tracking.
    """

    _instance: Optional["TokenTracker"] = None
    _lock = threading.Lock()

    def __new__(cls) -> "TokenTracker":
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super().__new__(cls)
                    cls._instance._initialized = False
        return cls._instance

    def __init__(self):
        if self._initialized:
            return

        self._records: list[UsageRecord] = []
        self._records_lock = threading.Lock()

        # In-memory aggregations (reset daily)
        self._daily_totals: dict[str, dict[str, float]] = defaultdict(
            lambda: {"tokens": 0, "cost": 0.0, "requests": 0}
        )
        self._monthly_totals: dict[str, dict[str, float]] = defaultdict(
            lambda: {"tokens": 0, "cost": 0.0, "requests": 0}
        )

        # Model configs
        self._model_configs: dict[str, ModelConfig] = DEFAULT_MODEL_CONFIGS.copy()

        # Callbacks for alerts
        self._alert_callbacks: list[callable] = []

        self._initialized = True
        logger.info("TokenTracker initialized")

    def record(
        self,
        agent_id: str,
        session_id: str,
        model: str,
        prompt_tokens: int,
        completion_tokens: int,
        latency_ms: float,
        user_id: Optional[str] = None,
        org_id: Optional[str] = None,
        request_type: RequestType = RequestType.MODERATE,
        cache_status: CacheStatus = CacheStatus.MISS,
        compressed: bool = False,
        original_prompt_tokens: int = 0,
        metadata: Optional[dict[str, Any]] = None,
    ) -> UsageRecord:
        """
        Record a single LLM operation.

        Returns the created UsageRecord.
        """
        now = datetime.utcnow()

        # Get model config for pricing
        config = self._model_configs.get(model)
        if config:
            cost_usd = config.calculate_cost(prompt_tokens, completion_tokens)
            model_tier = config.tier
        else:
            # Fallback pricing estimate
            cost_usd = (prompt_tokens + completion_tokens) * 0.000002
            model_tier = ModelTier.STANDARD
            logger.warning(f"Unknown model '{model}', using fallback pricing")

        tokens = TokenCount(
            prompt_tokens=prompt_tokens,
            completion_tokens=completion_tokens,
            cached_tokens=prompt_tokens if cache_status == CacheStatus.HIT else 0,
        )

        record = UsageRecord(
            timestamp=now,
            agent_id=agent_id,
            session_id=session_id,
            user_id=user_id,
            org_id=org_id,
            model=model,
            model_tier=model_tier,
            request_type=request_type,
            tokens=tokens,
            cost_usd=cost_usd,
            cache_status=cache_status,
            latency_ms=latency_ms,
            compressed=compressed,
            original_prompt_tokens=original_prompt_tokens or prompt_tokens,
            metadata=metadata or {},
        )

        with self._records_lock:
            self._records.append(record)

            # Update aggregations
            day_key = now.strftime("%Y-%m-%d")
            month_key = now.strftime("%Y-%m")

            self._daily_totals[day_key]["tokens"] += tokens.total_tokens
            self._daily_totals[day_key]["cost"] += cost_usd
            self._daily_totals[day_key]["requests"] += 1

            self._monthly_totals[month_key]["tokens"] += tokens.total_tokens
            self._monthly_totals[month_key]["cost"] += cost_usd
            self._monthly_totals[month_key]["requests"] += 1

        logger.debug(
            f"Recorded: {model} | {tokens.total_tokens} tokens | ${cost_usd:.6f} | "
            f"agent={agent_id}"
        )

        return record

    def get_stats(
        self,
        period_hours: int = 24,
        agent_id: Optional[str] = None,
        user_id: Optional[str] = None,
        org_id: Optional[str] = None,
        model: Optional[str] = None,
    ) -> UsageStats:
        """
        Get aggregated usage statistics for a time period.
        """
        now = datetime.utcnow()
        period_start = now - timedelta(hours=period_hours)

        with self._records_lock:
            # Filter records
            filtered = [
                r for r in self._records
                if r.timestamp >= period_start
                and (agent_id is None or r.agent_id == agent_id)
                and (user_id is None or r.user_id == user_id)
                and (org_id is None or r.org_id == org_id)
                and (model is None or r.model == model)
            ]

        if not filtered:
            return UsageStats(period_start=period_start, period_end=now)

        # Calculate totals
        stats = UsageStats(
            period_start=period_start,
            period_end=now,
            total_requests=len(filtered),
            total_tokens=sum(r.tokens.total_tokens for r in filtered),
            total_prompt_tokens=sum(r.tokens.prompt_tokens for r in filtered),
            total_completion_tokens=sum(r.tokens.completion_tokens for r in filtered),
            total_cost_usd=sum(r.cost_usd for r in filtered),
        )

        # Cache savings
        cached_records = [r for r in filtered if r.cache_status == CacheStatus.HIT]
        stats.cached_requests = len(cached_records)
        stats.cached_tokens = sum(r.tokens.cached_tokens for r in cached_records)

        # Compression savings
        compressed_records = [r for r in filtered if r.compressed]
        stats.tokens_saved_by_compression = sum(
            r.original_prompt_tokens - r.tokens.prompt_tokens
            for r in compressed_records
        )

        # Calculate cost savings
        # Estimate: saved tokens * average cost per token
        avg_cost_per_token = stats.total_cost_usd / max(stats.total_tokens, 1)
        stats.tokens_saved_by_cache = stats.cached_tokens
        stats.cost_saved_usd = (
            stats.tokens_saved_by_compression + stats.tokens_saved_by_cache
        ) * avg_cost_per_token

        # Breakdowns
        stats.by_model = self._aggregate_by_field(filtered, "model")
        stats.by_agent = self._aggregate_by_field(filtered, "agent_id")
        stats.by_user = self._aggregate_by_field(filtered, "user_id")
        stats.by_org = self._aggregate_by_field(filtered, "org_id")
        stats.by_tier = self._aggregate_by_field(
            filtered, "model_tier",
            key_transform=lambda x: x.value if x else "unknown"
        )

        # Averages
        stats.avg_prompt_tokens = stats.total_prompt_tokens / len(filtered)
        stats.avg_completion_tokens = stats.total_completion_tokens / len(filtered)
        stats.avg_latency_ms = sum(r.latency_ms for r in filtered) / len(filtered)
        stats.cache_hit_rate = stats.cached_requests / len(filtered) if filtered else 0

        if compressed_records:
            total_original = sum(r.original_prompt_tokens for r in compressed_records)
            total_compressed = sum(r.tokens.prompt_tokens for r in compressed_records)
            stats.compression_ratio = 1 - (total_compressed / max(total_original, 1))

        return stats

    def _aggregate_by_field(
        self,
        records: list[UsageRecord],
        field: str,
        key_transform: Optional[callable] = None,
    ) -> dict[str, dict[str, Any]]:
        """Aggregate records by a specific field."""
        result: dict[str, dict[str, Any]] = defaultdict(
            lambda: {"requests": 0, "tokens": 0, "cost": 0.0}
        )

        for r in records:
            key = getattr(r, field, None)
            if key is None:
                key = "unknown"
            elif key_transform:
                key = key_transform(key)

            result[key]["requests"] += 1
            result[key]["tokens"] += r.tokens.total_tokens
            result[key]["cost"] += r.cost_usd

        return dict(result)

    def get_daily_total(self, date: Optional[str] = None) -> dict[str, float]:
        """Get total usage for a specific day (default: today)."""
        if date is None:
            date = datetime.utcnow().strftime("%Y-%m-%d")
        return dict(self._daily_totals.get(date, {"tokens": 0, "cost": 0.0, "requests": 0}))

    def get_monthly_total(self, month: Optional[str] = None) -> dict[str, float]:
        """Get total usage for a specific month (default: current month)."""
        if month is None:
            month = datetime.utcnow().strftime("%Y-%m")
        return dict(self._monthly_totals.get(month, {"tokens": 0, "cost": 0.0, "requests": 0}))

    def estimate_token_count(self, text: str) -> int:
        """
        Estimate token count for a text string.
        Uses rough approximation: ~4 characters per token for English.
        """
        # More accurate: use tiktoken if available
        try:
            import tiktoken
            enc = tiktoken.get_encoding("cl100k_base")
            return len(enc.encode(text))
        except ImportError:
            # Fallback: rough estimate
            return len(text) // 4

    def register_alert_callback(self, callback: callable) -> None:
        """Register a callback for usage alerts."""
        self._alert_callbacks.append(callback)

    def check_alerts(self, policy_budget: float, current_usage: float) -> None:
        """Check if any alert thresholds are exceeded."""
        if policy_budget <= 0:
            return

        usage_percent = (current_usage / policy_budget) * 100

        if usage_percent >= 100:
            self._trigger_alert("BUDGET_EXCEEDED", usage_percent, current_usage, policy_budget)
        elif usage_percent >= 90:
            self._trigger_alert("BUDGET_CRITICAL", usage_percent, current_usage, policy_budget)
        elif usage_percent >= 80:
            self._trigger_alert("BUDGET_WARNING", usage_percent, current_usage, policy_budget)

    def _trigger_alert(
        self,
        alert_type: str,
        usage_percent: float,
        current: float,
        budget: float,
    ) -> None:
        """Trigger alert callbacks."""
        alert_data = {
            "type": alert_type,
            "usage_percent": round(usage_percent, 2),
            "current_usd": round(current, 4),
            "budget_usd": round(budget, 4),
            "timestamp": datetime.utcnow().isoformat(),
        }

        logger.warning(f"Cost alert: {alert_type} - {usage_percent:.1f}% of budget used")

        for callback in self._alert_callbacks:
            try:
                callback(alert_data)
            except Exception as e:
                logger.error(f"Alert callback failed: {e}")

    def export_records(
        self,
        period_hours: int = 24,
        format: str = "json",
    ) -> str:
        """Export usage records for external analysis."""
        now = datetime.utcnow()
        period_start = now - timedelta(hours=period_hours)

        with self._records_lock:
            filtered = [r for r in self._records if r.timestamp >= period_start]

        if format == "json":
            return json.dumps([
                {
                    "timestamp": r.timestamp.isoformat(),
                    "agent_id": r.agent_id,
                    "session_id": r.session_id,
                    "user_id": r.user_id,
                    "org_id": r.org_id,
                    "model": r.model,
                    "model_tier": r.model_tier.value,
                    "tokens": {
                        "prompt": r.tokens.prompt_tokens,
                        "completion": r.tokens.completion_tokens,
                        "total": r.tokens.total_tokens,
                    },
                    "cost_usd": r.cost_usd,
                    "cache_status": r.cache_status.value,
                    "latency_ms": r.latency_ms,
                    "compressed": r.compressed,
                }
                for r in filtered
            ], indent=2)

        raise ValueError(f"Unsupported format: {format}")

    def clear_old_records(self, keep_days: int = 30) -> int:
        """Clear records older than N days. Returns count of deleted records."""
        cutoff = datetime.utcnow() - timedelta(days=keep_days)

        with self._records_lock:
            original_count = len(self._records)
            self._records = [r for r in self._records if r.timestamp >= cutoff]
            deleted = original_count - len(self._records)

        if deleted > 0:
            logger.info(f"Cleared {deleted} old usage records")

        return deleted
