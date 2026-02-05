"""
In-A-Lign Efficiency Engine.

Provides cost optimization and smart routing.
"""

from app.efficiency.engine import (
    EfficiencyEngine,
    SmartRouter,
    ResponseCache,
    ComplexityAnalyzer,
    UsageStats,
    get_engine,
    optimize,
    record,
    stats,
)

__all__ = [
    "EfficiencyEngine",
    "SmartRouter",
    "ResponseCache",
    "ComplexityAnalyzer",
    "UsageStats",
    "get_engine",
    "optimize",
    "record",
    "stats",
]
