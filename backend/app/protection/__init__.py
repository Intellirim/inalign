"""
In-A-Lign Protection Shield.

Cloudflare-style protection layer for AI applications.
"""

from app.protection.shield import (
    Shield,
    ThreatLevel,
    Action,
    ThreatEvent,
    UserProfile,
    RateLimiter,
    AnomalyDetector,
)

__all__ = [
    "Shield",
    "ThreatLevel",
    "Action",
    "ThreatEvent",
    "UserProfile",
    "RateLimiter",
    "AnomalyDetector",
]
