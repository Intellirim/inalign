"""
In-A-Lign Platform - AI Security & Efficiency Solution.

One integration for:
- Security: Injection detection, threat blocking, anomaly detection
- Efficiency: Smart routing, caching, cost optimization
- Protection: Rate limiting, auto-ban, user tracking

Usage:
    from app.platform import InALign, process, record

    # Option 1: Use global instance
    platform = init(api_key="your_key")
    result = process("user input", user_id="user123")

    # Option 2: Use class directly
    platform = InALign(api_key="your_key")
    result = platform.process("user input", user_id="user123")

    # Option 3: Auto-configure from project
    platform = InALign.from_project("/path/to/project")
"""

from app.platform.inalign import (
    InALign,
    PlatformConfig,
    init,
    get_platform,
    process,
    record,
    stats,
)

__all__ = [
    "InALign",
    "PlatformConfig",
    "init",
    "get_platform",
    "process",
    "record",
    "stats",
]
