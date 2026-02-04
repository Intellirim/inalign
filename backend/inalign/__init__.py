"""
In-A-Lign SDK - AI Agent Security & Efficiency

Usage:
    from inalign import Guard

    guard = Guard()
    result = guard.check("user input here")

    if result.safe:
        # proceed with LLM call
    else:
        print(f"Blocked: {result.threats}")
"""

from inalign.guard import Guard, GuardResult
from inalign.config import InALignConfig

__version__ = "0.1.0"
__all__ = ["Guard", "GuardResult", "InALignConfig"]
