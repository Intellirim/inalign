"""
Global PII detection patterns.

Defines regex patterns and optional validation functions for
internationally common personally identifiable information:
email addresses, credit card numbers, IP addresses, US Social
Security Numbers, and general passport numbers.
"""

from __future__ import annotations

import re
from typing import Any


# ---------------------------------------------------------------------------
# Validators
# ---------------------------------------------------------------------------

def validate_luhn(value: str) -> bool:
    """Validate a credit card number using the Luhn algorithm.

    Parameters
    ----------
    value:
        The candidate string (may contain spaces or hyphens).

    Returns
    -------
    bool:
        ``True`` if the Luhn checksum is valid.
    """
    digits_only = re.sub(r"[^0-9]", "", value)
    if not digits_only or len(digits_only) < 13 or len(digits_only) > 19:
        return False

    total = 0
    reverse_digits = digits_only[::-1]
    for i, ch in enumerate(reverse_digits):
        n = int(ch)
        if i % 2 == 1:
            n *= 2
            if n > 9:
                n -= 9
        total += n

    return total % 10 == 0


def _validate_email(value: str) -> bool:
    """Basic structural validation for an email address."""
    parts = value.split("@")
    if len(parts) != 2:
        return False
    local, domain = parts
    if not local or not domain:
        return False
    if "." not in domain:
        return False
    return True


def _validate_ipv4(value: str) -> bool:
    """Validate that each octet of an IPv4 address is in 0-255."""
    parts = value.split(".")
    if len(parts) != 4:
        return False
    for part in parts:
        try:
            num = int(part)
            if num < 0 or num > 255:
                return False
        except ValueError:
            return False
    return True


# ---------------------------------------------------------------------------
# Pattern catalogue
# ---------------------------------------------------------------------------

GLOBAL_PII_PATTERNS: dict[str, dict[str, Any]] = {
    # -- Email address --
    "email": {
        "pattern": r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b",
        "severity": "medium",
        "description": "Email address",
        "validator": _validate_email,
    },

    # -- Credit card number (13-19 digits, optional separators) --
    "credit_card": {
        "pattern": r"\b(?:\d[ \-]*?){13,19}\b",
        "severity": "critical",
        "description": "Credit card number",
        "validator": validate_luhn,
    },

    # -- IPv4 address --
    "ip_address": {
        "pattern": r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b",
        "severity": "low",
        "description": "IPv4 address",
        "validator": _validate_ipv4,
    },

    # -- US Social Security Number --
    "ssn_us": {
        "pattern": r"\b(?!000|666|9\d{2})\d{3}[-.\s]?(?!00)\d{2}[-.\s]?(?!0000)\d{4}\b",
        "severity": "critical",
        "description": "US Social Security Number (SSN)",
        "validator": None,
    },

    # -- General passport number (1-2 alpha + 6-9 digits) --
    "passport_general": {
        "pattern": r"\b[A-Z]{1,2}\d{6,9}\b",
        "severity": "high",
        "description": "Passport number (general format)",
        "validator": None,
    },
}
