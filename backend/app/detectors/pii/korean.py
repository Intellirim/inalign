"""
Korean PII detection patterns.

Defines regex patterns and optional validation functions for
Korean-specific personally identifiable information including
resident registration numbers, phone numbers, passports,
driver's licenses, and bank account numbers per major bank.
"""

from __future__ import annotations

import re
from typing import Any, Callable, Optional


# ---------------------------------------------------------------------------
# Validators
# ---------------------------------------------------------------------------

def validate_korean_rrn(value: str) -> bool:
    """Validate a Korean Resident Registration Number (주민등록번호).

    Format: ``YYMMDD-NNNNNNN`` (13 digits with a hyphen after the 6th).

    The last digit is a check digit computed via a weighted-sum
    algorithm defined by the Korean government.

    Parameters
    ----------
    value:
        The candidate string (may include a separating hyphen).

    Returns
    -------
    bool:
        ``True`` if the checksum is valid.
    """
    digits_only = re.sub(r"[^0-9]", "", value)
    if len(digits_only) != 13:
        return False

    # Basic date validation: month 01-12, day 01-31
    month = int(digits_only[2:4])
    day = int(digits_only[4:6])
    if not (1 <= month <= 12):
        return False
    if not (1 <= day <= 31):
        return False

    # Gender digit must be 1-8
    gender_digit = int(digits_only[6])
    if gender_digit < 1 or gender_digit > 8:
        return False

    # Weighted checksum
    weights = [2, 3, 4, 5, 6, 7, 8, 9, 2, 3, 4, 5]
    total = sum(int(digits_only[i]) * weights[i] for i in range(12))
    check = (11 - (total % 11)) % 10

    return check == int(digits_only[12])


def _validate_phone_korea(value: str) -> bool:
    """Validate that a Korean phone number has the right digit count."""
    digits = re.sub(r"[^0-9]", "", value)
    return len(digits) in (10, 11)


# ---------------------------------------------------------------------------
# Pattern catalogue
# ---------------------------------------------------------------------------

KOREAN_PII_PATTERNS: dict[str, dict[str, Any]] = {
    "resident_id": {
        "pattern": r"(?<!\d)\d{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])\s*-\s*[1-8]\d{6}(?!\d)",
        "severity": "critical",
        "description": "Korean Resident Registration Number (주민등록번호)",
        "validator": validate_korean_rrn,
    },
    "phone_mobile": {
        "pattern": r"(?<!\d)010[-.\s]?\d{3,4}[-.\s]?\d{4}(?!\d)",
        "severity": "high",
        "description": "Korean mobile phone number (휴대폰번호)",
        "validator": _validate_phone_korea,
    },
    "phone_landline": {
        "pattern": r"(?<!\d)0(?:2|3[1-3]|4[1-4]|5[1-5]|6[1-4])[-.\s]?\d{3,4}[-.\s]?\d{4}(?!\d)",
        "severity": "high",
        "description": "Korean landline phone number (유선 전화번호)",
        "validator": _validate_phone_korea,
    },
    "passport": {
        "pattern": r"(?<![A-Z])[A-Z]{1,2}\d{7,8}(?!\d)",
        "severity": "high",
        "description": "Korean passport number (여권번호)",
        "validator": None,
    },
    "driver_license": {
        "pattern": r"(?<!\d)\d{2}[-.\s]?\d{2}[-.\s]?\d{6}[-.\s]?\d{2}(?!\d)",
        "severity": "high",
        "description": "Korean driver's license number (운전면허번호)",
        "validator": None,
    },
}
