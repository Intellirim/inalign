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
    # -- Resident Registration Number (주민등록번호) --
    "resident_id": {
        "pattern": r"\b(\d{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01]))\s*[-]\s*([1-8]\d{6})\b",
        "severity": "critical",
        "description": "Korean Resident Registration Number (주민등록번호)",
        "validator": validate_korean_rrn,
    },

    # -- Mobile phone (010-xxxx-xxxx) --
    "phone_mobile": {
        "pattern": r"\b(010)[-.\s]?(\d{3,4})[-.\s]?(\d{4})\b",
        "severity": "high",
        "description": "Korean mobile phone number (휴대폰번호)",
        "validator": _validate_phone_korea,
    },

    # -- Landline phone --
    "phone_landline": {
        "pattern": r"\b(0(?:2|3[1-3]|4[1-4]|5[1-5]|6[1-4]))[-.\s]?(\d{3,4})[-.\s]?(\d{4})\b",
        "severity": "high",
        "description": "Korean landline phone number (유선 전화번호)",
        "validator": _validate_phone_korea,
    },

    # -- Passport (여권번호) --
    "passport": {
        "pattern": r"\b([A-Z]{1,2}\d{7,8})\b",
        "severity": "high",
        "description": "Korean passport number (여권번호)",
        "validator": None,
    },

    # -- Driver's license (운전면허번호) --
    "driver_license": {
        "pattern": r"\b(\d{2})[-.\s]?(\d{2})[-.\s]?(\d{6})[-.\s]?(\d{2})\b",
        "severity": "high",
        "description": "Korean driver's license number (운전면허번호)",
        "validator": None,
    },

    # -- Bank account numbers per bank --
    "bank_kb": {
        "pattern": r"\b(\d{3})[-.\s]?(\d{2})[-.\s]?(\d{4})[-.\s]?(\d{3})\b",
        "severity": "high",
        "description": "KB Kookmin Bank account number (국민은행 계좌번호)",
        "validator": None,
    },
    "bank_shinhan": {
        "pattern": r"\b(\d{3})[-.\s]?(\d{3})[-.\s]?(\d{6})\b",
        "severity": "high",
        "description": "Shinhan Bank account number (신한은행 계좌번호)",
        "validator": None,
    },
    "bank_woori": {
        "pattern": r"\b(\d{4})[-.\s]?(\d{3})[-.\s]?(\d{6})\b",
        "severity": "high",
        "description": "Woori Bank account number (우리은행 계좌번호)",
        "validator": None,
    },
    "bank_hana": {
        "pattern": r"\b(\d{3})[-.\s]?(\d{6})[-.\s]?(\d{5})\b",
        "severity": "high",
        "description": "Hana Bank account number (하나은행 계좌번호)",
        "validator": None,
    },
    "bank_nh": {
        "pattern": r"\b(\d{3})[-.\s]?(\d{4})[-.\s]?(\d{4})[-.\s]?(\d{2})\b",
        "severity": "high",
        "description": "NH NongHyup Bank account number (농협 계좌번호)",
        "validator": None,
    },
}
