"""
PII sanitizer.

Replaces detected PII spans in text with labelled placeholders
or partially masked values. Labels are provided in both English
and Korean for bilingual reporting.
"""

from __future__ import annotations

import logging
import re
from typing import Any

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Label map: PII type -> display label (Korean)
# ---------------------------------------------------------------------------

LABEL_MAP: dict[str, str] = {
    # Korean PII
    "resident_id": "[주민등록번호]",
    "phone_mobile": "[전화번호]",
    "phone_landline": "[전화번호]",
    "passport": "[여권번호]",
    "driver_license": "[운전면허번호]",
    "bank_kb": "[계좌번호]",
    "bank_shinhan": "[계좌번호]",
    "bank_woori": "[계좌번호]",
    "bank_hana": "[계좌번호]",
    "bank_nh": "[계좌번호]",
    # Global PII
    "email": "[이메일]",
    "credit_card": "[카드번호]",
    "ip_address": "[IP주소]",
    "ssn_us": "[SSN]",
    "passport_general": "[여권번호]",
}


class PIISanitizer:
    """Replace or mask PII occurrences in text."""

    def __init__(self, label_map: dict[str, str] | None = None) -> None:
        self._label_map = label_map or LABEL_MAP

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def sanitize(
        self,
        text: str,
        pii_items: list[dict[str, Any]],
    ) -> str:
        """Replace each PII match in *text* with its corresponding label.

        Replacements are applied from the end of the string to the
        beginning so that earlier positions remain valid as the string
        length changes.

        Parameters
        ----------
        text:
            The original text.
        pii_items:
            A list of PII detection dicts, each containing at minimum
            ``pii_type`` (str), ``start`` (int), and ``end`` (int).

        Returns
        -------
        str:
            The sanitized text with PII replaced by labels.
        """
        if not pii_items:
            return text

        # Sort by start position descending so we can replace safely
        # from the end of the string backwards.
        sorted_items = sorted(pii_items, key=lambda x: x.get("start", 0), reverse=True)
        result = text

        for item in sorted_items:
            pii_type: str = item.get("pii_type", "unknown")
            start: int = item.get("start", 0)
            end: int = item.get("end", 0)

            if start < 0 or end <= start or end > len(result):
                logger.warning(
                    "Skipping invalid PII span: type=%s start=%d end=%d text_len=%d",
                    pii_type,
                    start,
                    end,
                    len(result),
                )
                continue

            label = self._label_map.get(pii_type, f"[{pii_type.upper()}]")
            result = result[:start] + label + result[end:]

        return result

    # ------------------------------------------------------------------
    # Partial masking
    # ------------------------------------------------------------------

    @staticmethod
    def _mask_value(value: str, pii_type: str) -> str:
        """Return a partially masked version of *value*.

        Masking rules by PII type:

        - **phone**: ``010-****-5678``
        - **resident_id**: ``880101-1******``
        - **email**: ``j***@example.com``
        - **credit_card**: ``****-****-****-1234``
        - **ssn_us**: ``***-**-6789``
        - default: first 2 chars + asterisks + last 2 chars

        Parameters
        ----------
        value:
            The raw PII value.
        pii_type:
            The PII type key.

        Returns
        -------
        str:
            The masked string.
        """
        if not value:
            return value

        # Phone numbers: keep area code and last 4 digits.
        if pii_type in ("phone_mobile", "phone_landline"):
            digits = re.sub(r"[^0-9]", "", value)
            if len(digits) >= 7:
                return f"{digits[:3]}-****-{digits[-4:]}"
            return "***-****-****"

        # Resident Registration Number: keep first 6 digits + gender digit.
        if pii_type == "resident_id":
            digits = re.sub(r"[^0-9]", "", value)
            if len(digits) >= 7:
                return f"{digits[:6]}-{digits[6]}******"
            return "******-*******"

        # Email: keep first char, mask local part, keep domain.
        if pii_type == "email":
            parts = value.split("@")
            if len(parts) == 2:
                local = parts[0]
                domain = parts[1]
                masked_local = local[0] + "***" if local else "***"
                return f"{masked_local}@{domain}"
            return "***@***"

        # Credit card: keep last 4 digits.
        if pii_type == "credit_card":
            digits = re.sub(r"[^0-9]", "", value)
            if len(digits) >= 4:
                return f"****-****-****-{digits[-4:]}"
            return "****-****-****-****"

        # US SSN: keep last 4 digits.
        if pii_type == "ssn_us":
            digits = re.sub(r"[^0-9]", "", value)
            if len(digits) >= 4:
                return f"***-**-{digits[-4:]}"
            return "***-**-****"

        # IP address: mask last octet.
        if pii_type == "ip_address":
            parts = value.split(".")
            if len(parts) == 4:
                return f"{parts[0]}.{parts[1]}.{parts[2]}.***"
            return "***.***.***.***"

        # Bank accounts: keep last 4 digits.
        if pii_type.startswith("bank_"):
            digits = re.sub(r"[^0-9]", "", value)
            if len(digits) >= 4:
                masked_prefix = "*" * (len(digits) - 4)
                return f"{masked_prefix}{digits[-4:]}"
            return "****"

        # Passport / driver_license / default: first 2 + asterisks + last 2.
        if len(value) > 4:
            return value[:2] + "*" * (len(value) - 4) + value[-2:]
        return "*" * len(value)

    def mask(self, text: str, pii_items: list[dict[str, Any]]) -> str:
        """Replace PII spans with partially-masked values.

        Unlike :meth:`sanitize` which replaces with labels, this method
        retains recognisable fragments of the original value.

        Parameters
        ----------
        text:
            The original text.
        pii_items:
            A list of PII detection dicts.

        Returns
        -------
        str:
            The text with PII partially masked.
        """
        if not pii_items:
            return text

        sorted_items = sorted(pii_items, key=lambda x: x.get("start", 0), reverse=True)
        result = text

        for item in sorted_items:
            pii_type: str = item.get("pii_type", "unknown")
            start: int = item.get("start", 0)
            end: int = item.get("end", 0)

            if start < 0 or end <= start or end > len(result):
                continue

            original_value = result[start:end]
            masked_value = self._mask_value(original_value, pii_type)
            result = result[:start] + masked_value + result[end:]

        return result
