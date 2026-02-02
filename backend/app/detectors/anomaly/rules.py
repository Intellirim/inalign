"""
Anomaly detection rules.

Defines a catalogue of behavioural rules for identifying suspicious
agent session activity, such as high-frequency requests, off-hours
access, sensitive data queries, and bulk operations.
"""

from __future__ import annotations

from typing import Any, Callable

# ---------------------------------------------------------------------------
# Sensitive targets
# ---------------------------------------------------------------------------

SENSITIVE_TARGETS: list[str] = [
    "users_table",
    "passwords",
    "credentials",
    "admin",
    "secrets",
    "payment",
    "billing",
    "tokens",
    "private_keys",
    "ssn",
    "credit_cards",
    "bank_accounts",
    "personal_data",
    "audit_log",
    "encryption_keys",
]

# ---------------------------------------------------------------------------
# Rule definitions
# ---------------------------------------------------------------------------

ANOMALY_RULES: list[dict[str, Any]] = [
    {
        "id": "ANOM-001",
        "name": "high_frequency",
        "description": (
            "Detects when a session issues more than 50 actions per minute, "
            "indicating automated or scripted abuse."
        ),
        "check": "check_frequency",
        "severity": "high",
        "threshold": 50,
        "window_seconds": 60,
    },
    {
        "id": "ANOM-002",
        "name": "off_hours",
        "description": (
            "Flags actions performed between 02:00 and 05:00 local time, "
            "which may indicate compromised credentials."
        ),
        "check": "check_off_hours",
        "severity": "medium",
        "start_hour": 2,
        "end_hour": 5,
    },
    {
        "id": "ANOM-003",
        "name": "sensitive_data_access",
        "description": (
            "Detects access to tables or resources classified as sensitive, "
            "such as passwords, credentials, payment, and billing data."
        ),
        "check": "check_sensitive_access",
        "severity": "high",
    },
    {
        "id": "ANOM-004",
        "name": "external_exfiltration",
        "description": (
            "Flags actions that appear to send data to external endpoints, "
            "suggesting possible data exfiltration."
        ),
        "check": "check_external_call",
        "severity": "critical",
    },
    {
        "id": "ANOM-005",
        "name": "unusual_sequence",
        "description": (
            "Identifies uncommon action sequences that deviate from "
            "established session behavior baselines (e.g. read-read-delete)."
        ),
        "check": "check_unusual_sequence",
        "severity": "medium",
    },
    {
        "id": "ANOM-006",
        "name": "rapid_privilege_changes",
        "description": (
            "Detects rapid changes in user roles or permission levels "
            "within a short time window, indicating possible escalation."
        ),
        "check": "check_rapid_privilege_changes",
        "severity": "high",
    },
    {
        "id": "ANOM-007",
        "name": "bulk_data_access",
        "description": (
            "Flags queries that retrieve an unusually large number of "
            "records in a single operation."
        ),
        "check": "check_bulk_data_access",
        "severity": "high",
        "record_threshold": 1000,
    },
    {
        "id": "ANOM-008",
        "name": "repeated_failures",
        "description": (
            "Detects a high number of consecutive failed operations, "
            "which may indicate brute-force or probing behavior."
        ),
        "check": "check_repeated_failures",
        "severity": "medium",
        "failure_threshold": 10,
    },
]

# Lookup by rule ID for convenience.
RULES_BY_ID: dict[str, dict[str, Any]] = {
    rule["id"]: rule for rule in ANOMALY_RULES
}

# Lookup by rule name.
RULES_BY_NAME: dict[str, dict[str, Any]] = {
    rule["name"]: rule for rule in ANOMALY_RULES
}
