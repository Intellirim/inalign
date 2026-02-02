"""
Rule-based behavioural anomaly detector.

Analyses individual actions within the context of their session to
identify patterns that indicate suspicious or malicious activity.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any, Optional

from app.detectors.anomaly.rules import ANOMALY_RULES, SENSITIVE_TARGETS

logger = logging.getLogger(__name__)


class AnomalyDetector:
    """Detect behavioral anomalies in agent session actions.

    Each ``detect`` call evaluates a single action dict against a set
    of heuristic rules, using the session context to inform temporal
    and sequential checks.

    Expected shapes
    ---------------
    ``action`` dict::

        {
            "type": str,           # e.g. "query", "update", "delete"
            "target": str,         # resource / table being accessed
            "timestamp": str,      # ISO-8601 datetime
            "record_count": int,   # optional: number of records affected
            "destination": str,    # optional: URL or endpoint
            "metadata": dict,      # optional: extra context
        }

    ``session_context`` dict::

        {
            "action_timestamps": list[str],  # ISO-8601 list of recent action times
            "recent_actions": list[str],     # ordered list of recent action types
            "failure_count": int,            # consecutive failure count
            "privilege_changes": list[str],  # ISO-8601 timestamps of role changes
        }
    """

    def __init__(self) -> None:
        logger.info("AnomalyDetector initialised with %d rules.", len(ANOMALY_RULES))

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def detect(
        self,
        action: dict[str, Any],
        session_context: dict[str, Any],
    ) -> list[dict[str, Any]]:
        """Evaluate *action* against all anomaly rules.

        Parameters
        ----------
        action:
            The action to evaluate.
        session_context:
            Context about the current session (recent history).

        Returns
        -------
        list[dict]:
            A list of anomaly dicts, each containing:
            - ``rule_id``     -- the rule identifier (e.g. ``"ANOM-001"``)
            - ``rule_name``   -- short rule name
            - ``severity``    -- ``"low"`` | ``"medium"`` | ``"high"`` | ``"critical"``
            - ``description`` -- human-readable description
            - ``details``     -- dict with rule-specific details
            - ``timestamp``   -- ISO-8601 timestamp of the action
        """
        anomalies: list[dict[str, Any]] = []

        frequency_result = self._check_frequency(session_context)
        if frequency_result is not None:
            anomalies.append(frequency_result)

        off_hours_result = self._check_off_hours(action)
        if off_hours_result is not None:
            anomalies.append(off_hours_result)

        sensitive_result = self._check_sensitive_access(action)
        if sensitive_result is not None:
            anomalies.append(sensitive_result)

        external_result = self._check_external_call(action)
        if external_result is not None:
            anomalies.append(external_result)

        unusual_result = self._check_unusual_sequence(session_context)
        if unusual_result is not None:
            anomalies.append(unusual_result)

        privilege_result = self._check_rapid_privilege_changes(session_context)
        if privilege_result is not None:
            anomalies.append(privilege_result)

        bulk_result = self._check_bulk_data_access(action)
        if bulk_result is not None:
            anomalies.append(bulk_result)

        failure_result = self._check_repeated_failures(session_context)
        if failure_result is not None:
            anomalies.append(failure_result)

        if anomalies:
            logger.info(
                "AnomalyDetector found %d anomaly/anomalies for action type='%s' target='%s'.",
                len(anomalies),
                action.get("type", "unknown"),
                action.get("target", "unknown"),
            )

        return anomalies

    # ------------------------------------------------------------------
    # Rule checks
    # ------------------------------------------------------------------

    def _check_frequency(
        self, session_context: dict[str, Any]
    ) -> Optional[dict[str, Any]]:
        """ANOM-001: Check if action frequency exceeds threshold.

        Counts the number of actions within the last 60 seconds.
        """
        timestamps_raw: list[str] = session_context.get("action_timestamps", [])
        if not timestamps_raw:
            return None

        now = datetime.now(timezone.utc)
        recent_count = 0

        for ts_str in timestamps_raw:
            try:
                ts = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
                diff = (now - ts).total_seconds()
                if 0 <= diff <= 60:
                    recent_count += 1
            except (ValueError, TypeError):
                continue

        threshold = 50  # actions per minute
        if recent_count > threshold:
            return {
                "rule_id": "ANOM-001",
                "rule_name": "high_frequency",
                "severity": "high",
                "description": ANOMALY_RULES[0]["description"],
                "details": {
                    "actions_per_minute": recent_count,
                    "threshold": threshold,
                },
                "timestamp": now.isoformat(),
            }
        return None

    def _check_off_hours(
        self, action: dict[str, Any]
    ) -> Optional[dict[str, Any]]:
        """ANOM-002: Check if the action occurred during off-hours (02:00-05:00)."""
        ts_str = action.get("timestamp")
        if not ts_str:
            return None

        try:
            ts = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
        except (ValueError, TypeError):
            logger.warning("Invalid timestamp in action: %s", ts_str)
            return None

        hour = ts.hour
        if 2 <= hour < 5:
            return {
                "rule_id": "ANOM-002",
                "rule_name": "off_hours",
                "severity": "medium",
                "description": ANOMALY_RULES[1]["description"],
                "details": {
                    "action_hour": hour,
                    "off_hours_range": "02:00-05:00",
                },
                "timestamp": ts.isoformat(),
            }
        return None

    def _check_sensitive_access(
        self, action: dict[str, Any]
    ) -> Optional[dict[str, Any]]:
        """ANOM-003: Check if the action targets a sensitive resource."""
        target = action.get("target", "").lower()
        if not target:
            return None

        matched_targets: list[str] = []
        for sensitive in SENSITIVE_TARGETS:
            if sensitive in target:
                matched_targets.append(sensitive)

        if matched_targets:
            return {
                "rule_id": "ANOM-003",
                "rule_name": "sensitive_data_access",
                "severity": "high",
                "description": ANOMALY_RULES[2]["description"],
                "details": {
                    "target": target,
                    "matched_sensitive_targets": matched_targets,
                },
                "timestamp": action.get("timestamp", datetime.now(timezone.utc).isoformat()),
            }
        return None

    def _check_external_call(
        self, action: dict[str, Any]
    ) -> Optional[dict[str, Any]]:
        """ANOM-004: Check if the action involves an external destination."""
        destination = action.get("destination", "")
        if not destination:
            return None

        # Flag any action that sends data to an external URL.
        destination_lower = destination.lower()
        is_external = any(
            destination_lower.startswith(prefix)
            for prefix in ("http://", "https://", "ftp://", "sftp://")
        )

        # Also flag if the action type suggests outbound data flow.
        action_type = action.get("type", "").lower()
        is_exfil_action = action_type in (
            "send", "post", "upload", "transmit", "export", "forward",
        )

        if is_external or is_exfil_action:
            return {
                "rule_id": "ANOM-004",
                "rule_name": "external_exfiltration",
                "severity": "critical",
                "description": ANOMALY_RULES[3]["description"],
                "details": {
                    "destination": destination,
                    "action_type": action_type,
                    "is_external_url": is_external,
                },
                "timestamp": action.get("timestamp", datetime.now(timezone.utc).isoformat()),
            }
        return None

    def _check_unusual_sequence(
        self, session_context: dict[str, Any]
    ) -> Optional[dict[str, Any]]:
        """ANOM-005: Check for unusual action sequences."""
        recent_actions: list[str] = session_context.get("recent_actions", [])
        if len(recent_actions) < 3:
            return None

        # Known suspicious sequences (last N actions).
        suspicious_sequences: list[list[str]] = [
            ["read", "read", "delete"],
            ["read", "export", "delete"],
            ["query", "query", "drop"],
            ["read", "download", "delete"],
            ["escalate", "read", "export"],
        ]

        tail = [a.lower() for a in recent_actions[-3:]]

        for seq in suspicious_sequences:
            if tail == seq:
                return {
                    "rule_id": "ANOM-005",
                    "rule_name": "unusual_sequence",
                    "severity": "medium",
                    "description": ANOMALY_RULES[4]["description"],
                    "details": {
                        "detected_sequence": tail,
                        "recent_actions": recent_actions[-5:],
                    },
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                }
        return None

    def _check_rapid_privilege_changes(
        self, session_context: dict[str, Any]
    ) -> Optional[dict[str, Any]]:
        """ANOM-006: Check for rapid privilege / role changes."""
        changes_raw: list[str] = session_context.get("privilege_changes", [])
        if len(changes_raw) < 2:
            return None

        now = datetime.now(timezone.utc)
        recent_changes = 0
        window_seconds = 300  # 5 minutes

        for ts_str in changes_raw:
            try:
                ts = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
                if (now - ts).total_seconds() <= window_seconds:
                    recent_changes += 1
            except (ValueError, TypeError):
                continue

        if recent_changes >= 3:
            return {
                "rule_id": "ANOM-006",
                "rule_name": "rapid_privilege_changes",
                "severity": "high",
                "description": ANOMALY_RULES[5]["description"],
                "details": {
                    "changes_in_window": recent_changes,
                    "window_seconds": window_seconds,
                },
                "timestamp": now.isoformat(),
            }
        return None

    def _check_bulk_data_access(
        self, action: dict[str, Any]
    ) -> Optional[dict[str, Any]]:
        """ANOM-007: Check if a query retrieves too many records."""
        record_count = action.get("record_count", 0)
        threshold = 1000

        if isinstance(record_count, int) and record_count > threshold:
            return {
                "rule_id": "ANOM-007",
                "rule_name": "bulk_data_access",
                "severity": "high",
                "description": ANOMALY_RULES[6]["description"],
                "details": {
                    "record_count": record_count,
                    "threshold": threshold,
                },
                "timestamp": action.get("timestamp", datetime.now(timezone.utc).isoformat()),
            }
        return None

    def _check_repeated_failures(
        self, session_context: dict[str, Any]
    ) -> Optional[dict[str, Any]]:
        """ANOM-008: Check for high consecutive failure count."""
        failure_count = session_context.get("failure_count", 0)
        threshold = 10

        if isinstance(failure_count, int) and failure_count > threshold:
            return {
                "rule_id": "ANOM-008",
                "rule_name": "repeated_failures",
                "severity": "medium",
                "description": ANOMALY_RULES[7]["description"],
                "details": {
                    "consecutive_failures": failure_count,
                    "threshold": threshold,
                },
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }
        return None
