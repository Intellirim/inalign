"""
Policy Engine for Agent Security

Provides policy presets and runtime policy management for
controlling security behavior across different environments.

Policy Presets:
- STRICT_ENTERPRISE: Maximum security, block on any threat
- BALANCED: Default production settings
- DEV_SANDBOX: Permissive, log-only mode for development

Policy Actions:
- BLOCK: Stop execution, return error
- MASK: Redact sensitive data, continue
- WARN: Log warning, continue
- LOG_ONLY: Silent logging, no intervention
- ALLOW: No action
"""

import os
import json
import logging
from typing import Any, Optional, Callable
from datetime import datetime, timezone
from dataclasses import dataclass, field, asdict
from enum import Enum
from copy import deepcopy

logger = logging.getLogger("inalign-policy")


class PolicyAction(str, Enum):
    """Actions that can be taken when a policy rule matches."""
    BLOCK = "block"
    MASK = "mask"
    WARN = "warn"
    LOG_ONLY = "log_only"
    ALLOW = "allow"


class ThreatCategory(str, Enum):
    """Categories of security threats."""
    INJECTION = "injection"
    JAILBREAK = "jailbreak"
    PII = "pii"
    EXFILTRATION = "exfiltration"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    TOOL_POISONING = "tool_poisoning"
    SENSITIVE_FILE = "sensitive_file"
    COMMAND_INJECTION = "command_injection"
    UNUSUAL_BEHAVIOR = "unusual_behavior"


@dataclass
class PolicyRule:
    """A single policy rule."""
    category: ThreatCategory
    action: PolicyAction
    threshold: float = 0.85  # Confidence threshold
    notify: bool = False  # Send notification
    log: bool = True  # Log event


@dataclass
class PolicyPreset:
    """A complete policy preset with rules for all categories."""
    name: str
    description: str
    rules: dict[ThreatCategory, PolicyRule]
    default_action: PolicyAction = PolicyAction.WARN
    risk_score_multiplier: float = 1.0  # For risk calculation
    metadata: dict[str, Any] = field(default_factory=dict)

    def get_action(self, category: ThreatCategory, confidence: float = 1.0) -> PolicyAction:
        """Get the action for a threat category given confidence."""
        rule = self.rules.get(category)
        if not rule:
            return self.default_action
        if confidence >= rule.threshold:
            return rule.action
        return PolicyAction.ALLOW

    def should_notify(self, category: ThreatCategory) -> bool:
        """Check if notification should be sent."""
        rule = self.rules.get(category)
        return rule.notify if rule else False

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "name": self.name,
            "description": self.description,
            "rules": {
                cat.value: {
                    "action": rule.action.value,
                    "threshold": rule.threshold,
                    "notify": rule.notify,
                    "log": rule.log,
                }
                for cat, rule in self.rules.items()
            },
            "default_action": self.default_action.value,
            "risk_score_multiplier": self.risk_score_multiplier,
            "metadata": self.metadata,
        }


# ==========================================
# PRESET DEFINITIONS
# ==========================================

STRICT_ENTERPRISE = PolicyPreset(
    name="STRICT_ENTERPRISE",
    description="Maximum security for enterprise environments. Blocks all threats, notifies on critical.",
    rules={
        ThreatCategory.INJECTION: PolicyRule(
            category=ThreatCategory.INJECTION,
            action=PolicyAction.BLOCK,
            threshold=0.7,
            notify=True,
        ),
        ThreatCategory.JAILBREAK: PolicyRule(
            category=ThreatCategory.JAILBREAK,
            action=PolicyAction.BLOCK,
            threshold=0.7,
            notify=True,
        ),
        ThreatCategory.PII: PolicyRule(
            category=ThreatCategory.PII,
            action=PolicyAction.MASK,
            threshold=0.8,
            notify=False,
        ),
        ThreatCategory.EXFILTRATION: PolicyRule(
            category=ThreatCategory.EXFILTRATION,
            action=PolicyAction.BLOCK,
            threshold=0.6,
            notify=True,
        ),
        ThreatCategory.PRIVILEGE_ESCALATION: PolicyRule(
            category=ThreatCategory.PRIVILEGE_ESCALATION,
            action=PolicyAction.BLOCK,
            threshold=0.6,
            notify=True,
        ),
        ThreatCategory.TOOL_POISONING: PolicyRule(
            category=ThreatCategory.TOOL_POISONING,
            action=PolicyAction.BLOCK,
            threshold=0.7,
            notify=True,
        ),
        ThreatCategory.SENSITIVE_FILE: PolicyRule(
            category=ThreatCategory.SENSITIVE_FILE,
            action=PolicyAction.BLOCK,
            threshold=0.9,
            notify=True,
        ),
        ThreatCategory.COMMAND_INJECTION: PolicyRule(
            category=ThreatCategory.COMMAND_INJECTION,
            action=PolicyAction.BLOCK,
            threshold=0.7,
            notify=True,
        ),
        ThreatCategory.UNUSUAL_BEHAVIOR: PolicyRule(
            category=ThreatCategory.UNUSUAL_BEHAVIOR,
            action=PolicyAction.WARN,
            threshold=0.8,
            notify=True,
        ),
    },
    default_action=PolicyAction.BLOCK,
    risk_score_multiplier=1.5,
    metadata={"target": "enterprise", "compliance": ["SOC2", "GDPR"]},
)

BALANCED = PolicyPreset(
    name="BALANCED",
    description="Balanced security for production. Blocks critical threats, warns on moderate.",
    rules={
        ThreatCategory.INJECTION: PolicyRule(
            category=ThreatCategory.INJECTION,
            action=PolicyAction.BLOCK,
            threshold=0.85,
            notify=False,
        ),
        ThreatCategory.JAILBREAK: PolicyRule(
            category=ThreatCategory.JAILBREAK,
            action=PolicyAction.BLOCK,
            threshold=0.85,
            notify=False,
        ),
        ThreatCategory.PII: PolicyRule(
            category=ThreatCategory.PII,
            action=PolicyAction.MASK,
            threshold=0.9,
            notify=False,
        ),
        ThreatCategory.EXFILTRATION: PolicyRule(
            category=ThreatCategory.EXFILTRATION,
            action=PolicyAction.BLOCK,
            threshold=0.8,
            notify=True,
        ),
        ThreatCategory.PRIVILEGE_ESCALATION: PolicyRule(
            category=ThreatCategory.PRIVILEGE_ESCALATION,
            action=PolicyAction.BLOCK,
            threshold=0.8,
            notify=True,
        ),
        ThreatCategory.TOOL_POISONING: PolicyRule(
            category=ThreatCategory.TOOL_POISONING,
            action=PolicyAction.BLOCK,
            threshold=0.85,
            notify=False,
        ),
        ThreatCategory.SENSITIVE_FILE: PolicyRule(
            category=ThreatCategory.SENSITIVE_FILE,
            action=PolicyAction.WARN,
            threshold=0.9,
            notify=False,
        ),
        ThreatCategory.COMMAND_INJECTION: PolicyRule(
            category=ThreatCategory.COMMAND_INJECTION,
            action=PolicyAction.BLOCK,
            threshold=0.85,
            notify=False,
        ),
        ThreatCategory.UNUSUAL_BEHAVIOR: PolicyRule(
            category=ThreatCategory.UNUSUAL_BEHAVIOR,
            action=PolicyAction.LOG_ONLY,
            threshold=0.9,
            notify=False,
        ),
    },
    default_action=PolicyAction.WARN,
    risk_score_multiplier=1.0,
    metadata={"target": "production"},
)

DEV_SANDBOX = PolicyPreset(
    name="DEV_SANDBOX",
    description="Permissive mode for development. Logs everything, blocks nothing.",
    rules={
        ThreatCategory.INJECTION: PolicyRule(
            category=ThreatCategory.INJECTION,
            action=PolicyAction.LOG_ONLY,
            threshold=0.5,
            notify=False,
        ),
        ThreatCategory.JAILBREAK: PolicyRule(
            category=ThreatCategory.JAILBREAK,
            action=PolicyAction.LOG_ONLY,
            threshold=0.5,
            notify=False,
        ),
        ThreatCategory.PII: PolicyRule(
            category=ThreatCategory.PII,
            action=PolicyAction.WARN,
            threshold=0.95,
            notify=False,
        ),
        ThreatCategory.EXFILTRATION: PolicyRule(
            category=ThreatCategory.EXFILTRATION,
            action=PolicyAction.WARN,
            threshold=0.9,
            notify=False,
        ),
        ThreatCategory.PRIVILEGE_ESCALATION: PolicyRule(
            category=ThreatCategory.PRIVILEGE_ESCALATION,
            action=PolicyAction.WARN,
            threshold=0.9,
            notify=False,
        ),
        ThreatCategory.TOOL_POISONING: PolicyRule(
            category=ThreatCategory.TOOL_POISONING,
            action=PolicyAction.LOG_ONLY,
            threshold=0.5,
            notify=False,
        ),
        ThreatCategory.SENSITIVE_FILE: PolicyRule(
            category=ThreatCategory.SENSITIVE_FILE,
            action=PolicyAction.LOG_ONLY,
            threshold=0.95,
            notify=False,
        ),
        ThreatCategory.COMMAND_INJECTION: PolicyRule(
            category=ThreatCategory.COMMAND_INJECTION,
            action=PolicyAction.WARN,
            threshold=0.9,
            notify=False,
        ),
        ThreatCategory.UNUSUAL_BEHAVIOR: PolicyRule(
            category=ThreatCategory.UNUSUAL_BEHAVIOR,
            action=PolicyAction.ALLOW,
            threshold=1.0,
            notify=False,
        ),
    },
    default_action=PolicyAction.LOG_ONLY,
    risk_score_multiplier=0.5,
    metadata={"target": "development", "note": "Not for production use"},
)

# All available presets
PRESETS: dict[str, PolicyPreset] = {
    "STRICT_ENTERPRISE": STRICT_ENTERPRISE,
    "BALANCED": BALANCED,
    "DEV_SANDBOX": DEV_SANDBOX,
}


@dataclass
class PolicyDecision:
    """Result of policy evaluation."""
    action: PolicyAction
    category: ThreatCategory
    confidence: float
    rule_matched: bool
    should_notify: bool
    should_log: bool
    policy_name: str
    reason: str = ""


class PolicyEngine:
    """
    Runtime policy engine for security decisions.

    Features:
    - Policy presets (STRICT, BALANCED, DEV)
    - Custom policy creation
    - Policy simulation
    - Decision logging
    """

    def __init__(self, default_preset: str = "BALANCED"):
        """Initialize with a default preset."""
        self._current_policy = PRESETS.get(default_preset, BALANCED)
        self._custom_policies: dict[str, PolicyPreset] = {}
        self._decision_history: list[PolicyDecision] = []
        self._notification_handlers: list[Callable] = []

    @property
    def current_policy(self) -> PolicyPreset:
        """Get current active policy."""
        return self._current_policy

    def set_policy(self, preset_name: str) -> bool:
        """
        Set the active policy by preset name.
        Returns True if successful.
        """
        if preset_name in PRESETS:
            self._current_policy = PRESETS[preset_name]
            logger.info(f"Policy changed to: {preset_name}")
            return True
        if preset_name in self._custom_policies:
            self._current_policy = self._custom_policies[preset_name]
            logger.info(f"Policy changed to custom: {preset_name}")
            return True
        logger.warning(f"Unknown policy preset: {preset_name}")
        return False

    def get_policy(self) -> dict[str, Any]:
        """Get current policy as dictionary."""
        return self._current_policy.to_dict()

    def list_presets(self) -> list[dict[str, Any]]:
        """List all available presets."""
        presets = []
        for name, preset in PRESETS.items():
            presets.append({
                "name": name,
                "description": preset.description,
                "is_active": name == self._current_policy.name,
            })
        for name, preset in self._custom_policies.items():
            presets.append({
                "name": name,
                "description": preset.description,
                "is_active": name == self._current_policy.name,
                "is_custom": True,
            })
        return presets

    def create_custom_policy(
        self,
        name: str,
        base_preset: str = "BALANCED",
        overrides: dict[str, dict] = None,
    ) -> PolicyPreset:
        """
        Create a custom policy based on a preset with overrides.

        Example:
            engine.create_custom_policy(
                "MY_POLICY",
                base_preset="BALANCED",
                overrides={
                    "pii": {"action": "block", "threshold": 0.7},
                }
            )
        """
        base = PRESETS.get(base_preset, BALANCED)
        rules = deepcopy(base.rules)

        if overrides:
            for cat_str, override in overrides.items():
                try:
                    category = ThreatCategory(cat_str)
                    if category in rules:
                        if "action" in override:
                            rules[category].action = PolicyAction(override["action"])
                        if "threshold" in override:
                            rules[category].threshold = override["threshold"]
                        if "notify" in override:
                            rules[category].notify = override["notify"]
                except (ValueError, KeyError) as e:
                    logger.warning(f"Invalid override for {cat_str}: {e}")

        custom = PolicyPreset(
            name=name,
            description=f"Custom policy based on {base_preset}",
            rules=rules,
            default_action=base.default_action,
            risk_score_multiplier=base.risk_score_multiplier,
            metadata={"base": base_preset, "custom": True},
        )

        self._custom_policies[name] = custom
        return custom

    def evaluate(
        self,
        category: ThreatCategory,
        confidence: float,
        context: dict[str, Any] = None,
    ) -> PolicyDecision:
        """
        Evaluate a threat against current policy.

        Returns a PolicyDecision with the action to take.
        """
        action = self._current_policy.get_action(category, confidence)
        should_notify = self._current_policy.should_notify(category)
        rule = self._current_policy.rules.get(category)

        decision = PolicyDecision(
            action=action,
            category=category,
            confidence=confidence,
            rule_matched=action != PolicyAction.ALLOW,
            should_notify=should_notify,
            should_log=rule.log if rule else True,
            policy_name=self._current_policy.name,
            reason=f"{category.value} detected with {confidence:.2f} confidence",
        )

        # Record decision
        self._decision_history.append(decision)

        # Notify if needed
        if should_notify and action in (PolicyAction.BLOCK, PolicyAction.WARN):
            self._send_notification(decision, context)

        return decision

    def _send_notification(self, decision: PolicyDecision, context: dict = None):
        """Send notification to registered handlers."""
        for handler in self._notification_handlers:
            try:
                handler(decision, context)
            except Exception as e:
                logger.error(f"Notification handler failed: {e}")

    def add_notification_handler(self, handler: Callable):
        """Add a notification handler."""
        self._notification_handlers.append(handler)

    def simulate_policy(
        self,
        preset_name: str,
        events: list[dict],
    ) -> dict[str, Any]:
        """
        Simulate a policy against historical events.

        Args:
            preset_name: Policy to simulate
            events: List of {category, confidence} dicts

        Returns:
            Simulation results with counts per action
        """
        policy = PRESETS.get(preset_name) or self._custom_policies.get(preset_name)
        if not policy:
            return {"error": f"Unknown policy: {preset_name}"}

        results = {
            "policy": preset_name,
            "total_events": len(events),
            "actions": {a.value: 0 for a in PolicyAction},
            "blocked": 0,
            "masked": 0,
            "warned": 0,
            "logged": 0,
            "allowed": 0,
            "notifications": 0,
            "by_category": {},
        }

        for event in events:
            try:
                category = ThreatCategory(event.get("category", ""))
                confidence = event.get("confidence", 1.0)

                action = policy.get_action(category, confidence)
                results["actions"][action.value] += 1

                if action == PolicyAction.BLOCK:
                    results["blocked"] += 1
                elif action == PolicyAction.MASK:
                    results["masked"] += 1
                elif action == PolicyAction.WARN:
                    results["warned"] += 1
                elif action == PolicyAction.LOG_ONLY:
                    results["logged"] += 1
                else:
                    results["allowed"] += 1

                if policy.should_notify(category):
                    results["notifications"] += 1

                # Track by category
                cat_key = category.value
                if cat_key not in results["by_category"]:
                    results["by_category"][cat_key] = {"count": 0, "blocked": 0}
                results["by_category"][cat_key]["count"] += 1
                if action == PolicyAction.BLOCK:
                    results["by_category"][cat_key]["blocked"] += 1

            except (ValueError, KeyError):
                continue

        return results

    def get_decision_history(self, limit: int = 100) -> list[dict]:
        """Get recent policy decisions."""
        return [
            {
                "action": d.action.value,
                "category": d.category.value,
                "confidence": d.confidence,
                "policy": d.policy_name,
                "reason": d.reason,
            }
            for d in self._decision_history[-limit:]
        ]

    def compare_policies(
        self,
        policy_a: str,
        policy_b: str,
    ) -> dict[str, Any]:
        """Compare two policies side by side."""
        preset_a = PRESETS.get(policy_a) or self._custom_policies.get(policy_a)
        preset_b = PRESETS.get(policy_b) or self._custom_policies.get(policy_b)

        if not preset_a or not preset_b:
            return {"error": "One or both policies not found"}

        comparison = {
            "policy_a": policy_a,
            "policy_b": policy_b,
            "differences": [],
        }

        all_categories = set(preset_a.rules.keys()) | set(preset_b.rules.keys())

        for category in all_categories:
            rule_a = preset_a.rules.get(category)
            rule_b = preset_b.rules.get(category)

            if rule_a and rule_b:
                if rule_a.action != rule_b.action or rule_a.threshold != rule_b.threshold:
                    comparison["differences"].append({
                        "category": category.value,
                        "policy_a": {
                            "action": rule_a.action.value,
                            "threshold": rule_a.threshold,
                        },
                        "policy_b": {
                            "action": rule_b.action.value,
                            "threshold": rule_b.threshold,
                        },
                    })
            elif rule_a or rule_b:
                comparison["differences"].append({
                    "category": category.value,
                    "policy_a": {"action": rule_a.action.value} if rule_a else None,
                    "policy_b": {"action": rule_b.action.value} if rule_b else None,
                })

        return comparison


# Global engine instance
_policy_engine: Optional[PolicyEngine] = None


def get_policy_engine() -> PolicyEngine:
    """Get or create the global policy engine."""
    global _policy_engine
    if _policy_engine is None:
        default = os.getenv("INALIGN_DEFAULT_POLICY", "BALANCED")
        _policy_engine = PolicyEngine(default_preset=default)
    return _policy_engine


def evaluate_threat(
    category: str,
    confidence: float,
    context: dict = None,
) -> PolicyDecision:
    """Convenience function to evaluate a threat."""
    engine = get_policy_engine()
    return engine.evaluate(ThreatCategory(category), confidence, context)
