"""
Notification dispatcher service for AgentShield.

Automatically dispatches alerts and policy violations to configured
notification channels (Slack, Telegram, Email, Webhooks).
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any, Optional
from dataclasses import dataclass
from enum import Enum

from app.notifications.slack import SlackNotifier
from app.notifications.telegram import TelegramNotifier
from app.notifications.email import EmailNotifier
from app.notifications.webhook import WebhookNotifier
from app.config import get_settings


logger = logging.getLogger("agentshield.services.notification_dispatcher")


class NotificationChannel(str, Enum):
    """Supported notification channels."""
    SLACK = "slack"
    TELEGRAM = "telegram"
    EMAIL = "email"
    WEBHOOK = "webhook"


class NotificationPriority(str, Enum):
    """Notification priority levels."""
    CRITICAL = "critical"  # Immediate notification
    HIGH = "high"          # Within 1 minute
    MEDIUM = "medium"      # Batched every 5 minutes
    LOW = "low"            # Batched every 15 minutes


@dataclass
class NotificationConfig:
    """Configuration for a notification channel."""
    channel: NotificationChannel
    enabled: bool = True
    webhook_url: Optional[str] = None
    bot_token: Optional[str] = None
    chat_id: Optional[str] = None
    email_to: Optional[list[str]] = None
    min_severity: str = "medium"


class NotificationDispatcher:
    """Central dispatcher for all notification channels.

    Manages notification routing, batching, and delivery across
    multiple configured channels based on severity and preferences.

    Usage::

        dispatcher = NotificationDispatcher()
        dispatcher.configure_slack(webhook_url="https://hooks.slack.com/...")

        await dispatcher.dispatch_alert(
            alert_type="policy_violation",
            severity="high",
            title="Unauthorized Action Blocked",
            description="Agent attempted to access restricted resource",
            agent_id="coding-assistant",
            session_id="sess-abc123",
        )
    """

    def __init__(self) -> None:
        """Initialize the notification dispatcher."""
        self._slack = SlackNotifier()
        self._telegram = TelegramNotifier()
        self._email = EmailNotifier()
        self._webhook = WebhookNotifier()

        self._configs: dict[NotificationChannel, NotificationConfig] = {}
        self._batch_queue: dict[NotificationPriority, list[dict[str, Any]]] = {
            NotificationPriority.CRITICAL: [],
            NotificationPriority.HIGH: [],
            NotificationPriority.MEDIUM: [],
            NotificationPriority.LOW: [],
        }

        # Load default configuration from settings
        self._load_default_config()

    def _load_default_config(self) -> None:
        """Load notification configuration from environment settings."""
        settings = get_settings()

        # Slack configuration
        if settings.slack_webhook_url:
            self._configs[NotificationChannel.SLACK] = NotificationConfig(
                channel=NotificationChannel.SLACK,
                enabled=True,
                webhook_url=settings.slack_webhook_url,
                min_severity=settings.slack_min_severity,
            )
            logger.info("Slack notifications enabled (min_severity=%s)", settings.slack_min_severity)

        # Telegram configuration
        if settings.telegram_bot_token and settings.telegram_chat_id:
            self._configs[NotificationChannel.TELEGRAM] = NotificationConfig(
                channel=NotificationChannel.TELEGRAM,
                enabled=True,
                bot_token=settings.telegram_bot_token,
                chat_id=settings.telegram_chat_id,
                min_severity=settings.telegram_min_severity,
            )
            logger.info("Telegram notifications enabled (min_severity=%s)", settings.telegram_min_severity)

        # Generic webhook configuration
        if settings.webhook_notification_url:
            self._configs[NotificationChannel.WEBHOOK] = NotificationConfig(
                channel=NotificationChannel.WEBHOOK,
                enabled=True,
                webhook_url=settings.webhook_notification_url,
                min_severity=settings.webhook_min_severity,
            )
            logger.info("Webhook notifications enabled (min_severity=%s)", settings.webhook_min_severity)

        # Email configuration
        if settings.sendgrid_api_key and settings.notification_to_emails:
            self._configs[NotificationChannel.EMAIL] = NotificationConfig(
                channel=NotificationChannel.EMAIL,
                enabled=True,
                email_to=settings.notification_to_emails,
                min_severity="high",
            )
            logger.info("Email notifications enabled")

    def configure_slack(
        self,
        webhook_url: str,
        enabled: bool = True,
        min_severity: str = "medium",
    ) -> None:
        """Configure Slack notification channel.

        Parameters
        ----------
        webhook_url:
            Slack Incoming Webhook URL.
        enabled:
            Whether the channel is enabled.
        min_severity:
            Minimum severity to trigger notifications.
        """
        self._configs[NotificationChannel.SLACK] = NotificationConfig(
            channel=NotificationChannel.SLACK,
            enabled=enabled,
            webhook_url=webhook_url,
            min_severity=min_severity,
        )
        logger.info("Slack notification configured (min_severity=%s)", min_severity)

    def configure_telegram(
        self,
        bot_token: str,
        chat_id: str,
        enabled: bool = True,
        min_severity: str = "high",
    ) -> None:
        """Configure Telegram notification channel.

        Parameters
        ----------
        bot_token:
            Telegram Bot API token.
        chat_id:
            Target chat/channel ID.
        enabled:
            Whether the channel is enabled.
        min_severity:
            Minimum severity to trigger notifications.
        """
        self._configs[NotificationChannel.TELEGRAM] = NotificationConfig(
            channel=NotificationChannel.TELEGRAM,
            enabled=enabled,
            bot_token=bot_token,
            chat_id=chat_id,
            min_severity=min_severity,
        )
        logger.info("Telegram notification configured (min_severity=%s)", min_severity)

    def configure_webhook(
        self,
        webhook_url: str,
        enabled: bool = True,
        min_severity: str = "low",
    ) -> None:
        """Configure generic webhook notification channel.

        Parameters
        ----------
        webhook_url:
            Target webhook URL.
        enabled:
            Whether the channel is enabled.
        min_severity:
            Minimum severity to trigger notifications.
        """
        self._configs[NotificationChannel.WEBHOOK] = NotificationConfig(
            channel=NotificationChannel.WEBHOOK,
            enabled=enabled,
            webhook_url=webhook_url,
            min_severity=min_severity,
        )
        logger.info("Webhook notification configured (min_severity=%s)", min_severity)

    async def dispatch_alert(
        self,
        alert_type: str,
        severity: str,
        title: str,
        description: str,
        agent_id: str,
        session_id: str,
        alert_id: Optional[str] = None,
        details: Optional[dict[str, Any]] = None,
    ) -> dict[str, bool]:
        """Dispatch an alert to all configured notification channels.

        Parameters
        ----------
        alert_type:
            Type of alert (e.g., 'policy_violation', 'threat_detected').
        severity:
            Alert severity ('critical', 'high', 'medium', 'low').
        title:
            Short alert title.
        description:
            Detailed description.
        agent_id:
            ID of the agent involved.
        session_id:
            Session where the alert occurred.
        alert_id:
            Optional alert identifier.
        details:
            Additional metadata.

        Returns
        -------
        dict[str, bool]
            Delivery status for each channel attempted.
        """
        alert_data = {
            "alert_type": alert_type,
            "severity": severity,
            "title": title,
            "description": description,
            "agent_id": agent_id,
            "session_id": session_id,
            "alert_id": alert_id or "N/A",
            "details": details or {},
        }

        logger.info(
            "Dispatching alert: type=%s severity=%s agent=%s",
            alert_type, severity, agent_id,
        )

        results: dict[str, bool] = {}
        tasks = []

        for channel, config in self._configs.items():
            if not config.enabled:
                continue

            if not self._meets_severity_threshold(severity, config.min_severity):
                logger.debug(
                    "Skipping %s (severity %s below threshold %s)",
                    channel.value, severity, config.min_severity,
                )
                continue

            task = self._dispatch_to_channel(channel, config, alert_data)
            tasks.append((channel.value, task))

        # Execute all dispatches concurrently
        for channel_name, task in tasks:
            try:
                success = await task
                results[channel_name] = success
            except Exception as e:
                logger.error("Failed to dispatch to %s: %s", channel_name, e)
                results[channel_name] = False

        return results

    async def dispatch_policy_violation(
        self,
        agent_id: str,
        session_id: str,
        action_type: str,
        action_target: str,
        violation_reason: str,
        policy_name: str,
        risk_score: float = 0.0,
    ) -> dict[str, bool]:
        """Dispatch a policy violation notification.

        Convenience method that formats policy violation data
        into a standard alert format.
        """
        severity = "high" if risk_score > 0.7 else "medium" if risk_score > 0.4 else "low"

        return await self.dispatch_alert(
            alert_type="policy_violation",
            severity=severity,
            title=f"Policy Violation: {action_type}",
            description=(
                f"Agent '{agent_id}' attempted '{action_type}' on '{action_target}' "
                f"but was blocked by policy '{policy_name}'.\n\n"
                f"Reason: {violation_reason}"
            ),
            agent_id=agent_id,
            session_id=session_id,
            details={
                "action_type": action_type,
                "action_target": action_target,
                "policy_name": policy_name,
                "risk_score": risk_score,
            },
        )

    async def dispatch_threat_detected(
        self,
        agent_id: str,
        session_id: str,
        threat_type: str,
        threat_details: str,
        confidence: float,
        blocked: bool = True,
    ) -> dict[str, bool]:
        """Dispatch a threat detection notification.

        Convenience method for security threat alerts.
        """
        severity = "critical" if confidence > 0.9 else "high" if confidence > 0.7 else "medium"
        status = "blocked" if blocked else "detected (allowed)"

        return await self.dispatch_alert(
            alert_type="threat_detected",
            severity=severity,
            title=f"Threat {status.title()}: {threat_type}",
            description=(
                f"Security threat detected in agent '{agent_id}'.\n\n"
                f"Type: {threat_type}\n"
                f"Confidence: {confidence:.1%}\n"
                f"Status: {status}\n\n"
                f"Details: {threat_details}"
            ),
            agent_id=agent_id,
            session_id=session_id,
            details={
                "threat_type": threat_type,
                "confidence": confidence,
                "blocked": blocked,
            },
        )

    async def dispatch_anomaly_detected(
        self,
        agent_id: str,
        session_id: str,
        anomaly_type: str,
        description: str,
        metrics: dict[str, Any],
    ) -> dict[str, bool]:
        """Dispatch an anomaly detection notification."""
        return await self.dispatch_alert(
            alert_type="anomaly_detected",
            severity="medium",
            title=f"Anomaly Detected: {anomaly_type}",
            description=description,
            agent_id=agent_id,
            session_id=session_id,
            details={"anomaly_type": anomaly_type, "metrics": metrics},
        )

    async def _dispatch_to_channel(
        self,
        channel: NotificationChannel,
        config: NotificationConfig,
        alert_data: dict[str, Any],
    ) -> bool:
        """Dispatch alert to a specific channel."""
        try:
            if channel == NotificationChannel.SLACK:
                return await self._slack.send(config.webhook_url, alert_data)

            elif channel == NotificationChannel.TELEGRAM:
                return await self._telegram.send(
                    config.bot_token,
                    config.chat_id,
                    alert_data,
                )

            elif channel == NotificationChannel.WEBHOOK:
                return await self._webhook.send(config.webhook_url, alert_data)

            elif channel == NotificationChannel.EMAIL:
                return await self._email.send(config.email_to, alert_data)

            else:
                logger.warning("Unknown notification channel: %s", channel)
                return False

        except Exception as e:
            logger.error("Error dispatching to %s: %s", channel.value, e, exc_info=True)
            return False

    @staticmethod
    def _meets_severity_threshold(severity: str, threshold: str) -> bool:
        """Check if severity meets the minimum threshold.

        Severity levels (highest to lowest):
        critical > high > medium > low > info
        """
        levels = ["info", "low", "medium", "high", "critical"]
        try:
            sev_idx = levels.index(severity.lower())
            threshold_idx = levels.index(threshold.lower())
            return sev_idx >= threshold_idx
        except ValueError:
            return True  # Unknown severity, allow notification


# Singleton instance for easy access
_dispatcher: Optional[NotificationDispatcher] = None


def get_notification_dispatcher() -> NotificationDispatcher:
    """Get or create the global notification dispatcher instance."""
    global _dispatcher
    if _dispatcher is None:
        _dispatcher = NotificationDispatcher()
    return _dispatcher
