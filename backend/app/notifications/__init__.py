"""
Notification channel integrations for AgentShield alerts.

Provides pluggable notifiers for Slack, Telegram, email (SendGrid),
and generic webhooks.  All notifiers inherit from :class:`BaseNotifier`.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any


class BaseNotifier(ABC):
    """Abstract base class for all notification channel implementations.

    Subclasses must implement the :meth:`send` method which delivers an
    alert payload to the respective channel.  All implementations must
    be fully asynchronous.
    """

    @abstractmethod
    async def send(self, *args: Any, **kwargs: Any) -> bool:
        """Send an alert notification.

        Returns
        -------
        bool
            ``True`` if the notification was delivered successfully,
            ``False`` otherwise.
        """
        ...


from app.notifications.slack import SlackNotifier
from app.notifications.telegram import TelegramNotifier
from app.notifications.email import EmailNotifier
from app.notifications.webhook import WebhookNotifier

__all__ = [
    "BaseNotifier",
    "SlackNotifier",
    "TelegramNotifier",
    "EmailNotifier",
    "WebhookNotifier",
]
