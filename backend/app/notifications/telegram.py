"""
Telegram notification channel via Bot API.

Sends MarkdownV2-formatted alert messages to a specified chat using
the Telegram Bot ``sendMessage`` endpoint.
"""

from __future__ import annotations

import logging
import re
from typing import Any

import httpx

from app.notifications import BaseNotifier

logger = logging.getLogger("agentshield.notifications.telegram")

# ---------------------------------------------------------------------------
# Severity emoji mapping
# ---------------------------------------------------------------------------
_SEVERITY_EMOJI: dict[str, str] = {
    "critical": "\U0001F6A8",   # rotating light
    "high": "\u26A0\uFE0F",     # warning
    "medium": "\U0001F7E1",      # yellow circle
    "low": "\u2139\uFE0F",      # info
    "info": "\U0001F4AC",       # speech balloon
}

_TELEGRAM_API_BASE = "https://api.telegram.org"


class TelegramNotifier(BaseNotifier):
    """Send alert notifications to Telegram via the Bot API.

    Messages are formatted using MarkdownV2 with severity-appropriate
    emoji indicators.
    """

    async def send(
        self,
        bot_token: str,
        chat_id: str,
        alert_data: dict[str, Any],
    ) -> bool:
        """Deliver an alert to a Telegram chat.

        Parameters
        ----------
        bot_token:
            The Telegram bot token.
        chat_id:
            The target chat ID (user, group, or channel).
        alert_data:
            Alert dictionary with ``title``, ``severity``,
            ``description``, and optionally ``session_id``, ``agent_id``.

        Returns
        -------
        bool
            ``True`` on successful delivery.
        """
        text = self._format_message(alert_data)
        url = f"{_TELEGRAM_API_BASE}/bot{bot_token}/sendMessage"

        payload: dict[str, Any] = {
            "chat_id": chat_id,
            "text": text,
            "parse_mode": "MarkdownV2",
            "disable_web_page_preview": True,
        }

        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                response = await client.post(url, json=payload)
                response.raise_for_status()

            data = response.json()
            if data.get("ok"):
                logger.info(
                    "Telegram notification sent: chat_id=%s alert=%s",
                    chat_id,
                    alert_data.get("alert_id", "N/A"),
                )
                return True
            else:
                logger.error(
                    "Telegram API error: %s",
                    data.get("description", "Unknown error"),
                )
                return False

        except httpx.HTTPStatusError as exc:
            logger.error(
                "Telegram API returned %d: %s",
                exc.response.status_code,
                exc.response.text,
            )
            return False
        except Exception as exc:
            logger.error("Telegram notification failed: %s", exc, exc_info=True)
            return False

    @staticmethod
    def _format_message(alert_data: dict[str, Any]) -> str:
        """Build a MarkdownV2-formatted message from alert data.

        Parameters
        ----------
        alert_data:
            The alert information dictionary.

        Returns
        -------
        str
            Telegram MarkdownV2 formatted text.
        """
        severity: str = alert_data.get("severity", "medium").lower()
        emoji: str = _SEVERITY_EMOJI.get(severity, "\U0001F514")
        title: str = alert_data.get("title", "AgentShield Alert")
        description: str = alert_data.get("description", "")
        session_id: str = alert_data.get("session_id", "N/A")
        agent_id: str = alert_data.get("agent_id", "N/A")
        alert_id: str = alert_data.get("alert_id", "N/A")

        def _escape(text: str) -> str:
            """Escape special characters for MarkdownV2."""
            special_chars = r"_*[]()~`>#+-=|{}.!"
            return re.sub(
                f"([{re.escape(special_chars)}])",
                r"\\\1",
                text,
            )

        lines: list[str] = [
            f"{emoji} *{_escape(title)}*",
            "",
            f"\U0001F6E1 *Severity:* `{_escape(severity.upper())}`",
            f"\U0001F4CB *Alert ID:* `{_escape(alert_id)}`",
            f"\U0001F4C1 *Session:* `{_escape(session_id)}`",
            f"\U0001F916 *Agent:* `{_escape(agent_id)}`",
        ]

        if description:
            truncated = description[:500]
            lines.append("")
            lines.append(f"\U0001F4DD *Description:*")
            lines.append(_escape(truncated))

        lines.append("")
        lines.append(f"\U0001F6E1 _Sent by AgentShield_")

        return "\n".join(lines)
