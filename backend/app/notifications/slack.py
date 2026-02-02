"""
Slack notification channel via Incoming Webhooks.

Uses Slack Block Kit to produce rich, colour-coded alert messages
based on alert severity.
"""

from __future__ import annotations

import logging
from typing import Any

import httpx

from app.notifications import BaseNotifier

logger = logging.getLogger("agentshield.notifications.slack")

# ---------------------------------------------------------------------------
# Severity colour mapping (Slack attachment colour hex codes)
# ---------------------------------------------------------------------------
_SEVERITY_COLOURS: dict[str, str] = {
    "critical": "#FF0000",
    "high": "#FF6600",
    "medium": "#FFCC00",
    "low": "#36A64F",
    "info": "#0099FF",
}

_SEVERITY_EMOJI: dict[str, str] = {
    "critical": ":rotating_light:",
    "high": ":warning:",
    "medium": ":large_yellow_circle:",
    "low": ":information_source:",
    "info": ":speech_balloon:",
}


class SlackNotifier(BaseNotifier):
    """Send alert notifications to Slack via Incoming Webhook.

    Formats messages using Slack Block Kit with severity-appropriate
    colours and structured sections.
    """

    async def send(self, webhook_url: str, alert_data: dict[str, Any]) -> bool:
        """Deliver an alert to a Slack channel.

        Parameters
        ----------
        webhook_url:
            The Slack Incoming Webhook URL.
        alert_data:
            Alert dictionary with at least ``title``, ``severity``,
            ``description``, and optionally ``session_id``, ``agent_id``,
            ``alert_id``.

        Returns
        -------
        bool
            ``True`` on successful delivery.
        """
        payload = self._format_blocks(alert_data)

        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                response = await client.post(webhook_url, json=payload)
                response.raise_for_status()

            logger.info(
                "Slack notification sent: alert_id=%s title=%s",
                alert_data.get("alert_id", "N/A"),
                alert_data.get("title", "N/A"),
            )
            return True

        except httpx.HTTPStatusError as exc:
            logger.error(
                "Slack webhook returned %d: %s",
                exc.response.status_code,
                exc.response.text,
            )
            return False
        except Exception as exc:
            logger.error("Slack notification failed: %s", exc, exc_info=True)
            return False

    @staticmethod
    def _format_blocks(alert_data: dict[str, Any]) -> dict[str, Any]:
        """Build a Slack Block Kit payload from alert data.

        Parameters
        ----------
        alert_data:
            The alert information dictionary.

        Returns
        -------
        dict
            Slack-compatible JSON payload with ``blocks`` and
            ``attachments``.
        """
        severity: str = alert_data.get("severity", "medium").lower()
        colour: str = _SEVERITY_COLOURS.get(severity, "#CCCCCC")
        emoji: str = _SEVERITY_EMOJI.get(severity, ":bell:")
        title: str = alert_data.get("title", "AgentShield Alert")
        description: str = alert_data.get("description", "")
        session_id: str = alert_data.get("session_id", "N/A")
        agent_id: str = alert_data.get("agent_id", "N/A")
        alert_id: str = alert_data.get("alert_id", "N/A")

        blocks: list[dict[str, Any]] = [
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": f"{emoji} {title}",
                    "emoji": True,
                },
            },
            {
                "type": "section",
                "fields": [
                    {
                        "type": "mrkdwn",
                        "text": f"*Severity:*\n`{severity.upper()}`",
                    },
                    {
                        "type": "mrkdwn",
                        "text": f"*Alert ID:*\n`{alert_id}`",
                    },
                    {
                        "type": "mrkdwn",
                        "text": f"*Session:*\n`{session_id}`",
                    },
                    {
                        "type": "mrkdwn",
                        "text": f"*Agent:*\n`{agent_id}`",
                    },
                ],
            },
        ]

        if description:
            blocks.append(
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": f"*Description:*\n{description[:2000]}",
                    },
                }
            )

        blocks.append({"type": "divider"})
        blocks.append(
            {
                "type": "context",
                "elements": [
                    {
                        "type": "mrkdwn",
                        "text": ":shield: Sent by *AgentShield*",
                    }
                ],
            }
        )

        return {
            "blocks": blocks,
            "attachments": [{"color": colour, "blocks": []}],
        }
