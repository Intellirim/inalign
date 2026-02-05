"""
Email notification channel via SendGrid API.

Sends HTML-formatted alert emails using the SendGrid v3 Mail Send
endpoint.
"""

from __future__ import annotations

import logging
from typing import Any

import httpx

from app.notifications import BaseNotifier

logger = logging.getLogger("inalign.notifications.email")

_SENDGRID_API_URL = "https://api.sendgrid.com/v3/mail/send"

# ---------------------------------------------------------------------------
# Severity colour mapping (HTML)
# ---------------------------------------------------------------------------
_SEVERITY_COLOURS: dict[str, str] = {
    "critical": "#FF0000",
    "high": "#FF6600",
    "medium": "#FFCC00",
    "low": "#36A64F",
    "info": "#0099FF",
}


class EmailNotifier(BaseNotifier):
    """Send alert notifications via SendGrid email.

    Builds an HTML email body with severity-colour-coded header,
    structured alert details, and InALign branding.
    """

    async def send(
        self,
        to_email: str,
        alert_data: dict[str, Any],
        sendgrid_api_key: str,
    ) -> bool:
        """Deliver an alert via email.

        Parameters
        ----------
        to_email:
            Recipient email address.
        alert_data:
            Alert dictionary with ``title``, ``severity``,
            ``description``, and optional fields.
        sendgrid_api_key:
            SendGrid API key for authentication.

        Returns
        -------
        bool
            ``True`` on successful delivery.
        """
        from_email: str = "alerts@inalign.io"

        try:
            from app.config import get_settings

            settings = get_settings()
            if settings.notification_from_email:
                from_email = settings.notification_from_email
        except Exception:
            pass

        severity: str = alert_data.get("severity", "medium").lower()
        title: str = alert_data.get("title", "InALign Alert")
        html_body: str = self._build_html(alert_data)

        payload: dict[str, Any] = {
            "personalizations": [
                {
                    "to": [{"email": to_email}],
                    "subject": f"[InALign] [{severity.upper()}] {title}",
                }
            ],
            "from": {"email": from_email, "name": "InALign"},
            "content": [
                {
                    "type": "text/html",
                    "value": html_body,
                }
            ],
        }

        headers = {
            "Authorization": f"Bearer {sendgrid_api_key}",
            "Content-Type": "application/json",
        }

        try:
            async with httpx.AsyncClient(timeout=15.0) as client:
                response = await client.post(
                    _SENDGRID_API_URL,
                    json=payload,
                    headers=headers,
                )
                # SendGrid returns 202 on success
                if response.status_code in (200, 201, 202):
                    logger.info(
                        "Email notification sent: to=%s alert=%s",
                        to_email,
                        alert_data.get("alert_id", "N/A"),
                    )
                    return True
                else:
                    logger.error(
                        "SendGrid returned %d: %s",
                        response.status_code,
                        response.text,
                    )
                    return False

        except Exception as exc:
            logger.error(
                "Email notification failed: to=%s error=%s",
                to_email,
                exc,
                exc_info=True,
            )
            return False

    @staticmethod
    def _build_html(alert_data: dict[str, Any]) -> str:
        """Build an HTML email body from alert data.

        Parameters
        ----------
        alert_data:
            The alert information dictionary.

        Returns
        -------
        str
            Complete HTML document string.
        """
        severity: str = alert_data.get("severity", "medium").lower()
        colour: str = _SEVERITY_COLOURS.get(severity, "#CCCCCC")
        title: str = alert_data.get("title", "InALign Alert")
        description: str = alert_data.get("description", "No description provided.")
        session_id: str = alert_data.get("session_id", "N/A")
        agent_id: str = alert_data.get("agent_id", "N/A")
        alert_id: str = alert_data.get("alert_id", "N/A")

        html = f"""\
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>InALign Alert</title>
</head>
<body style="margin:0; padding:0; font-family:Arial, Helvetica, sans-serif; background-color:#f4f4f4;">
    <table width="100%" cellpadding="0" cellspacing="0" style="max-width:600px; margin:0 auto; background:#ffffff;">
        <!-- Header -->
        <tr>
            <td style="background-color:{colour}; padding:20px 30px;">
                <h1 style="color:#ffffff; margin:0; font-size:22px;">
                    InALign Security Alert
                </h1>
                <p style="color:#ffffff; margin:5px 0 0 0; font-size:14px; opacity:0.9;">
                    Severity: {severity.upper()}
                </p>
            </td>
        </tr>
        <!-- Body -->
        <tr>
            <td style="padding:30px;">
                <h2 style="color:#333333; margin:0 0 15px 0; font-size:18px;">
                    {title}
                </h2>
                <p style="color:#555555; line-height:1.6; margin:0 0 20px 0;">
                    {description}
                </p>
                <table width="100%" cellpadding="8" cellspacing="0"
                       style="border:1px solid #eeeeee; border-radius:4px;">
                    <tr style="background-color:#f9f9f9;">
                        <td style="font-weight:bold; color:#333; width:120px;">Alert ID</td>
                        <td style="color:#555;">{alert_id}</td>
                    </tr>
                    <tr>
                        <td style="font-weight:bold; color:#333;">Session ID</td>
                        <td style="color:#555;">{session_id}</td>
                    </tr>
                    <tr style="background-color:#f9f9f9;">
                        <td style="font-weight:bold; color:#333;">Agent ID</td>
                        <td style="color:#555;">{agent_id}</td>
                    </tr>
                    <tr>
                        <td style="font-weight:bold; color:#333;">Severity</td>
                        <td>
                            <span style="background-color:{colour}; color:#ffffff;
                                         padding:3px 10px; border-radius:3px;
                                         font-size:12px; font-weight:bold;">
                                {severity.upper()}
                            </span>
                        </td>
                    </tr>
                </table>
            </td>
        </tr>
        <!-- Footer -->
        <tr>
            <td style="background-color:#f9f9f9; padding:15px 30px;
                        border-top:1px solid #eeeeee; text-align:center;">
                <p style="color:#999999; font-size:12px; margin:0;">
                    This alert was automatically generated by InALign.
                    Please do not reply to this email.
                </p>
            </td>
        </tr>
    </table>
</body>
</html>"""
        return html
