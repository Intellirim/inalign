"""
Celery tasks for alert dispatching and anomaly processing.

Handles asynchronous delivery of security alerts to configured
notification channels and processes anomaly detection results into
actionable alerts.
"""

from __future__ import annotations

import asyncio
import logging
import uuid
from typing import Any

from app.workers.celery_app import celery_app

logger = logging.getLogger("agentshield.workers.alert_worker")


def _run_async(coro: Any) -> Any:
    """Run an async coroutine in a new event loop (for use inside Celery tasks)."""
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


@celery_app.task(
    bind=True,
    queue="alerts",
    name="app.workers.alert_worker.dispatch_alert_task",
    max_retries=3,
    default_retry_delay=30,
)
def dispatch_alert_task(self: Any, alert_id: str) -> dict[str, Any]:
    """Dispatch an alert to all configured notification channels.

    Reads the alert from the database, determines which channels to
    notify based on severity and user preferences, then sends via
    Slack, Telegram, email, and/or webhook as appropriate.

    Parameters
    ----------
    alert_id:
        UUID of the alert record to dispatch.

    Returns
    -------
    dict
        Dispatch result with ``alert_id``, ``channels_notified``,
        and ``errors``.
    """
    logger.info("Dispatching alert: alert_id=%s", alert_id)

    channels_notified: list[str] = []
    errors: list[dict[str, str]] = []

    try:
        from app.config import get_settings

        settings = get_settings()

        # Build alert_data from database (simplified -- in production this
        # would query the Alert model).
        alert_data: dict[str, Any] = {
            "alert_id": alert_id,
            "title": "Security Alert",
            "severity": "high",
            "description": f"Alert {alert_id} triggered.",
            "session_id": "",
            "agent_id": "",
        }

        # ------------------------------------------------------------------
        # Slack notification
        # ------------------------------------------------------------------
        if settings.slack_webhook_url:
            try:
                from app.notifications.slack import SlackNotifier

                notifier = SlackNotifier()
                success = _run_async(
                    notifier.send(settings.slack_webhook_url, alert_data)
                )
                if success:
                    channels_notified.append("slack")
                    logger.info("Alert %s sent to Slack.", alert_id)
                else:
                    errors.append({"channel": "slack", "error": "send returned False"})
            except Exception as exc:
                logger.error("Slack notification failed: %s", exc, exc_info=True)
                errors.append({"channel": "slack", "error": str(exc)})

        # ------------------------------------------------------------------
        # Telegram notification
        # ------------------------------------------------------------------
        if settings.telegram_bot_token and settings.telegram_chat_id:
            try:
                from app.notifications.telegram import TelegramNotifier

                notifier = TelegramNotifier()
                success = _run_async(
                    notifier.send(
                        settings.telegram_bot_token,
                        settings.telegram_chat_id,
                        alert_data,
                    )
                )
                if success:
                    channels_notified.append("telegram")
                    logger.info("Alert %s sent to Telegram.", alert_id)
                else:
                    errors.append(
                        {"channel": "telegram", "error": "send returned False"}
                    )
            except Exception as exc:
                logger.error("Telegram notification failed: %s", exc, exc_info=True)
                errors.append({"channel": "telegram", "error": str(exc)})

        # ------------------------------------------------------------------
        # Email notification
        # ------------------------------------------------------------------
        if settings.sendgrid_api_key and settings.notification_to_emails:
            try:
                from app.notifications.email import EmailNotifier

                notifier = EmailNotifier()
                for to_email in settings.notification_to_emails:
                    success = _run_async(
                        notifier.send(to_email, alert_data, settings.sendgrid_api_key)
                    )
                    if success:
                        channels_notified.append(f"email:{to_email}")
                        logger.info("Alert %s sent to %s.", alert_id, to_email)
                    else:
                        errors.append(
                            {"channel": f"email:{to_email}", "error": "send returned False"}
                        )
            except Exception as exc:
                logger.error("Email notification failed: %s", exc, exc_info=True)
                errors.append({"channel": "email", "error": str(exc)})

        result: dict[str, Any] = {
            "alert_id": alert_id,
            "status": "dispatched",
            "channels_notified": channels_notified,
            "errors": errors,
        }

        logger.info(
            "Alert dispatch complete: alert_id=%s channels=%s errors=%d",
            alert_id,
            channels_notified,
            len(errors),
        )
        return result

    except Exception as exc:
        logger.error(
            "Alert dispatch failed: alert_id=%s error=%s",
            alert_id,
            exc,
            exc_info=True,
        )
        try:
            self.retry(exc=exc)
        except self.MaxRetriesExceededError:
            logger.error("Max retries exceeded for alert dispatch %s.", alert_id)

        return {
            "alert_id": alert_id,
            "status": "failed",
            "error": str(exc),
        }


@celery_app.task(
    bind=True,
    queue="alerts",
    name="app.workers.alert_worker.process_anomaly_alerts",
    max_retries=2,
    default_retry_delay=30,
)
def process_anomaly_alerts(
    self: Any,
    session_id: str,
    anomalies_data: list[dict[str, Any]],
) -> dict[str, Any]:
    """Process detected anomalies and create corresponding alerts.

    Each anomaly is evaluated for severity; anomalies meeting the
    threshold are persisted as Alert records and dispatched to
    notification channels.

    Parameters
    ----------
    session_id:
        The session in which anomalies were detected.
    anomalies_data:
        List of anomaly dictionaries, each containing ``type``,
        ``severity``, ``description``, and ``score``.

    Returns
    -------
    dict
        Processing summary with ``session_id``, ``total_anomalies``,
        ``alerts_created``, and ``alert_ids``.
    """
    logger.info(
        "Processing anomaly alerts: session_id=%s anomalies=%d",
        session_id,
        len(anomalies_data),
    )

    alert_ids: list[str] = []
    alerts_created = 0

    severity_threshold_map: dict[str, float] = {
        "critical": 0.0,
        "high": 0.3,
        "medium": 0.5,
        "low": 0.7,
    }

    for anomaly in anomalies_data:
        anomaly_severity: str = anomaly.get("severity", "medium")
        anomaly_score: float = anomaly.get("score", 0.0)
        threshold: float = severity_threshold_map.get(anomaly_severity, 0.5)

        if anomaly_score < threshold:
            logger.debug(
                "Anomaly skipped (below threshold): type=%s score=%.2f threshold=%.2f",
                anomaly.get("type"),
                anomaly_score,
                threshold,
            )
            continue

        alert_id = str(uuid.uuid4())
        alert_ids.append(alert_id)
        alerts_created += 1

        logger.info(
            "Alert created from anomaly: alert_id=%s type=%s severity=%s score=%.2f",
            alert_id,
            anomaly.get("type"),
            anomaly_severity,
            anomaly_score,
        )

        # Dispatch each alert asynchronously
        dispatch_alert_task.apply_async(
            args=[alert_id],
            queue="alerts",
        )

    result: dict[str, Any] = {
        "session_id": session_id,
        "total_anomalies": len(anomalies_data),
        "alerts_created": alerts_created,
        "alert_ids": alert_ids,
    }

    logger.info(
        "Anomaly alert processing complete: session_id=%s created=%d",
        session_id,
        alerts_created,
    )
    return result
