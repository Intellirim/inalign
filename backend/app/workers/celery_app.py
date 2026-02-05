"""
Celery application configuration for InALign background workers.

Configures the Celery application with Redis as the message broker and
result backend, JSON serialisation, task time limits, named queues,
and periodic beat schedules.
"""

from __future__ import annotations

import logging
from typing import Any

from celery import Celery
from celery.schedules import crontab
from kombu import Exchange, Queue

from app.config import get_settings

logger = logging.getLogger("inalign.workers.celery_app")

# ---------------------------------------------------------------------------
# Settings
# ---------------------------------------------------------------------------
settings = get_settings()
_broker_url: str = str(settings.redis_url)
_result_backend: str = str(settings.redis_url)

# ---------------------------------------------------------------------------
# Celery application
# ---------------------------------------------------------------------------
celery_app = Celery(
    "inalign",
    broker=_broker_url,
    backend=_result_backend,
)

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
celery_app.conf.update(
    # Serialisation
    task_serializer="json",
    result_serializer="json",
    accept_content=["json"],
    # Time limits (seconds)
    task_time_limit=300,
    task_soft_time_limit=240,
    # Timezone
    timezone="UTC",
    enable_utc=True,
    # Result expiration (24 hours)
    result_expires=86400,
    # Worker settings
    worker_prefetch_multiplier=1,
    worker_max_tasks_per_child=1000,
    # Task acknowledgement
    task_acks_late=True,
    task_reject_on_worker_lost=True,
)

# ---------------------------------------------------------------------------
# Queues
# ---------------------------------------------------------------------------
default_exchange = Exchange("default", type="direct")

celery_app.conf.task_queues = (
    Queue("default", default_exchange, routing_key="default"),
    Queue("reports", Exchange("reports", type="direct"), routing_key="reports"),
    Queue("alerts", Exchange("alerts", type="direct"), routing_key="alerts"),
    Queue("cleanup", Exchange("cleanup", type="direct"), routing_key="cleanup"),
)

celery_app.conf.task_default_queue = "default"
celery_app.conf.task_default_exchange = "default"
celery_app.conf.task_default_routing_key = "default"

# ---------------------------------------------------------------------------
# Beat schedule (periodic tasks)
# ---------------------------------------------------------------------------
celery_app.conf.beat_schedule: dict[str, dict[str, Any]] = {
    "cleanup_old_sessions": {
        "task": "app.workers.cleanup_worker.cleanup_old_sessions",
        "schedule": crontab(hour=2, minute=0),  # Every day at 02:00 UTC
        "kwargs": {"days": 90},
        "options": {"queue": "cleanup"},
    },
    "aggregate_daily_stats": {
        "task": "app.workers.cleanup_worker.aggregate_daily_stats",
        "schedule": crontab(hour=3, minute=0),  # Every day at 03:00 UTC
        "options": {"queue": "cleanup"},
    },
}

# ---------------------------------------------------------------------------
# Auto-discover tasks
# ---------------------------------------------------------------------------
celery_app.autodiscover_tasks(
    [
        "app.workers.report_worker",
        "app.workers.alert_worker",
        "app.workers.cleanup_worker",
    ]
)

logger.info("Celery application configured: broker=%s", _broker_url)
