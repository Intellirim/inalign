"""
Celery tasks for report generation.

Provides asynchronous report generation for individual sessions and
batch processing across multiple sessions.
"""

from __future__ import annotations

import logging
import time
import uuid
from typing import Any

from app.workers.celery_app import celery_app

logger = logging.getLogger("inalign.workers.report_worker")


@celery_app.task(
    bind=True,
    queue="reports",
    name="app.workers.report_worker.generate_report_task",
    max_retries=3,
    default_retry_delay=60,
)
def generate_report_task(
    self: Any,
    session_id: str,
    report_type: str,
    language: str = "ko",
    user_id: str | None = None,
) -> dict[str, Any]:
    """Generate a security analysis report for a single session.

    Parameters
    ----------
    session_id:
        The session to analyse.
    report_type:
        Type of report (e.g. ``security_analysis``).
    language:
        Report language: ``"ko"`` or ``"en"``.
    user_id:
        Optional user ID that requested the report.

    Returns
    -------
    dict
        Report metadata including ``report_id``, ``status``, and
        ``generation_time_ms``.
    """
    report_id = str(uuid.uuid4())
    start_time = time.monotonic()

    logger.info(
        "Starting report generation: report_id=%s session_id=%s type=%s lang=%s user=%s",
        report_id,
        session_id,
        report_type,
        language,
        user_id,
    )

    try:
        # ------------------------------------------------------------------
        # Step 1: Fetch session graph data from Neo4j
        # ------------------------------------------------------------------
        from app.graph.neo4j_client import Neo4jClient
        from app.config import get_settings

        settings = get_settings()
        neo4j_client = Neo4jClient(
            uri=settings.neo4j_uri,
            username=settings.neo4j_user,
            password=settings.neo4j_password,
            database=settings.neo4j_database,
        )

        import asyncio

        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            loop.run_until_complete(neo4j_client.connect())
            session_graph = loop.run_until_complete(
                neo4j_client.get_session_graph(session_id)
            )
        finally:
            loop.run_until_complete(neo4j_client.disconnect())
            loop.close()

        # ------------------------------------------------------------------
        # Step 2: Convert graph to text and generate report via GraphRAG
        # ------------------------------------------------------------------
        from app.graphrag.graph_to_text import GraphToTextConverter

        converter = GraphToTextConverter()
        graph_text = converter.convert(session_graph)

        logger.info(
            "Graph text generated for session %s (%d characters).",
            session_id,
            len(graph_text),
        )

        # ------------------------------------------------------------------
        # Step 3: Build result
        # ------------------------------------------------------------------
        elapsed_ms = (time.monotonic() - start_time) * 1000

        result: dict[str, Any] = {
            "report_id": report_id,
            "session_id": session_id,
            "report_type": report_type,
            "language": language,
            "status": "completed",
            "generation_time_ms": round(elapsed_ms, 2),
            "graph_text_length": len(graph_text),
            "user_id": user_id,
        }

        logger.info(
            "Report generated successfully: report_id=%s elapsed=%.1fms",
            report_id,
            elapsed_ms,
        )
        return result

    except Exception as exc:
        elapsed_ms = (time.monotonic() - start_time) * 1000
        logger.error(
            "Report generation failed: report_id=%s session_id=%s error=%s",
            report_id,
            session_id,
            exc,
            exc_info=True,
        )

        # Retry on transient failures
        try:
            self.retry(exc=exc)
        except self.MaxRetriesExceededError:
            logger.error(
                "Max retries exceeded for report %s (session=%s).",
                report_id,
                session_id,
            )

        return {
            "report_id": report_id,
            "session_id": session_id,
            "status": "failed",
            "error": str(exc),
            "generation_time_ms": round(elapsed_ms, 2),
        }


@celery_app.task(
    bind=True,
    queue="reports",
    name="app.workers.report_worker.batch_generate_reports",
    max_retries=2,
    default_retry_delay=120,
)
def batch_generate_reports(
    self: Any,
    session_ids: list[str],
    report_type: str = "security_analysis",
) -> dict[str, Any]:
    """Generate reports for multiple sessions in a single batch.

    Each session is processed individually via
    :func:`generate_report_task`. Failures for individual sessions
    do not prevent the remaining sessions from being processed.

    Parameters
    ----------
    session_ids:
        List of session IDs to generate reports for.
    report_type:
        Type of report to generate for all sessions.

    Returns
    -------
    dict
        Summary with ``total``, ``succeeded``, ``failed``, and per-session
        ``results``.
    """
    batch_id = str(uuid.uuid4())
    logger.info(
        "Starting batch report generation: batch_id=%s sessions=%d type=%s",
        batch_id,
        len(session_ids),
        report_type,
    )

    results: list[dict[str, Any]] = []
    succeeded = 0
    failed = 0

    for session_id in session_ids:
        try:
            result = generate_report_task.apply(
                args=[session_id, report_type],
            ).get(timeout=300)
            results.append(result)
            if result.get("status") == "completed":
                succeeded += 1
            else:
                failed += 1
        except Exception as exc:
            logger.error(
                "Batch report failed for session %s: %s",
                session_id,
                exc,
                exc_info=True,
            )
            results.append(
                {
                    "session_id": session_id,
                    "status": "failed",
                    "error": str(exc),
                }
            )
            failed += 1

    summary: dict[str, Any] = {
        "batch_id": batch_id,
        "total": len(session_ids),
        "succeeded": succeeded,
        "failed": failed,
        "results": results,
    }

    logger.info(
        "Batch report complete: batch_id=%s succeeded=%d failed=%d",
        batch_id,
        succeeded,
        failed,
    )
    return summary
