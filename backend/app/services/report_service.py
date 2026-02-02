"""
Report generation service.

Leverages the GraphRAG pipeline to produce security analysis reports
for monitored agent sessions.
"""

from __future__ import annotations

import logging
import time
from datetime import datetime, timezone
from uuid import uuid4

from app.schemas.report import (
    ReportRequest,
    ReportResponse,
    ReportSummary,
    ReportAnalysis,
    Recommendation,
)
from app.schemas.common import RiskLevel, Severity

logger = logging.getLogger("agentshield.services.report")


class ReportService:
    """Generates, retrieves, and lists security analysis reports."""

    def __init__(
        self,
        graphrag_pipeline: object,
        db_session: object,
    ) -> None:
        self._graphrag = graphrag_pipeline
        self._db = db_session

    # ------------------------------------------------------------------
    # Generate a new report
    # ------------------------------------------------------------------

    async def generate_report(
        self,
        session_id: str,
        request: ReportRequest,
    ) -> ReportResponse:
        """Generate a security analysis report for the given session.

        Parameters
        ----------
        session_id:
            The target session to analyse.
        request:
            Report configuration (type, language, recommendations flag).

        Returns
        -------
        ReportResponse
            The complete generated report.
        """
        request_id = str(uuid4())
        report_id = str(uuid4())
        start = time.perf_counter()

        logger.info(
            "generate_report  request_id=%s  session=%s  type=%s  lang=%s",
            request_id,
            session_id,
            request.report_type,
            request.language,
        )

        # Run the GraphRAG pipeline ------------------------------------------
        analysis: ReportAnalysis | None = None
        summary: ReportSummary | None = None
        recommendations: list[Recommendation] = []
        raw_graph_data: dict | None = None

        try:
            pipeline_result = await self._graphrag.analyse(  # type: ignore[attr-defined]
                session_id=session_id,
                report_type=request.report_type,
                language=request.language,
            )

            # Parse pipeline output
            raw_graph_data = pipeline_result.get("graph_data")

            risk_score = float(pipeline_result.get("risk_score", 0.0))
            risk_level = _risk_level_from_score(risk_score)

            summary = ReportSummary(
                risk_level=risk_level,
                risk_score=risk_score,
                primary_concerns=pipeline_result.get("primary_concerns", []),
            )

            analysis = ReportAnalysis(
                timeline_analysis=pipeline_result.get("timeline_analysis", ""),
            )

            if request.include_recommendations:
                raw_recs = pipeline_result.get("recommendations", [])
                for r in raw_recs:
                    recommendations.append(
                        Recommendation(
                            priority=Severity(r.get("priority", "medium")),
                            action=r.get("action", ""),
                            reason=r.get("reason", ""),
                        )
                    )

        except Exception:
            logger.exception("GraphRAG pipeline failed for session %s", session_id)
            summary = ReportSummary(
                risk_level=RiskLevel.NONE,
                risk_score=0.0,
                primary_concerns=["Report generation failed -- analysis unavailable"],
            )

        generation_time_ms = round((time.perf_counter() - start) * 1000, 2)

        # Persist report metadata ---------------------------------------------
        try:
            from sqlalchemy import text as sa_text  # noqa: WPS433

            await self._db.execute(  # type: ignore[attr-defined]
                sa_text(
                    "INSERT INTO reports (id, session_id, report_type, status, "
                    "generated_at, generation_time_ms) "
                    "VALUES (:id, :session_id, :report_type, :status, "
                    ":generated_at, :generation_time_ms)"
                ),
                {
                    "id": report_id,
                    "session_id": session_id,
                    "report_type": request.report_type,
                    "status": "completed",
                    "generated_at": datetime.now(timezone.utc),
                    "generation_time_ms": generation_time_ms,
                },
            )
        except Exception:
            logger.warning("Failed to persist report %s metadata", report_id, exc_info=True)

        logger.info(
            "generate_report  report_id=%s  session=%s  time=%.1fms",
            report_id,
            session_id,
            generation_time_ms,
        )

        return ReportResponse(
            request_id=request_id,
            report_id=report_id,
            session_id=session_id,
            status="completed",
            generated_at=datetime.now(timezone.utc),
            generation_time_ms=generation_time_ms,
            summary=summary,
            analysis=analysis,
            recommendations=recommendations,
            raw_graph_data=raw_graph_data,
        )

    # ------------------------------------------------------------------
    # Retrieve an existing report
    # ------------------------------------------------------------------

    async def get_report(self, report_id: str) -> ReportResponse:
        """Fetch a previously generated report by its ID.

        Parameters
        ----------
        report_id:
            UUID of the report.

        Returns
        -------
        ReportResponse
            The stored report data.

        Raises
        ------
        ValueError
            If no report with the given ID exists.
        """
        logger.info("get_report  report_id=%s", report_id)

        try:
            from sqlalchemy import text as sa_text  # noqa: WPS433

            result = await self._db.execute(  # type: ignore[attr-defined]
                sa_text("SELECT * FROM reports WHERE id = :id"),
                {"id": report_id},
            )
            row = result.mappings().first()
        except Exception:
            logger.exception("Failed to query report %s", report_id)
            raise ValueError(f"Report '{report_id}' not found")

        if not row:
            raise ValueError(f"Report '{report_id}' not found")

        return ReportResponse(
            report_id=str(row["id"]),
            session_id=str(row.get("session_id", "")),
            status=row.get("status", "completed"),
            generated_at=row.get("generated_at"),
            generation_time_ms=float(row.get("generation_time_ms", 0)),
        )

    # ------------------------------------------------------------------
    # List reports
    # ------------------------------------------------------------------

    async def list_reports(self, page: int = 1, size: int = 20) -> list[ReportResponse]:
        """Return a paginated list of generated reports.

        Parameters
        ----------
        page:
            1-based page number.
        size:
            Number of results per page.

        Returns
        -------
        list[ReportResponse]
            Ordered by generation time descending.
        """
        logger.info("list_reports  page=%d  size=%d", page, size)
        offset = (page - 1) * size

        try:
            from sqlalchemy import text as sa_text  # noqa: WPS433

            result = await self._db.execute(  # type: ignore[attr-defined]
                sa_text(
                    "SELECT * FROM reports ORDER BY generated_at DESC "
                    "OFFSET :offset LIMIT :limit"
                ),
                {"offset": offset, "limit": size},
            )
            rows = result.mappings().all()
        except Exception:
            logger.exception("Failed to list reports")
            return []

        reports: list[ReportResponse] = []
        for row in rows:
            reports.append(
                ReportResponse(
                    report_id=str(row["id"]),
                    session_id=str(row.get("session_id", "")),
                    status=row.get("status", "completed"),
                    generated_at=row.get("generated_at"),
                    generation_time_ms=float(row.get("generation_time_ms", 0)),
                )
            )

        return reports


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _risk_level_from_score(score: float) -> RiskLevel:
    """Map a 0-1 risk score to a discrete risk level."""
    if score >= 0.9:
        return RiskLevel.CRITICAL
    if score >= 0.7:
        return RiskLevel.HIGH
    if score >= 0.3:
        return RiskLevel.MEDIUM
    if score > 0.0:
        return RiskLevel.LOW
    return RiskLevel.NONE
