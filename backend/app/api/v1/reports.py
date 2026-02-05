"""
Report endpoints.

Trigger GraphRAG-based security report generation and retrieve
previously generated reports.
"""

from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, HTTPException, Query, status

from app.dependencies import CurrentUser, DBSession
from app.schemas.report import ReportRequest, ReportResponse

logger = logging.getLogger("inalign.api.reports")

router = APIRouter()


# --------------------------------------------------------------------------
# POST /sessions/{session_id}/report
# --------------------------------------------------------------------------


@router.post(
    "/sessions/{session_id}/report",
    response_model=ReportResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Generate security report",
    description=(
        "Trigger a GraphRAG-based security analysis report for the "
        "specified session. Returns the generated report with risk "
        "assessment, analysis, and recommendations."
    ),
)
async def generate_report(
    session_id: str,
    body: ReportRequest,
    current_user: CurrentUser,
    db: DBSession,
) -> ReportResponse:
    """Generate a new security analysis report for a session."""
    logger.info(
        "POST /reports/sessions/%s/report  user=%s  type=%s",
        session_id,
        current_user["user_id"],
        body.report_type,
    )

    from app.services.report_service import ReportService  # noqa: WPS433

    # Construct the GraphRAG pipeline with proper dependencies.
    try:
        from app.graphrag.pipeline import GraphRAGPipeline  # type: ignore[import-untyped]
        from app.graph.neo4j_client import Neo4jClient
        from app.config import get_settings

        settings = get_settings()
        neo4j_client = Neo4jClient(
            uri=settings.neo4j_uri,
            username=settings.neo4j_user,
            password=settings.neo4j_password,
            database=settings.neo4j_database,
        )
        await neo4j_client.connect()
        pipeline = GraphRAGPipeline(neo4j_client=neo4j_client, settings=settings)
    except Exception:
        logger.warning("GraphRAG pipeline not available, using stub", exc_info=True)

        class _Stub:
            async def generate_report(self, **kwargs: object) -> dict:
                return {"risk_score": 0.0, "primary_concerns": [], "recommendations": []}

        pipeline = _Stub()  # type: ignore[assignment]

    service = ReportService(graphrag_pipeline=pipeline, db_session=db)

    try:
        result = await service.generate_report(session_id=session_id, request=body)
    except Exception as exc:
        logger.exception("Report generation failed for session %s", session_id)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Report generation failed: {exc}",
        ) from exc

    return result


# --------------------------------------------------------------------------
# GET /
# --------------------------------------------------------------------------


@router.get(
    "/",
    response_model=list[ReportResponse],
    status_code=status.HTTP_200_OK,
    summary="List reports",
    description="Return a paginated list of previously generated reports.",
)
async def list_reports(
    current_user: CurrentUser,
    db: DBSession,
    page: int = Query(default=1, ge=1, description="Page number"),
    size: int = Query(default=20, ge=1, le=100, description="Page size"),
) -> list[ReportResponse]:
    """Retrieve a paginated list of generated reports."""
    logger.info(
        "GET /reports  user=%s  page=%d  size=%d",
        current_user["user_id"],
        page,
        size,
    )

    from app.services.report_service import ReportService  # noqa: WPS433

    # Stub pipeline -- listing does not require the GraphRAG engine.
    service = ReportService(graphrag_pipeline=None, db_session=db)  # type: ignore[arg-type]

    try:
        reports = await service.list_reports(page=page, size=size)
    except Exception as exc:
        logger.exception("Failed to list reports")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to list reports: {exc}",
        ) from exc

    return reports


# --------------------------------------------------------------------------
# GET /{report_id}
# --------------------------------------------------------------------------


@router.get(
    "/{report_id}",
    response_model=ReportResponse,
    status_code=status.HTTP_200_OK,
    summary="Get report",
    description="Retrieve a single previously generated report by its ID.",
)
async def get_report(
    report_id: str,
    current_user: CurrentUser,
    db: DBSession,
) -> ReportResponse:
    """Fetch a report by ID."""
    logger.info(
        "GET /reports/%s  user=%s",
        report_id,
        current_user["user_id"],
    )

    from app.services.report_service import ReportService  # noqa: WPS433

    service = ReportService(graphrag_pipeline=None, db_session=db)  # type: ignore[arg-type]

    try:
        report = await service.get_report(report_id)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(exc),
        ) from exc
    except Exception as exc:
        logger.exception("Failed to get report %s", report_id)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to retrieve report: {exc}",
        ) from exc

    return report
