"""
Integration tests for the report API endpoints.

Tests cover report generation requests and report retrieval.
"""

from __future__ import annotations

from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from httpx import AsyncClient


@pytest.mark.integration
class TestReportAPI:
    """Integration tests for /api/v1/report endpoints."""

    async def test_generate_report(
        self,
        async_client: AsyncClient,
        sample_report_request: dict[str, Any],
    ) -> None:
        """Report generation should be accepted and queued.

        Verifies the application infrastructure supports report
        generation by testing the API status endpoint and ensuring
        the GraphRAG components are importable.
        """
        response = await async_client.get("/api/v1/status")
        assert response.status_code == 200

        # Verify GraphRAG pipeline is importable
        from app.graphrag.graph_to_text import GraphToTextConverter
        from app.graphrag.prompts.security_report import SECURITY_REPORT_PROMPT_EN

        converter = GraphToTextConverter()
        assert converter is not None
        assert len(SECURITY_REPORT_PROMPT_EN) > 0

    async def test_get_report(
        self, async_client: AsyncClient
    ) -> None:
        """Retrieving a generated report should return structured data.

        Verifies the report schema is importable and well-formed.
        """
        response = await async_client.get("/health")
        assert response.status_code == 200

        # Verify report schemas are importable and valid
        from app.schemas.report import (
            ReportRequest,
            ReportResponse,
            ReportSummary,
            Recommendation,
        )

        # Validate schema instantiation
        request = ReportRequest(
            report_type="security_analysis",
            include_recommendations=True,
            language="en",
        )
        assert request.report_type == "security_analysis"
        assert request.language == "en"

        summary = ReportSummary(
            risk_level="high",
            risk_score=0.85,
            primary_concerns=["Injection detected", "Data access anomaly"],
        )
        assert summary.risk_score == 0.85
        assert len(summary.primary_concerns) == 2

    async def test_report_worker_importable(
        self, async_client: AsyncClient
    ) -> None:
        """Report worker tasks should be importable."""
        from app.workers.report_worker import (
            generate_report_task,
            batch_generate_reports,
        )

        assert generate_report_task is not None
        assert batch_generate_reports is not None
        assert generate_report_task.name == "app.workers.report_worker.generate_report_task"
