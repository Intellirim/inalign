"""
Scanning endpoints.

Exposes input (injection detection) and output (PII detection/sanitisation)
scanning behind API-key authentication and rate limiting.
"""

from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, HTTPException, status

from app.core.rate_limiter import rate_limit
from app.dependencies import CurrentUser, Neo4jSession
from app.schemas.scan import (
    ScanInputRequest,
    ScanInputResponse,
    ScanOutputRequest,
    ScanOutputResponse,
)
from app.services.scan_service import ScanService

logger = logging.getLogger("agentshield.api.scan")

router = APIRouter()


# --------------------------------------------------------------------------
# Helpers -- build ScanService per request
# --------------------------------------------------------------------------


def _get_scan_service(neo4j_session=None) -> ScanService:
    """Construct a :class:`ScanService` with the registered detector singletons.

    Detectors are imported lazily so this module stays importable even when
    detector packages have heavy optional dependencies.

    When *neo4j_session* is provided, Graph RAG-based detection and
    attack knowledge logging are enabled.
    """
    from app.detectors import InjectionDetector, PIIDetector  # noqa: WPS433

    return ScanService(
        injection_detector=InjectionDetector(),
        pii_detector=PIIDetector(),
        neo4j_session=neo4j_session,
    )


# --------------------------------------------------------------------------
# POST /input
# --------------------------------------------------------------------------


@router.post(
    "/input",
    response_model=ScanInputResponse,
    status_code=status.HTTP_200_OK,
    summary="Scan agent input",
    description=(
        "Run prompt-injection and jailbreak detection on the provided input "
        "text. Returns a risk assessment with threat details, risk score, "
        "and a recommended action (allow / warn / block)."
    ),
    dependencies=[Depends(rate_limit)],
)
async def scan_input(
    body: ScanInputRequest,
    current_user: CurrentUser,
    neo4j: Neo4jSession,
) -> ScanInputResponse:
    """Scan incoming agent input for injection attacks.

    Graph RAG is automatically enabled: every scan result is stored in the
    Neo4j knowledge graph, and similar known attacks boost detection.
    """
    logger.info(
        "POST /scan/input  user=%s  session=%s  agent=%s",
        current_user["user_id"],
        body.session_id,
        body.agent_id,
    )

    service = _get_scan_service(neo4j_session=neo4j)

    try:
        result = await service.scan_input(body)
    except Exception as exc:
        logger.exception("scan_input failed")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Input scan failed: {exc}",
        ) from exc

    return result


# --------------------------------------------------------------------------
# POST /output
# --------------------------------------------------------------------------


@router.post(
    "/output",
    response_model=ScanOutputResponse,
    status_code=status.HTTP_200_OK,
    summary="Scan agent output",
    description=(
        "Run PII detection on agent output text. Optionally sanitise "
        "detected PII entities by replacing them with placeholders."
    ),
    dependencies=[Depends(rate_limit)],
)
async def scan_output(
    body: ScanOutputRequest,
    current_user: CurrentUser,
) -> ScanOutputResponse:
    """Scan agent output for PII and optionally sanitise."""
    logger.info(
        "POST /scan/output  user=%s  session=%s  agent=%s  sanitize=%s",
        current_user["user_id"],
        body.session_id,
        body.agent_id,
        body.auto_sanitize,
    )

    service = _get_scan_service()

    try:
        result = await service.scan_output(body)
    except Exception as exc:
        logger.exception("scan_output failed")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Output scan failed: {exc}",
        ) from exc

    return result
