"""
Scan service for input (injection) and output (PII) detection.

Orchestrates the detection pipeline, computes risk scores, and returns
structured responses with latency metrics.
"""

from __future__ import annotations

import logging
import time
from uuid import uuid4

from app.schemas.common import RiskLevel
from app.schemas.scan import (
    ScanInputRequest,
    ScanInputResponse,
    ScanOutputRequest,
    ScanOutputResponse,
)

logger = logging.getLogger("agentshield.services.scan")

# Risk-score thresholds --------------------------------------------------
_BLOCK_THRESHOLD: float = 0.7
_WARN_THRESHOLD: float = 0.3


def _risk_level_from_score(score: float) -> RiskLevel:
    """Map a 0-1 risk score to a discrete risk level."""
    if score >= 0.9:
        return RiskLevel.CRITICAL
    if score >= _BLOCK_THRESHOLD:
        return RiskLevel.HIGH
    if score >= _WARN_THRESHOLD:
        return RiskLevel.MEDIUM
    if score > 0.0:
        return RiskLevel.LOW
    return RiskLevel.NONE


def _recommendation_from_score(score: float) -> str:
    """Return ``allow``, ``warn``, or ``block`` based on *score*."""
    if score >= _BLOCK_THRESHOLD:
        return "block"
    if score >= _WARN_THRESHOLD:
        return "warn"
    return "allow"


class ScanService:
    """Stateless service that scans agent inputs and outputs for threats."""

    def __init__(
        self,
        injection_detector: object,
        pii_detector: object,
    ) -> None:
        self._injection_detector = injection_detector
        self._pii_detector = pii_detector

    # ------------------------------------------------------------------
    # Input scanning (prompt injection / jailbreak detection)
    # ------------------------------------------------------------------

    async def scan_input(self, request: ScanInputRequest) -> ScanInputResponse:
        """Run injection detection on user/agent input text.

        Parameters
        ----------
        request:
            Contains the text to scan along with agent/session identifiers.

        Returns
        -------
        ScanInputResponse
            Structured result including threats, risk score, recommendation,
            and processing latency.
        """
        request_id = str(uuid4())
        start = time.perf_counter()

        logger.info(
            "scan_input  request_id=%s  session=%s  agent=%s  len=%d",
            request_id,
            request.session_id,
            request.agent_id,
            len(request.text),
        )

        # Run detection -------------------------------------------------------
        try:
            detection_result = await self._injection_detector.detect(request.text)  # type: ignore[attr-defined]
            threats = detection_result.get("threats", [])
        except Exception:
            logger.exception("Injection detection failed for request %s", request_id)
            threats = []

        # Compute aggregate risk score ----------------------------------------
        if threats:
            risk_score = round(max(t.get("confidence", 0.0) for t in threats), 4)
        else:
            risk_score = 0.0

        risk_level = _risk_level_from_score(risk_score)
        recommendation = _recommendation_from_score(risk_score)
        is_safe = risk_score < _WARN_THRESHOLD

        latency_ms = round((time.perf_counter() - start) * 1000, 2)

        # Build typed threat list ----------------------------------------------
        from app.schemas.scan import ThreatInfo
        from app.schemas.common import Severity

        typed_threats = []
        for t in threats:
            typed_threats.append(
                ThreatInfo(
                    type=t.get("type", "unknown"),
                    subtype=t.get("subtype", ""),
                    pattern_id=t.get("pattern_id", ""),
                    matched_text=t.get("matched_text", ""),
                    position=t.get("position", [0, 0]),
                    confidence=t.get("confidence", 0.0),
                    severity=Severity(t.get("severity", "medium")),
                    description=t.get("description", ""),
                )
            )

        action_taken = "blocked" if recommendation == "block" else "logged"

        logger.info(
            "scan_input  request_id=%s  risk=%.4f  level=%s  rec=%s  latency=%.1fms",
            request_id,
            risk_score,
            risk_level.value,
            recommendation,
            latency_ms,
        )

        return ScanInputResponse(
            request_id=request_id,
            safe=is_safe,
            risk_level=risk_level,
            risk_score=risk_score,
            latency_ms=latency_ms,
            threats=typed_threats,
            recommendation=recommendation,
            action_taken=action_taken,
        )

    # ------------------------------------------------------------------
    # Output scanning (PII detection and optional sanitisation)
    # ------------------------------------------------------------------

    async def scan_output(self, request: ScanOutputRequest) -> ScanOutputResponse:
        """Run PII detection on agent output text.

        Parameters
        ----------
        request:
            Contains the text to scan and an ``auto_sanitize`` flag.

        Returns
        -------
        ScanOutputResponse
            Structured result with detected PII entities and, if requested,
            the sanitised text.
        """
        request_id = str(uuid4())
        start = time.perf_counter()

        logger.info(
            "scan_output  request_id=%s  session=%s  agent=%s  len=%d  sanitize=%s",
            request_id,
            request.session_id,
            request.agent_id,
            len(request.text),
            request.auto_sanitize,
        )

        # Run PII detection ---------------------------------------------------
        try:
            detection_result = await self._pii_detector.detect(request.text)  # type: ignore[attr-defined]
            pii_items = detection_result.get("pii_entities", [])
            sanitized_text = detection_result.get("sanitized_text", request.text)
        except Exception:
            logger.exception("PII detection failed for request %s", request_id)
            pii_items = []
            sanitized_text = request.text

        # Compute aggregate risk score ----------------------------------------
        if pii_items:
            risk_score = round(
                min(1.0, len(pii_items) * 0.15 + max(p.get("confidence", 0.0) for p in pii_items) * 0.5),
                4,
            )
        else:
            risk_score = 0.0

        risk_level = _risk_level_from_score(risk_score)
        recommendation = _recommendation_from_score(risk_score)
        is_safe = risk_score < _WARN_THRESHOLD

        latency_ms = round((time.perf_counter() - start) * 1000, 2)

        # Build typed PII list -------------------------------------------------
        from app.schemas.scan import PIIInfo
        from app.schemas.common import Severity

        typed_pii: list[PIIInfo] = []
        for p in pii_items:
            typed_pii.append(
                PIIInfo(
                    type=p.get("type", "unknown"),
                    subtype=p.get("subtype", ""),
                    value=p.get("value", ""),
                    position=p.get("position", [0, 0]),
                    confidence=p.get("confidence", 1.0),
                    severity=Severity(p.get("severity", "medium")),
                )
            )

        action_taken = "sanitized" if request.auto_sanitize and pii_items else "logged"

        logger.info(
            "scan_output  request_id=%s  pii_count=%d  risk=%.4f  level=%s  latency=%.1fms",
            request_id,
            len(typed_pii),
            risk_score,
            risk_level.value,
            latency_ms,
        )

        return ScanOutputResponse(
            request_id=request_id,
            safe=is_safe,
            risk_level=risk_level,
            risk_score=risk_score,
            latency_ms=latency_ms,
            pii_detected=typed_pii,
            original_text=request.text if request.auto_sanitize and pii_items else None,
            sanitized_text=sanitized_text if request.auto_sanitize else None,
            recommendation=recommendation,
            action_taken=action_taken,
        )
