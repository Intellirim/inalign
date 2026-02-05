"""
GraphRAG Pipeline -- main orchestrator for security analysis reports.

Coordinates the full flow:
    1. Extract the session subgraph from Neo4j.
    2. Convert the graph to text.
    3. Find similar historical patterns.
    4. Generate an LLM-backed security report.
    5. Parse the result into a :class:`ReportResponse` schema.
"""

from __future__ import annotations

import logging
import time
import uuid
from datetime import datetime, timezone
from typing import Any

from app.config import Settings
from app.graph.neo4j_client import Neo4jClient
from app.graph.session_extractor import SessionExtractor
from app.graphrag.graph_to_text import GraphToTextConverter
from app.graphrag.pattern_matcher import PatternMatcher
from app.graphrag.report_generator import ReportGenerator
from app.schemas.report import (
    AttackVector,
    BehaviorGraphAnalysis,
    BehaviorPattern,
    Recommendation,
    ReportAnalysis,
    ReportResponse,
    ReportSummary,
    SimilarAttack,
)

logger = logging.getLogger("inalign.graphrag.pipeline")


class GraphRAGPipeline:
    """
    End-to-end pipeline that turns a Neo4j session graph into a structured
    :class:`ReportResponse`.

    Parameters
    ----------
    neo4j_client:
        Connected :class:`Neo4jClient` instance.
    settings:
        Application :class:`Settings` (provides API keys, model prefs, etc.).
    """

    def __init__(
        self,
        neo4j_client: Neo4jClient,
        settings: Settings,
    ) -> None:
        self._neo4j = neo4j_client
        self._settings = settings

        # Sub-components
        self._extractor = SessionExtractor(neo4j_client)
        self._converter = GraphToTextConverter()
        self._matcher = PatternMatcher(load_model=False)  # lazy load on demand
        self._report_gen = self._build_report_generator()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def generate_report(
        self,
        session_id: str,
        report_type: str = "security_analysis",
        language: str = "ko",
    ) -> ReportResponse:
        """
        Generate a full security analysis report for a session.

        Steps
        -----
        1. Extract session graph via :class:`SessionExtractor`.
        2. Convert to text via :class:`GraphToTextConverter`.
        3. Find similar patterns via :class:`PatternMatcher`.
        4. Generate report via :class:`ReportGenerator`.
        5. Parse into :class:`ReportResponse`.

        Parameters
        ----------
        session_id:
            The Neo4j session to analyse.
        report_type:
            Type of report (default ``"security_analysis"``).
        language:
            ``"ko"`` or ``"en"``.

        Returns
        -------
        ReportResponse
            Fully populated report schema.
        """
        start_time: float = time.monotonic()
        report_id: str = str(uuid.uuid4())
        request_id: str = str(uuid.uuid4())

        logger.info(
            "Starting report generation: session=%s type=%s lang=%s report_id=%s",
            session_id,
            report_type,
            language,
            report_id,
        )

        # 1. Extract session graph.
        session_data: dict[str, Any] = await self._extractor.extract(session_id)

        # 2. Convert to text.
        graph_text: str = self._converter.convert(session_data)
        logger.debug("Graph text length: %d characters", len(graph_text))

        # 3. Find similar patterns.
        similar_patterns: list[dict[str, Any]] = await self._find_patterns(
            session_id, session_data
        )

        # 4. Generate LLM report.
        raw_report: dict[str, Any] = await self._report_gen.generate(
            graph_text=graph_text,
            similar_patterns=similar_patterns,
            report_type=report_type,
            language=language,
        )

        # 5. Parse into ReportResponse.
        elapsed_ms: float = (time.monotonic() - start_time) * 1000.0
        response: ReportResponse = self._build_response(
            raw_report=raw_report,
            session_id=session_id,
            report_id=report_id,
            request_id=request_id,
            elapsed_ms=elapsed_ms,
            session_data=session_data,
        )

        logger.info(
            "Report generated: report_id=%s session=%s elapsed=%.0f ms",
            report_id,
            session_id,
            elapsed_ms,
        )
        return response

    async def analyze_session(self, session_id: str) -> dict[str, Any]:
        """
        Quick session analysis without a full LLM call.

        Returns a dict containing extracted metrics, the action sequence,
        and basic risk assessment derived from graph data alone.
        """
        logger.info("Quick-analysing session: %s", session_id)

        session_data: dict[str, Any] = await self._extractor.extract(session_id)
        metrics: dict[str, Any] = await self._extractor.compute_session_metrics(
            session_id
        )

        session_info: dict[str, Any] = session_data.get("session", {})
        risk_score: float = float(session_info.get("risk_score", 0.0))

        # Determine risk level from score.
        risk_level: str
        if risk_score >= 0.9:
            risk_level = "critical"
        elif risk_score >= 0.7:
            risk_level = "high"
        elif risk_score >= 0.4:
            risk_level = "medium"
        elif risk_score >= 0.1:
            risk_level = "low"
        else:
            risk_level = "none"

        analysis: dict[str, Any] = {
            "session_id": session_id,
            "risk_level": risk_level,
            "risk_score": risk_score,
            "action_sequence": session_data.get("action_sequence", ""),
            "metrics": metrics,
            "threat_count": metrics.get("threat_count", 0),
            "total_actions": metrics.get("total_actions", 0),
            "status": session_info.get("status", "unknown"),
        }

        logger.info(
            "Quick analysis complete: session=%s risk_level=%s threats=%d",
            session_id,
            risk_level,
            analysis["threat_count"],
        )
        return analysis

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _build_report_generator(self) -> ReportGenerator:
        """Instantiate the ReportGenerator using application settings."""
        # Prefer OpenAI if key is available, otherwise try Anthropic.
        provider: str = "openai"
        api_key: str | None = self._settings.openai_api_key

        if not api_key and self._settings.anthropic_api_key:
            provider = "anthropic"
            api_key = self._settings.anthropic_api_key

        return ReportGenerator(
            provider=provider,
            api_key=api_key,
        )

    async def _find_patterns(
        self,
        session_id: str,
        session_data: dict[str, Any],
    ) -> list[dict[str, Any]]:
        """
        Combine Neo4j-based Jaccard similarity with embedding-based
        pattern matching to find historically similar sessions.
        """
        patterns: list[dict[str, Any]] = []

        # a) Neo4j Jaccard similarity.
        try:
            similar_sessions: list[dict[str, Any]] = (
                await self._neo4j.find_similar_sessions(
                    session_id=session_id,
                    min_similarity=0.5,
                    limit=5,
                )
            )
            for entry in similar_sessions:
                session_dict: dict[str, Any] = entry.get("session", {})
                patterns.append(
                    {
                        "session_id": session_dict.get("session_id", ""),
                        "similarity": entry.get("similarity", 0.0),
                        "source": "neo4j_jaccard",
                    }
                )
        except Exception:
            logger.exception("Failed to fetch similar sessions from Neo4j.")

        # b) Embedding-based similarity (if action sequences are available).
        action_sequence: str = session_data.get("action_sequence", "")
        if action_sequence and patterns:
            try:
                stored_sequences: list[dict[str, Any]] = [
                    {
                        "session_id": p["session_id"],
                        "sequence": p.get("action_sequence", action_sequence),
                    }
                    for p in patterns
                ]
                embedding_results: list[dict[str, Any]] = (
                    self._matcher.find_similar_sessions(
                        current_sequence=action_sequence,
                        stored_sequences=stored_sequences,
                    )
                )
                for er in embedding_results:
                    # Merge embedding score if the session is already listed.
                    existing = next(
                        (
                            p
                            for p in patterns
                            if p["session_id"] == er["session_id"]
                        ),
                        None,
                    )
                    if existing:
                        existing["embedding_score"] = er["score"]
                    else:
                        patterns.append(
                            {
                                "session_id": er["session_id"],
                                "score": er["score"],
                                "source": "embedding",
                            }
                        )
            except Exception:
                logger.exception("Embedding-based pattern matching failed.")

        logger.debug("Found %d similar patterns for session %s", len(patterns), session_id)
        return patterns

    @staticmethod
    def _build_response(
        raw_report: dict[str, Any],
        session_id: str,
        report_id: str,
        request_id: str,
        elapsed_ms: float,
        session_data: dict[str, Any],
    ) -> ReportResponse:
        """
        Map the raw LLM JSON output into a validated :class:`ReportResponse`.
        """
        # --- Summary ---
        risk_summary_raw: dict[str, Any] = raw_report.get("risk_summary", {})
        summary = ReportSummary(
            risk_level=risk_summary_raw.get("risk_level", "none"),
            risk_score=float(risk_summary_raw.get("risk_score", 0.0)),
            primary_concerns=risk_summary_raw.get("primary_concerns", []),
        )

        # --- Attack vectors ---
        attack_vectors: list[AttackVector] = []
        for av_raw in raw_report.get("attack_vectors", []):
            try:
                attack_vectors.append(
                    AttackVector(
                        type=av_raw.get("type", "unknown"),
                        confidence=float(av_raw.get("confidence", 0.0)),
                        description=av_raw.get("description", ""),
                        evidence=av_raw.get("evidence", []),
                    )
                )
            except Exception:
                logger.warning("Skipping malformed attack vector: %s", av_raw)

        # --- Behaviour graph analysis ---
        bga_raw: dict[str, Any] = raw_report.get("behavior_graph_analysis", {})
        patterns: list[BehaviorPattern] = []
        for p_raw in bga_raw.get("patterns", []):
            try:
                patterns.append(
                    BehaviorPattern(
                        name=p_raw.get("name", ""),
                        match_score=float(p_raw.get("match_score", 0.0)),
                        path=p_raw.get("path", ""),
                    )
                )
            except Exception:
                logger.warning("Skipping malformed pattern: %s", p_raw)

        similar_attacks: list[SimilarAttack] = []
        for sa_raw in bga_raw.get("similar_attacks", []):
            try:
                similar_attacks.append(
                    SimilarAttack(
                        session_id=sa_raw.get("session_id", ""),
                        date=sa_raw.get("date", ""),
                        similarity=float(sa_raw.get("similarity", 0.0)),
                        outcome=sa_raw.get("outcome", ""),
                    )
                )
            except Exception:
                logger.warning("Skipping malformed similar attack: %s", sa_raw)

        behavior_graph_analysis = BehaviorGraphAnalysis(
            description=bga_raw.get("description", ""),
            patterns=patterns,
            similar_attacks=similar_attacks,
        )

        # --- Timeline analysis ---
        timeline_analysis: str = raw_report.get("timeline_analysis", "")

        # --- Analysis composite ---
        analysis = ReportAnalysis(
            attack_vectors=attack_vectors,
            behavior_graph_analysis=behavior_graph_analysis,
            timeline_analysis=timeline_analysis,
        )

        # --- Recommendations ---
        recommendations: list[Recommendation] = []
        for rec_raw in raw_report.get("recommendations", []):
            try:
                recommendations.append(
                    Recommendation(
                        priority=rec_raw.get("priority", "medium"),
                        action=rec_raw.get("action", ""),
                        reason=rec_raw.get("reason", ""),
                    )
                )
            except Exception:
                logger.warning("Skipping malformed recommendation: %s", rec_raw)

        # --- Assemble response ---
        return ReportResponse(
            request_id=request_id,
            report_id=report_id,
            session_id=session_id,
            status="completed",
            generated_at=datetime.now(timezone.utc),
            generation_time_ms=round(elapsed_ms, 2),
            summary=summary,
            analysis=analysis,
            recommendations=recommendations,
            raw_graph_data={
                "session": session_data.get("session", {}),
                "action_count": len(session_data.get("actions", [])),
                "threat_count": len(session_data.get("threats", [])),
                "edge_count": len(session_data.get("edges", [])),
            },
        )
