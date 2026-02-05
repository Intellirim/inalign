"""
Provenance Query API

RESTful API for querying agent provenance data.
Provides endpoints for:
- Session queries
- Activity lookups
- Pattern detection
- Risk analysis
- Audit reports
"""

import json
import logging
from typing import Any, Optional
from datetime import datetime, timezone, timedelta
from dataclasses import dataclass, asdict

try:
    from fastapi import FastAPI, HTTPException, Query, Depends
    from fastapi.middleware.cors import CORSMiddleware
    from pydantic import BaseModel, Field
    FASTAPI_AVAILABLE = True
except ImportError:
    FASTAPI_AVAILABLE = False

from .graph_store import ProvenanceGraphStore, get_graph_store, Neo4jConfig
from .graph_rag import GraphRAGAnalyzer, analyze_session_risk, RiskLevel
from .provenance import ProvenanceChain, ProvenanceRecord, ActivityType

logger = logging.getLogger("inalign-api")


# ==========================================
# Pydantic Models for API
# ==========================================

if FASTAPI_AVAILABLE:
    class SessionQuery(BaseModel):
        """Query parameters for session lookup."""
        session_id: str
        include_activities: bool = True
        include_analysis: bool = False

    class ActivityQuery(BaseModel):
        """Query parameters for activity lookup."""
        activity_id: Optional[str] = None
        record_hash: Optional[str] = None
        session_id: Optional[str] = None
        activity_type: Optional[str] = None
        start_time: Optional[str] = None
        end_time: Optional[str] = None
        limit: int = Field(default=100, le=1000)
        offset: int = Field(default=0, ge=0)

    class RiskAnalysisRequest(BaseModel):
        """Request for risk analysis."""
        session_id: str
        include_similar: bool = True
        include_recommendations: bool = True

    class AuditReportRequest(BaseModel):
        """Request for audit report generation."""
        session_id: str
        format: str = Field(default="json", pattern="^(json|prov-jsonld|summary)$")
        include_chain_verification: bool = True

    class RecordActionRequest(BaseModel):
        """Request to record a new action."""
        session_id: str
        action_type: str
        action_name: str
        inputs: Optional[dict] = None
        outputs: Optional[dict] = None
        agent_name: str = "claude"

    class VerifyChainRequest(BaseModel):
        """Request to verify chain integrity."""
        session_id: str

    class PatternSearchRequest(BaseModel):
        """Request to search for patterns across sessions."""
        pattern_type: str
        min_confidence: float = Field(default=0.7, ge=0.0, le=1.0)
        limit: int = Field(default=50, le=500)


# ==========================================
# Query Functions (Non-FastAPI)
# ==========================================

class ProvenanceQueryService:
    """
    Service class for provenance queries.
    Can be used standalone or with FastAPI.
    """

    def __init__(self, graph_store: Optional[ProvenanceGraphStore] = None):
        self.store = graph_store or get_graph_store()
        self.analyzer = GraphRAGAnalyzer(self.store)

    def get_session(
        self,
        session_id: str,
        include_activities: bool = True,
        include_analysis: bool = False,
    ) -> dict[str, Any]:
        """Get session details with optional activities and analysis."""
        stats = self.store.get_session_stats(session_id)
        if not stats.get('session_id'):
            return {"error": "Session not found", "session_id": session_id}

        result = {
            "session_id": session_id,
            "stats": stats,
        }

        if include_activities:
            result["activities"] = self.store.get_session_chain(session_id)

        if include_analysis:
            result["risk_analysis"] = analyze_session_risk(session_id, self.store)

        return result

    def get_activity(
        self,
        activity_id: Optional[str] = None,
        record_hash: Optional[str] = None,
    ) -> Optional[dict]:
        """Get a specific activity by ID or hash."""
        if record_hash:
            return self.store.get_activity_by_hash(record_hash)
        # Would need to add get_activity_by_id to store
        return None

    def search_activities(
        self,
        session_id: Optional[str] = None,
        activity_type: Optional[str] = None,
        start_time: Optional[str] = None,
        end_time: Optional[str] = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[dict]:
        """Search activities with filters."""
        # Build dynamic query
        conditions = []
        params = {"limit": limit, "offset": offset}

        if session_id:
            conditions.append("a.session_id = $session_id")
            params["session_id"] = session_id

        if activity_type:
            conditions.append("a.activity_type = $activity_type")
            params["activity_type"] = activity_type

        if start_time:
            conditions.append("a.timestamp >= $start_time")
            params["start_time"] = start_time

        if end_time:
            conditions.append("a.timestamp <= $end_time")
            params["end_time"] = end_time

        where_clause = " AND ".join(conditions) if conditions else "true"

        query = f"""
        MATCH (a:Activity)
        WHERE {where_clause}
        RETURN a
        ORDER BY a.timestamp DESC
        SKIP $offset
        LIMIT $limit
        """

        try:
            with self.store.session() as session:
                result = session.run(query, **params)
                return [dict(row["a"]) for row in result]
        except Exception as e:
            logger.error(f"Search error: {e}")
            return []

    def analyze_risk(
        self,
        session_id: str,
        include_similar: bool = True,
        include_recommendations: bool = True,
    ) -> dict[str, Any]:
        """Run comprehensive risk analysis on a session."""
        analysis = analyze_session_risk(session_id, self.store)

        if not include_similar:
            analysis.pop('similar_sessions', None)

        if not include_recommendations:
            for pattern in analysis.get('patterns', []):
                pattern.pop('recommendation', None)

        return analysis

    def verify_chain(self, session_id: str) -> dict[str, Any]:
        """Verify the integrity of a session's provenance chain."""
        is_valid, error = self.store.verify_chain_integrity(session_id)

        # Also compute merkle root
        chain = self.store.get_session_chain(session_id)

        return {
            "session_id": session_id,
            "valid": is_valid,
            "error": error,
            "record_count": len(chain),
            "verification_timestamp": datetime.now(timezone.utc).isoformat(),
        }

    def generate_audit_report(
        self,
        session_id: str,
        format: str = "json",
        include_chain_verification: bool = True,
    ) -> dict[str, Any]:
        """Generate a comprehensive audit report for a session."""
        session = self.get_session(session_id, include_activities=True, include_analysis=True)

        if "error" in session:
            return session

        report = {
            "report_type": "agent_provenance_audit",
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "session_id": session_id,
            "session_stats": session.get("stats", {}),
            "risk_analysis": session.get("risk_analysis", {}),
        }

        if include_chain_verification:
            report["chain_verification"] = self.verify_chain(session_id)

        if format == "summary":
            # Return only summary, no full activity list
            report["summary"] = {
                "total_activities": session.get("stats", {}).get("activity_count", 0),
                "risk_level": session.get("risk_analysis", {}).get("overall_risk", "unknown"),
                "patterns_detected": session.get("risk_analysis", {}).get("patterns_detected", 0),
                "chain_valid": report.get("chain_verification", {}).get("valid", None),
            }
        elif format == "prov-jsonld":
            # Would need to convert to W3C PROV format
            report["@context"] = {
                "prov": "http://www.w3.org/ns/prov#",
                "inalign": "https://in-a-lign.com/prov#",
            }
            report["activities"] = session.get("activities", [])
        else:
            report["activities"] = session.get("activities", [])

        return report

    def search_patterns(
        self,
        pattern_type: str,
        min_confidence: float = 0.7,
        limit: int = 50,
    ) -> list[dict]:
        """Search for pattern occurrences across all sessions."""
        # This would need a more sophisticated query
        # For now, return placeholder
        query = """
        MATCH (se:SecurityEvent)
        WHERE se.event_type CONTAINS $pattern_type
        MATCH (se)-[:DETECTED_IN]->(a:Activity)-[:PART_OF]->(s:Session)
        RETURN DISTINCT s.session_id as session_id,
               count(se) as occurrences,
               collect(se.description)[0..5] as descriptions
        ORDER BY occurrences DESC
        LIMIT $limit
        """

        try:
            with self.store.session() as session:
                result = session.run(query, pattern_type=pattern_type, limit=limit)
                return [dict(row) for row in result]
        except Exception as e:
            logger.error(f"Pattern search error: {e}")
            return []

    def get_global_statistics(self) -> dict[str, Any]:
        """Get global statistics across all sessions."""
        query = """
        MATCH (s:Session)
        OPTIONAL MATCH (a:Activity)-[:PART_OF]->(s)
        OPTIONAL MATCH (se:SecurityEvent)-[:DETECTED_IN]->(a)
        WITH count(DISTINCT s) as sessions,
             count(DISTINCT a) as activities,
             count(DISTINCT se) as security_events
        RETURN sessions, activities, security_events
        """

        try:
            with self.store.session() as session:
                result = session.run(query)
                row = result.single()
                if row:
                    return {
                        "total_sessions": row["sessions"],
                        "total_activities": row["activities"],
                        "total_security_events": row["security_events"],
                        "tool_distribution": self.analyzer.get_global_stats().get("tool_distribution", {}),
                    }
                return {}
        except Exception as e:
            logger.error(f"Stats error: {e}")
            return {"error": str(e)}


# ==========================================
# FastAPI Application
# ==========================================

def create_api(graph_store: Optional[ProvenanceGraphStore] = None) -> "FastAPI":
    """Create FastAPI application for provenance queries."""
    if not FASTAPI_AVAILABLE:
        raise RuntimeError("FastAPI not installed. Run: pip install fastapi uvicorn")

    app = FastAPI(
        title="In-A-Lign Provenance API",
        description="Query and analyze AI agent provenance data",
        version="1.0.0",
    )

    # CORS middleware
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # Service instance
    service = ProvenanceQueryService(graph_store)

    @app.get("/health")
    async def health_check():
        """Health check endpoint."""
        return {"status": "healthy", "service": "inalign-provenance-api"}

    @app.get("/sessions/{session_id}")
    async def get_session(
        session_id: str,
        include_activities: bool = Query(True),
        include_analysis: bool = Query(False),
    ):
        """Get session details."""
        result = service.get_session(session_id, include_activities, include_analysis)
        if "error" in result:
            raise HTTPException(status_code=404, detail=result["error"])
        return result

    @app.get("/activities")
    async def search_activities(
        session_id: Optional[str] = Query(None),
        activity_type: Optional[str] = Query(None),
        start_time: Optional[str] = Query(None),
        end_time: Optional[str] = Query(None),
        limit: int = Query(100, le=1000),
        offset: int = Query(0, ge=0),
    ):
        """Search activities with filters."""
        return service.search_activities(
            session_id=session_id,
            activity_type=activity_type,
            start_time=start_time,
            end_time=end_time,
            limit=limit,
            offset=offset,
        )

    @app.get("/activities/{record_hash}")
    async def get_activity(record_hash: str):
        """Get activity by record hash."""
        result = service.get_activity(record_hash=record_hash)
        if not result:
            raise HTTPException(status_code=404, detail="Activity not found")
        return result

    @app.post("/analyze/risk")
    async def analyze_risk(request: RiskAnalysisRequest):
        """Run risk analysis on a session."""
        return service.analyze_risk(
            session_id=request.session_id,
            include_similar=request.include_similar,
            include_recommendations=request.include_recommendations,
        )

    @app.post("/verify")
    async def verify_chain(request: VerifyChainRequest):
        """Verify chain integrity."""
        return service.verify_chain(request.session_id)

    @app.post("/audit")
    async def generate_audit(request: AuditReportRequest):
        """Generate audit report."""
        return service.generate_audit_report(
            session_id=request.session_id,
            format=request.format,
            include_chain_verification=request.include_chain_verification,
        )

    @app.post("/patterns/search")
    async def search_patterns(request: PatternSearchRequest):
        """Search for patterns across sessions."""
        return service.search_patterns(
            pattern_type=request.pattern_type,
            min_confidence=request.min_confidence,
            limit=request.limit,
        )

    @app.get("/stats/global")
    async def get_global_stats():
        """Get global statistics."""
        return service.get_global_statistics()

    return app


# ==========================================
# CLI Runner
# ==========================================

def run_api(
    host: str = "0.0.0.0",
    port: int = 8080,
    reload: bool = False,
):
    """Run the API server."""
    try:
        import uvicorn
    except ImportError:
        raise RuntimeError("uvicorn not installed. Run: pip install uvicorn")

    app = create_api()
    uvicorn.run(app, host=host, port=port, reload=reload)


if __name__ == "__main__":
    run_api()
