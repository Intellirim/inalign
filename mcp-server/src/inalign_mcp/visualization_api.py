"""
Provenance Visualization REST API.

Provides endpoints for the dashboard to visualize:
- Session activity graphs
- Agent behavior patterns
- Security event timelines
- Attack path analysis
"""

import logging
from typing import Optional, Any
from datetime import datetime, timezone

logger = logging.getLogger("inalign-visualization-api")

# FastAPI app (created on demand)
_app = None


def create_app():
    """Create FastAPI app for visualization API."""
    try:
        from fastapi import FastAPI, HTTPException, Query
        from fastapi.middleware.cors import CORSMiddleware
        from pydantic import BaseModel
    except ImportError:
        logger.error("FastAPI not installed. Install with: pip install fastapi uvicorn")
        return None

    from .provenance_graph import (
        init_neo4j,
        is_neo4j_available,
        get_session_graph,
        get_agent_behavior_graph,
        get_attack_path_graph,
        get_tool_usage_stats,
        get_security_event_stats,
        detect_anomalous_patterns,
        sync_chain_to_graph,
        get_visualization_data,
    )
    from .provenance import get_or_create_chain, get_chain_summary

    app = FastAPI(
        title="InALign Provenance Visualization API",
        description="API for visualizing agent activity graphs and security events",
        version="0.2.0",
    )

    # CORS for dashboard
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],  # Configure for production
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # ============================================
    # Health & Status
    # ============================================

    @app.get("/health")
    async def health():
        """Health check endpoint."""
        return {
            "status": "healthy",
            "neo4j_available": is_neo4j_available(),
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

    @app.post("/init")
    async def initialize(
        neo4j_uri: str = "bolt://localhost:7687",
        neo4j_user: str = "neo4j",
        neo4j_password: str = "password",
    ):
        """Initialize Neo4j connection."""
        success = init_neo4j(neo4j_uri, neo4j_user, neo4j_password)
        return {"success": success, "neo4j_available": is_neo4j_available()}

    # ============================================
    # Session Visualization
    # ============================================

    @app.get("/api/v1/sessions/{session_id}/graph")
    async def get_session_graph_endpoint(session_id: str):
        """
        Get the provenance graph for a session.

        Returns nodes and edges for visualization:
        - ProvenanceRecord nodes (activities)
        - Agent nodes
        - Tool nodes
        - Decision nodes
        - Relationships between them
        """
        data = get_visualization_data(session_id=session_id, view_type="session")
        if "error" in data:
            raise HTTPException(status_code=404, detail=data["error"])
        return data

    @app.get("/api/v1/sessions/{session_id}/timeline")
    async def get_session_timeline(session_id: str):
        """
        Get session activity as a timeline.

        Returns activities in chronological order with metadata.
        """
        summary = get_chain_summary(session_id)
        if "error" in summary:
            raise HTTPException(status_code=404, detail=summary["error"])
        return summary

    @app.get("/api/v1/sessions/{session_id}/attack-path")
    async def get_session_attack_path(session_id: str):
        """
        Analyze potential attack paths in a session.

        Highlights security events and their context.
        """
        data = get_visualization_data(session_id=session_id, view_type="attack_path")
        if "error" in data:
            raise HTTPException(status_code=404, detail=data["error"])
        return data

    @app.post("/api/v1/sessions/{session_id}/sync")
    async def sync_session_to_graph(session_id: str):
        """
        Sync a session's provenance chain to Neo4j.

        Call this to persist in-memory records to the graph database.
        """
        count = sync_chain_to_graph(session_id)
        return {"session_id": session_id, "records_synced": count}

    # ============================================
    # Agent Visualization
    # ============================================

    @app.get("/api/v1/agents/{agent_id}/behavior")
    async def get_agent_behavior(
        agent_id: str,
        limit: int = Query(default=100, le=1000),
    ):
        """
        Get behavior graph for an agent.

        Shows aggregated tool usage and decision patterns.
        """
        data = get_visualization_data(agent_id=agent_id, view_type="agent")
        if "error" in data:
            raise HTTPException(status_code=404, detail=data["error"])
        return data

    # ============================================
    # Analytics & Stats
    # ============================================

    @app.get("/api/v1/stats/tools")
    async def get_tool_stats(days: int = Query(default=7, le=90)):
        """
        Get tool usage statistics.

        Returns counts of tool calls over the specified period.
        """
        return get_tool_usage_stats(days)

    @app.get("/api/v1/stats/security")
    async def get_security_stats(days: int = Query(default=7, le=90)):
        """
        Get security event statistics.

        Returns counts of blocks, warnings, and decisions.
        """
        return get_security_event_stats(days)

    @app.get("/api/v1/anomalies")
    async def get_anomalies():
        """
        Detect anomalous behavior patterns.

        Uses graph algorithms to identify suspicious activity.
        """
        return {"anomalies": detect_anomalous_patterns()}

    # ============================================
    # Bulk Operations
    # ============================================

    class BulkSyncRequest(BaseModel):
        session_ids: list[str]

    @app.post("/api/v1/bulk/sync")
    async def bulk_sync_sessions(request: BulkSyncRequest):
        """Sync multiple sessions to Neo4j."""
        results = {}
        for session_id in request.session_ids:
            count = sync_chain_to_graph(session_id)
            results[session_id] = count
        return {"synced": results, "total_sessions": len(results)}

    return app


def get_app():
    """Get or create the FastAPI app."""
    global _app
    if _app is None:
        _app = create_app()
    return _app


def run_api(host: str = "0.0.0.0", port: int = 8001):
    """Run the visualization API server."""
    try:
        import uvicorn
    except ImportError:
        print("uvicorn not installed. Install with: pip install uvicorn")
        return

    app = get_app()
    if app is None:
        print("Failed to create API app. Install dependencies: pip install fastapi uvicorn")
        return

    print(f"Starting Provenance Visualization API at http://{host}:{port}")
    print("API docs available at: http://{host}:{port}/docs")
    uvicorn.run(app, host=host, port=port)


# CLI entry point
if __name__ == "__main__":
    run_api()
