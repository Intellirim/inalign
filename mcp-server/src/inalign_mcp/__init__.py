"""
In-A-Lign Agent Provenance & Security Platform

Modular Architecture:
=====================

CORE (Always Available):
- Scanner: Threat detection (regex + ML + GraphRAG)
- Policy Engine: Configurable security policies
- Provenance: W3C PROV compliant audit trails

OPTIONAL (Require Extra Dependencies):
- ML Scanner: DistilBERT classification (torch, transformers)
- Graph Scanner: Neo4j GraphRAG (neo4j)
- Context Extractor: Project context analysis
- Provenance Graph: Neo4j visualization (neo4j)
- Visualization API: REST endpoints (fastapi)
- Anchoring: Blockchain anchoring

Usage Examples:
==============

Basic scanning:
    from inalign_mcp import scan_text, PolicyEngine
    result = scan_text("user input")
    engine = PolicyEngine("BALANCED")
    decision = engine.evaluate(result.threats[0].category, result.risk_score)

Full stack with provenance:
    from inalign_mcp import (
        scan_with_context,
        record_tool_call,
        get_or_create_chain,
        PolicyEngine,
    )

Run as services:
    python -m inalign_mcp.server          # MCP server
    python -m inalign_mcp.query_api       # Query API
    python -m inalign_mcp.visualization_api  # Visualization API
"""

__version__ = "0.2.3"
__author__ = "In-A-Lign"

# ============================================
# CORE: Scanner (Always Available)
# ============================================
from .scanner import (
    scan_text,
    scan_text_with_graph,
    scan_tool_call,
    mask_pii,
    ScanResult,
    Threat,
    Severity,
)

# Context-aware scanning
try:
    from .scanner import scan_with_context, get_context_summary
    CONTEXT_SCAN_AVAILABLE = True
except ImportError:
    CONTEXT_SCAN_AVAILABLE = False

# ============================================
# CORE: Policy Engine (Always Available)
# ============================================
from .policy import (
    PolicyEngine,
    PolicyAction,
    PolicyDecision,
    ThreatCategory,
)

# ============================================
# CORE: Provenance Chain (Always Available)
# ============================================
from .provenance import (
    ProvenanceRecord,
    ProvenanceChain,
    Entity,
    Agent,
    ActivityType,
    get_or_create_chain,
    record_tool_call,
    record_decision,
    get_chain_summary,
)

# ============================================
# OPTIONAL: ML Scanner (requires torch)
# ============================================
try:
    from .ml_scanner import (
        MLScanner,
        MLScanResult,
        ml_scan,
        get_ml_scanner,
        get_ml_scan_summary,
    )
    ML_SCANNER_AVAILABLE = True
except ImportError:
    ML_SCANNER_AVAILABLE = False

# ============================================
# OPTIONAL: Graph Scanner (requires neo4j)
# ============================================
try:
    from .graph_scanner import (
        GraphScanResult,
        graph_scan,
    )
    GRAPH_SCANNER_AVAILABLE = True
except ImportError:
    GRAPH_SCANNER_AVAILABLE = False

# ============================================
# OPTIONAL: Context Extractor
# ============================================
try:
    from .context import (
        ContextExtractor,
        ProjectContext,
        get_context_extractor,
        extract_context,
        get_session_context,
    )
    CONTEXT_AVAILABLE = True
except ImportError:
    CONTEXT_AVAILABLE = False

# ============================================
# OPTIONAL: Graph Store (requires neo4j)
# ============================================
try:
    from .graph_store import (
        ProvenanceGraphStore,
        get_graph_store,
        store_provenance,
        store_chain,
        Neo4jConfig,
    )
    GRAPHSTORE_AVAILABLE = True
except ImportError:
    GRAPHSTORE_AVAILABLE = False

# ============================================
# OPTIONAL: Provenance Graph Visualization
# ============================================
try:
    from .provenance_graph import (
        init_neo4j as init_provenance_graph,
        is_neo4j_available as is_provenance_graph_available,
        store_record as store_provenance_record,
        store_chain as store_provenance_chain,
        get_session_graph,
        get_agent_behavior_graph,
        get_attack_path_graph,
        get_tool_usage_stats,
        get_security_event_stats,
        detect_anomalous_patterns,
        sync_chain_to_graph,
        get_visualization_data,
        ProvenanceGraph,
        GraphNode,
        GraphEdge,
    )
    PROVENANCE_GRAPH_AVAILABLE = True
except ImportError:
    PROVENANCE_GRAPH_AVAILABLE = False

# ============================================
# OPTIONAL: GraphRAG Analysis
# ============================================
try:
    from .graph_rag import (
        GraphRAGAnalyzer,
        analyze_session_risk,
        PatternMatch,
        PatternType,
        RiskLevel,
        BehaviorProfile,
    )
    GRAPHRAG_AVAILABLE = True
except ImportError:
    GRAPHRAG_AVAILABLE = False

# ============================================
# OPTIONAL: Blockchain Anchoring
# ============================================
try:
    from .anchoring import (
        AnchorService,
        AnchorProof,
        AnchorConfig,
        ChainType,
        get_anchor_service,
        anchor_chain,
        get_anchor_proof,
    )
    ANCHORING_AVAILABLE = True
except ImportError:
    ANCHORING_AVAILABLE = False


# ============================================
# Feature Summary
# ============================================
def get_available_features() -> dict[str, bool]:
    """Get dictionary of available features."""
    return {
        "core_scanner": True,
        "core_policy": True,
        "core_provenance": True,
        "ml_scanner": ML_SCANNER_AVAILABLE,
        "graph_scanner": GRAPH_SCANNER_AVAILABLE,
        "context_extractor": CONTEXT_AVAILABLE,
        "context_aware_scan": CONTEXT_SCAN_AVAILABLE,
        "graph_store": GRAPHSTORE_AVAILABLE,
        "provenance_graph": PROVENANCE_GRAPH_AVAILABLE,
        "graph_rag": GRAPHRAG_AVAILABLE,
        "anchoring": ANCHORING_AVAILABLE,
    }


def print_feature_status():
    """Print status of all features."""
    features = get_available_features()
    print("InALign MCP Server - Feature Status")
    print("=" * 40)
    for feature, available in features.items():
        status = "OK" if available else "Not Available"
        print(f"  {feature}: {status}")
    print("=" * 40)


__all__ = [
    # Version
    "__version__",
    # Core Scanner
    "scan_text",
    "scan_text_with_graph",
    "scan_tool_call",
    "mask_pii",
    "ScanResult",
    "Threat",
    "Severity",
    # Core Policy
    "PolicyEngine",
    "PolicyAction",
    "PolicyDecision",
    "ThreatCategory",
    # Core Provenance
    "ProvenanceRecord",
    "ProvenanceChain",
    "Entity",
    "Agent",
    "ActivityType",
    "get_or_create_chain",
    "record_tool_call",
    "record_decision",
    "get_chain_summary",
    # Feature flags
    "ML_SCANNER_AVAILABLE",
    "GRAPH_SCANNER_AVAILABLE",
    "CONTEXT_AVAILABLE",
    "CONTEXT_SCAN_AVAILABLE",
    "GRAPHSTORE_AVAILABLE",
    "PROVENANCE_GRAPH_AVAILABLE",
    "GRAPHRAG_AVAILABLE",
    "ANCHORING_AVAILABLE",
    # Utilities
    "get_available_features",
    "print_feature_status",
]
