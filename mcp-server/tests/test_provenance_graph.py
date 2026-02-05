"""
Test Provenance Graph (without Neo4j - mock tests).
"""
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from inalign_mcp.provenance import (
    get_or_create_chain,
    record_tool_call,
    record_decision,
)
from inalign_mcp.provenance_graph import (
    ProvenanceGraph,
    GraphNode,
    GraphEdge,
    is_neo4j_available,
)


def test_graph_data_structures():
    """Test graph data structures work correctly."""
    print("\nTEST: Graph Data Structures")
    print("=" * 50)

    # Create sample nodes
    nodes = [
        GraphNode(id="r1", label="scan_input", type="record", properties={"sequence": 1}),
        GraphNode(id="t1", label="scan_text", type="tool", properties={}),
        GraphNode(id="a1", label="claude", type="agent", properties={}),
    ]

    # Create sample edges
    edges = [
        GraphEdge(source="r1", target="t1", type="CALLED", properties={}),
        GraphEdge(source="r1", target="a1", type="PERFORMED_BY", properties={}),
    ]

    # Create graph
    graph = ProvenanceGraph(
        nodes=nodes,
        edges=edges,
        metadata={"session_id": "test-001", "record_count": 1}
    )

    # Convert to dict
    data = graph.to_dict()

    print(f"  Nodes: {len(data['nodes'])}")
    print(f"  Edges: {len(data['edges'])}")
    print(f"  Metadata: {data['metadata']}")

    assert len(data["nodes"]) == 3
    assert len(data["edges"]) == 2
    assert data["metadata"]["session_id"] == "test-001"

    print("  [PASS] Graph data structures working")


def test_provenance_chain_for_graph():
    """Test that provenance chain produces data suitable for graphing."""
    print("\nTEST: Provenance Chain for Graph")
    print("=" * 50)

    session_id = "graph-test-001"

    # Create chain and add records
    chain = get_or_create_chain(session_id)

    record1 = record_tool_call(
        session_id=session_id,
        tool_name="scan_input",
        arguments={"text": "test input"},
        result={"safe": True},
    )

    record2 = record_decision(
        session_id=session_id,
        decision="allow",
        reasoning="Input is safe",
    )

    record3 = record_tool_call(
        session_id=session_id,
        tool_name="generate_response",
        arguments={"prompt": "Hello"},
        result={"response": "Hi there!"},
    )

    # Verify chain structure
    chain = get_or_create_chain(session_id)
    print(f"  Records in chain: {len(chain.records)}")

    # Check each record has graph-compatible data
    for i, record in enumerate(chain.records):
        print(f"  Record {i+1}:")
        print(f"    ID: {record.id}")
        print(f"    Type: {record.activity_type.value}")
        print(f"    Name: {record.activity_name}")
        print(f"    Hash: {record.record_hash[:16]}...")
        print(f"    Prev: {record.previous_hash[:16] if record.previous_hash else 'None'}...")

        # These fields are needed for graph visualization
        assert record.id is not None
        assert record.activity_type is not None
        assert record.activity_name is not None
        assert record.record_hash is not None
        assert record.timestamp is not None

    # Verify chain links
    for i in range(1, len(chain.records)):
        curr = chain.records[i]
        prev = chain.records[i-1]
        assert curr.previous_hash == prev.record_hash, "Chain link broken"

    print("  [PASS] Provenance chain suitable for graphing")


def test_mock_visualization_data():
    """Test generating visualization data without Neo4j."""
    print("\nTEST: Mock Visualization Data")
    print("=" * 50)

    session_id = "viz-test-001"

    # Create some activity
    chain = get_or_create_chain(session_id)

    record_tool_call(session_id, "read_file", {"path": "/app/main.py"}, {"content": "..."})
    record_decision(session_id, "allow", "File read is permitted")
    record_tool_call(session_id, "edit_file", {"path": "/app/main.py"}, {"success": True})
    record_decision(session_id, "warn", "File modification detected")

    chain = get_or_create_chain(session_id)

    # Manually create visualization data (what Neo4j would return)
    nodes = []
    edges = []

    # Add session node
    nodes.append(GraphNode(
        id=f"session:{session_id}",
        label=session_id,
        type="session",
        properties={}
    ))

    prev_id = None
    for record in chain.records:
        # Record node
        nodes.append(GraphNode(
            id=record.id,
            label=record.activity_name,
            type=record.activity_type.value,
            properties={
                "timestamp": record.timestamp,
                "sequence": record.sequence_number,
            }
        ))

        # Link to session
        edges.append(GraphEdge(
            source=record.id,
            target=f"session:{session_id}",
            type="BELONGS_TO",
            properties={}
        ))

        # Chain link
        if prev_id:
            edges.append(GraphEdge(
                source=record.id,
                target=prev_id,
                type="FOLLOWS",
                properties={}
            ))

        prev_id = record.id

    graph = ProvenanceGraph(nodes=nodes, edges=edges, metadata={
        "session_id": session_id,
        "record_count": len(chain.records),
    })

    data = graph.to_dict()
    print(f"  Generated visualization with {len(data['nodes'])} nodes, {len(data['edges'])} edges")

    # This is what the frontend would receive
    print(f"  Sample node: {data['nodes'][1]}")
    print(f"  Sample edge: {data['edges'][0]}")

    assert len(data["nodes"]) == 5  # 1 session + 4 records
    assert len(data["edges"]) >= 4  # At least 4 BELONGS_TO edges

    print("  [PASS] Mock visualization data generated")


def test_neo4j_availability():
    """Check Neo4j availability (informational)."""
    print("\nTEST: Neo4j Availability Check")
    print("=" * 50)

    available = is_neo4j_available()
    print(f"  Neo4j available: {available}")

    if not available:
        print("  Note: Neo4j not connected. Graph visualization will use mock data.")
        print("  To enable: Start Neo4j and call init_neo4j()")

    print("  [INFO] Check complete")


def run_all_tests():
    """Run all provenance graph tests."""
    print("\n" + "*" * 50)
    print("*  PROVENANCE GRAPH TESTS  *")
    print("*" * 50)

    try:
        test_graph_data_structures()
        test_provenance_chain_for_graph()
        test_mock_visualization_data()
        test_neo4j_availability()

        print("\n" + "=" * 50)
        print("  ALL PROVENANCE GRAPH TESTS PASSED!")
        print("=" * 50)
        return True

    except Exception as e:
        print(f"\n  [FAIL] {e}")
        import traceback
        traceback.print_exc()
        return False


if __name__ == "__main__":
    success = run_all_tests()
    sys.exit(0 if success else 1)
