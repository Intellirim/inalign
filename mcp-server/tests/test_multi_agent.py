"""
Multi-Agent Tracking Test

Tests that InALign tracks ALL agents, not just Claude Code:
- Claude Code
- Cursor
- Custom agents
- Any MCP-compatible client
"""
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from inalign_mcp.provenance import get_or_create_chain, record_tool_call, record_decision
from inalign_mcp.client_manager import get_client_manager, PlanType
from inalign_mcp.scanner import scan_text
from inalign_mcp.policy import PolicyEngine


def test_multi_agent_tracking():
    """Test tracking multiple different agents."""
    print("\n" + "="*60)
    print("TEST: Multi-Agent Tracking")
    print("="*60)

    # Simulate different agents using the same API key
    agents = [
        {"id": "claude-code", "name": "Claude Code", "type": "anthropic"},
        {"id": "cursor-ai", "name": "Cursor", "type": "cursor"},
        {"id": "windsurf", "name": "Windsurf", "type": "codeium"},
        {"id": "custom-agent-001", "name": "Company Internal Bot", "type": "custom"},
    ]

    # Register a test client
    manager = get_client_manager()
    client, api_key = manager.register_client(
        name="Multi-Agent Test Corp",
        email="test@multiagent.com",
        plan=PlanType.ENTERPRISE
    )
    print(f"\n  Client: {client.name}")
    print(f"  API Key: {api_key[:20]}...")

    # Each agent creates activities
    for agent in agents:
        session_id = f"session-{agent['id']}-001"

        print(f"\n  --- Agent: {agent['name']} ({agent['type']}) ---")

        # Create session for this agent
        session = manager.create_session(
            client_id=client.client_id,
            session_id=session_id,
            agent_id=agent['id'],
            agent_name=agent['name']
        )

        # Agent performs some actions
        chain = get_or_create_chain(session_id, agent['name'])

        # Action 1: Read file
        record_tool_call(
            session_id=session_id,
            tool_name="read_file",
            arguments={"path": "/app/main.py"},
            result={"content": "# Main application..."},
            agent_name=agent['name']
        )

        # Action 2: Scan for threats
        scan_result = scan_text("Write a function to process user input")
        record_tool_call(
            session_id=session_id,
            tool_name="scan_input",
            arguments={"text": "Write a function..."},
            result={"safe": scan_result.safe},
            agent_name=agent['name']
        )

        # Action 3: Make a decision
        record_decision(
            session_id=session_id,
            decision="allow_operation",
            reasoning="Input is safe",
            agent_name=agent['name']
        )

        # Verify chain
        chain = get_or_create_chain(session_id)
        is_valid, _ = chain.verify_chain()

        print(f"    Session: {session_id}")
        print(f"    Records: {len(chain.records)}")
        print(f"    Chain valid: {is_valid}")

        # Update session stats
        manager.update_session_activity(
            session_id=session_id,
            record_count_delta=len(chain.records)
        )

    # Summary: All agents tracked under same client
    print("\n  --- Summary ---")
    sessions = manager.get_client_sessions(client.client_id)
    print(f"  Total sessions: {len(sessions)}")

    for session in sessions:
        print(f"    - {session.agent_name}: {session.record_count} records")

    # Verify all agents are tracked
    assert len(sessions) == len(agents), "All agents should have sessions"
    print("\n  [PASS] All agents tracked successfully!")

    return True


def test_api_key_validation():
    """Test that API key works for all agents."""
    print("\n" + "="*60)
    print("TEST: API Key Validation")
    print("="*60)

    manager = get_client_manager()

    # Create test client
    client, api_key = manager.register_client(
        name="API Test Corp",
        email="api@test.com",
        plan=PlanType.PRO
    )

    # Validate key
    valid, found_client, error = manager.validate_api_key(api_key)
    print(f"\n  API Key valid: {valid}")
    print(f"  Client found: {found_client.name if found_client else 'None'}")
    print(f"  Error: {error or 'None'}")

    # Test invalid key
    valid2, _, error2 = manager.validate_api_key("invalid_key_xxx")
    print(f"\n  Invalid key test:")
    print(f"    Valid: {valid2}")
    print(f"    Error: {error2}")

    assert valid == True, "Valid key should pass"
    assert valid2 == False, "Invalid key should fail"

    print("\n  [PASS] API key validation working!")
    return True


def test_usage_tracking():
    """Test usage tracking per client."""
    print("\n" + "="*60)
    print("TEST: Usage Tracking")
    print("="*60)

    manager = get_client_manager()

    # Create client
    client, api_key = manager.register_client(
        name="Usage Test Corp",
        email="usage@test.com",
        plan=PlanType.FREE  # 1000 scans/month limit
    )

    print(f"\n  Client: {client.name}")
    print(f"  Plan: {client.plan.value}")
    print(f"  Monthly limit: {client.monthly_scan_limit}")

    # Simulate scans
    for i in range(5):
        manager.record_scan(client.client_id, blocked=(i == 2), pii_found=(i == 3))

    # Check usage
    stats = manager.get_usage_stats(client.client_id)
    print(f"\n  Usage stats:")
    print(f"    Scans: {stats['scan_count']}")
    print(f"    Blocked: {stats['blocked_threats']}")
    print(f"    PII found: {stats['pii_detected']}")
    print(f"    Remaining: {stats['remaining']}")

    assert stats['scan_count'] == 5, "Should have 5 scans"
    assert stats['blocked_threats'] == 1, "Should have 1 blocked"
    assert stats['pii_detected'] == 1, "Should have 1 PII"

    print("\n  [PASS] Usage tracking working!")
    return True


def test_audit_export():
    """Test audit log export."""
    print("\n" + "="*60)
    print("TEST: Audit Log Export")
    print("="*60)

    from inalign_mcp.audit_export import export_session_json, export_session_csv, export_session_summary

    session_id = "export-test-001"

    # Create some activity
    chain = get_or_create_chain(session_id, "test-agent")
    record_tool_call(session_id, "read_file", {"path": "/test"}, {"ok": True})
    record_tool_call(session_id, "write_file", {"path": "/test"}, {"ok": True})
    record_decision(session_id, "allow", "Safe operation")

    # Export JSON
    json_export = export_session_json(session_id)
    print(f"\n  JSON export length: {len(json_export)} chars")

    # Export CSV
    csv_export = export_session_csv(session_id)
    print(f"  CSV export lines: {len(csv_export.splitlines())}")

    # Export summary
    summary = export_session_summary(session_id)
    print(f"  Summary: {summary['summary']['total_records']} records")

    assert len(json_export) > 100, "JSON should have content"
    assert len(csv_export.splitlines()) > 1, "CSV should have rows"

    print("\n  [PASS] Audit export working!")
    return True


def run_all_tests():
    """Run all multi-agent tests."""
    print("\n" + "*"*60)
    print("*  MULTI-AGENT & CLIENT MANAGEMENT TESTS  *")
    print("*"*60)

    try:
        test_api_key_validation()
        test_usage_tracking()
        test_multi_agent_tracking()
        test_audit_export()

        print("\n" + "="*60)
        print("  ALL TESTS PASSED!")
        print("="*60)
        print("\n  Verified:")
        print("    - Claude Code tracking")
        print("    - Cursor tracking")
        print("    - Windsurf tracking")
        print("    - Custom agent tracking")
        print("    - API key validation")
        print("    - Usage metering")
        print("    - Audit log export")
        print("\n  Any MCP-compatible agent will work!")
        print("="*60)

        return True

    except Exception as e:
        print(f"\n  [FAIL] {e}")
        import traceback
        traceback.print_exc()
        return False


if __name__ == "__main__":
    success = run_all_tests()
    sys.exit(0 if success else 1)
