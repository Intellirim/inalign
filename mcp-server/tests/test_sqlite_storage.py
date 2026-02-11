"""Tests for SQLite local storage backend."""

import os
import sqlite3
import tempfile
import pytest

from inalign_mcp.sqlite_storage import (
    _init_schema,
    store_session,
    store_record,
    load_chain,
    list_sessions,
    get_session_count,
    get_record_count,
)
from inalign_mcp.provenance import (
    ProvenanceChain,
    ProvenanceRecord,
    Agent,
    ActivityType,
)


@pytest.fixture
def test_db():
    """Create a temporary SQLite database for testing."""
    import inalign_mcp.sqlite_storage as mod

    # Save original
    orig_conn = mod._connection
    orig_path = mod.DB_PATH

    # Create temp db
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    conn = sqlite3.connect(path, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    _init_schema(conn)

    mod._connection = conn
    mod.DB_PATH = path

    yield conn

    # Cleanup
    conn.close()
    os.unlink(path)
    mod._connection = orig_conn
    mod.DB_PATH = orig_path


def test_store_and_load_chain(test_db):
    """Test storing records and loading them back preserves chain integrity."""
    agent = Agent(id="agent:test:001", type="ai_agent", name="test-bot")
    chain = ProvenanceChain("session-test-001", agent, "client-001")

    store_session("session-test-001", agent, "client-001")

    r1 = chain.record_activity(
        activity_type=ActivityType.USER_INPUT,
        activity_name="user_command",
        generated=[("hello world", "user_command")],
    )
    store_record(r1)

    r2 = chain.record_activity(
        activity_type=ActivityType.TOOL_CALL,
        activity_name="read_file",
        used=[("/tmp/test.py", "tool_input")],
    )
    store_record(r2)

    # Load back
    loaded = load_chain("session-test-001")
    assert loaded is not None
    assert len(loaded.records) == 2
    assert loaded.records[0].record_hash == r1.record_hash
    assert loaded.records[1].record_hash == r2.record_hash

    # Verify chain integrity preserved
    is_valid, error = loaded.verify_chain()
    assert is_valid
    assert error is None


def test_chain_links_preserved(test_db):
    """Test that hash chain links are correctly preserved through SQLite."""
    agent = Agent(id="agent:test:002", type="ai_agent", name="test-bot")
    chain = ProvenanceChain("session-test-002", agent)

    store_session("session-test-002", agent)

    records = []
    for i in range(5):
        r = chain.record_activity(
            activity_type=ActivityType.DECISION,
            activity_name=f"decision_{i}",
            attributes={"step": i},
        )
        store_record(r)
        records.append(r)

    loaded = load_chain("session-test-002")
    assert len(loaded.records) == 5

    # Check chain links
    assert loaded.records[0].previous_hash == ""
    for i in range(1, 5):
        assert loaded.records[i].previous_hash == loaded.records[i - 1].record_hash

    # Full chain verification
    is_valid, error = loaded.verify_chain()
    assert is_valid


def test_session_listing(test_db):
    """Test listing sessions."""
    agent = Agent(id="agent:test:003", type="ai_agent", name="bot-a")
    store_session("session-a", agent, "client-a")
    store_session("session-b", agent, "client-a")
    store_session("session-c", agent, "client-b")

    all_sessions = list_sessions()
    assert len(all_sessions) == 3

    client_a_sessions = list_sessions(client_id="client-a")
    assert len(client_a_sessions) == 2

    client_b_sessions = list_sessions(client_id="client-b")
    assert len(client_b_sessions) == 1


def test_counts(test_db):
    """Test session and record counts."""
    assert get_session_count() == 0
    assert get_record_count() == 0

    agent = Agent(id="agent:test:004", type="ai_agent", name="counter")
    chain = ProvenanceChain("session-count", agent)
    store_session("session-count", agent)

    assert get_session_count() == 1

    r = chain.record_activity(
        activity_type=ActivityType.TOOL_CALL,
        activity_name="test",
    )
    store_record(r)

    assert get_record_count() == 1


def test_load_nonexistent_session(test_db):
    """Test loading a session that doesn't exist returns None."""
    loaded = load_chain("does-not-exist")
    assert loaded is None
