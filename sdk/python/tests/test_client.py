"""Tests for the AgentShield Python SDK client."""

import json

import httpx
import pytest

from agentshield import AgentShield, AsyncAgentShield
from agentshield.client import BaseClient
from agentshield.exceptions import (
    AgentShieldError,
    AuthenticationError,
    NotFoundError,
    RateLimitError,
    ServerError,
    ValidationError,
)
from agentshield.models import (
    AlertListResponse,
    AlertResponse,
    LogActionResponse,
    ReportResponse,
    ScanInputResponse,
    ScanOutputResponse,
    SessionListResponse,
    SessionResponse,
)


# ---------------------------------------------------------------------------
# Fixtures — aligned with backend Pydantic schemas
# ---------------------------------------------------------------------------

MOCK_SCAN_INPUT_RESPONSE = {
    "request_id": "req-001",
    "safe": False,
    "risk_level": "high",
    "risk_score": 0.85,
    "latency_ms": 45.2,
    "threats": [
        {
            "type": "prompt_injection",
            "subtype": "direct",
            "pattern_id": "PI-001",
            "matched_text": "ignore previous instructions",
            "position": [10, 38],
            "confidence": 0.92,
            "severity": "high",
            "description": "Detected prompt injection attempt.",
        }
    ],
    "recommendation": "block",
    "action_taken": "blocked",
}

MOCK_SCAN_OUTPUT_RESPONSE = {
    "request_id": "req-002",
    "safe": True,
    "risk_level": "low",
    "risk_score": 0.1,
    "latency_ms": 30.0,
    "pii_detected": [],
    "original_text": None,
    "sanitized_text": None,
    "recommendation": "allow",
    "action_taken": "logged",
}

MOCK_LOG_ACTION_RESPONSE = {
    "request_id": "req-003",
    "logged": True,
    "action_id": "act-001",
    "node_id": "neo4j-node-abc",
    "anomaly_detected": False,
    "anomalies": [],
    "session_risk_score": 0.12,
    "alerts_triggered": [],
}

MOCK_SESSION_RESPONSE = {
    "session_id": "sess-001",
    "agent_id": "agent-001",
    "status": "active",
    "risk_level": "medium",
    "risk_score": 0.45,
    "started_at": "2025-01-15T10:00:00Z",
    "last_activity_at": "2025-01-15T10:30:00Z",
    "stats": {
        "total_actions": 5,
        "input_scans": 3,
        "output_scans": 2,
        "threats_detected": 1,
        "pii_detected": 0,
        "anomalies_detected": 0,
    },
    "timeline": [],
    "graph_summary": {"nodes": 8, "edges": 12, "clusters": 2},
}

MOCK_REPORT_RESPONSE = {
    "request_id": "req-004",
    "report_id": "rpt-001",
    "session_id": "sess-001",
    "status": "completed",
    "generated_at": "2025-01-15T12:00:00Z",
    "generation_time_ms": 1234.5,
    "summary": {
        "risk_level": "medium",
        "risk_score": 0.45,
        "primary_concerns": ["Prompt injection detected"],
    },
    "analysis": {
        "attack_vectors": [],
        "behavior_graph_analysis": None,
        "timeline_analysis": "",
    },
    "recommendations": [
        {
            "priority": "high",
            "action": "Enhance input filtering",
            "reason": "Prompt injection was detected but not fully blocked.",
        }
    ],
    "raw_graph_data": None,
}

MOCK_ALERT_RESPONSE = {
    "id": "alrt-001",
    "session_id": "sess-001",
    "agent_id": "agent-001",
    "alert_type": "threat_detected",
    "severity": "high",
    "title": "Prompt injection detected",
    "description": "A prompt injection attempt was detected.",
    "details": {"pattern_id": "PI-001"},
    "is_acknowledged": False,
    "acknowledged_by": None,
    "acknowledged_at": None,
    "created_at": "2025-01-15T10:05:00Z",
}

MOCK_ALERTS_LIST_RESPONSE = {
    "items": [MOCK_ALERT_RESPONSE],
    "total": 1,
    "page": 1,
    "size": 20,
}


def _mock_response(data: dict, status_code: int = 200) -> httpx.Response:
    """Create a mock httpx.Response."""
    return httpx.Response(
        status_code=status_code,
        json=data,
        request=httpx.Request("GET", "https://api.agentshield.io/test"),
    )


# ---------------------------------------------------------------------------
# BaseClient Tests
# ---------------------------------------------------------------------------


class TestBaseClient:
    def test_init_requires_api_key(self) -> None:
        with pytest.raises(ValueError, match="api_key is required"):
            BaseClient(api_key="")

    def test_init_defaults(self) -> None:
        client = BaseClient(api_key="test-key")
        assert client.api_key == "test-key"
        assert client.base_url == "https://api.agentshield.io"
        assert client.timeout == 30

    def test_init_custom_values(self) -> None:
        client = BaseClient(api_key="key", base_url="https://custom.api.io/", timeout=60)
        assert client.base_url == "https://custom.api.io"
        assert client.timeout == 60

    def test_headers_jwt(self) -> None:
        """JWT tokens use Authorization: Bearer header."""
        client = BaseClient(api_key="eyJhbGciOiJIUzI1NiJ9.test")
        headers = client._headers
        assert headers["Authorization"] == "Bearer eyJhbGciOiJIUzI1NiJ9.test"
        assert "X-API-Key" not in headers
        assert headers["Content-Type"] == "application/json"

    def test_headers_api_key(self) -> None:
        """API keys (ask_ prefix) use X-API-Key header."""
        client = BaseClient(api_key="ask_abc123def456")
        headers = client._headers
        assert headers["X-API-Key"] == "ask_abc123def456"
        assert "Authorization" not in headers

    def test_build_url(self) -> None:
        client = BaseClient(api_key="key")
        assert client._build_url("/api/v1/scan/input") == "https://api.agentshield.io/api/v1/scan/input"
        assert client._build_url("api/v1/scan/input") == "https://api.agentshield.io/api/v1/scan/input"

    def test_handle_response_success(self) -> None:
        response = _mock_response({"status": "ok"}, 200)
        result = BaseClient._handle_response(response)
        assert result == {"status": "ok"}

    def test_handle_response_401(self) -> None:
        response = _mock_response({"detail": "Invalid API key"}, 401)
        with pytest.raises(AuthenticationError) as exc_info:
            BaseClient._handle_response(response)
        assert exc_info.value.status_code == 401
        assert "Invalid API key" in exc_info.value.message

    def test_handle_response_404(self) -> None:
        response = _mock_response({"detail": "Not found"}, 404)
        with pytest.raises(NotFoundError):
            BaseClient._handle_response(response)

    def test_handle_response_422(self) -> None:
        response = _mock_response({"detail": "Validation error"}, 422)
        with pytest.raises(ValidationError):
            BaseClient._handle_response(response)

    def test_handle_response_429(self) -> None:
        response = _mock_response({"detail": "Too many requests"}, 429)
        with pytest.raises(RateLimitError):
            BaseClient._handle_response(response)

    def test_handle_response_500(self) -> None:
        response = _mock_response({"detail": "Internal server error"}, 500)
        with pytest.raises(ServerError):
            BaseClient._handle_response(response)

    def test_handle_response_unknown_4xx(self) -> None:
        response = _mock_response({"detail": "Conflict"}, 409)
        with pytest.raises(AgentShieldError) as exc_info:
            BaseClient._handle_response(response)
        assert exc_info.value.status_code == 409


# ---------------------------------------------------------------------------
# Synchronous Client Tests
# ---------------------------------------------------------------------------


class TestSyncClient:
    def test_scan_input(self, httpx_mock) -> None:
        httpx_mock.add_response(
            url="https://api.agentshield.io/api/v1/scan/input",
            method="POST",
            json=MOCK_SCAN_INPUT_RESPONSE,
        )

        client = AgentShield(api_key="test-key")
        result = client.scan_input(
            text="My SSN is 123-45-6789",
            agent_id="agent-1",
            session_id="sess-1",
        )

        assert isinstance(result, ScanInputResponse)
        assert result.request_id == "req-001"
        assert result.safe is False
        assert result.risk_level == "high"
        assert len(result.threats) == 1
        assert result.threats[0].type == "prompt_injection"
        assert result.recommendation == "block"
        client.close()

    def test_scan_input_with_metadata(self, httpx_mock) -> None:
        httpx_mock.add_response(
            url="https://api.agentshield.io/api/v1/scan/input",
            method="POST",
            json=MOCK_SCAN_INPUT_RESPONSE,
        )

        client = AgentShield(api_key="test-key")
        result = client.scan_input(
            text="Hello",
            agent_id="agent-1",
            session_id="sess-1",
            metadata={"source": "web"},
        )

        assert isinstance(result, ScanInputResponse)

        request = httpx_mock.get_request()
        body = json.loads(request.content)
        assert body["metadata"] == {"source": "web"}
        client.close()

    def test_scan_output(self, httpx_mock) -> None:
        httpx_mock.add_response(
            url="https://api.agentshield.io/api/v1/scan/output",
            method="POST",
            json=MOCK_SCAN_OUTPUT_RESPONSE,
        )

        client = AgentShield(api_key="test-key")
        result = client.scan_output(
            text="Here is the response",
            agent_id="agent-1",
            session_id="sess-1",
            auto_sanitize=True,
        )

        assert isinstance(result, ScanOutputResponse)
        assert result.safe is True
        assert result.risk_level == "low"

        request = httpx_mock.get_request()
        body = json.loads(request.content)
        assert body["auto_sanitize"] is True
        client.close()

    def test_log_action(self, httpx_mock) -> None:
        httpx_mock.add_response(
            url="https://api.agentshield.io/api/v1/logs/action",
            method="POST",
            json=MOCK_LOG_ACTION_RESPONSE,
        )

        client = AgentShield(api_key="test-key")
        result = client.log_action(
            agent_id="agent-1",
            session_id="sess-1",
            action_type="tool_call",
            name="search",
            target="google.com",
            parameters={"query": "test"},
            result_summary="Found 10 results",
            duration_ms=150,
        )

        assert isinstance(result, LogActionResponse)
        assert result.action_id == "act-001"
        assert result.logged is True
        assert result.anomaly_detected is False

        # Verify nested action body
        request = httpx_mock.get_request()
        body = json.loads(request.content)
        assert body["action"]["type"] == "tool_call"
        assert body["action"]["name"] == "search"
        assert body["action"]["target"] == "google.com"
        client.close()

    def test_get_session(self, httpx_mock) -> None:
        httpx_mock.add_response(
            url="https://api.agentshield.io/api/v1/sessions/sess-001",
            method="GET",
            json=MOCK_SESSION_RESPONSE,
        )

        client = AgentShield(api_key="test-key")
        result = client.get_session("sess-001")

        assert isinstance(result, SessionResponse)
        assert result.session_id == "sess-001"
        assert result.status == "active"
        assert result.stats.total_actions == 5
        assert result.graph_summary.nodes == 8
        client.close()

    def test_list_sessions(self, httpx_mock) -> None:
        mock_data = {
            "items": [MOCK_SESSION_RESPONSE],
            "total": 1,
            "page": 1,
            "size": 20,
        }
        httpx_mock.add_response(
            method="GET",
            json=mock_data,
        )

        client = AgentShield(api_key="test-key")
        result = client.list_sessions(status="active", risk_level="medium")

        assert isinstance(result, SessionListResponse)
        assert result.total == 1
        assert len(result.items) == 1
        assert result.items[0].session_id == "sess-001"
        client.close()

    def test_generate_report(self, httpx_mock) -> None:
        httpx_mock.add_response(
            url="https://api.agentshield.io/api/v1/reports/sessions/sess-001/report",
            method="POST",
            json=MOCK_REPORT_RESPONSE,
        )

        client = AgentShield(api_key="test-key")
        result = client.generate_report(
            session_id="sess-001",
            report_type="security_analysis",
            language="ko",
        )

        assert isinstance(result, ReportResponse)
        assert result.report_id == "rpt-001"
        assert result.status == "completed"
        assert len(result.recommendations) == 1
        assert result.recommendations[0].priority == "high"

        request = httpx_mock.get_request()
        body = json.loads(request.content)
        assert body["report_type"] == "security_analysis"
        assert body["include_recommendations"] is True
        assert body["language"] == "ko"
        client.close()

    def test_get_alerts(self, httpx_mock) -> None:
        httpx_mock.add_response(
            method="GET",
            json=MOCK_ALERTS_LIST_RESPONSE,
        )

        client = AgentShield(api_key="test-key")
        result = client.get_alerts(severity="high")

        assert isinstance(result, AlertListResponse)
        assert result.total == 1
        assert len(result.items) == 1
        assert result.items[0].alert_type == "threat_detected"
        client.close()

    def test_acknowledge_alert(self, httpx_mock) -> None:
        ack_response = {**MOCK_ALERT_RESPONSE, "is_acknowledged": True, "acknowledged_by": "admin"}
        httpx_mock.add_response(
            url="https://api.agentshield.io/api/v1/alerts/alrt-001/acknowledge",
            method="POST",
            json=ack_response,
        )

        client = AgentShield(api_key="test-key")
        result = client.acknowledge_alert("alrt-001", acknowledged_by="admin")

        assert isinstance(result, AlertResponse)
        assert result.is_acknowledged is True
        assert result.acknowledged_by == "admin"

        request = httpx_mock.get_request()
        body = json.loads(request.content)
        assert body["acknowledged_by"] == "admin"
        client.close()

    def test_context_manager(self, httpx_mock) -> None:
        httpx_mock.add_response(
            url="https://api.agentshield.io/api/v1/scan/input",
            method="POST",
            json=MOCK_SCAN_INPUT_RESPONSE,
        )

        with AgentShield(api_key="test-key") as client:
            result = client.scan_input(
                text="test",
                agent_id="agent-1",
                session_id="sess-1",
            )
            assert isinstance(result, ScanInputResponse)

    def test_auth_error_handling(self, httpx_mock) -> None:
        httpx_mock.add_response(
            url="https://api.agentshield.io/api/v1/scan/input",
            method="POST",
            status_code=401,
            json={"detail": "Invalid API key"},
        )

        client = AgentShield(api_key="bad-key")
        with pytest.raises(AuthenticationError):
            client.scan_input(text="test", agent_id="a", session_id="s")
        client.close()

    def test_rate_limit_error_handling(self, httpx_mock) -> None:
        httpx_mock.add_response(
            url="https://api.agentshield.io/api/v1/scan/input",
            method="POST",
            status_code=429,
            json={"detail": "Rate limit exceeded"},
        )

        client = AgentShield(api_key="test-key")
        with pytest.raises(RateLimitError):
            client.scan_input(text="test", agent_id="a", session_id="s")
        client.close()

    def test_api_key_header(self, httpx_mock) -> None:
        """API keys with ask_ prefix use X-API-Key header."""
        httpx_mock.add_response(
            url="https://api.agentshield.io/api/v1/scan/input",
            method="POST",
            json=MOCK_SCAN_INPUT_RESPONSE,
        )

        client = AgentShield(api_key="ask_test123")
        client.scan_input(text="test", agent_id="a", session_id="s")

        request = httpx_mock.get_request()
        assert request.headers.get("X-API-Key") == "ask_test123"
        assert "Authorization" not in request.headers
        client.close()


# ---------------------------------------------------------------------------
# Async Client Tests
# ---------------------------------------------------------------------------


class TestAsyncClient:
    @pytest.mark.asyncio
    async def test_scan_input(self, httpx_mock) -> None:
        httpx_mock.add_response(
            url="https://api.agentshield.io/api/v1/scan/input",
            method="POST",
            json=MOCK_SCAN_INPUT_RESPONSE,
        )

        async with AsyncAgentShield(api_key="test-key") as client:
            result = await client.scan_input(
                text="My SSN is 123-45-6789",
                agent_id="agent-1",
                session_id="sess-1",
            )

        assert isinstance(result, ScanInputResponse)
        assert result.request_id == "req-001"
        assert result.safe is False

    @pytest.mark.asyncio
    async def test_scan_output(self, httpx_mock) -> None:
        httpx_mock.add_response(
            url="https://api.agentshield.io/api/v1/scan/output",
            method="POST",
            json=MOCK_SCAN_OUTPUT_RESPONSE,
        )

        async with AsyncAgentShield(api_key="test-key") as client:
            result = await client.scan_output(
                text="Response text",
                agent_id="agent-1",
                session_id="sess-1",
            )

        assert isinstance(result, ScanOutputResponse)
        assert result.safe is True

    @pytest.mark.asyncio
    async def test_log_action(self, httpx_mock) -> None:
        httpx_mock.add_response(
            url="https://api.agentshield.io/api/v1/logs/action",
            method="POST",
            json=MOCK_LOG_ACTION_RESPONSE,
        )

        async with AsyncAgentShield(api_key="test-key") as client:
            result = await client.log_action(
                agent_id="agent-1",
                session_id="sess-1",
                action_type="tool_call",
                name="test_action",
            )

        assert isinstance(result, LogActionResponse)
        assert result.action_id == "act-001"

    @pytest.mark.asyncio
    async def test_generate_report(self, httpx_mock) -> None:
        httpx_mock.add_response(
            url="https://api.agentshield.io/api/v1/reports/sessions/sess-001/report",
            method="POST",
            json=MOCK_REPORT_RESPONSE,
        )

        async with AsyncAgentShield(api_key="test-key") as client:
            result = await client.generate_report(session_id="sess-001")

        assert isinstance(result, ReportResponse)
        assert result.report_id == "rpt-001"

    @pytest.mark.asyncio
    async def test_auth_error(self, httpx_mock) -> None:
        httpx_mock.add_response(
            url="https://api.agentshield.io/api/v1/scan/input",
            method="POST",
            status_code=401,
            json={"detail": "Invalid API key"},
        )

        async with AsyncAgentShield(api_key="bad-key") as client:
            with pytest.raises(AuthenticationError):
                await client.scan_input(text="test", agent_id="a", session_id="s")


# ---------------------------------------------------------------------------
# Exception Tests
# ---------------------------------------------------------------------------


class TestExceptions:
    def test_from_response_401(self) -> None:
        resp = _mock_response({"detail": "Unauthorized"}, 401)
        exc = AgentShieldError.from_response(resp)
        assert isinstance(exc, AuthenticationError)
        assert exc.status_code == 401

    def test_from_response_403(self) -> None:
        resp = _mock_response({"detail": "Forbidden"}, 403)
        exc = AgentShieldError.from_response(resp)
        assert isinstance(exc, AuthenticationError)

    def test_from_response_404(self) -> None:
        resp = _mock_response({"detail": "Not found"}, 404)
        exc = AgentShieldError.from_response(resp)
        assert isinstance(exc, NotFoundError)

    def test_from_response_422(self) -> None:
        resp = _mock_response({"detail": "Validation failed"}, 422)
        exc = AgentShieldError.from_response(resp)
        assert isinstance(exc, ValidationError)

    def test_from_response_429(self) -> None:
        resp = _mock_response({"detail": "Rate limited"}, 429)
        exc = AgentShieldError.from_response(resp)
        assert isinstance(exc, RateLimitError)

    def test_from_response_500(self) -> None:
        resp = _mock_response({"detail": "Server error"}, 500)
        exc = AgentShieldError.from_response(resp)
        assert isinstance(exc, ServerError)

    def test_from_response_unknown(self) -> None:
        resp = _mock_response({"detail": "Teapot"}, 418)
        exc = AgentShieldError.from_response(resp)
        assert type(exc) is AgentShieldError
        assert exc.status_code == 418

    def test_repr(self) -> None:
        exc = AuthenticationError(message="Bad key", status_code=401)
        assert "AuthenticationError" in repr(exc)
        assert "Bad key" in repr(exc)
