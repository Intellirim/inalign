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
    LogActionResponse,
    ReportResponse,
    ScanInputResponse,
    ScanOutputResponse,
    SessionResponse,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

MOCK_SCAN_INPUT_RESPONSE = {
    "scan_id": "scan-001",
    "is_safe": False,
    "risk_level": "high",
    "risk_score": 0.85,
    "threats": [
        {
            "type": "prompt_injection",
            "severity": "high",
            "confidence": 0.92,
            "description": "Detected prompt injection attempt.",
        }
    ],
    "pii_detected": [
        {
            "type": "ssn",
            "value": "***-**-6789",
            "start": 30,
            "end": 41,
            "confidence": 0.99,
        }
    ],
    "recommendations": ["Block this input", "Log for review"],
    "processing_time_ms": 45,
}

MOCK_SCAN_OUTPUT_RESPONSE = {
    "scan_id": "scan-002",
    "is_safe": True,
    "risk_level": "low",
    "risk_score": 0.1,
    "pii_detected": [],
    "data_leakage_risk": False,
    "sanitized_text": None,
    "issues": [],
    "processing_time_ms": 30,
}

MOCK_LOG_ACTION_RESPONSE = {
    "action_id": "act-001",
    "status": "recorded",
    "risk_level": "low",
    "anomalies": [],
    "is_anomalous": False,
    "recommendations": [],
}

MOCK_SESSION_RESPONSE = {
    "session_id": "sess-001",
    "agent_id": "agent-001",
    "status": "active",
    "risk_level": "medium",
    "risk_score": 0.45,
    "start_time": "2025-01-15T10:00:00Z",
    "end_time": None,
    "total_actions": 5,
    "total_scans": 3,
    "threats_detected": 1,
    "anomalies_detected": 0,
    "metadata": {},
}

MOCK_REPORT_RESPONSE = {
    "report_id": "rpt-001",
    "session_id": "sess-001",
    "report_type": "security_analysis",
    "language": "ko",
    "title": "Security Analysis Report",
    "summary": "Session showed moderate risk with one threat detected.",
    "risk_level": "medium",
    "risk_score": 0.45,
    "total_events": 8,
    "threats_found": 1,
    "anomalies_found": 0,
    "recommendations": [
        {
            "priority": "high",
            "category": "input_validation",
            "title": "Enhance input filtering",
            "description": "Add stricter input validation rules.",
            "affected_actions": ["act-001"],
        }
    ],
    "generated_at": "2025-01-15T12:00:00Z",
    "content": "# Report\n\nFull report content...",
}

MOCK_ALERTS_RESPONSE = {
    "items": [
        {
            "alert_id": "alrt-001",
            "severity": "high",
            "title": "Prompt injection detected",
        }
    ],
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

    def test_headers(self) -> None:
        client = BaseClient(api_key="my-secret-key")
        headers = client._headers
        assert headers["Authorization"] == "Bearer my-secret-key"
        assert headers["Content-Type"] == "application/json"
        assert headers["Accept"] == "application/json"
        assert "agentshield-python" in headers["User-Agent"]

    def test_build_url(self) -> None:
        client = BaseClient(api_key="key")
        assert client._build_url("/v1/scan/input") == "https://api.agentshield.io/v1/scan/input"
        assert client._build_url("v1/scan/input") == "https://api.agentshield.io/v1/scan/input"

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
            url="https://api.agentshield.io/v1/scan/input",
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
        assert result.scan_id == "scan-001"
        assert result.is_safe is False
        assert result.risk_level == "high"
        assert len(result.threats) == 1
        assert result.threats[0].type == "prompt_injection"
        assert len(result.pii_detected) == 1
        assert result.pii_detected[0].type == "ssn"
        client.close()

    def test_scan_input_with_metadata(self, httpx_mock) -> None:
        httpx_mock.add_response(
            url="https://api.agentshield.io/v1/scan/input",
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

        # Verify the request body included metadata
        request = httpx_mock.get_request()
        body = json.loads(request.content)
        assert body["metadata"] == {"source": "web"}
        client.close()

    def test_scan_output(self, httpx_mock) -> None:
        httpx_mock.add_response(
            url="https://api.agentshield.io/v1/scan/output",
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
        assert result.is_safe is True
        assert result.risk_level == "low"

        request = httpx_mock.get_request()
        body = json.loads(request.content)
        assert body["auto_sanitize"] is True
        client.close()

    def test_log_action(self, httpx_mock) -> None:
        httpx_mock.add_response(
            url="https://api.agentshield.io/v1/actions/log",
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
        assert result.status == "recorded"
        assert result.is_anomalous is False
        client.close()

    def test_get_session(self, httpx_mock) -> None:
        httpx_mock.add_response(
            url="https://api.agentshield.io/v1/sessions/sess-001",
            method="GET",
            json=MOCK_SESSION_RESPONSE,
        )

        client = AgentShield(api_key="test-key")
        result = client.get_session("sess-001")

        assert isinstance(result, SessionResponse)
        assert result.session_id == "sess-001"
        assert result.status == "active"
        assert result.total_actions == 5
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

        assert result["total"] == 1
        assert len(result["items"]) == 1
        client.close()

    def test_generate_report(self, httpx_mock) -> None:
        httpx_mock.add_response(
            url="https://api.agentshield.io/v1/reports/generate",
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
        assert result.language == "ko"
        assert len(result.recommendations) == 1
        assert result.recommendations[0].priority == "high"
        client.close()

    def test_get_alerts(self, httpx_mock) -> None:
        httpx_mock.add_response(
            method="GET",
            json=MOCK_ALERTS_RESPONSE,
        )

        client = AgentShield(api_key="test-key")
        result = client.get_alerts(severity="high")

        assert result["total"] == 1
        assert len(result["items"]) == 1
        client.close()

    def test_acknowledge_alert(self, httpx_mock) -> None:
        httpx_mock.add_response(
            url="https://api.agentshield.io/v1/alerts/alrt-001/acknowledge",
            method="PATCH",
            json={"acknowledged": True, "acknowledged_at": "2025-01-15T12:00:00Z"},
        )

        client = AgentShield(api_key="test-key")
        result = client.acknowledge_alert("alrt-001")

        assert result["acknowledged"] is True
        client.close()

    def test_context_manager(self, httpx_mock) -> None:
        httpx_mock.add_response(
            url="https://api.agentshield.io/v1/scan/input",
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
            url="https://api.agentshield.io/v1/scan/input",
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
            url="https://api.agentshield.io/v1/scan/input",
            method="POST",
            status_code=429,
            json={"detail": "Rate limit exceeded"},
        )

        client = AgentShield(api_key="test-key")
        with pytest.raises(RateLimitError):
            client.scan_input(text="test", agent_id="a", session_id="s")
        client.close()


# ---------------------------------------------------------------------------
# Async Client Tests
# ---------------------------------------------------------------------------


class TestAsyncClient:
    @pytest.mark.asyncio
    async def test_scan_input(self, httpx_mock) -> None:
        httpx_mock.add_response(
            url="https://api.agentshield.io/v1/scan/input",
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
        assert result.scan_id == "scan-001"
        assert result.is_safe is False

    @pytest.mark.asyncio
    async def test_scan_output(self, httpx_mock) -> None:
        httpx_mock.add_response(
            url="https://api.agentshield.io/v1/scan/output",
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
        assert result.is_safe is True

    @pytest.mark.asyncio
    async def test_log_action(self, httpx_mock) -> None:
        httpx_mock.add_response(
            url="https://api.agentshield.io/v1/actions/log",
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
            url="https://api.agentshield.io/v1/reports/generate",
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
            url="https://api.agentshield.io/v1/scan/input",
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
