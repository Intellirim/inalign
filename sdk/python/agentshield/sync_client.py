"""Synchronous client for AgentShield SDK."""

from __future__ import annotations

from typing import Any, Optional

import httpx

from agentshield.client import BaseClient
from agentshield.models import (
    LogActionResponse,
    ReportResponse,
    ScanInputResponse,
    ScanOutputResponse,
    SessionResponse,
)


class AgentShield(BaseClient):
    """Synchronous AgentShield client.

    Usage::

        from agentshield import AgentShield

        client = AgentShield(api_key="your-api-key")
        result = client.scan_input(
            text="Hello, my SSN is 123-45-6789",
            agent_id="agent-1",
            session_id="sess-abc",
        )
        print(result.risk_level)
    """

    def __init__(
        self,
        api_key: str,
        base_url: str = "https://api.agentshield.io",
        timeout: int = 30,
    ) -> None:
        super().__init__(api_key, base_url, timeout)
        self._client = httpx.Client(
            headers=self._headers,
            timeout=self.timeout,
        )

    def __enter__(self) -> "AgentShield":
        return self

    def __exit__(self, *args: Any) -> None:
        self.close()

    def close(self) -> None:
        """Close the underlying HTTP client."""
        self._client.close()

    def _request(self, method: str, path: str, **kwargs: Any) -> dict:
        """Make a synchronous HTTP request.

        Args:
            method: HTTP method (GET, POST, PUT, PATCH, DELETE).
            path: Relative API path.
            **kwargs: Additional arguments passed to httpx.Client.request.

        Returns:
            Parsed JSON response.
        """
        url = self._build_url(path)
        response = self._client.request(method, url, **kwargs)
        return self._handle_response(response)

    def scan_input(
        self,
        text: str,
        agent_id: str,
        session_id: str,
        metadata: Optional[dict] = None,
    ) -> ScanInputResponse:
        """Scan user input for threats and PII before processing.

        Args:
            text: The user input text to scan.
            agent_id: Identifier of the AI agent.
            session_id: Current session identifier.
            metadata: Optional additional metadata.

        Returns:
            ScanInputResponse with threat analysis results.
        """
        payload: dict[str, Any] = {
            "text": text,
            "agent_id": agent_id,
            "session_id": session_id,
        }
        if metadata is not None:
            payload["metadata"] = metadata
        data = self._request("POST", "/v1/scan/input", json=payload)
        return ScanInputResponse(**data)

    def scan_output(
        self,
        text: str,
        agent_id: str,
        session_id: str,
        auto_sanitize: bool = False,
    ) -> ScanOutputResponse:
        """Scan agent output for sensitive data leakage.

        Args:
            text: The agent output text to scan.
            agent_id: Identifier of the AI agent.
            session_id: Current session identifier.
            auto_sanitize: Whether to automatically redact sensitive data.

        Returns:
            ScanOutputResponse with analysis and optional sanitized text.
        """
        payload = {
            "text": text,
            "agent_id": agent_id,
            "session_id": session_id,
            "auto_sanitize": auto_sanitize,
        }
        data = self._request("POST", "/v1/scan/output", json=payload)
        return ScanOutputResponse(**data)

    def log_action(
        self,
        agent_id: str,
        session_id: str,
        action_type: str,
        name: str,
        target: str = "",
        parameters: Optional[dict] = None,
        result_summary: str = "",
        duration_ms: int = 0,
        context: Optional[dict] = None,
    ) -> LogActionResponse:
        """Log an agent action for audit and anomaly detection.

        Args:
            agent_id: Identifier of the AI agent.
            session_id: Current session identifier.
            action_type: Type of action (e.g., "tool_call", "api_request").
            name: Name of the action performed.
            target: Target resource of the action.
            parameters: Action parameters.
            result_summary: Summary of the action result.
            duration_ms: Duration of the action in milliseconds.
            context: Additional context information.

        Returns:
            LogActionResponse with anomaly analysis.
        """
        payload: dict[str, Any] = {
            "agent_id": agent_id,
            "session_id": session_id,
            "action_type": action_type,
            "name": name,
            "target": target,
            "parameters": parameters or {},
            "result_summary": result_summary,
            "duration_ms": duration_ms,
        }
        if context is not None:
            payload["context"] = context
        data = self._request("POST", "/v1/actions/log", json=payload)
        return LogActionResponse(**data)

    def get_session(self, session_id: str) -> SessionResponse:
        """Retrieve detailed information about a session.

        Args:
            session_id: The session identifier.

        Returns:
            SessionResponse with session details and security summary.
        """
        data = self._request("GET", f"/v1/sessions/{session_id}")
        return SessionResponse(**data)

    def list_sessions(
        self,
        status: Optional[str] = None,
        risk_level: Optional[str] = None,
        page: int = 1,
        size: int = 20,
    ) -> dict:
        """List sessions with optional filtering.

        Args:
            status: Filter by session status (active, completed, flagged).
            risk_level: Filter by risk level (low, medium, high, critical).
            page: Page number for pagination.
            size: Number of items per page.

        Returns:
            Dict containing items list and pagination metadata.
        """
        params: dict[str, Any] = {"page": page, "size": size}
        if status is not None:
            params["status"] = status
        if risk_level is not None:
            params["risk_level"] = risk_level
        return self._request("GET", "/v1/sessions", params=params)

    def generate_report(
        self,
        session_id: str,
        report_type: str = "security_analysis",
        language: str = "ko",
    ) -> ReportResponse:
        """Generate a security analysis report for a session.

        Args:
            session_id: The session identifier.
            report_type: Type of report to generate.
            language: Language for the report (default: "ko" for Korean).

        Returns:
            ReportResponse with the generated report.
        """
        payload = {
            "session_id": session_id,
            "report_type": report_type,
            "language": language,
        }
        data = self._request("POST", "/v1/reports/generate", json=payload)
        return ReportResponse(**data)

    def get_alerts(
        self,
        severity: Optional[str] = None,
        acknowledged: Optional[bool] = None,
        page: int = 1,
        size: int = 20,
    ) -> dict:
        """Retrieve security alerts with optional filtering.

        Args:
            severity: Filter by severity (low, medium, high, critical).
            acknowledged: Filter by acknowledgement status.
            page: Page number for pagination.
            size: Number of items per page.

        Returns:
            Dict containing alerts list and pagination metadata.
        """
        params: dict[str, Any] = {"page": page, "size": size}
        if severity is not None:
            params["severity"] = severity
        if acknowledged is not None:
            params["acknowledged"] = str(acknowledged).lower()
        return self._request("GET", "/v1/alerts", params=params)

    def acknowledge_alert(self, alert_id: str) -> dict:
        """Acknowledge a security alert.

        Args:
            alert_id: The alert identifier.

        Returns:
            Dict with acknowledgement confirmation.
        """
        return self._request("PATCH", f"/v1/alerts/{alert_id}/acknowledge")
