"""Base client for AgentShield SDK."""

from __future__ import annotations

from typing import Any

from agentshield.exceptions import AgentShieldError


class BaseClient:
    """Base client providing shared configuration and utilities.

    Args:
        api_key: Your AgentShield API key (``ask_`` prefixed) or a JWT token.
        base_url: Base URL for the AgentShield API.
        timeout: Request timeout in seconds.
    """

    def __init__(
        self,
        api_key: str,
        base_url: str = "https://api.agentshield.io",
        timeout: int = 30,
    ) -> None:
        if not api_key:
            raise ValueError("api_key is required and cannot be empty.")
        self.api_key = api_key
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout

    @property
    def _headers(self) -> dict[str, str]:
        """Return default headers with the appropriate auth header.

        API keys (prefixed with ``ask_``) are sent via ``X-API-Key``.
        JWT tokens are sent via ``Authorization: Bearer``.
        """
        headers: dict[str, str] = {
            "Content-Type": "application/json",
            "Accept": "application/json",
            "User-Agent": "agentshield-python/0.1.0",
        }
        if self.api_key.startswith("ask_"):
            headers["X-API-Key"] = self.api_key
        else:
            headers["Authorization"] = f"Bearer {self.api_key}"
        return headers

    def _build_url(self, path: str) -> str:
        """Build a full URL from a relative API path.

        Args:
            path: The relative API path (e.g., "/api/v1/scan/input").

        Returns:
            The full URL string.
        """
        path = path.lstrip("/")
        return f"{self.base_url}/{path}"

    @staticmethod
    def _handle_response(response: Any) -> dict:
        """Handle an HTTP response, raising typed exceptions on errors.

        Args:
            response: An httpx.Response object.

        Returns:
            The parsed JSON response body as a dict.

        Raises:
            AgentShieldError: Or a subclass for specific HTTP error codes.
        """
        if response.status_code >= 400:
            raise AgentShieldError.from_response(response)
        return response.json()
