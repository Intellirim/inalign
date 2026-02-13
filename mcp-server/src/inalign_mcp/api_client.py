"""
InALign API Client — HTTP proxy for Neo4j operations.

Instead of connecting to Neo4j directly (which exposes credentials),
the MCP server sends data to the InALign API on EC2, which handles
Neo4j operations server-side.

Usage:
    from .api_client import ApiClient

    client = ApiClient(api_url="http://15.165.20.75:8080", api_key="ial_xxx")
    client.store_record(record_data)
    risk = client.analyze_risk(session_id="abc123")
"""

import json
import logging
from typing import Any, Optional

logger = logging.getLogger("inalign-api-client")

# Use httpx (already a dependency via mcp) for HTTP calls
try:
    import httpx
    HTTPX_AVAILABLE = True
except ImportError:
    HTTPX_AVAILABLE = False


class ApiClient:
    """HTTP client for InALign API proxy."""

    def __init__(self, api_url: str, api_key: str):
        self.api_url = api_url.rstrip("/")
        self.api_key = api_key
        self._headers = {"X-API-Key": api_key, "Content-Type": "application/json"}

        if not HTTPX_AVAILABLE:
            logger.error("httpx not available — pip install httpx")

    def _post(self, path: str, data: dict, timeout: float = 10.0) -> Optional[dict]:
        """Make a POST request to the API."""
        if not HTTPX_AVAILABLE:
            return None
        url = f"{self.api_url}{path}"
        try:
            with httpx.Client(timeout=timeout) as client:
                resp = client.post(url, json=data, headers=self._headers)
                if resp.status_code == 200:
                    return resp.json()
                else:
                    logger.warning(f"API {path} returned {resp.status_code}: {resp.text[:200]}")
                    return {"error": resp.text, "status_code": resp.status_code}
        except Exception as e:
            logger.warning(f"API {path} failed: {e}")
            return {"error": str(e)}

    def store_record(
        self,
        record_id: str,
        timestamp: str,
        activity_type: str,
        activity_name: str,
        record_hash: str,
        previous_hash: str = "",
        sequence_number: int = 0,
        session_id: str = "",
        client_id: str = "",
        agent_id: str = "",
        agent_name: str = "",
        agent_type: str = "",
        activity_attributes: str = "{}",
    ) -> bool:
        """Store a provenance record via the API."""
        result = self._post("/api/v1/provenance/store", {
            "record_id": record_id,
            "timestamp": timestamp,
            "activity_type": activity_type,
            "activity_name": activity_name,
            "record_hash": record_hash,
            "previous_hash": previous_hash,
            "sequence_number": sequence_number,
            "session_id": session_id,
            "client_id": client_id,
            "agent_id": agent_id,
            "agent_name": agent_name,
            "agent_type": agent_type,
            "activity_attributes": activity_attributes,
        })
        if result and result.get("status") == "ok":
            return True
        logger.warning(f"store_record failed: {result}")
        return False

    def analyze_risk(self, session_id: str = "") -> dict[str, Any]:
        """Run risk analysis via the API."""
        result = self._post("/api/v1/risk/analyze", {"session_id": session_id})
        return result or {"error": "API call failed"}

    def get_agent_risk(self, agent_id: str) -> dict[str, Any]:
        """Get agent risk profile via the API."""
        result = self._post("/api/v1/risk/agent", {"agent_id": agent_id})
        return result or {"error": "API call failed"}

    def get_user_risk(self, user_id: str) -> dict[str, Any]:
        """Get user risk profile via the API."""
        result = self._post("/api/v1/risk/user", {"user_id": user_id})
        return result or {"error": "API call failed"}

    def get_all_agents_summary(self, limit: int = 20) -> dict[str, Any]:
        """Get all agents risk summary via the API."""
        result = self._post("/api/v1/risk/agents", {"limit": limit})
        return result or {"error": "API call failed"}


# Singleton instance
_api_client: Optional[ApiClient] = None


def init_api_client(api_url: str, api_key: str) -> ApiClient:
    """Initialize the global API client."""
    global _api_client
    _api_client = ApiClient(api_url, api_key)
    logger.info(f"[API] Initialized client → {api_url}")
    return _api_client


def get_api_client() -> Optional[ApiClient]:
    """Get the global API client instance."""
    return _api_client
