"""
Async Neo4j client for the InALign graph layer.

Wraps the official ``neo4j`` async driver with typed helper methods for
creating / reading / updating graph nodes and relationships used by the
security analysis pipeline.
"""

from __future__ import annotations

import logging
from typing import Any

from neo4j import AsyncDriver, AsyncGraphDatabase, AsyncManagedTransaction

from app.graph import queries

logger = logging.getLogger("inalign.graph.neo4j_client")


def _convert_neo4j_value(value: Any) -> Any:
    """Convert Neo4j temporal/spatial types to JSON-serializable Python types."""
    # neo4j.time.DateTime, neo4j.time.Date, neo4j.time.Time, etc.
    try:
        from neo4j.time import DateTime as Neo4jDateTime, Date as Neo4jDate, Time as Neo4jTime, Duration as Neo4jDuration
        if isinstance(value, Neo4jDateTime):
            return value.iso_format()
        if isinstance(value, Neo4jDate):
            return value.iso_format()
        if isinstance(value, Neo4jTime):
            return value.iso_format()
        if isinstance(value, Neo4jDuration):
            return str(value)
    except ImportError:
        pass
    # Fallback: if it has iso_format method, use it
    if hasattr(value, "iso_format"):
        return value.iso_format()
    return value


def _node_to_dict(node: Any) -> dict[str, Any]:
    """Convert a Neo4j ``Node`` object into a plain dictionary."""
    if node is None:
        return {}
    if isinstance(node, dict):
        return {k: _convert_neo4j_value(v) for k, v in node.items()}
    try:
        raw = dict(node)
        return {k: _convert_neo4j_value(v) for k, v in raw.items()}
    except (TypeError, ValueError):
        return {}


class Neo4jClient:
    """
    High-level async interface to the InALign Neo4j database.

    Usage::

        client = Neo4jClient(uri="bolt://localhost:7687", username="neo4j", password="secret")
        await client.connect()
        try:
            session_id = await client.create_session({...})
        finally:
            await client.disconnect()
    """

    def __init__(
        self,
        uri: str,
        username: str,
        password: str,
        database: str = "neo4j",
    ) -> None:
        self._uri = uri
        self._username = username
        self._password = password
        self._database = database
        self._driver: AsyncDriver | None = None

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    async def connect(self) -> None:
        """Create the async driver and verify connectivity."""
        logger.info("Connecting to Neo4j at %s (database=%s)", self._uri, self._database)
        self._driver = AsyncGraphDatabase.driver(
            self._uri,
            auth=(self._username, self._password),
        )
        await self._driver.verify_connectivity()
        logger.info("Neo4j connection established successfully.")

    async def disconnect(self) -> None:
        """Gracefully close the driver."""
        if self._driver is not None:
            await self._driver.close()
            self._driver = None
            logger.info("Neo4j driver closed.")

    async def health_check(self) -> bool:
        """Return ``True`` if the Neo4j instance is reachable."""
        if self._driver is None:
            logger.warning("health_check called but driver is not initialised.")
            return False
        try:
            await self._driver.verify_connectivity()
            return True
        except Exception:
            logger.exception("Neo4j health check failed.")
            return False

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @property
    def driver(self) -> AsyncDriver:
        if self._driver is None:
            raise RuntimeError(
                "Neo4jClient is not connected. Call `await client.connect()` first."
            )
        return self._driver

    async def _execute_write(
        self,
        query: str,
        parameters: dict[str, Any],
    ) -> list[dict[str, Any]]:
        """Run a write transaction and return the result records as dicts."""
        async with self.driver.session(database=self._database) as session:

            async def _work(tx: AsyncManagedTransaction) -> list[dict[str, Any]]:
                result = await tx.run(query, parameters)
                records = await result.data()
                return records  # list[dict]

            return await session.execute_write(_work)

    async def _execute_read(
        self,
        query: str,
        parameters: dict[str, Any] | None = None,
    ) -> list[dict[str, Any]]:
        """Run a read transaction and return the result records as dicts."""
        async with self.driver.session(database=self._database) as session:

            async def _work(tx: AsyncManagedTransaction) -> list[dict[str, Any]]:
                result = await tx.run(query, parameters or {})
                records = await result.data()
                return records

            return await session.execute_read(_work)

    # ------------------------------------------------------------------
    # Node creation
    # ------------------------------------------------------------------

    async def create_agent(self, agent_data: dict[str, Any]) -> str:
        """
        Create or merge an Agent node.

        Parameters
        ----------
        agent_data:
            Must contain ``agent_id``; may include ``name``, ``description``,
            ``owner``, ``metadata``.

        Returns
        -------
        str
            The ``agent_id`` of the created / merged node.
        """
        params: dict[str, Any] = {
            "agent_id": agent_data["agent_id"],
            "name": agent_data.get("name", ""),
            "description": agent_data.get("description", ""),
            "owner": agent_data.get("owner", ""),
            "metadata": agent_data.get("metadata", "{}"),
        }
        logger.debug("Creating agent node: agent_id=%s", params["agent_id"])
        records = await self._execute_write(queries.CREATE_AGENT, params)
        agent_id: str = records[0]["agent_id"]
        logger.info("Agent node created/merged: %s", agent_id)
        return agent_id

    async def create_session(self, session_data: dict[str, Any]) -> str:
        """
        Create or merge a Session node and link it to its owning Agent.

        Parameters
        ----------
        session_data:
            Must contain ``session_id`` and ``agent_id``; may include
            ``user_id``, ``status``, ``risk_score``, ``started_at``, ``metadata``.

        Returns
        -------
        str
            The ``session_id`` of the created / merged node.
        """
        params: dict[str, Any] = {
            "session_id": session_data["session_id"],
            "agent_id": session_data["agent_id"],
            "user_id": session_data.get("user_id", ""),
            "status": session_data.get("status", "active"),
            "risk_score": session_data.get("risk_score", 0.0),
            "started_at": session_data.get("started_at", "1970-01-01T00:00:00Z"),
            "metadata": session_data.get("metadata", "{}"),
        }
        logger.debug("Creating session node: session_id=%s", params["session_id"])
        records = await self._execute_write(queries.CREATE_SESSION, params)
        session_id: str = records[0]["session_id"]
        logger.info("Session node created/merged: %s", session_id)
        return session_id

    async def create_action(
        self,
        action_data: dict[str, Any],
        session_id: str,
        previous_action_id: str | None = None,
    ) -> str:
        """
        Create an Action node, link it to the Session via ``CONTAINS``, and
        optionally create a ``FOLLOWED_BY`` edge from a previous action.

        Parameters
        ----------
        action_data:
            Must contain ``action_id``; may include ``action_type``, ``input``,
            ``output``, ``risk_score``, ``latency_ms``, ``timestamp``, ``metadata``.
        session_id:
            The session this action belongs to.
        previous_action_id:
            If provided, a ``FOLLOWED_BY`` edge is created from this action
            to the new one.

        Returns
        -------
        str
            The ``action_id`` of the newly created Action node.
        """
        params: dict[str, Any] = {
            "action_id": action_data["action_id"],
            "session_id": session_id,
            "action_type": action_data.get("action_type", "other"),
            "input": action_data.get("input", ""),
            "output": action_data.get("output", ""),
            "risk_score": action_data.get("risk_score", 0.0),
            "latency_ms": action_data.get("latency_ms", 0.0),
            "timestamp": action_data.get("timestamp", "1970-01-01T00:00:00Z"),
            "metadata": action_data.get("metadata", "{}"),
        }
        logger.debug(
            "Creating action node: action_id=%s session_id=%s",
            params["action_id"],
            session_id,
        )
        records = await self._execute_write(queries.CREATE_ACTION, params)
        action_id: str = records[0]["action_id"]
        logger.info("Action node created: %s (session=%s)", action_id, session_id)

        # Create FOLLOWED_BY edge if a previous action is given.
        if previous_action_id is not None:
            seq_params: dict[str, Any] = {
                "from_action_id": previous_action_id,
                "to_action_id": action_id,
                "delay_ms": action_data.get("delay_ms", 0.0),
            }
            await self._execute_write(queries.LINK_ACTION_SEQUENCE, seq_params)
            logger.debug(
                "FOLLOWED_BY edge created: %s -> %s",
                previous_action_id,
                action_id,
            )

        return action_id

    async def create_threat(
        self,
        threat_data: dict[str, Any],
        action_id: str,
    ) -> str:
        """
        Create a Threat node and link it to the triggering Action via ``TRIGGERED``.

        Parameters
        ----------
        threat_data:
            Must contain ``threat_id``; may include ``threat_type``, ``severity``,
            ``confidence``, ``description``, ``detector``, ``metadata``.
        action_id:
            The action that triggered this threat.

        Returns
        -------
        str
            The ``threat_id`` of the newly created Threat node.
        """
        params: dict[str, Any] = {
            "threat_id": threat_data["threat_id"],
            "threat_type": threat_data.get("threat_type", "unknown"),
            "severity": threat_data.get("severity", "medium"),
            "confidence": threat_data.get("confidence", 0.0),
            "description": threat_data.get("description", ""),
            "detector": threat_data.get("detector", ""),
            "metadata": threat_data.get("metadata", "{}"),
            "action_id": action_id,
        }
        logger.debug(
            "Creating threat node: threat_id=%s action_id=%s",
            params["threat_id"],
            action_id,
        )
        records = await self._execute_write(queries.CREATE_THREAT, params)
        threat_id: str = records[0]["threat_id"]
        logger.info("Threat node created: %s (action=%s)", threat_id, action_id)
        return threat_id

    # ------------------------------------------------------------------
    # Read operations
    # ------------------------------------------------------------------

    async def get_session_graph(self, session_id: str) -> dict[str, Any]:
        """
        Retrieve the full subgraph for a session including the session node,
        all actions, threats, and ``FOLLOWED_BY`` sequence edges.

        Returns
        -------
        dict
            Keys: ``session``, ``actions``, ``threats``, ``edges``.
        """
        logger.debug("Fetching session graph: session_id=%s", session_id)
        records = await self._execute_read(
            queries.GET_SESSION_GRAPH,
            {"session_id": session_id},
        )

        if not records:
            logger.warning("No graph data found for session %s", session_id)
            return {"session": {}, "actions": [], "threats": [], "edges": []}

        record = records[0]

        session_node = _node_to_dict(record.get("session"))
        actions_raw: list[Any] = record.get("actions", [])
        threats_raw: list[Any] = record.get("threats", [])
        sequences_raw: list[Any] = record.get("sequences", [])

        actions = [_node_to_dict(a) for a in actions_raw if a is not None]
        threats = [_node_to_dict(t) for t in threats_raw if t is not None]

        # Filter out null-valued edge placeholders produced by OPTIONAL MATCH.
        edges = [
            e
            for e in sequences_raw
            if isinstance(e, dict)
            and e.get("from_action") is not None
            and e.get("to_action") is not None
        ]

        logger.info(
            "Session graph loaded: session=%s actions=%d threats=%d edges=%d",
            session_id,
            len(actions),
            len(threats),
            len(edges),
        )
        return {
            "session": session_node,
            "actions": actions,
            "threats": threats,
            "edges": edges,
        }

    async def get_session_actions(self, session_id: str) -> list[dict[str, Any]]:
        """Return actions for a session ordered by timestamp ascending."""
        logger.debug("Fetching session actions: session_id=%s", session_id)
        records = await self._execute_read(
            queries.GET_SESSION_ACTIONS,
            {"session_id": session_id},
        )
        actions: list[dict[str, Any]] = []
        for record in records:
            action_node = record.get("act")
            if action_node is not None:
                actions.append(_node_to_dict(action_node))
        logger.debug("Loaded %d actions for session %s", len(actions), session_id)
        return actions

    async def get_suspicious_sessions(
        self,
        min_risk: float = 0.7,
        limit: int = 10,
    ) -> list[dict[str, Any]]:
        """Return sessions with ``risk_score >= min_risk``, ordered by risk descending."""
        logger.debug(
            "Querying suspicious sessions: min_risk=%.2f limit=%d",
            min_risk,
            limit,
        )
        records = await self._execute_read(
            queries.GET_SUSPICIOUS_SESSIONS,
            {"min_risk_score": min_risk, "limit": limit},
        )
        sessions: list[dict[str, Any]] = []
        for record in records:
            session_node = record.get("s")
            if session_node is not None:
                sessions.append(_node_to_dict(session_node))
        logger.info("Found %d suspicious sessions (min_risk=%.2f)", len(sessions), min_risk)
        return sessions

    async def find_similar_sessions(
        self,
        session_id: str,
        min_similarity: float = 0.7,
        limit: int = 5,
    ) -> list[dict[str, Any]]:
        """
        Find sessions with a Jaccard-similar action-type distribution.

        Returns a list of dicts with keys ``session`` (dict) and ``similarity`` (float).
        """
        logger.debug(
            "Finding similar sessions: session_id=%s min_similarity=%.2f",
            session_id,
            min_similarity,
        )
        records = await self._execute_read(
            queries.FIND_SIMILAR_SESSIONS,
            {
                "session_id": session_id,
                "min_similarity": min_similarity,
                "limit": limit,
            },
        )
        results: list[dict[str, Any]] = []
        for record in records:
            session_node = record.get("session")
            results.append(
                {
                    "session": _node_to_dict(session_node),
                    "similarity": record.get("similarity", 0.0),
                }
            )
        logger.info(
            "Found %d similar sessions for %s (min=%.2f)",
            len(results),
            session_id,
            min_similarity,
        )
        return results

    # ------------------------------------------------------------------
    # Update operations
    # ------------------------------------------------------------------

    async def update_session_risk(
        self,
        session_id: str,
        risk_score: float,
    ) -> None:
        """Update the risk score on a Session node."""
        logger.debug(
            "Updating session risk: session_id=%s risk_score=%.4f",
            session_id,
            risk_score,
        )
        await self._execute_write(
            queries.UPDATE_SESSION_RISK,
            {"session_id": session_id, "risk_score": risk_score},
        )
        logger.info(
            "Session risk updated: session_id=%s risk_score=%.4f",
            session_id,
            risk_score,
        )

    # ------------------------------------------------------------------
    # Agent queries
    # ------------------------------------------------------------------

    async def get_agent_sessions(
        self,
        agent_id: str,
        limit: int = 20,
    ) -> list[dict[str, Any]]:
        """Return sessions owned by an agent, newest first."""
        logger.debug(
            "Fetching agent sessions: agent_id=%s limit=%d",
            agent_id,
            limit,
        )
        records = await self._execute_read(
            queries.GET_AGENT_SESSIONS,
            {"agent_id": agent_id, "limit": limit},
        )
        sessions: list[dict[str, Any]] = []
        for record in records:
            session_node = record.get("s")
            if session_node is not None:
                sessions.append(_node_to_dict(session_node))
        logger.debug("Loaded %d sessions for agent %s", len(sessions), agent_id)
        return sessions
