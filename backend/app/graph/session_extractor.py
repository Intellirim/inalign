"""
Session graph extraction and metric computation.

``SessionExtractor`` fetches a complete session subgraph from Neo4j and
reshapes the raw data into structured dictionaries suitable for downstream
analysis (GraphRAG pipeline, reporting, dashboards).
"""

from __future__ import annotations

import logging
from typing import Any

from app.graph.neo4j_client import Neo4jClient
from app.graph import queries

logger = logging.getLogger("agentshield.graph.session_extractor")


class SessionExtractor:
    """
    Extract, order, and summarise session graph data from Neo4j.

    Parameters
    ----------
    neo4j_client:
        An initialised and connected :class:`Neo4jClient` instance.
    """

    def __init__(self, neo4j_client: Neo4jClient) -> None:
        self._client = neo4j_client

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def extract(self, session_id: str) -> dict[str, Any]:
        """
        Retrieve the full session subgraph and return a structured dict.

        Returns
        -------
        dict
            Keys:
            - ``session`` -- session node properties.
            - ``actions`` -- list of action dicts ordered by timestamp.
            - ``threats`` -- list of threat dicts linked to those actions.
            - ``edges``   -- list of ``FOLLOWED_BY`` sequence edges.
            - ``action_sequence`` -- human-readable string of the action flow.
        """
        logger.info("Extracting session graph: session_id=%s", session_id)

        graph_data: dict[str, Any] = await self._client.get_session_graph(session_id)

        session_info: dict[str, Any] = graph_data.get("session", {})
        actions: list[dict[str, Any]] = graph_data.get("actions", [])
        threats: list[dict[str, Any]] = graph_data.get("threats", [])
        edges: list[dict[str, Any]] = graph_data.get("edges", [])

        # Order actions by timestamp (ascending).
        actions = self._order_actions(actions)

        # Build the human-readable sequence string.
        action_sequence: str = self.generate_action_sequence(actions)

        result: dict[str, Any] = {
            "session": session_info,
            "actions": actions,
            "threats": threats,
            "edges": edges,
            "action_sequence": action_sequence,
        }
        logger.info(
            "Session extracted: session=%s actions=%d threats=%d edges=%d",
            session_id,
            len(actions),
            len(threats),
            len(edges),
        )
        return result

    async def compute_session_metrics(self, session_id: str) -> dict[str, Any]:
        """
        Compute aggregate metrics for a session.

        Returns
        -------
        dict
            Keys:
            - ``total_actions`` (int)
            - ``threat_count`` (int)
            - ``risk_timeline`` (list[dict]) -- per-action risk scores in order.
            - ``avg_risk_score`` (float)
            - ``max_risk_score`` (float)
            - ``action_type_distribution`` (dict[str, int])
            - ``threat_severity_distribution`` (dict[str, int])
        """
        logger.debug("Computing metrics for session %s", session_id)

        # Fetch actions.
        actions: list[dict[str, Any]] = await self._client.get_session_actions(session_id)

        # Fetch threats.
        threats: list[dict[str, Any]] = await self._fetch_session_threats(session_id)

        total_actions = len(actions)
        threat_count = len(threats)

        # Risk timeline -- ordered list of (timestamp, risk_score) pairs.
        risk_timeline: list[dict[str, Any]] = []
        risk_scores: list[float] = []
        action_type_dist: dict[str, int] = {}

        for action in actions:
            score = float(action.get("risk_score", 0.0))
            risk_scores.append(score)
            risk_timeline.append(
                {
                    "action_id": action.get("action_id", ""),
                    "timestamp": str(action.get("timestamp", "")),
                    "risk_score": score,
                    "action_type": action.get("action_type", "other"),
                }
            )
            atype = str(action.get("action_type", "other"))
            action_type_dist[atype] = action_type_dist.get(atype, 0) + 1

        avg_risk: float = sum(risk_scores) / max(len(risk_scores), 1)
        max_risk: float = max(risk_scores) if risk_scores else 0.0

        # Threat severity distribution.
        severity_dist: dict[str, int] = {}
        for threat in threats:
            severity = str(threat.get("severity", "medium"))
            severity_dist[severity] = severity_dist.get(severity, 0) + 1

        metrics: dict[str, Any] = {
            "total_actions": total_actions,
            "threat_count": threat_count,
            "risk_timeline": risk_timeline,
            "avg_risk_score": round(avg_risk, 4),
            "max_risk_score": round(max_risk, 4),
            "action_type_distribution": action_type_dist,
            "threat_severity_distribution": severity_dist,
        }
        logger.info(
            "Metrics computed for session %s: actions=%d threats=%d avg_risk=%.4f",
            session_id,
            total_actions,
            threat_count,
            avg_risk,
        )
        return metrics

    # ------------------------------------------------------------------
    # Static / class utilities
    # ------------------------------------------------------------------

    @staticmethod
    def generate_action_sequence(actions: list[dict[str, Any]]) -> str:
        """
        Build a human-readable string showing the ordered action types.

        Example output::

            tool_call -> llm_call -> database_query -> http_request

        Parameters
        ----------
        actions:
            A list of action dicts, assumed to be in chronological order.

        Returns
        -------
        str
            Arrow-delimited sequence of action types.
        """
        if not actions:
            return ""

        types: list[str] = [
            str(action.get("action_type", "unknown")) for action in actions
        ]
        return " -> ".join(types)

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _order_actions(
        actions: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        """Sort actions by their ``timestamp`` field (ascending)."""

        def _sort_key(action: dict[str, Any]) -> str:
            ts = action.get("timestamp")
            if ts is None:
                return ""
            return str(ts)

        return sorted(actions, key=_sort_key)

    async def _fetch_session_threats(
        self,
        session_id: str,
    ) -> list[dict[str, Any]]:
        """Fetch all threat nodes linked to actions in the given session."""
        records = await self._client._execute_read(
            queries.GET_SESSION_THREATS,
            {"session_id": session_id},
        )
        threats: list[dict[str, Any]] = []
        for record in records:
            threat_node = record.get("t")
            if threat_node is not None:
                threat_dict = dict(threat_node) if not isinstance(threat_node, dict) else threat_node
                threat_dict["source_action_id"] = record.get("source_action_id", "")
                threats.append(threat_dict)
        return threats
