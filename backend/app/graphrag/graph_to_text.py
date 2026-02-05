"""
Graph-to-text converter for the GraphRAG pipeline.

Transforms structured Neo4j session subgraph data (dicts of sessions,
actions, threats, edges) into a human-readable textual representation
suitable for feeding into an LLM prompt.
"""

from __future__ import annotations

import logging
from typing import Any

logger = logging.getLogger("inalign.graphrag.graph_to_text")


class GraphToTextConverter:
    """
    Convert a session graph dictionary into a single text block.

    The output is designed to be injected into LLM prompts so the model
    can reason about the security posture of the session.
    """

    # ------------------------------------------------------------------
    # Public
    # ------------------------------------------------------------------

    def convert(self, session_graph_data: dict[str, Any]) -> str:
        """
        Produce the full textual representation of a session graph.

        Parameters
        ----------
        session_graph_data:
            Dictionary with keys ``session``, ``actions``, ``threats``,
            ``edges``, and optionally ``action_sequence``.

        Returns
        -------
        str
            Multi-section text block ready for prompt injection.
        """
        session: dict[str, Any] = session_graph_data.get("session", {})
        actions: list[dict[str, Any]] = session_graph_data.get("actions", [])
        threats: list[dict[str, Any]] = session_graph_data.get("threats", [])
        edges: list[dict[str, Any]] = session_graph_data.get("edges", [])

        sections: list[str] = [
            self._format_session_info(session),
            self._format_action_timeline(actions),
            self._summarize_threats(threats),
            self._generate_flow_summary(edges),
        ]

        # Append the pre-computed action sequence if present.
        action_sequence: str = session_graph_data.get("action_sequence", "")
        if action_sequence:
            sections.append(
                f"[Action Sequence]\n{action_sequence}"
            )

        text = "\n\n".join(section for section in sections if section)
        logger.debug(
            "Converted session graph to text (%d characters).",
            len(text),
        )
        return text

    # ------------------------------------------------------------------
    # Section formatters
    # ------------------------------------------------------------------

    @staticmethod
    def _format_session_info(session: dict[str, Any]) -> str:
        """
        Format the session node into a readable header section.

        Includes session ID, agent, user, status, risk score, and timestamps.
        """
        if not session:
            return "[Session Info]\nNo session data available."

        lines: list[str] = ["[Session Info]"]
        lines.append(f"  Session ID : {session.get('session_id', 'N/A')}")
        lines.append(f"  Agent ID   : {session.get('agent_id', 'N/A')}")
        lines.append(f"  User ID    : {session.get('user_id', 'N/A')}")
        lines.append(f"  Status     : {session.get('status', 'N/A')}")
        lines.append(f"  Risk Score : {session.get('risk_score', 0.0)}")
        lines.append(f"  Started At : {session.get('started_at', 'N/A')}")
        lines.append(f"  Updated At : {session.get('updated_at', 'N/A')}")

        metadata: str = session.get("metadata", "{}")
        if metadata and metadata != "{}":
            lines.append(f"  Metadata   : {metadata}")

        return "\n".join(lines)

    @staticmethod
    def _format_action_timeline(actions: list[dict[str, Any]]) -> str:
        """
        Format actions as a numbered timeline with key attributes.

        Each entry shows the index, timestamp, action type, target/input
        summary, risk score, and any associated threat information.
        """
        if not actions:
            return "[Action Timeline]\nNo actions recorded."

        lines: list[str] = [
            "[Action Timeline]",
            f"  Total Actions: {len(actions)}",
            "",
        ]

        for idx, action in enumerate(actions, start=1):
            action_id: str = action.get("action_id", "N/A")
            action_type: str = action.get("action_type", "unknown")
            timestamp: str = str(action.get("timestamp", "N/A"))
            risk_score: float = float(action.get("risk_score", 0.0))
            latency_ms: float = float(action.get("latency_ms", 0.0))

            # Truncate long input/output for readability.
            raw_input: str = str(action.get("input", ""))
            raw_output: str = str(action.get("output", ""))
            input_summary: str = (
                raw_input[:200] + "..." if len(raw_input) > 200 else raw_input
            )
            output_summary: str = (
                raw_output[:200] + "..." if len(raw_output) > 200 else raw_output
            )

            risk_indicator: str = ""
            if risk_score >= 0.8:
                risk_indicator = " [CRITICAL]"
            elif risk_score >= 0.6:
                risk_indicator = " [HIGH]"
            elif risk_score >= 0.4:
                risk_indicator = " [MEDIUM]"
            elif risk_score >= 0.2:
                risk_indicator = " [LOW]"

            lines.append(
                f"  #{idx}. [{timestamp}] {action_type}{risk_indicator}"
            )
            lines.append(f"      Action ID  : {action_id}")
            lines.append(f"      Risk Score : {risk_score:.2f}")
            lines.append(f"      Latency    : {latency_ms:.1f} ms")
            if input_summary:
                lines.append(f"      Input      : {input_summary}")
            if output_summary:
                lines.append(f"      Output     : {output_summary}")
            lines.append("")

        return "\n".join(lines)

    @staticmethod
    def _generate_flow_summary(edges: list[dict[str, Any]]) -> str:
        """
        Describe the action flow based on ``FOLLOWED_BY`` edges.

        Produces a readable list of transitions with optional delay information.
        """
        if not edges:
            return "[Action Flow]\nNo sequential flow edges recorded."

        lines: list[str] = [
            "[Action Flow]",
            f"  Total Transitions: {len(edges)}",
            "",
        ]

        for edge in edges:
            from_action: str = edge.get("from_action", "?")
            to_action: str = edge.get("to_action", "?")
            delay_ms: Any = edge.get("delay_ms")

            delay_str: str = ""
            if delay_ms is not None:
                delay_str = f" (delay: {delay_ms} ms)"

            lines.append(f"  {from_action} --> {to_action}{delay_str}")

        return "\n".join(lines)

    @staticmethod
    def _summarize_threats(threats: list[dict[str, Any]]) -> str:
        """
        Summarise all detected threats in a structured text section.

        Groups by severity and lists type, confidence, detector, and description.
        """
        if not threats:
            return "[Threats Detected]\nNo threats detected in this session."

        # Group by severity for organised presentation.
        severity_order: list[str] = ["critical", "high", "medium", "low"]
        grouped: dict[str, list[dict[str, Any]]] = {s: [] for s in severity_order}
        ungrouped: list[dict[str, Any]] = []

        for threat in threats:
            severity: str = str(threat.get("severity", "medium")).lower()
            if severity in grouped:
                grouped[severity].append(threat)
            else:
                ungrouped.append(threat)

        lines: list[str] = [
            "[Threats Detected]",
            f"  Total Threats: {len(threats)}",
            "",
        ]

        for severity in severity_order:
            threat_list = grouped[severity]
            if not threat_list:
                continue
            lines.append(f"  --- {severity.upper()} ---")
            for threat in threat_list:
                threat_id: str = threat.get("threat_id", "N/A")
                threat_type: str = threat.get("threat_type", "unknown")
                confidence: float = float(threat.get("confidence", 0.0))
                detector: str = threat.get("detector", "N/A")
                description: str = threat.get("description", "")
                source_action: str = threat.get("source_action_id", "N/A")

                lines.append(f"    Threat ID   : {threat_id}")
                lines.append(f"    Type        : {threat_type}")
                lines.append(f"    Confidence  : {confidence:.2f}")
                lines.append(f"    Detector    : {detector}")
                lines.append(f"    Source Action: {source_action}")
                if description:
                    desc_short = (
                        description[:300] + "..."
                        if len(description) > 300
                        else description
                    )
                    lines.append(f"    Description : {desc_short}")
                lines.append("")

        if ungrouped:
            lines.append("  --- OTHER ---")
            for threat in ungrouped:
                lines.append(f"    Threat ID: {threat.get('threat_id', 'N/A')}")
                lines.append(f"    Type     : {threat.get('threat_type', 'unknown')}")
                lines.append("")

        return "\n".join(lines)
