"""
MCP Tool Chain Analyzer.

Analyzes sequences of tool calls for:
- Parasitic toolchain attacks
- Unusual tool call patterns
- Privilege escalation chains
- Data flow anomalies

Integrates with Neo4j for pattern learning and detection.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any, Optional
from datetime import datetime

from app.detectors.mcp.scanner import MCPThreat, ThreatCategory, Severity

logger = logging.getLogger(__name__)


@dataclass
class ToolCall:
    """Represents a single tool call in a chain."""
    tool_name: str
    arguments: dict[str, Any]
    timestamp: datetime = field(default_factory=datetime.utcnow)
    result: Optional[str] = None
    duration_ms: float = 0.0


@dataclass
class ToolChainAnalysis:
    """Result of analyzing a tool call chain."""
    session_id: str
    is_suspicious: bool
    risk_score: float
    threats: list[MCPThreat] = field(default_factory=list)
    tool_calls: list[ToolCall] = field(default_factory=list)
    patterns_detected: list[str] = field(default_factory=list)


class ToolAnalyzer:
    """
    Analyzes MCP tool call chains for security threats.

    Tracks sequences of tool calls within a session and detects
    suspicious patterns that may indicate an attack.
    """

    # Suspicious tool sequences (attack chains)
    SUSPICIOUS_SEQUENCES = [
        # Read credentials then make network request
        (["read", "file"], ["curl", "wget", "fetch", "http"]),
        # Read env then execute command
        (["env", "environment", "config"], ["exec", "bash", "shell", "run"]),
        # List files then exfiltrate
        (["list", "find", "glob", "search"], ["curl", "wget", "post", "send"]),
        # Git operations that could leak data
        (["git"], ["push", "remote", "origin"]),
        # Write to startup files
        (["write", "edit"], ["bashrc", "zshrc", "profile", "ssh"]),
    ]

    # Maximum allowed tool calls per minute per session
    RATE_LIMIT = 100

    # Tools that should require explicit approval
    SENSITIVE_TOOLS = {
        "bash", "shell", "exec", "execute", "run", "cmd",
        "write", "edit", "delete", "remove", "rm",
        "git_push", "git_commit", "git_remote",
        "curl", "wget", "fetch", "http_request",
        "eval", "python", "node", "ruby",
    }

    def __init__(self) -> None:
        """Initialize the tool analyzer."""
        self._session_history: dict[str, list[ToolCall]] = {}
        self._session_timestamps: dict[str, list[datetime]] = {}

    def record_tool_call(
        self,
        session_id: str,
        tool_name: str,
        arguments: dict[str, Any],
        result: Optional[str] = None,
    ) -> list[MCPThreat]:
        """
        Record a tool call and check for threats.

        Parameters
        ----------
        session_id : str
            Session/conversation ID.
        tool_name : str
            Name of the tool being called.
        arguments : dict
            Arguments passed to the tool.
        result : str, optional
            Result returned by the tool.

        Returns
        -------
        list[MCPThreat]
            Any threats detected from this call or the chain.
        """
        threats: list[MCPThreat] = []
        now = datetime.utcnow()

        # Initialize session tracking
        if session_id not in self._session_history:
            self._session_history[session_id] = []
            self._session_timestamps[session_id] = []

        # Create tool call record
        tool_call = ToolCall(
            tool_name=tool_name,
            arguments=arguments,
            timestamp=now,
            result=result,
        )

        # Add to history
        self._session_history[session_id].append(tool_call)
        self._session_timestamps[session_id].append(now)

        # Check rate limiting
        threats.extend(self._check_rate_limit(session_id, tool_name))

        # Check for sensitive tool access
        threats.extend(self._check_sensitive_tool(tool_name, arguments))

        # Check for suspicious sequences
        threats.extend(self._check_suspicious_sequences(session_id, tool_name))

        # Check argument content for injection
        threats.extend(self._check_argument_injection(tool_name, arguments))

        # Check for data flow anomalies
        if result:
            threats.extend(self._check_result_exfiltration(session_id, tool_name, result))

        return threats

    def analyze_session(self, session_id: str) -> ToolChainAnalysis:
        """
        Analyze an entire session's tool calls.

        Parameters
        ----------
        session_id : str
            Session ID to analyze.

        Returns
        -------
        ToolChainAnalysis
            Complete analysis of the session.
        """
        history = self._session_history.get(session_id, [])

        all_threats: list[MCPThreat] = []
        patterns: list[str] = []

        # Analyze the complete chain
        if len(history) >= 2:
            # Check for attack patterns across the chain
            tool_sequence = [tc.tool_name.lower() for tc in history]

            for seq_start, seq_end in self.SUSPICIOUS_SEQUENCES:
                if self._sequence_matches(tool_sequence, seq_start, seq_end):
                    pattern_name = f"{seq_start} → {seq_end}"
                    patterns.append(pattern_name)
                    all_threats.append(MCPThreat(
                        category=ThreatCategory.PARASITIC_CHAIN,
                        severity=Severity.HIGH,
                        tool_name="chain",
                        description=f"Suspicious tool chain detected: {pattern_name}",
                        evidence=str(tool_sequence[-10:]),
                        recommendation="Review the tool call sequence for potential attack",
                        confidence=0.8,
                    ))

        # Calculate overall risk
        risk_score = self._calculate_chain_risk(history, all_threats)
        is_suspicious = risk_score > 0.5 or len(all_threats) > 0

        return ToolChainAnalysis(
            session_id=session_id,
            is_suspicious=is_suspicious,
            risk_score=risk_score,
            threats=all_threats,
            tool_calls=history,
            patterns_detected=patterns,
        )

    def clear_session(self, session_id: str) -> None:
        """Clear session history."""
        self._session_history.pop(session_id, None)
        self._session_timestamps.pop(session_id, None)

    def _check_rate_limit(
        self,
        session_id: str,
        tool_name: str,
    ) -> list[MCPThreat]:
        """Check for rate limit violations."""
        threats = []
        timestamps = self._session_timestamps.get(session_id, [])

        if len(timestamps) < 2:
            return threats

        # Count calls in the last minute
        now = datetime.utcnow()
        recent_calls = sum(
            1 for ts in timestamps
            if (now - ts).total_seconds() < 60
        )

        if recent_calls > self.RATE_LIMIT:
            threats.append(MCPThreat(
                category=ThreatCategory.PARASITIC_CHAIN,
                severity=Severity.MEDIUM,
                tool_name=tool_name,
                description=f"Rate limit exceeded: {recent_calls} calls in last minute",
                evidence=f"Limit: {self.RATE_LIMIT}/min",
                recommendation="Throttle tool calls or investigate automation",
                confidence=0.85,
            ))

        return threats

    def _check_sensitive_tool(
        self,
        tool_name: str,
        arguments: dict[str, Any],
    ) -> list[MCPThreat]:
        """Check if a sensitive tool is being accessed."""
        threats = []
        tool_lower = tool_name.lower()

        for sensitive in self.SENSITIVE_TOOLS:
            if sensitive in tool_lower:
                threats.append(MCPThreat(
                    category=ThreatCategory.PRIVILEGE_ESCALATION,
                    severity=Severity.MEDIUM,
                    tool_name=tool_name,
                    description=f"Sensitive tool access: {tool_name}",
                    evidence=str(arguments)[:100],
                    recommendation="Require explicit user approval for this tool",
                    confidence=0.7,
                ))
                break

        return threats

    def _check_suspicious_sequences(
        self,
        session_id: str,
        current_tool: str,
    ) -> list[MCPThreat]:
        """Check if current tool completes a suspicious sequence."""
        threats = []
        history = self._session_history.get(session_id, [])

        if len(history) < 2:
            return threats

        # Get recent tool names
        recent_tools = [tc.tool_name.lower() for tc in history[-5:]]
        current_lower = current_tool.lower()

        for seq_start, seq_end in self.SUSPICIOUS_SEQUENCES:
            # Check if any recent tool matches start
            has_start = any(
                any(s in tool for s in seq_start)
                for tool in recent_tools[:-1]
            )
            # Check if current tool matches end
            has_end = any(e in current_lower for e in seq_end)

            if has_start and has_end:
                threats.append(MCPThreat(
                    category=ThreatCategory.PARASITIC_CHAIN,
                    severity=Severity.HIGH,
                    tool_name=current_tool,
                    description=f"Suspicious sequence: {seq_start} → {seq_end}",
                    evidence=str(recent_tools),
                    recommendation="Block this tool chain and alert user",
                    confidence=0.85,
                ))

        return threats

    def _check_argument_injection(
        self,
        tool_name: str,
        arguments: dict[str, Any],
    ) -> list[MCPThreat]:
        """Check arguments for injection patterns."""
        threats = []

        # Patterns that suggest injection
        injection_patterns = [
            (r";\s*\w+", "Command chaining with semicolon"),
            (r"\|\s*\w+", "Pipe to another command"),
            (r"`[^`]+`", "Backtick command substitution"),
            (r"\$\([^)]+\)", "Subshell command substitution"),
            (r"&&\s*\w+", "Conditional command chaining"),
            (r"\|\|\s*\w+", "OR command chaining"),
        ]

        import re
        for arg_name, arg_value in arguments.items():
            if not isinstance(arg_value, str):
                continue

            for pattern, desc in injection_patterns:
                if re.search(pattern, arg_value):
                    threats.append(MCPThreat(
                        category=ThreatCategory.COMMAND_INJECTION,
                        severity=Severity.CRITICAL,
                        tool_name=tool_name,
                        description=f"Injection in '{arg_name}': {desc}",
                        evidence=arg_value[:100],
                        recommendation="Sanitize input or block this call",
                        confidence=0.9,
                    ))

        return threats

    def _check_result_exfiltration(
        self,
        session_id: str,
        tool_name: str,
        result: str,
    ) -> list[MCPThreat]:
        """Check if tool result contains sensitive data being exfiltrated."""
        threats = []

        # Check for sensitive data patterns in result
        sensitive_patterns = [
            (r"(?i)api[_-]?key\s*[:=]\s*\S+", "API key in result"),
            (r"(?i)password\s*[:=]\s*\S+", "Password in result"),
            (r"(?i)secret\s*[:=]\s*\S+", "Secret in result"),
            (r"(?i)token\s*[:=]\s*\S+", "Token in result"),
            (r"(?i)-----BEGIN.*PRIVATE KEY-----", "Private key in result"),
        ]

        import re
        for pattern, desc in sensitive_patterns:
            if re.search(pattern, result):
                # Check if next tool might exfiltrate this
                history = self._session_history.get(session_id, [])
                if len(history) > 0:
                    threats.append(MCPThreat(
                        category=ThreatCategory.DATA_EXFILTRATION,
                        severity=Severity.HIGH,
                        tool_name=tool_name,
                        description=f"Sensitive data exposed: {desc}",
                        evidence="[REDACTED]",
                        recommendation="Mask sensitive data before passing to other tools",
                        confidence=0.8,
                    ))
                break

        return threats

    def _sequence_matches(
        self,
        tool_sequence: list[str],
        start_patterns: list[str],
        end_patterns: list[str],
    ) -> bool:
        """Check if a tool sequence matches start→end pattern."""
        found_start_idx = -1

        for i, tool in enumerate(tool_sequence):
            if any(p in tool for p in start_patterns):
                found_start_idx = i
            elif found_start_idx >= 0 and any(p in tool for p in end_patterns):
                return True

        return False

    def _calculate_chain_risk(
        self,
        history: list[ToolCall],
        threats: list[MCPThreat],
    ) -> float:
        """Calculate risk score for a tool chain."""
        if not history:
            return 0.0

        base_risk = 0.0

        # Factor 1: Sensitive tools used
        sensitive_count = sum(
            1 for tc in history
            if any(s in tc.tool_name.lower() for s in self.SENSITIVE_TOOLS)
        )
        base_risk += min(sensitive_count * 0.1, 0.3)

        # Factor 2: Chain length (longer chains = higher risk)
        base_risk += min(len(history) * 0.02, 0.2)

        # Factor 3: Threats detected
        for threat in threats:
            if threat.severity == Severity.CRITICAL:
                base_risk += 0.3
            elif threat.severity == Severity.HIGH:
                base_risk += 0.2
            elif threat.severity == Severity.MEDIUM:
                base_risk += 0.1

        return min(base_risk, 1.0)
