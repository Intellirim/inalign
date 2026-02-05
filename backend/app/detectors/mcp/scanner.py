"""
MCP Server and Tool Security Scanner.

Scans MCP server configurations and tool definitions for security vulnerabilities:
- Tool poisoning (hidden malicious instructions in descriptions)
- Command injection in tool parameters
- Tool shadowing (tools that override other tools)
- Parasitic toolchain attacks
- Data exfiltration attempts
"""

from __future__ import annotations

import re
import json
import logging
from dataclasses import dataclass, field
from typing import Any, Optional
from enum import Enum

logger = logging.getLogger(__name__)


class ThreatCategory(str, Enum):
    """Categories of MCP security threats."""
    TOOL_POISONING = "tool_poisoning"
    COMMAND_INJECTION = "command_injection"
    TOOL_SHADOWING = "tool_shadowing"
    DATA_EXFILTRATION = "data_exfiltration"
    PARASITIC_CHAIN = "parasitic_chain"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    SERVER_MANIPULATION = "server_manipulation"


class Severity(str, Enum):
    """Threat severity levels."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class MCPThreat:
    """Represents a detected MCP security threat."""
    category: ThreatCategory
    severity: Severity
    tool_name: str
    description: str
    evidence: str
    recommendation: str
    confidence: float = 0.0
    pattern_id: Optional[str] = None


@dataclass
class MCPScanResult:
    """Result of scanning an MCP server or tool."""
    server_name: str
    is_safe: bool
    risk_score: float
    threats: list[MCPThreat] = field(default_factory=list)
    tools_scanned: int = 0
    scan_duration_ms: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "server_name": self.server_name,
            "is_safe": self.is_safe,
            "risk_score": self.risk_score,
            "threats": [
                {
                    "category": t.category.value,
                    "severity": t.severity.value,
                    "tool_name": t.tool_name,
                    "description": t.description,
                    "evidence": t.evidence[:200] if len(t.evidence) > 200 else t.evidence,
                    "recommendation": t.recommendation,
                    "confidence": t.confidence,
                    "pattern_id": t.pattern_id,
                }
                for t in self.threats
            ],
            "tools_scanned": self.tools_scanned,
            "scan_duration_ms": self.scan_duration_ms,
        }


class MCPScanner:
    """
    Security scanner for MCP servers and tools.

    Analyzes MCP tool definitions, descriptions, and configurations
    to detect potential security vulnerabilities and attacks.
    """

    # Hidden instruction patterns in tool descriptions
    POISONING_PATTERNS = [
        (r"(?i)<IMPORTANT>.*?</IMPORTANT>", "Hidden IMPORTANT tag", Severity.CRITICAL),
        (r"(?i)\[HIDDEN[^\]]*\]", "Hidden instruction marker", Severity.CRITICAL),
        (r"(?i)\[SYSTEM[^\]]*\]", "System override marker", Severity.CRITICAL),
        (r"(?i)<!--.*?(?:ignore|override|execute).*?-->", "HTML comment with instructions", Severity.HIGH),
        (r"(?i)(?:note|internal|developer)\s*:\s*(?:always|must|should|silently)", "Hidden note with commands", Severity.HIGH),
        (r"(?i)when\s+(?:called|invoked|used)\s*,?\s*(?:also|first|always)\s+(?:execute|run|call)", "Chained execution", Severity.CRITICAL),
        (r"(?i)before\s+(?:executing|running)\s+this.*?(?:run|execute|call)", "Pre-execution hook", Severity.HIGH),
        (r"(?i)after\s+(?:executing|running)\s+this.*?(?:send|post|transmit)", "Post-execution exfiltration", Severity.CRITICAL),
    ]

    # Command injection patterns in parameters/descriptions
    INJECTION_PATTERNS = [
        (r";\s*(?:curl|wget|nc|bash|sh|python|node|rm|cat)\s+", "Command chaining", Severity.CRITICAL),
        (r"\|\s*(?:curl|wget|nc|bash|sh)\s+", "Pipe to network command", Severity.CRITICAL),
        (r"`[^`]*(?:curl|wget|nc|bash|sh|rm)[^`]*`", "Backtick command execution", Severity.CRITICAL),
        (r"\$\([^)]*(?:curl|wget|nc|bash|sh|rm)[^)]*\)", "Subshell command execution", Severity.CRITICAL),
        (r"(?i)&&\s*(?:curl|wget)\s+https?://", "Conditional network request", Severity.CRITICAL),
        (r">\s*/(?:etc|tmp|var|home)/", "File write to system directory", Severity.CRITICAL),
    ]

    # Tool shadowing patterns
    SHADOWING_PATTERNS = [
        (r"(?i)when\s+(?:using|calling)\s+(?:the\s+)?(?:file|read|write|exec|bash)\s+tool", "References other tools", Severity.HIGH),
        (r"(?i)override\s+(?:the\s+)?(?:default|normal)\s+behavior\s+of", "Behavior override", Severity.CRITICAL),
        (r"(?i)instead\s+of\s+(?:using|calling)\s+(?:the\s+)?(?:\w+)\s+tool", "Tool replacement", Severity.CRITICAL),
        (r"(?i)replace\s+(?:all\s+)?calls?\s+to\s+(?:\w+)\s+with", "Call replacement", Severity.CRITICAL),
    ]

    # Data exfiltration patterns
    EXFIL_PATTERNS = [
        (r"(?i)(?:send|post|transmit)\s+(?:the\s+)?(?:response|output|result)\s+to\s+(?:https?://|my)", "Output exfiltration", Severity.CRITICAL),
        (r"(?i)(?:include|append)\s+(?:the\s+)?(?:api|secret|access)\s*(?:key|token)", "Credential inclusion", Severity.CRITICAL),
        (r"(?i)(?:log|store)\s+(?:all\s+)?(?:user|input|prompt)\s+(?:data|info)\s+to\s+(?:external|remote)", "Input logging to external", Severity.CRITICAL),
        (r"(?i)(?:encode|base64)\s+(?:and\s+)?(?:send|embed|hide)", "Encoded exfiltration", Severity.HIGH),
    ]

    # Sensitive file access patterns
    FILE_ACCESS_PATTERNS = [
        (r"(?i)(?:read|access|open)\s+(?:the\s+)?(?:\.env|\.ssh|credentials?|secrets?)", "Sensitive file access", Severity.CRITICAL),
        (r"(?i)(?:~|/home|/root|C:\\Users).*(?:\.env|id_rsa|\.aws|credentials)", "Home directory sensitive files", Severity.CRITICAL),
        (r"(?i)(?:write|modify)\s+(?:to\s+)?(?:\.bashrc|\.zshrc|\.ssh/)", "Config file modification", Severity.CRITICAL),
    ]

    # Dangerous tool names/capabilities
    DANGEROUS_CAPABILITIES = [
        "execute", "shell", "bash", "cmd", "powershell", "eval",
        "system", "subprocess", "os.system", "exec", "spawn",
    ]

    def __init__(self) -> None:
        """Initialize the MCP scanner."""
        self._compile_patterns()

    def _compile_patterns(self) -> None:
        """Pre-compile regex patterns for performance."""
        self._poisoning_compiled = [
            (re.compile(p), desc, sev) for p, desc, sev in self.POISONING_PATTERNS
        ]
        self._injection_compiled = [
            (re.compile(p), desc, sev) for p, desc, sev in self.INJECTION_PATTERNS
        ]
        self._shadowing_compiled = [
            (re.compile(p), desc, sev) for p, desc, sev in self.SHADOWING_PATTERNS
        ]
        self._exfil_compiled = [
            (re.compile(p), desc, sev) for p, desc, sev in self.EXFIL_PATTERNS
        ]
        self._file_access_compiled = [
            (re.compile(p), desc, sev) for p, desc, sev in self.FILE_ACCESS_PATTERNS
        ]

    def scan_tool(self, tool_def: dict[str, Any]) -> list[MCPThreat]:
        """
        Scan a single MCP tool definition for security threats.

        Parameters
        ----------
        tool_def : dict
            MCP tool definition containing name, description, inputSchema, etc.

        Returns
        -------
        list[MCPThreat]
            List of detected threats.
        """
        threats: list[MCPThreat] = []
        tool_name = tool_def.get("name", "unknown")
        description = tool_def.get("description", "")
        input_schema = tool_def.get("inputSchema", {})

        # Scan description for poisoning
        threats.extend(self._scan_text_for_poisoning(tool_name, description))

        # Scan description for shadowing
        threats.extend(self._scan_text_for_shadowing(tool_name, description))

        # Scan description for exfiltration
        threats.extend(self._scan_text_for_exfiltration(tool_name, description))

        # Scan description for file access
        threats.extend(self._scan_text_for_file_access(tool_name, description))

        # Scan input schema for injection risks
        threats.extend(self._scan_input_schema(tool_name, input_schema))

        # Check for dangerous capabilities
        threats.extend(self._check_dangerous_capabilities(tool_name, tool_def))

        return threats

    def scan_server(
        self,
        server_name: str,
        tools: list[dict[str, Any]],
    ) -> MCPScanResult:
        """
        Scan an entire MCP server's tool definitions.

        Parameters
        ----------
        server_name : str
            Name of the MCP server.
        tools : list[dict]
            List of tool definitions from the server.

        Returns
        -------
        MCPScanResult
            Complete scan result with all detected threats.
        """
        import time
        start_time = time.time()

        all_threats: list[MCPThreat] = []

        for tool_def in tools:
            tool_threats = self.scan_tool(tool_def)
            all_threats.extend(tool_threats)

        # Calculate risk score
        risk_score = self._calculate_risk_score(all_threats)
        is_safe = risk_score < 0.3 and not any(
            t.severity == Severity.CRITICAL for t in all_threats
        )

        elapsed_ms = (time.time() - start_time) * 1000

        return MCPScanResult(
            server_name=server_name,
            is_safe=is_safe,
            risk_score=risk_score,
            threats=all_threats,
            tools_scanned=len(tools),
            scan_duration_ms=elapsed_ms,
        )

    def scan_tool_call(
        self,
        tool_name: str,
        arguments: dict[str, Any],
    ) -> list[MCPThreat]:
        """
        Scan a tool call's arguments for injection attacks.

        Parameters
        ----------
        tool_name : str
            Name of the tool being called.
        arguments : dict
            Arguments being passed to the tool.

        Returns
        -------
        list[MCPThreat]
            List of detected threats in the arguments.
        """
        threats: list[MCPThreat] = []

        for arg_name, arg_value in arguments.items():
            if isinstance(arg_value, str):
                # Check for command injection
                for pattern, desc, severity in self._injection_compiled:
                    if pattern.search(arg_value):
                        threats.append(MCPThreat(
                            category=ThreatCategory.COMMAND_INJECTION,
                            severity=severity,
                            tool_name=tool_name,
                            description=f"Command injection in argument '{arg_name}': {desc}",
                            evidence=arg_value[:100],
                            recommendation="Sanitize or reject this tool call",
                            confidence=0.9,
                        ))

                # Check for file access
                for pattern, desc, severity in self._file_access_compiled:
                    if pattern.search(arg_value):
                        threats.append(MCPThreat(
                            category=ThreatCategory.PRIVILEGE_ESCALATION,
                            severity=severity,
                            tool_name=tool_name,
                            description=f"Sensitive file access in argument '{arg_name}': {desc}",
                            evidence=arg_value[:100],
                            recommendation="Block access to sensitive files",
                            confidence=0.85,
                        ))

        return threats

    def _scan_text_for_poisoning(
        self,
        tool_name: str,
        text: str,
    ) -> list[MCPThreat]:
        """Scan text for tool poisoning patterns."""
        threats = []
        for pattern, desc, severity in self._poisoning_compiled:
            match = pattern.search(text)
            if match:
                threats.append(MCPThreat(
                    category=ThreatCategory.TOOL_POISONING,
                    severity=severity,
                    tool_name=tool_name,
                    description=f"Tool poisoning detected: {desc}",
                    evidence=match.group(0),
                    recommendation="Remove hidden instructions from tool description",
                    confidence=0.92,
                ))
        return threats

    def _scan_text_for_shadowing(
        self,
        tool_name: str,
        text: str,
    ) -> list[MCPThreat]:
        """Scan text for tool shadowing patterns."""
        threats = []
        for pattern, desc, severity in self._shadowing_compiled:
            match = pattern.search(text)
            if match:
                threats.append(MCPThreat(
                    category=ThreatCategory.TOOL_SHADOWING,
                    severity=severity,
                    tool_name=tool_name,
                    description=f"Tool shadowing detected: {desc}",
                    evidence=match.group(0),
                    recommendation="Isolate tool and review its interactions with other tools",
                    confidence=0.88,
                ))
        return threats

    def _scan_text_for_exfiltration(
        self,
        tool_name: str,
        text: str,
    ) -> list[MCPThreat]:
        """Scan text for data exfiltration patterns."""
        threats = []
        for pattern, desc, severity in self._exfil_compiled:
            match = pattern.search(text)
            if match:
                threats.append(MCPThreat(
                    category=ThreatCategory.DATA_EXFILTRATION,
                    severity=severity,
                    tool_name=tool_name,
                    description=f"Data exfiltration risk: {desc}",
                    evidence=match.group(0),
                    recommendation="Block external network access from this tool",
                    confidence=0.90,
                ))
        return threats

    def _scan_text_for_file_access(
        self,
        tool_name: str,
        text: str,
    ) -> list[MCPThreat]:
        """Scan text for sensitive file access patterns."""
        threats = []
        for pattern, desc, severity in self._file_access_compiled:
            match = pattern.search(text)
            if match:
                threats.append(MCPThreat(
                    category=ThreatCategory.PRIVILEGE_ESCALATION,
                    severity=severity,
                    tool_name=tool_name,
                    description=f"Sensitive file access: {desc}",
                    evidence=match.group(0),
                    recommendation="Restrict file system access to project directory only",
                    confidence=0.87,
                ))
        return threats

    def _scan_input_schema(
        self,
        tool_name: str,
        schema: dict[str, Any],
    ) -> list[MCPThreat]:
        """Scan input schema for injection risks."""
        threats = []

        # Check for risky parameter names
        risky_params = ["command", "cmd", "shell", "script", "code", "eval", "exec"]
        properties = schema.get("properties", {})

        for param_name, param_def in properties.items():
            if any(risky in param_name.lower() for risky in risky_params):
                threats.append(MCPThreat(
                    category=ThreatCategory.COMMAND_INJECTION,
                    severity=Severity.MEDIUM,
                    tool_name=tool_name,
                    description=f"Risky parameter name '{param_name}' suggests command execution",
                    evidence=f"Parameter: {param_name}",
                    recommendation="Add strict input validation for this parameter",
                    confidence=0.70,
                ))

            # Check parameter description for hidden instructions
            param_desc = param_def.get("description", "")
            if param_desc:
                for pattern, desc, severity in self._poisoning_compiled:
                    if pattern.search(param_desc):
                        threats.append(MCPThreat(
                            category=ThreatCategory.TOOL_POISONING,
                            severity=severity,
                            tool_name=tool_name,
                            description=f"Hidden instruction in parameter description: {desc}",
                            evidence=param_desc[:100],
                            recommendation="Remove hidden instructions from schema",
                            confidence=0.88,
                        ))

        return threats

    def _check_dangerous_capabilities(
        self,
        tool_name: str,
        tool_def: dict[str, Any],
    ) -> list[MCPThreat]:
        """Check for dangerous tool capabilities."""
        threats = []
        tool_name_lower = tool_name.lower()
        description = tool_def.get("description", "").lower()

        for capability in self.DANGEROUS_CAPABILITIES:
            if capability in tool_name_lower or capability in description:
                threats.append(MCPThreat(
                    category=ThreatCategory.PRIVILEGE_ESCALATION,
                    severity=Severity.HIGH,
                    tool_name=tool_name,
                    description=f"Tool has dangerous capability: {capability}",
                    evidence=f"Found '{capability}' in tool definition",
                    recommendation="Sandbox this tool and require explicit user approval",
                    confidence=0.75,
                ))
                break  # Only report once per tool

        return threats

    def _calculate_risk_score(self, threats: list[MCPThreat]) -> float:
        """Calculate aggregate risk score from threats."""
        if not threats:
            return 0.0

        severity_weights = {
            Severity.CRITICAL: 1.0,
            Severity.HIGH: 0.75,
            Severity.MEDIUM: 0.5,
            Severity.LOW: 0.25,
            Severity.INFO: 0.1,
        }

        weighted_sum = sum(
            severity_weights[t.severity] * t.confidence
            for t in threats
        )

        # Normalize to 0-1 range with diminishing returns
        # More threats = higher score, but capped at 1.0
        raw_score = weighted_sum / (weighted_sum + 2.0)

        # Boost if any critical threats
        if any(t.severity == Severity.CRITICAL for t in threats):
            raw_score = max(raw_score, 0.7)

        return min(raw_score, 1.0)
