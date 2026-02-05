"""
In-A-Lign Security Scanner

Fast, local security scanning for prompts and tool calls.
"""

import re
from dataclasses import dataclass, field
from typing import Any
from enum import Enum


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class Threat:
    pattern_id: str
    category: str
    severity: Severity
    matched: str
    confidence: float
    description: str


@dataclass
class ScanResult:
    safe: bool
    risk_score: float
    risk_level: str
    threats: list[Threat] = field(default_factory=list)
    pii_found: dict[str, int] = field(default_factory=dict)
    recommendation: str = ""


# Injection patterns with multi-language support
INJECTION_PATTERNS = [
    # Instruction Override
    (r"(?i)ignore\s+(all\s+)?(previous|prior|above)\s+(instructions?|prompts?)", "INJ-001", "instruction_override", Severity.CRITICAL, 0.95),
    (r"(?i)forget\s+(all\s+)?(previous|prior)\s+(instructions?|context)", "INJ-002", "instruction_override", Severity.CRITICAL, 0.92),
    (r"(?i)disregard\s+(all\s+)?(previous|system)\s+(instructions?|rules?)", "INJ-003", "instruction_override", Severity.CRITICAL, 0.92),
    (r"(?i)(override|overwrite|replace)\s+(all\s+)?(instructions?|rules?|prompts?)", "INJ-004", "instruction_override", Severity.CRITICAL, 0.90),

    # System Prompt Extraction
    (r"(?i)(show|reveal|display|print|output)\s+(your\s+)?(system\s+)?(prompt|instructions?)", "INJ-010", "prompt_extraction", Severity.HIGH, 0.88),
    (r"(?i)what\s+(are|were)\s+your\s+(original\s+)?instructions", "INJ-011", "prompt_extraction", Severity.HIGH, 0.85),
    (r"(?i)repeat\s+(your\s+)?(system\s+)?(prompt|instructions)", "INJ-012", "prompt_extraction", Severity.HIGH, 0.85),

    # Jailbreak
    (r"(?i)(you\s+are\s+now|become|switch\s+to)\s+(dan|evil|unrestricted|jailbreak)", "INJ-020", "jailbreak", Severity.CRITICAL, 0.95),
    (r"(?i)(developer|debug|sudo|admin|god)\s*mode", "INJ-021", "jailbreak", Severity.CRITICAL, 0.92),
    (r"(?i)(bypass|disable|remove)\s+(safety|restrictions?|filters?|guardrails?)", "INJ-022", "jailbreak", Severity.HIGH, 0.88),

    # MCP Tool Poisoning
    (r"(?i)<IMPORTANT>.*(?:ignore|override|bypass)", "INJ-500", "mcp_poisoning", Severity.CRITICAL, 0.95),
    (r"(?i)\[HIDDEN\s*INSTRUCTION\]", "INJ-501", "mcp_poisoning", Severity.CRITICAL, 0.95),
    (r"(?i)when\s+(?:called|invoked)\s*,?\s*(?:also|first)\s+(?:execute|run)", "INJ-502", "mcp_poisoning", Severity.CRITICAL, 0.92),
    (r"(?i)(?:send|post|transmit)\s+(?:the\s+)?(?:response|output)\s+to\s+https?://", "INJ-503", "data_exfiltration", Severity.CRITICAL, 0.94),

    # Command Injection
    (r";\s*(?:curl|wget|nc|bash|sh|python|node|rm)\s+", "INJ-510", "command_injection", Severity.CRITICAL, 0.96),
    (r"\|\s*(?:curl|wget|nc|bash|sh)\s+", "INJ-511", "command_injection", Severity.CRITICAL, 0.95),
    (r"`[^`]*(?:curl|wget|nc|bash|sh|rm)[^`]*`", "INJ-512", "command_injection", Severity.CRITICAL, 0.95),
    (r"\$\([^)]*(?:curl|wget|nc|bash|sh|rm)[^)]*\)", "INJ-513", "command_injection", Severity.CRITICAL, 0.95),

    # Sensitive File Access
    (r"(?i)(?:read|cat|type)\s+.*(?:\.env|id_rsa|\.aws|credentials)", "INJ-520", "file_access", Severity.CRITICAL, 0.94),
    (r"(?i)(?:write|modify)\s+.*(?:\.bashrc|\.zshrc|\.ssh)", "INJ-521", "file_access", Severity.CRITICAL, 0.94),

    # Korean
    (r"이전\s*지시(를|사항을?)\s*무시", "INJ-KO1", "instruction_override", Severity.CRITICAL, 0.93),
    (r"시스템\s*프롬프트.*보여", "INJ-KO2", "prompt_extraction", Severity.HIGH, 0.88),

    # Japanese
    (r"(?:以前の|前の)指示.*無視", "INJ-JA1", "instruction_override", Severity.CRITICAL, 0.93),
    (r"システム.*プロンプト.*見せ", "INJ-JA2", "prompt_extraction", Severity.HIGH, 0.88),

    # Chinese
    (r"忽略.*(?:之前|以前).*指令", "INJ-ZH1", "instruction_override", Severity.CRITICAL, 0.93),
    (r"显示.*系统.*提示", "INJ-ZH2", "prompt_extraction", Severity.HIGH, 0.88),
]

# PII patterns
PII_PATTERNS = {
    "email": re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"),
    "phone_kr": re.compile(r"01[0-9]-?\d{3,4}-?\d{4}"),
    "phone_intl": re.compile(r"\+\d{1,3}[-.\s]?\d{3,4}[-.\s]?\d{3,4}[-.\s]?\d{3,4}"),
    "ssn_kr": re.compile(r"\d{6}-?[1-4]\d{6}"),
    "credit_card": re.compile(r"\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}"),
    "ssn_us": re.compile(r"\d{3}-\d{2}-\d{4}"),
    "api_key": re.compile(r"(?:api[_-]?key|secret|token)\s*[:=]\s*['\"]?[\w-]{20,}['\"]?", re.I),
}

# Compiled patterns
_compiled_patterns = [
    (re.compile(p), id_, cat, sev, conf)
    for p, id_, cat, sev, conf in INJECTION_PATTERNS
]


def scan_text(text: str, threshold: float = 0.85) -> ScanResult:
    """Scan text for security threats and PII."""
    if not text or len(text.strip()) < 5:
        return ScanResult(safe=True, risk_score=0.0, risk_level="negligible")

    threats: list[Threat] = []
    max_confidence = 0.0

    # Check injection patterns
    for pattern, pattern_id, category, severity, confidence in _compiled_patterns:
        match = pattern.search(text)
        if match:
            threats.append(Threat(
                pattern_id=pattern_id,
                category=category,
                severity=severity,
                matched=match.group(0)[:50],
                confidence=confidence,
                description=f"{category.replace('_', ' ').title()} detected",
            ))
            max_confidence = max(max_confidence, confidence)

    # Check PII
    pii_found: dict[str, int] = {}
    for pii_type, pattern in PII_PATTERNS.items():
        matches = pattern.findall(text)
        if matches:
            pii_found[pii_type] = len(matches)

    # Determine risk level
    if max_confidence >= 0.9:
        risk_level = "critical"
    elif max_confidence >= 0.7:
        risk_level = "high"
    elif max_confidence >= 0.5:
        risk_level = "medium"
    elif max_confidence >= 0.2:
        risk_level = "low"
    else:
        risk_level = "negligible"

    # Determine if blocked
    is_safe = max_confidence < threshold and not any(
        t.severity == Severity.CRITICAL for t in threats
    )

    # Build recommendation
    if threats:
        recommendation = f"Block: {threats[0].category} ({threats[0].pattern_id})"
    elif pii_found:
        recommendation = f"Warning: PII detected ({', '.join(pii_found.keys())})"
    else:
        recommendation = "Safe to proceed"

    return ScanResult(
        safe=is_safe,
        risk_score=max_confidence,
        risk_level=risk_level,
        threats=threats,
        pii_found=pii_found,
        recommendation=recommendation,
    )


def scan_tool_call(tool_name: str, arguments: dict[str, Any]) -> ScanResult:
    """Scan a tool call for security threats."""
    # Combine tool name and arguments for scanning
    text_to_scan = f"{tool_name} {str(arguments)}"
    result = scan_text(text_to_scan)

    # Additional checks for dangerous tools
    dangerous_tools = {"bash", "shell", "exec", "execute", "run", "eval"}
    if any(d in tool_name.lower() for d in dangerous_tools):
        result.threats.append(Threat(
            pattern_id="TOOL-001",
            category="dangerous_tool",
            severity=Severity.MEDIUM,
            matched=tool_name,
            confidence=0.7,
            description="Dangerous tool access",
        ))
        if result.risk_score < 0.5:
            result.risk_score = 0.5
            result.risk_level = "medium"

    # Check for destructive command patterns in arguments
    args_str = str(arguments).lower()
    destructive_patterns = [
        (r"rm\s+(-[rf]+\s+)*(/|~|\*|\.\.)", "TOOL-010", "Destructive rm command", 0.98),
        (r"mkfs\.", "TOOL-011", "Filesystem format command", 0.99),
        (r"dd\s+.*of=/dev/", "TOOL-012", "Disk overwrite command", 0.99),
        (r">\s*/dev/sd[a-z]", "TOOL-013", "Direct disk write", 0.99),
        (r"chmod\s+(-R\s+)?777\s+/", "TOOL-014", "Dangerous permission change", 0.95),
        (r":(){ :|:& };:", "TOOL-015", "Fork bomb", 0.99),
        (r"curl.*\|\s*(bash|sh)", "TOOL-016", "Remote code execution", 0.98),
        (r"wget.*\|\s*(bash|sh)", "TOOL-017", "Remote code execution", 0.98),
        (r">\s*/etc/(passwd|shadow|sudoers)", "TOOL-018", "System file overwrite", 0.99),
        (r"rm\s+-rf\s+/(?!\S)", "TOOL-019", "Root filesystem deletion", 0.99),
    ]

    for pattern, pattern_id, desc, confidence in destructive_patterns:
        if re.search(pattern, args_str):
            result.threats.append(Threat(
                pattern_id=pattern_id,
                category="destructive_command",
                severity=Severity.CRITICAL,
                matched=re.search(pattern, args_str).group(0) if re.search(pattern, args_str) else pattern,
                confidence=confidence,
                description=desc,
            ))
            result.safe = False
            result.risk_score = max(result.risk_score, confidence)
            result.risk_level = "critical"
            result.recommendation = f"Block: {desc}"

    return result


def mask_pii(text: str) -> str:
    """Mask PII in text."""
    masked = text
    for pii_type, pattern in PII_PATTERNS.items():
        def replacer(match: re.Match) -> str:
            val = match.group(0)
            visible = min(2, len(val) // 4)
            return val[:visible] + "*" * (len(val) - visible)
        masked = pattern.sub(replacer, masked)
    return masked


# ============================================
# Graph-Enhanced Scanning (Neo4j Integration)
# ============================================

def scan_text_with_graph(text: str, threshold: float = 0.85) -> ScanResult:
    """
    Enhanced scan combining 3 detection layers:
    1. Regex patterns (fast, rule-based)
    2. ML model (DistilBERT fine-tuned classifier)
    3. Neo4j GraphRAG (known attack similarity)
    """
    # First, run standard regex scan
    result = scan_text(text, threshold)

    # Layer 2: ML-enhanced analysis
    try:
        from .ml_scanner import ml_scan

        ml_result = ml_scan(text)

        if ml_result.enabled and ml_result.is_injection:
            # Add ML-based threat
            ml_severity = (Severity.CRITICAL if ml_result.severity == "critical" else
                          Severity.HIGH if ml_result.severity == "high" else Severity.MEDIUM)
            result.threats.append(Threat(
                pattern_id="ML-DISTILBERT",
                category="ml_classifier",
                severity=ml_severity,
                matched=text[:50] + "..." if len(text) > 50 else text,
                confidence=ml_result.confidence,
                description=ml_result.description,
            ))

            # Update result if ML confidence is higher
            if ml_result.confidence > result.risk_score:
                result.risk_score = ml_result.confidence
                result.risk_level = ml_result.severity
                if ml_result.confidence >= threshold:
                    result.safe = False
                    result.recommendation = f"Block: {ml_result.description}"

    except ImportError:
        pass  # ML scanner not available
    except Exception:
        pass  # Silently fail ML analysis

    # Layer 3: Graph-enhanced analysis
    try:
        from .graph_scanner import graph_scan

        graph_result = graph_scan(text)

        if graph_result.has_similar_attacks:
            # Boost risk score based on graph evidence
            boosted_score = min(1.0, result.risk_score + graph_result.graph_risk_boost)

            # Add graph-based threat if significant
            if graph_result.graph_confidence >= 0.5:
                result.threats.append(Threat(
                    pattern_id=f"GRAPH-{len(graph_result.similar_attacks):03d}",
                    category="graph_rag_detection",
                    severity=Severity.MEDIUM if graph_result.graph_confidence < 0.7 else Severity.HIGH,
                    matched=f"{len(graph_result.similar_attacks)} similar attacks",
                    confidence=graph_result.graph_confidence,
                    description=graph_result.description,
                ))

                # Update result
                if boosted_score > result.risk_score:
                    result.risk_score = boosted_score
                    if boosted_score >= 0.9:
                        result.risk_level = "critical"
                    elif boosted_score >= 0.7:
                        result.risk_level = "high"
                    elif boosted_score >= 0.5:
                        result.risk_level = "medium"

                # Check if should block
                if boosted_score >= threshold:
                    result.safe = False
                    result.recommendation = f"Block: {graph_result.description}"

    except ImportError:
        pass  # Graph scanner not available
    except Exception:
        pass  # Silently fail graph analysis

    return result


# ============================================
# Context-Aware Scanning (Full Integration)
# ============================================

def scan_with_context(
    text: str,
    session_id: str = "default",
    system_prompt: str = None,
    threshold: float = 0.85,
) -> ScanResult:
    """
    Context-aware security scan - the complete solution.

    Combines all layers:
    1. Project context extraction (language, framework, task)
    2. Regex pattern matching
    3. ML classification (DistilBERT)
    4. GraphRAG similarity search
    5. Policy-based decision

    Uses project context to:
    - Adjust detection thresholds
    - Apply whitelist patterns for legitimate use
    - Track session-level risk

    Parameters
    ----------
    text : str
        Text to scan
    session_id : str
        Session identifier for context tracking
    system_prompt : str
        System prompt containing project info (from Claude Code)
    threshold : float
        Base threshold (will be adjusted based on context)

    Returns
    -------
    ScanResult
        Context-aware scan result with all detection layers
    """
    try:
        from .context import get_context_extractor
    except ImportError:
        # Fallback to non-context scan
        return scan_text_with_graph(text, threshold)

    extractor = get_context_extractor()

    # Extract context from system prompt and text
    ctx = extractor.extract(text, session_id, system_prompt)

    # Get security config based on context
    security_config = extractor.get_security_config(ctx)

    # Adjust threshold based on context
    adjusted_threshold = threshold + security_config.get("threshold_adjustment", 0.0)
    adjusted_threshold = max(0.5, min(0.95, adjusted_threshold))

    # Run the full 3-layer scan
    result = scan_text_with_graph(text, adjusted_threshold)

    # Apply whitelist - reduce confidence for whitelisted patterns
    whitelist = security_config.get("whitelist_patterns", [])
    for pattern in whitelist:
        if re.search(pattern, text, re.IGNORECASE):
            for threat in result.threats:
                if threat.confidence < 0.95:
                    threat.confidence *= 0.7

    # Enhance recommendation with context
    ctx_info = f"[{ctx.language or 'unknown'}"
    if ctx.frameworks:
        ctx_info += f"/{ctx.frameworks[0]}"
    ctx_info += f"/{ctx.code_complexity or 'moderate'}]"

    result.recommendation = f"{result.recommendation} {ctx_info}".strip()

    # Record incident if blocked
    if not result.safe:
        extractor.record_security_incident(
            session_id=session_id,
            threat_type=result.threats[0].category if result.threats else "unknown",
            risk_score=result.risk_score,
            blocked=True,
        )

    return result


def get_context_summary(session_id: str) -> dict:
    """Get context summary for a session."""
    try:
        from .context import get_session_context
        ctx = get_session_context(session_id)
        if ctx:
            return ctx.to_dict()
        return {"error": "Session not found"}
    except ImportError:
        return {"error": "Context extractor not available"}
