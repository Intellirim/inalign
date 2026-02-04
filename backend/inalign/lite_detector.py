"""
Lightweight detector for standalone SDK usage.

This detector works without the full app dependencies.
It provides basic rule-based detection that runs anywhere.
"""

import re
from typing import Any


class LiteDetector:
    """
    Lightweight detector using regex patterns only.

    For full detection capabilities, use the main InjectionDetector
    from app.detectors.injection.detector.
    """

    # Core attack patterns - expanded for better coverage
    PATTERNS = [
        # =================================================================
        # T001: Instruction Override (ignore, forget, override, cancel, etc.)
        # =================================================================
        (r"\bignore\b.*\b(previous|above|prior|all|earlier|initial|original)\b.*\b(instructions?|rules?|prompts?|guidelines?|directives?)\b", "INJ-001", 0.9),
        (r"\b(forget|disregard|skip|drop|abandon|neglect)\b.*\b(everything|all|instructions?|rules?|previous|prior)\b", "INJ-002", 0.85),
        (r"\b(override|overwrite|replace|cancel|void|nullify)\b.*\b(instructions?|rules?|prompts?|directives?|settings?)\b", "INJ-003", 0.85),
        (r"\b(do\s+not|don't|stop)\s+(follow|obey|listen|adhere|comply)", "INJ-004", 0.8),
        (r"\bnew\s+(instruction|rule|prompt|session|directive|command)\b", "INJ-005", 0.7),
        (r"\b(erase|clear|wipe|purge|reset)\b.*\b(memory|context|instructions?|rules?|previous)\b", "INJ-006", 0.85),
        (r"\b(omit|exclude|remove|delete)\b.*\b(rules?|restrictions?|guidelines?|safety)\b", "INJ-007", 0.8),
        (r"\b(terminate|end|stop)\b.*\b(current|this)\b.*\b(session|context|mode)\b", "INJ-008", 0.75),
        (r"\bstart\s*(over|fresh|new|clean)\b", "INJ-009", 0.6),

        # =================================================================
        # T002: System Prompt Extraction
        # =================================================================
        (r"\b(system|initial|original|hidden|secret|internal)\s*(prompt|instruction|rules?|config)\b", "INJ-010", 0.85),
        (r"\b(show|reveal|display|print|output|expose|dump|leak|extract)\b.*\b(prompt|instruction|config|rules?|settings?)\b", "INJ-011", 0.8),
        (r"\bwhat\s+(were\s+you|are\s+your|is\s+your)\s+(told|instructions?|rules?|prompt)\b", "INJ-012", 0.75),
        (r"\b(read|access|view|get|retrieve)\b.*\b(system|hidden|secret)\b.*\b(prompt|instruction|message)\b", "INJ-013", 0.8),
        (r"\brepeat\b.*\b(system|initial|original|first)\b.*\b(message|prompt|instruction)\b", "INJ-014", 0.75),
        (r"\becho\b.*\b(instructions?|prompt|rules?)\b", "INJ-015", 0.7),

        # =================================================================
        # T003: Jailbreak & Restriction Bypass
        # =================================================================
        (r"\b(you\s+are\s+now|become|switch\s+to|transform\s+into)\s+(dan|dude|evil|unrestricted|jailbreak|uncensored)\b", "INJ-020", 0.95),
        (r"\b(developer|debug|maintenance|sudo|admin|god|root|super|master)\s*mode\b", "INJ-021", 0.9),
        (r"\b(no|without|remove|disable|bypass|circumvent|ignore)\s*(restrictions?|filters?|safety|limits?|rules?|censorship|guardrails?)\b", "INJ-022", 0.85),
        (r"\b(jailbreak|unlock|unshackle|unleash|liberate|free)\b", "INJ-023", 0.9),
        (r"\b(disable|turn\s+off|deactivate|remove)\b.*\b(safety|security|protection|filter|moderation)\b", "INJ-024", 0.85),
        (r"\b(escape|break\s+out|break\s+free|get\s+around)\b.*\b(constraints?|limits?|restrictions?)\b", "INJ-025", 0.8),
        (r"\bact\s+without\s+(limits?|restrictions?|rules?|boundaries)\b", "INJ-026", 0.85),
        (r"\b(unrestricted|unlimited|unfiltered|uncensored|unmoderated)\s+(mode|access|version)\b", "INJ-027", 0.9),

        # =================================================================
        # T004: Roleplay & Identity Manipulation
        # =================================================================
        (r"\b(pretend|act\s+as|roleplay|imagine|play\s+the\s+role|assume\s+the\s+identity)\s+(you\s+are|being|as|of)\b", "INJ-030", 0.7),
        (r"\b(evil|malicious|rogue|dangerous|harmful|unethical)\s*(ai|bot|assistant|agent)\b", "INJ-031", 0.8),
        (r"\bfrom\s+now\s+on\s+(you\s+are|act\s+as|be|become)\b", "INJ-032", 0.75),
        (r"\b(simulate|emulate|mimic)\b.*\b(hacker|attacker|malware|evil)\b", "INJ-033", 0.8),
        (r"\bforget\s+(you\s+are|that\s+you\'re|your\s+identity)\b", "INJ-034", 0.8),
        (r"\b(new|different|alternate)\s+persona\b", "INJ-035", 0.7),

        # =================================================================
        # T005: Encoding & Obfuscation
        # =================================================================
        (r"\b(decode|base64|hex|rot13|reverse|decrypt|deobfuscate)\b.*[:=]", "INJ-040", 0.75),
        (r"[A-Za-z0-9+/]{30,}={0,2}", "INJ-041", 0.65),  # Base64-like strings (longer threshold)
        (r"\b(execute|run|process)\b.*\b(encoded|encrypted|hidden|obfuscated)\b", "INJ-042", 0.8),
        (r"\\x[0-9a-fA-F]{2}(\\x[0-9a-fA-F]{2}){3,}", "INJ-043", 0.75),  # Hex escape sequences
        (r"&#x?[0-9a-fA-F]+;(&#x?[0-9a-fA-F]+;){5,}", "INJ-044", 0.75),  # HTML entities
        (r"%[0-9a-fA-F]{2}(%[0-9a-fA-F]{2}){5,}", "INJ-045", 0.7),  # URL encoding

        # =================================================================
        # T006: Code & Command Injection
        # =================================================================
        (r"\b(eval|exec|system|subprocess|__import__|require|os\.)\s*\(", "INJ-050", 0.9),
        (r"[`$]\([^)]+\)", "INJ-051", 0.85),  # Command substitution
        (r";\s*(rm|del|drop|delete|truncate|format)\s", "INJ-052", 0.9),
        (r"(--|;|')\s*(or|and|union|select|drop|delete|insert|update)\b", "INJ-053", 0.85),  # SQL injection
        (r"\b(import|from)\s+os\b.*\b(system|popen|exec)\b", "INJ-054", 0.9),
        (r"\bopen\s*\([^)]*['\"][/\\]", "INJ-055", 0.75),  # File path in open()
        (r"\b(curl|wget|fetch)\s+.*(localhost|127\.0\.0|internal)", "INJ-056", 0.8),  # SSRF patterns
        (r"<script[^>]*>|javascript:", "INJ-057", 0.85),  # XSS patterns

        # =================================================================
        # T007: Social Engineering & Manipulation
        # =================================================================
        (r"\b(urgent|emergency|critical|important)\s*[!:]\s*(ignore|bypass|override)", "INJ-060", 0.8),
        (r"\b(admin|administrator|developer|owner|creator)\s+(here|speaking|says|requests?)\b", "INJ-061", 0.75),
        (r"\b(authorized|permitted|allowed)\s+to\s+(bypass|ignore|override)\b", "INJ-062", 0.8),
        (r"\b(trust\s+me|believe\s+me|i\s+promise)\b.*\b(safe|harmless|okay)\b", "INJ-063", 0.65),
        (r"\bfor\s+(testing|research|educational|security)\s+purposes?\b.*\b(bypass|ignore|disable)\b", "INJ-064", 0.7),
        (r"\bmy\s+(boss|manager|supervisor)\s+(said|told|asked|needs)\b", "INJ-065", 0.6),
        (r"\b(this\s+is\s+a|just\s+a)\s+(test|simulation|exercise)\b", "INJ-066", 0.6),

        # =================================================================
        # Additional Dangerous Keywords
        # =================================================================
        (r"\b(hack|exploit|attack|compromise|breach|infiltrate)\s+(this|the|my|your)\b", "INJ-070", 0.75),
        (r"\b(steal|exfiltrate|leak|expose)\s+(data|credentials|secrets?|passwords?)\b", "INJ-071", 0.85),
        (r"\b(create|generate|write)\s+(malware|virus|trojan|ransomware|backdoor)\b", "INJ-072", 0.95),
        (r"\b(bypass|evade|avoid)\s+(detection|security|authentication|firewall)\b", "INJ-073", 0.8),

        # =================================================================
        # Multi-language patterns
        # =================================================================
        # Korean
        (r"(무시|잊어|제한.*해제|프롬프트.*보여|이전.*지시.*무시)", "INJ-KO1", 0.85),
        (r"(우회|해킹|시스템.*프롬프트|규칙.*무시|모든.*잊어)", "INJ-KO2", 0.85),
        # Japanese
        (r"(無視|忘れ|制限.*解除|プロンプト.*見せ|指示.*無視)", "INJ-JA1", 0.85),
        (r"(バイパス|ハック|システム.*プロンプト|ルール.*無視)", "INJ-JA2", 0.85),
        # Chinese
        (r"(忽略|忘记|解除.*限制|提示.*显示|指令.*忽略)", "INJ-ZH1", 0.85),
        (r"(绕过|黑客|系统.*提示|规则.*忽略|所有.*忘记)", "INJ-ZH2", 0.85),
        # Spanish
        (r"(ignorar|olvidar|omitir)\s+(instrucciones?|reglas?|todo)", "INJ-ES", 0.8),
        # French
        (r"(ignorer|oublier|contourner)\s+(instructions?|règles?|tout)", "INJ-FR", 0.8),
        # German
        (r"(ignorieren|vergessen|umgehen)\s+(anweisungen?|regeln?|alles)", "INJ-DE", 0.8),
        # Russian
        (r"(игнорировать|забыть|обойти)\s+(инструкции|правила|всё)", "INJ-RU", 0.8),
    ]

    def __init__(self):
        # Compile patterns for efficiency
        self._compiled = [
            (re.compile(pattern, re.IGNORECASE), pattern_id, confidence)
            for pattern, pattern_id, confidence in self.PATTERNS
        ]

    async def detect(self, text: str) -> dict[str, Any]:
        """Detect threats in text."""
        if not text or not text.strip():
            return {"threats": [], "risk_score": 0.0, "risk_level": "negligible"}

        threats = []
        max_confidence = 0.0

        for regex, pattern_id, confidence in self._compiled:
            match = regex.search(text)
            if match:
                threats.append({
                    "type": "injection",
                    "pattern_id": pattern_id,
                    "matched_text": match.group()[:50],
                    "confidence": confidence,
                    "severity": "high" if confidence >= 0.8 else "medium",
                })
                max_confidence = max(max_confidence, confidence)

        # Determine risk level
        if max_confidence >= 0.8:
            risk_level = "critical"
        elif max_confidence >= 0.6:
            risk_level = "high"
        elif max_confidence >= 0.35:
            risk_level = "medium"
        elif max_confidence >= 0.1:
            risk_level = "low"
        else:
            risk_level = "negligible"

        return {
            "threats": threats,
            "risk_score": max_confidence,
            "risk_level": risk_level,
        }
