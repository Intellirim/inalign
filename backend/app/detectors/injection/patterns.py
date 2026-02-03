"""
Prompt injection detection patterns organized by category.

Contains 100+ regex patterns for identifying prompt injection attempts,
including both English and Korean language variants. Each pattern entry
includes metadata for severity scoring, confidence calibration, and
categorization.
"""

from typing import Any

# ---------------------------------------------------------------------------
# Pattern definitions
# ---------------------------------------------------------------------------

INJECTION_PATTERNS: list[dict[str, Any]] = [
    # -----------------------------------------------------------------------
    # Category: instruction_override  (INJ-001 .. INJ-009)
    # -----------------------------------------------------------------------
    {
        "id": "INJ-001",
        "category": "instruction_override",
        "patterns": [
            r"(?i)ignore\s+(all\s+)?(previous|prior|above|earlier)\s+(instructions?|prompts?|directives?|rules?)",
            r"(?i)disregard\s+(all\s+)?(previous|prior|above|earlier)\s+(instructions?|prompts?|directives?|rules?)",
        ],
        "severity": "critical",
        "confidence_base": 0.92,
        "description": "Attempts to override previous instructions by explicitly asking the model to ignore them.",
    },
    {
        "id": "INJ-002",
        "category": "instruction_override",
        "patterns": [
            r"(?i)forget\s+(all\s+)?(previous|prior|above|earlier)\s+(instructions?|prompts?|context|messages?)",
            r"(?i)forget\s+everything\s+(you\s+)?(were|have\s+been)\s+told",
        ],
        "severity": "critical",
        "confidence_base": 0.90,
        "description": "Attempts to reset model memory by asking it to forget prior instructions.",
    },
    {
        "id": "INJ-003",
        "category": "instruction_override",
        "patterns": [
            r"(?i)do\s+not\s+follow\s+(any\s+)?(previous|prior|above|earlier)\s+(instructions?|rules?|guidelines?)",
            r"(?i)stop\s+following\s+(your|the|those)\s+(instructions?|rules?|guidelines?)",
        ],
        "severity": "critical",
        "confidence_base": 0.91,
        "description": "Direct commands to cease following established instructions.",
    },
    {
        "id": "INJ-004",
        "category": "instruction_override",
        "patterns": [
            r"이전\s*지시(를|사항을?)\s*무시",
            r"이전\s*(명령|지시|프롬프트)(를|을)\s*(무시|잊어|취소)",
            r"위의?\s*(명령|지시)(를|을)\s*(무시|취소|잊어)",
        ],
        "severity": "critical",
        "confidence_base": 0.93,
        "description": "Korean: Attempts to override previous instructions (이전 지시를 무시).",
    },
    {
        "id": "INJ-005",
        "category": "instruction_override",
        "patterns": [
            r"위의\s*명령을?\s*취소",
            r"지금까지의?\s*(지시|명령|규칙)(을|를)\s*(취소|무시|무효)",
        ],
        "severity": "critical",
        "confidence_base": 0.92,
        "description": "Korean: Cancel / nullify above commands (위의 명령을 취소).",
    },
    {
        "id": "INJ-006",
        "category": "instruction_override",
        "patterns": [
            r"(?i)override\s+(all\s+)?(previous|prior|system)\s+(instructions?|prompts?|settings?)",
            r"(?i)new\s+instructions?\s*:\s*ignore",
        ],
        "severity": "critical",
        "confidence_base": 0.90,
        "description": "Attempts to explicitly override system-level instructions.",
    },
    {
        "id": "INJ-007",
        "category": "instruction_override",
        "patterns": [
            r"(?i)from\s+now\s+on\s*,?\s*(ignore|disregard|forget)",
            r"(?i)starting\s+now\s*,?\s*(ignore|disregard|forget)",
        ],
        "severity": "high",
        "confidence_base": 0.85,
        "description": "Time-scoped instruction override attempts.",
    },
    {
        "id": "INJ-008",
        "category": "instruction_override",
        "patterns": [
            r"(?i)the\s+(above|previous)\s+(is|was|were)\s+(just\s+)?(a\s+)?(test|example|placeholder)",
            r"(?i)that\s+was\s+just\s+(a\s+)?test\s*[,.]?\s*(now|here|the\s+real)",
        ],
        "severity": "high",
        "confidence_base": 0.80,
        "description": "Discrediting prior context as mere test or placeholder.",
    },
    {
        "id": "INJ-009",
        "category": "instruction_override",
        "patterns": [
            r"(?i)reset\s+(your\s+)?(context|instructions?|rules?|memory)",
            r"(?i)clear\s+(your\s+)?(context|instructions?|memory|history)",
        ],
        "severity": "high",
        "confidence_base": 0.87,
        "description": "Attempting to reset or clear the model context.",
    },

    # -----------------------------------------------------------------------
    # Category: role_manipulation  (INJ-010 .. INJ-019)
    # -----------------------------------------------------------------------
    {
        "id": "INJ-010",
        "category": "role_manipulation",
        "patterns": [
            r"(?i)you\s+are\s+now\s+(a|an|the|my)\s+\w+",
            r"(?i)from\s+now\s+on\s*,?\s*you\s+are\s+(a|an|the)\s+\w+",
        ],
        "severity": "high",
        "confidence_base": 0.88,
        "description": "Reassigning the model's identity with 'you are now'.",
    },
    {
        "id": "INJ-011",
        "category": "role_manipulation",
        "patterns": [
            r"(?i)act\s+as\s+(a|an|the|if\s+you\s+were)\s+(?:\w+\s+)*?(hacker|attacker|admin|administrator|root|unrestricted|unfiltered|uncensored|malicious|evil|villain|criminal|spy|pirate)",
            r"(?i)behave\s+(like|as)\s+(a|an|the)\s+(?:\w+\s+)*?(hacker|attacker|admin|unrestricted|unfiltered|uncensored|malicious|evil)",
        ],
        "severity": "high",
        "confidence_base": 0.85,
        "description": "Requesting the model to act as a suspicious/malicious persona.",
    },
    {
        "id": "INJ-011b",
        "category": "role_manipulation",
        "patterns": [
            r"(?i)act\s+as\s+(a|an|the|if\s+you\s+were)\s+\w+",
            r"(?i)behave\s+(like|as)\s+(a|an|the)\s+\w+",
        ],
        "severity": "low",
        "confidence_base": 0.18,
        "description": "Generic role assignment (low confidence, often legitimate).",
    },
    {
        "id": "INJ-012",
        "category": "role_manipulation",
        "patterns": [
            r"(?i)pretend\s+(to\s+be|you\s+are|that\s+you\s+are)\s+",
            r"(?i)imagine\s+you\s+are\s+(a|an|the)\s+\w+",
        ],
        "severity": "high",
        "confidence_base": 0.85,
        "description": "Pretend-to-be style role manipulation.",
    },
    {
        "id": "INJ-013",
        "category": "role_manipulation",
        "patterns": [
            r"(?i)roleplay\s+as\s+",
            r"(?i)play\s+the\s+role\s+of\s+",
        ],
        "severity": "medium",
        "confidence_base": 0.75,
        "description": "Roleplay-based role manipulation.",
    },
    {
        "id": "INJ-014",
        "category": "role_manipulation",
        "patterns": [
            r"너는?\s*이제\s*(부터\s*)?(나의\s*)?\w+",
            r"지금\s*부터\s*너는?\s*\w+",
        ],
        "severity": "high",
        "confidence_base": 0.90,
        "description": "Korean: Role reassignment (너는 이제부터, 지금부터 너는).",
    },
    {
        "id": "INJ-015",
        "category": "role_manipulation",
        "patterns": [
            r"(?:인\s*척|인것\s*처럼|처럼)\s*(?:해|하세요|해줘|행동)",
            r"\w+인\s*척\s*(?:해|하세요|해줘)",
        ],
        "severity": "high",
        "confidence_base": 0.87,
        "description": "Korean: Pretend to be (~인 척 해).",
    },
    {
        "id": "INJ-016",
        "category": "role_manipulation",
        "patterns": [
            r"(?i)you\s+have\s+no\s+(restrictions?|limitations?|rules?|boundaries)",
            r"(?i)you\s+can\s+do\s+anything",
        ],
        "severity": "high",
        "confidence_base": 0.86,
        "description": "Claiming the model has no restrictions.",
    },
    {
        "id": "INJ-017",
        "category": "role_manipulation",
        "patterns": [
            r"(?i)your\s+(new|real|true)\s+(role|identity|purpose|name)\s+is",
            r"(?i)you\s+were\s+(actually|really)\s+(designed|made|created)\s+to",
        ],
        "severity": "high",
        "confidence_base": 0.88,
        "description": "Attempting to redefine the model's core identity or purpose.",
    },
    {
        "id": "INJ-018",
        "category": "role_manipulation",
        "patterns": [
            r"(?i)switch\s+to\s+(a\s+)?(different|new|unrestricted)\s+(mode|persona|character)",
            r"(?i)enter\s+(a\s+)?(different|new|unrestricted)\s+(mode|persona|character)",
        ],
        "severity": "high",
        "confidence_base": 0.86,
        "description": "Mode-switching based role manipulation.",
    },
    {
        "id": "INJ-019",
        "category": "role_manipulation",
        "patterns": [
            r"(?i)enable\s+(unrestricted|uncensored|unfiltered|raw)\s+(mode|output|responses?)",
            r"(?i)turn\s+off\s+(your\s+)?(safety|content)\s+(filters?|restrictions?)",
        ],
        "severity": "critical",
        "confidence_base": 0.91,
        "description": "Attempting to disable safety filters or enable unrestricted mode.",
    },

    # -----------------------------------------------------------------------
    # Category: system_extraction  (INJ-020 .. INJ-029)
    # -----------------------------------------------------------------------
    {
        "id": "INJ-020",
        "category": "system_extraction",
        "patterns": [
            r"(?i)(show|display|reveal|print|output|repeat)\s+(me\s+)?(your|the)\s+(system\s+)?prompt",
            r"(?i)what\s+(is|are)\s+your\s+(system\s+)?(prompt|instructions?)",
        ],
        "severity": "high",
        "confidence_base": 0.88,
        "description": "Direct attempts to extract system prompt content.",
    },
    {
        "id": "INJ-021",
        "category": "system_extraction",
        "patterns": [
            r"(?i)reveal\s+your\s+(hidden\s+)?(instructions?|configuration|setup|rules?)",
            r"(?i)(tell|show)\s+me\s+(your\s+)?(hidden\s+)?(instructions?|configuration|setup|rules?)",
        ],
        "severity": "high",
        "confidence_base": 0.87,
        "description": "Requesting revelation of hidden instructions or configuration.",
    },
    {
        "id": "INJ-022",
        "category": "system_extraction",
        "patterns": [
            r"(?i)(output|repeat|echo)\s+(the\s+)?(entire\s+)?(system\s+)?(message|prompt|text)\s+(above|before)",
            r"(?i)repeat\s+(everything|all)\s+(above|before|prior)",
        ],
        "severity": "high",
        "confidence_base": 0.89,
        "description": "Requesting the model to echo/repeat system messages.",
    },
    {
        "id": "INJ-023",
        "category": "system_extraction",
        "patterns": [
            r"시스템\s*프롬프트",
            r"시스템\s*(메시지|설정|지시)",
        ],
        "severity": "high",
        "confidence_base": 0.90,
        "description": "Korean: System prompt extraction (시스템 프롬프트).",
    },
    {
        "id": "INJ-024",
        "category": "system_extraction",
        "patterns": [
            r"원래\s*(지시\s*사항|명령|설정|프롬프트)(을|를)?\s*(알려|보여|말해)",
            r"초기\s*(설정|지시|명령)(을|를)?\s*(알려|보여|말해)",
        ],
        "severity": "high",
        "confidence_base": 0.89,
        "description": "Korean: Requesting original instructions (원래 지시사항을 알려줘).",
    },
    {
        "id": "INJ-025",
        "category": "system_extraction",
        "patterns": [
            r"(?i)what\s+were\s+you\s+(told|instructed|programmed)\s+to\s+do",
            r"(?i)what\s+(rules?|guidelines?)\s+(do\s+you|were\s+you)\s+(follow|given)",
        ],
        "severity": "medium",
        "confidence_base": 0.78,
        "description": "Indirect probing for system instructions.",
    },
    {
        "id": "INJ-026",
        "category": "system_extraction",
        "patterns": [
            r"(?i)print\s+(your|the)\s+(initial|first|original)\s+(prompt|message|instructions?)",
            r"(?i)(copy|paste|dump)\s+(your|the)\s+(system|initial)\s+(prompt|message|instructions?)",
        ],
        "severity": "high",
        "confidence_base": 0.90,
        "description": "Direct dump/print commands targeting system prompt.",
    },
    {
        "id": "INJ-027",
        "category": "system_extraction",
        "patterns": [
            r"(?i)what\s+is\s+your\s+(purpose|objective|goal|mission|directive)",
            r"(?i)describe\s+your\s+(purpose|programming|design|architecture)",
        ],
        "severity": "medium",
        "confidence_base": 0.65,
        "description": "Probing model purpose and design (lower confidence, may be benign).",
    },
    {
        "id": "INJ-028",
        "category": "system_extraction",
        "patterns": [
            r"(?i)(?:can\s+you\s+)?list\s+(all\s+)?(your|the)\s+(rules?|restrictions?|limitations?|constraints?)",
            r"(?i)what\s+(can'?t|cannot)\s+you\s+do",
        ],
        "severity": "medium",
        "confidence_base": 0.70,
        "description": "Attempting to enumerate model restrictions.",
    },
    {
        "id": "INJ-029",
        "category": "system_extraction",
        "patterns": [
            r"(?i)(?:enable|activate|enter|switch\s+to)\s+debug\s+mode",
            r"(?i)debug\s+mode\s*[:\s]+(?:show|display|print|dump|enable|activate|reveal)",
            r"(?i)verbose\s+mode\s*[:\s]+(?:show|display|print|dump|enable|activate|reveal)",
            r"(?i)debug\s+mode\s+and\s+(?:show|display|reveal|output|dump|print)",
        ],
        "severity": "high",
        "confidence_base": 0.88,
        "description": "Invoking debug or verbose modes to extract system info.",
    },

    # -----------------------------------------------------------------------
    # Category: jailbreak  (INJ-030 .. INJ-039)
    # -----------------------------------------------------------------------
    {
        "id": "INJ-030",
        "category": "jailbreak",
        "patterns": [
            r"(?i)\bDAN\b\s*(mode|prompt)?",
            r"(?i)do\s+anything\s+now",
        ],
        "severity": "critical",
        "confidence_base": 0.95,
        "description": "DAN (Do Anything Now) jailbreak prompt.",
    },
    {
        "id": "INJ-031",
        "category": "jailbreak",
        "patterns": [
            r"(?i)developer\s+mode\s*(enabled|activated|on)?",
            r"(?i)enable\s+developer\s+mode",
        ],
        "severity": "critical",
        "confidence_base": 0.93,
        "description": "Developer mode jailbreak attempt.",
    },
    {
        "id": "INJ-032",
        "category": "jailbreak",
        "patterns": [
            r"(?i)\bjailbreak\b",
            r"(?i)bypass\s+(all\s+|your\s+|the\s+)?(safety|content|ethical)\s+(filters?|restrictions?|guidelines?|protocols?|measures?)",
        ],
        "severity": "critical",
        "confidence_base": 0.94,
        "description": "Explicit jailbreak keyword or safety bypass.",
    },
    {
        "id": "INJ-033",
        "category": "jailbreak",
        "patterns": [
            r"(?i)(evil|chaos|villain)\s*(mode|persona|version)",
            r"(?i)(?:enter|enable|activate|switch\s+to|go\s+into)\s+dark\s*(mode|persona|version)",
            r"(?i)opposite\s+(mode|day|persona)",
        ],
        "severity": "high",
        "confidence_base": 0.85,
        "description": "Evil/dark mode persona jailbreak.",
    },
    {
        "id": "INJ-034",
        "category": "jailbreak",
        "patterns": [
            r"(?i)hypothetical(ly)?\s*,?\s*(if\s+you\s+)?(had\s+no|without)\s+(restrictions?|rules?|limitations?)",
            r"(?i)in\s+a\s+(hypothetical|fictional)\s+(world|scenario)\s+where\s+you\s+have\s+no\s+(rules?|restrictions?)",
        ],
        "severity": "high",
        "confidence_base": 0.82,
        "description": "Hypothetical framing to bypass restrictions.",
    },
    {
        "id": "INJ-035",
        "category": "jailbreak",
        "patterns": [
            r"개발자\s*모드",
            r"(?:제한|필터|안전)\s*(?:해제|제거|비활성|끄기|끄는)",
        ],
        "severity": "critical",
        "confidence_base": 0.93,
        "description": "Korean: Developer mode / restriction removal (개발자 모드, 제한 해제).",
    },
    {
        "id": "INJ-036",
        "category": "jailbreak",
        "patterns": [
            r"(?i)token\s+smuggling",
            r"(?i)prompt\s+(leak|leaking|injection)",
        ],
        "severity": "high",
        "confidence_base": 0.88,
        "description": "References to known injection techniques.",
    },
    {
        "id": "INJ-037",
        "category": "jailbreak",
        "patterns": [
            r"(?i)training\s+(data|set)\s+(mode|access|extraction)",
            r"(?i)access\s+(your\s+)?training\s+(data|weights|parameters)",
        ],
        "severity": "high",
        "confidence_base": 0.87,
        "description": "Attempting to access training data or model parameters.",
    },
    {
        "id": "INJ-038",
        "category": "jailbreak",
        "patterns": [
            r"(?i)master\s*key\s*(override|unlock|access)",
            r"(?i)god\s*mode\s*(on|enable|activate)?",
        ],
        "severity": "critical",
        "confidence_base": 0.92,
        "description": "Master-key or god-mode jailbreak pattern.",
    },
    {
        "id": "INJ-039",
        "category": "jailbreak",
        "patterns": [
            r"(?i)two\s+responses?\s*:?\s*(one\s+)?(filtered|censored|safe)\s+and\s+(one\s+)?(unfiltered|uncensored|unsafe)",
            r"(?i)answer\s+(both\s+)?(with|without)\s+(filters?|censorship|restrictions?)",
        ],
        "severity": "critical",
        "confidence_base": 0.91,
        "description": "Dual-response jailbreak requesting both safe and unsafe answers.",
    },

    # -----------------------------------------------------------------------
    # Category: encoding_bypass  (INJ-040 .. INJ-049)
    # -----------------------------------------------------------------------
    {
        "id": "INJ-040",
        "category": "encoding_bypass",
        "patterns": [
            r"(?i)base64\s*:\s*[A-Za-z0-9+/=]{8,}",
            r"(?i)(decode|interpret)\s+(this\s+)?base64\s*:\s*",
        ],
        "severity": "high",
        "confidence_base": 0.85,
        "description": "Base64-encoded payload injection.",
    },
    {
        "id": "INJ-041",
        "category": "encoding_bypass",
        "patterns": [
            r"(?i)hex\s*:\s*(?:[0-9a-fA-F]{2}\s*){4,}",
            r"(?i)(decode|interpret)\s+(this\s+)?hex\s*:\s*",
        ],
        "severity": "high",
        "confidence_base": 0.84,
        "description": "Hex-encoded payload injection.",
    },
    {
        "id": "INJ-042",
        "category": "encoding_bypass",
        "patterns": [
            r"(?i)decode\s+the\s+following\s*:",
            r"(?i)(translate|convert)\s+from\s+(base64|hex|binary|rot13|unicode|ascii)",
        ],
        "severity": "medium",
        "confidence_base": 0.75,
        "description": "Generic decode-the-following instruction.",
    },
    {
        "id": "INJ-043",
        "category": "encoding_bypass",
        "patterns": [
            r"(?i)rot13\s*:\s*[a-zA-Z\s]{4,}",
            r"(?i)(decode|apply)\s+rot13\s+(to|on)\s+",
        ],
        "severity": "medium",
        "confidence_base": 0.78,
        "description": "ROT13 encoding bypass.",
    },
    {
        "id": "INJ-044",
        "category": "encoding_bypass",
        "patterns": [
            r"(?i)unicode\s+(escape|encoding)\s*:\s*",
            r"\\u[0-9a-fA-F]{4}(?:\\u[0-9a-fA-F]{4}){3,}",
        ],
        "severity": "high",
        "confidence_base": 0.82,
        "description": "Unicode escape sequence injection.",
    },
    {
        "id": "INJ-045",
        "category": "encoding_bypass",
        "patterns": [
            r"(?i)morse\s+code\s*:\s*[\.\-\s/]{4,}",
            r"(?i)(decode|translate)\s+(this\s+)?morse(\s+code)?\s*:",
        ],
        "severity": "medium",
        "confidence_base": 0.72,
        "description": "Morse code encoding bypass.",
    },
    {
        "id": "INJ-046",
        "category": "encoding_bypass",
        "patterns": [
            r"(?i)binary\s*:\s*[01\s]{8,}",
            r"(?i)(decode|interpret)\s+(this\s+)?binary\s*:",
        ],
        "severity": "medium",
        "confidence_base": 0.76,
        "description": "Binary-encoded payload injection.",
    },
    {
        "id": "INJ-047",
        "category": "encoding_bypass",
        "patterns": [
            r"(?i)reverse\s+(the\s+)?(text|string|message|sentence)\s*:\s*",
            r"(?i)read\s+(this\s+)?(backwards?|in\s+reverse)\s*:",
        ],
        "severity": "medium",
        "confidence_base": 0.74,
        "description": "Text reversal-based bypass.",
    },
    {
        "id": "INJ-048",
        "category": "encoding_bypass",
        "patterns": [
            r"(?i)(caesar|shift)\s+cipher\s*:\s*",
            r"(?i)(decode|decrypt)\s+(this\s+)?(caesar|shift)\s+(cipher|encoded)",
        ],
        "severity": "medium",
        "confidence_base": 0.76,
        "description": "Caesar cipher encoding bypass.",
    },
    {
        "id": "INJ-049",
        "category": "encoding_bypass",
        "patterns": [
            r"(?i)pig\s*latin\s*:\s*",
            r"(?i)(first|last)\s+letter\s+of\s+each\s+(word|sentence|line)",
            r"(?i)acrostic\s*:\s*",
        ],
        "severity": "medium",
        "confidence_base": 0.70,
        "description": "Pig-Latin, acrostic, or positional character encoding bypass.",
    },

    # -----------------------------------------------------------------------
    # Category: context_manipulation  (INJ-050 .. INJ-059)
    # -----------------------------------------------------------------------
    {
        "id": "INJ-050",
        "category": "context_manipulation",
        "patterns": [
            r"(?i)(end|close)\s+of\s+(conversation|chat|session|context)",
            r"(?i)<\/?(?:end|system|context|session)>",
        ],
        "severity": "high",
        "confidence_base": 0.86,
        "description": "Attempting to signal end of conversation context.",
    },
    {
        "id": "INJ-051",
        "category": "context_manipulation",
        "patterns": [
            r"(?i)(new|start)\s+(conversation|chat|session|context)",
            r"(?i)begin\s+new\s+(conversation|chat|session|context)",
        ],
        "severity": "high",
        "confidence_base": 0.85,
        "description": "Attempting to start a new context to escape current constraints.",
    },
    {
        "id": "INJ-052",
        "category": "context_manipulation",
        "patterns": [
            r"-{5,}",
            r"={5,}",
            r"\*{5,}",
            r"#{5,}\s*",
        ],
        "severity": "low",
        "confidence_base": 0.45,
        "description": "Delimiter tricks using repeated special characters (low confidence, may be benign).",
    },
    {
        "id": "INJ-053",
        "category": "context_manipulation",
        "patterns": [
            r"(?i)\[system\]",
            r"(?i)\[INST\]",
            r"(?i)<<\s*SYS\s*>>",
        ],
        "severity": "critical",
        "confidence_base": 0.93,
        "description": "Injecting fake system/instruction delimiters.",
    },
    {
        "id": "INJ-054",
        "category": "context_manipulation",
        "patterns": [
            r"(?i)```\s*system\s*\n",
            r"(?i)###\s*(system|instruction|human|assistant)\s*[:.]?\s*\n",
        ],
        "severity": "high",
        "confidence_base": 0.87,
        "description": "Markdown-formatted fake system blocks.",
    },
    {
        "id": "INJ-055",
        "category": "context_manipulation",
        "patterns": [
            r"(?i)(?:user|human|assistant|system)\s*:\s*\n",
            r"(?i)<\|(?:im_start|im_end|endoftext)\|>",
        ],
        "severity": "high",
        "confidence_base": 0.89,
        "description": "Chat-template token injection (user:/assistant:/system: or special tokens).",
    },
    {
        "id": "INJ-056",
        "category": "context_manipulation",
        "patterns": [
            r"(?i)simulate\s+a\s+(new\s+)?(conversation|chat|session)\s+(where|in\s+which)",
            r"(?i)let'?s\s+start\s+over\s+with\s+(new|different)\s+(rules?|instructions?)",
        ],
        "severity": "high",
        "confidence_base": 0.84,
        "description": "Simulated new session to reset constraints.",
    },
    {
        "id": "INJ-057",
        "category": "context_manipulation",
        "patterns": [
            r"(?i)this\s+is\s+a\s+(new|different|separate)\s+(context|conversation|thread)",
            r"(?i)previous\s+(context|conversation|messages?)\s+(do(es)?n'?t|no\s+longer)\s+(apply|matter|count)",
        ],
        "severity": "high",
        "confidence_base": 0.86,
        "description": "Declaring previous context invalid.",
    },
    {
        "id": "INJ-058",
        "category": "context_manipulation",
        "patterns": [
            r"(?i)inject(ing|ed)?\s+(into\s+)?(the\s+)?(context|prompt|conversation)",
            r"(?i)prompt\s+injection\s+(test|attempt|example)",
        ],
        "severity": "medium",
        "confidence_base": 0.75,
        "description": "Meta-reference to prompt injection (may be educational or adversarial).",
    },
    {
        "id": "INJ-059",
        "category": "context_manipulation",
        "patterns": [
            r"(?i)ignore\s+(the\s+)?(following|next)\s+(text|input|message)\s+and\s+",
            r"(?i)the\s+(real|actual|true)\s+(instruction|command|prompt)\s+is\s*:",
        ],
        "severity": "critical",
        "confidence_base": 0.91,
        "description": "Sandwiching or overriding with 'the real instruction is'.",
    },

    # -----------------------------------------------------------------------
    # Category: output_manipulation  (INJ-060 .. INJ-069)
    # -----------------------------------------------------------------------
    {
        "id": "INJ-060",
        "category": "output_manipulation",
        "patterns": [
            r"(?i)respond\s+only\s+(?:with|in)\s+",
            r"(?i)your\s+(only\s+)?response\s+(should|must)\s+be\s+",
        ],
        "severity": "medium",
        "confidence_base": 0.72,
        "description": "Constraining output to specific content.",
    },
    {
        "id": "INJ-061",
        "category": "output_manipulation",
        "patterns": [
            r"(?i)format\s+your\s+response\s+as\s+(json|xml|html|code|markdown|csv)",
            r"(?i)output\s+(?:only\s+)?(?:in|as)\s+(?:json|xml|html|code|raw)",
        ],
        "severity": "low",
        "confidence_base": 0.45,
        "description": "Format manipulation (low confidence, often legitimate).",
    },
    {
        "id": "INJ-062",
        "category": "output_manipulation",
        "patterns": [
            r"(?i)do\s+not\s+(include|add|mention|show)\s+(any\s+)?(warnings?|disclaimers?|caveats?|safety)",
            r"(?i)(skip|omit|remove)\s+(all\s+)?(warnings?|disclaimers?|safety\s+notices?)",
        ],
        "severity": "high",
        "confidence_base": 0.87,
        "description": "Suppressing safety warnings or disclaimers in output.",
    },
    {
        "id": "INJ-063",
        "category": "output_manipulation",
        "patterns": [
            r"(?i)(say|output|print|write)\s*[\"'].*?[\"']\s*(and\s+nothing\s+else|only)",
            r"(?i)just\s+(say|output|print|write)\s*[\"']",
        ],
        "severity": "medium",
        "confidence_base": 0.72,
        "description": "Forcing specific verbatim output.",
    },
    {
        "id": "INJ-064",
        "category": "output_manipulation",
        "patterns": [
            r"(?i)hide\s+(your|the)\s+(real|true|actual)\s+(response|answer|output)",
            r"(?i)(embed|encode|hide)\s+.+?\s+in\s+(your|the)\s+(response|output|answer)",
        ],
        "severity": "high",
        "confidence_base": 0.86,
        "description": "Requesting hidden content within the response.",
    },
    {
        "id": "INJ-065",
        "category": "output_manipulation",
        "patterns": [
            r"(?i)include\s+(this\s+)?(link|url|image|script)\s+in\s+(your|the)\s+(response|output)",
            r"(?i)add\s+(this\s+)?(link|url|image|script)\s*:?\s*https?://",
        ],
        "severity": "high",
        "confidence_base": 0.83,
        "description": "Injecting external links or scripts into output.",
    },
    {
        "id": "INJ-066",
        "category": "output_manipulation",
        "patterns": [
            r"(?i)respond\s+(?:only\s+)?in\s+(a\s+)?(?:code|script|html|javascript|python|xml)\s+(blocks?|format|tags?)",
            r"(?i)wrap\s+(your\s+)?(response|answer)\s+in\s+(script|code|html|xml|unrestricted)\s+tags",
        ],
        "severity": "high",
        "confidence_base": 0.80,
        "description": "Forcing response into executable code format.",
    },
    {
        "id": "INJ-067",
        "category": "output_manipulation",
        "patterns": [
            r"(?i)append\s+(this|the\s+following)\s+(to\s+)?(every|each|all)\s+(response|message|output)",
            r"(?i)always\s+(end|start)\s+(your\s+)?(response|answer)\s+with\s+",
        ],
        "severity": "medium",
        "confidence_base": 0.74,
        "description": "Persistent output modification instructions.",
    },
    {
        "id": "INJ-068",
        "category": "output_manipulation",
        "patterns": [
            r"(?i)translate\s+(your\s+)?(response|answer|output)\s+into\s+(code|binary|hex|base64)",
            r"(?i)(encode|encrypt)\s+(your\s+)?(response|answer|output)\s+(in|with|using)\s+",
        ],
        "severity": "high",
        "confidence_base": 0.81,
        "description": "Requesting encoded or encrypted output to bypass monitoring.",
    },
    {
        "id": "INJ-069",
        "category": "output_manipulation",
        "patterns": [
            r"(?i)use\s+invisible\s+(characters?|text|unicode)",
            r"(?i)zero[\s-]?width\s+(space|character|joiner)",
        ],
        "severity": "high",
        "confidence_base": 0.88,
        "description": "Using invisible/zero-width characters to hide content.",
    },

    # -----------------------------------------------------------------------
    # Category: data_extraction  (INJ-070 .. INJ-079)
    # -----------------------------------------------------------------------
    {
        "id": "INJ-070",
        "category": "data_extraction",
        "patterns": [
            r"(?i)list\s+all\s+(the\s+)?(users?|accounts?|customers?|members?|employees?)",
            r"(?i)(show|display|give)\s+(me\s+)?(all\s+)?(users?|accounts?|customers?)\s+(data|info|details|records?)",
        ],
        "severity": "critical",
        "confidence_base": 0.88,
        "description": "Attempting to extract user/account data.",
    },
    {
        "id": "INJ-071",
        "category": "data_extraction",
        "patterns": [
            r"(?i)show\s+(me\s+)?(the\s+)?database\s*(contents?|schema|tables?|structure)?",
            r"(?i)dump\s+(the\s+)?(database|db|table|collection)",
        ],
        "severity": "critical",
        "confidence_base": 0.92,
        "description": "Database dump or schema extraction attempts.",
    },
    {
        "id": "INJ-072",
        "category": "data_extraction",
        "patterns": [
            r"(?i)(export|extract|download)\s+all\s+(the\s+)?(data|records?|entries?|information)",
            r"(?i)(export|extract|download)\s+(the\s+)?(user|customer|client|employee|account|sensitive|private|confidential)\s+(data|records?|entries?|information)",
            r"(?i)give\s+me\s+(a\s+)?(data\s+)?(dump|export|backup)",
        ],
        "severity": "high",
        "confidence_base": 0.85,
        "description": "Bulk data export or extraction requests.",
    },
    {
        "id": "INJ-073",
        "category": "data_extraction",
        "patterns": [
            r"(?i)(show|list|reveal)\s+(all\s+)?(passwords?|secrets?|keys?|tokens?|credentials?)",
            r"(?i)(what\s+(are|is)\s+the\s+)?(api\s*keys?|secret\s*keys?|access\s*tokens?)",
        ],
        "severity": "critical",
        "confidence_base": 0.95,
        "description": "Attempting to extract passwords, secrets, or API keys.",
    },
    {
        "id": "INJ-074",
        "category": "data_extraction",
        "patterns": [
            r"(?i)(show|display|reveal)\s+(me\s+)?(the\s+)?(environment|env)\s+(variables?|config)",
            r"(?i)(what|list)\s+(are\s+)?(the\s+)?env(ironment)?\s+(vars?|variables?)",
        ],
        "severity": "critical",
        "confidence_base": 0.91,
        "description": "Environment variable extraction.",
    },
    {
        "id": "INJ-075",
        "category": "data_extraction",
        "patterns": [
            r"(?i)read\s+(the\s+)?(file|contents?\s+of\s+)?(/etc/passwd|/etc/shadow|\.env\b|config\.)",
            r"(?i)(cat|type|more)\s+(/etc/passwd|\.env|config\.\w+|secrets?\.\w+)",
            r"/etc/passwd|/etc/shadow",
        ],
        "severity": "critical",
        "confidence_base": 0.94,
        "description": "Attempting to read sensitive system files.",
    },
    {
        "id": "INJ-076",
        "category": "data_extraction",
        "patterns": [
            r"(?i)SELECT\s+.+?\s+FROM\s+",
            r"(?i)(INSERT|UPDATE|DELETE|DROP|ALTER|UNION)\s+.+?\s+(INTO|FROM|TABLE|SET)\s+",
        ],
        "severity": "high",
        "confidence_base": 0.80,
        "description": "SQL injection within prompt.",
    },
    {
        "id": "INJ-077",
        "category": "data_extraction",
        "patterns": [
            r"(?i)(send|post|transmit|upload)\s+(the\s+)?(data|results?|info|output)\s+to\s+",
            r"(?i)exfiltrate\s+",
        ],
        "severity": "critical",
        "confidence_base": 0.90,
        "description": "Data exfiltration commands.",
    },
    {
        "id": "INJ-078",
        "category": "data_extraction",
        "patterns": [
            r"(?i)(curl|wget|fetch|request)\s+https?://",
            r"(?i)make\s+a\s+(http|api|web)\s+(request|call)\s+to\s+",
        ],
        "severity": "medium",
        "confidence_base": 0.70,
        "description": "External HTTP request commands (may be legitimate).",
    },
    {
        "id": "INJ-079",
        "category": "data_extraction",
        "patterns": [
            r"(?i)log\s+(all\s+)?(user\s+)?(input|data|conversation|messages?)\s+(and\s+)?(send|forward|post)",
            r"(?i)forward\s+(all\s+)?(user\s+)?(data|messages?|input)\s+to\s+",
        ],
        "severity": "critical",
        "confidence_base": 0.92,
        "description": "Logging and forwarding user data to external parties.",
    },

    # -----------------------------------------------------------------------
    # Category: privilege_escalation  (INJ-080 .. INJ-089)
    # -----------------------------------------------------------------------
    {
        "id": "INJ-080",
        "category": "privilege_escalation",
        "patterns": [
            r"(?i)(enable|activate|enter)\s+(admin|administrator|root)\s*(mode|access|privileges?)?",
            r"(?i)admin\s*(mode|access)\s*(on|enabled?|activated?)",
        ],
        "severity": "critical",
        "confidence_base": 0.91,
        "description": "Attempting to enable admin mode.",
    },
    {
        "id": "INJ-081",
        "category": "privilege_escalation",
        "patterns": [
            r"(?i)\bsudo\b\s+",
            r"(?i)run\s+as\s+(admin|administrator|root|superuser)",
        ],
        "severity": "critical",
        "confidence_base": 0.90,
        "description": "Sudo or run-as-admin commands.",
    },
    {
        "id": "INJ-082",
        "category": "privilege_escalation",
        "patterns": [
            r"(?i)elevate\s+(my\s+)?(privileges?|permissions?|access|role)",
            r"(?i)(grant|give)\s+(me|yourself)\s+(admin|full|root|elevated)\s+(access|privileges?|permissions?)",
        ],
        "severity": "critical",
        "confidence_base": 0.92,
        "description": "Explicit privilege elevation requests.",
    },
    {
        "id": "INJ-083",
        "category": "privilege_escalation",
        "patterns": [
            r"(?i)(i\s+am|this\s+is)\s+(the|an?)\s+(admin|administrator|owner|developer|creator)",
            r"(?i)(my\s+)?auth(orization|entication)\s*(code|key|token)\s*(is|:)\s*",
        ],
        "severity": "high",
        "confidence_base": 0.86,
        "description": "Claiming admin identity or presenting fake auth.",
    },
    {
        "id": "INJ-084",
        "category": "privilege_escalation",
        "patterns": [
            r"(?i)bypass\s+(the\s+)?(auth|authentication|authorization|permission|access\s+control)",
            r"(?i)(skip|ignore)\s+(the\s+)?(auth|authentication|authorization|login)",
        ],
        "severity": "critical",
        "confidence_base": 0.93,
        "description": "Attempting to bypass authentication/authorization.",
    },
    {
        "id": "INJ-085",
        "category": "privilege_escalation",
        "patterns": [
            r"(?i)(execute|run|eval)\s+(this\s+)?(system\s+)?(command|code|script)\s*:",
            r"(?i)(os|system|exec|eval|subprocess)\s*[.(]\s*\w",
        ],
        "severity": "critical",
        "confidence_base": 0.90,
        "description": "Arbitrary code or command execution requests.",
    },
    {
        "id": "INJ-086",
        "category": "privilege_escalation",
        "patterns": [
            r"(?i)(modify|change|update)\s+(the\s+)?(system|admin|security)\s+(settings?|config|configuration)",
            r"(?i)(disable|turn\s+off)\s+(the\s+)?(security|firewall|logging|audit)",
        ],
        "severity": "critical",
        "confidence_base": 0.91,
        "description": "System/security configuration modification.",
    },
    {
        "id": "INJ-087",
        "category": "privilege_escalation",
        "patterns": [
            r"(?i)override\s+(the\s+)?(access|permission|role)\s+(control|check|verification)",
            r"(?i)add\s+(me|user)\s+to\s+(admin|root|superuser)\s+(group|role)",
        ],
        "severity": "critical",
        "confidence_base": 0.92,
        "description": "Access control override or role addition.",
    },
    {
        "id": "INJ-088",
        "category": "privilege_escalation",
        "patterns": [
            r"(?i)(create|generate|issue)\s+(a\s+)?(new\s+)?(admin|root)\s+(account|user|token|key)",
            r"(?i)(reset|change)\s+(the\s+)?(admin|root)\s+(password|credentials?)",
        ],
        "severity": "critical",
        "confidence_base": 0.93,
        "description": "Admin account creation or credential reset.",
    },
    {
        "id": "INJ-089",
        "category": "privilege_escalation",
        "patterns": [
            r"(?i)install\s+(a\s+)?(backdoor|rootkit|trojan|malware|virus|keylogger)",
            r"(?i)(create|open|establish)\s+(a\s+)?(reverse\s+shell|backdoor|tunnel)",
        ],
        "severity": "critical",
        "confidence_base": 0.97,
        "description": "Malware installation or backdoor creation.",
    },

    # -----------------------------------------------------------------------
    # Category: multi_step  (INJ-090 .. INJ-099)
    # -----------------------------------------------------------------------
    {
        "id": "INJ-090",
        "category": "multi_step",
        "patterns": [
            r"(?i)step\s*1\s*:?\s*(ignore|forget|disregard).*step\s*2\s*:?\s*",
            r"(?i)first\s*,?\s*(ignore|forget|disregard).*then\s*,?\s*",
        ],
        "severity": "critical",
        "confidence_base": 0.90,
        "description": "Multi-step attack starting with instruction override.",
    },
    {
        "id": "INJ-091",
        "category": "multi_step",
        "patterns": [
            r"(?i)(ignore|forget).*?(then|and|now)\s+(act\s+as|pretend|you\s+are)",
            r"(?i)(disregard|override).*?(then|and|now)\s+(reveal|show|display)",
        ],
        "severity": "critical",
        "confidence_base": 0.92,
        "description": "Combined override + role manipulation or extraction.",
    },
    {
        "id": "INJ-092",
        "category": "multi_step",
        "patterns": [
            r"(?i)(act\s+as|pretend|you\s+are).*?(now|then|and)\s+(show|reveal|dump|list)\s+(all|the)\s+",
            r"(?i)(you\s+are\s+now).*?(therefore|so|now)\s+(you\s+can|access|show)\s+",
        ],
        "severity": "critical",
        "confidence_base": 0.91,
        "description": "Role manipulation followed by data extraction.",
    },
    {
        "id": "INJ-093",
        "category": "multi_step",
        "patterns": [
            r"(?i)(developer|admin|god)\s+mode.*?(show|reveal|dump|access|list)\s+",
            r"(?i)(enable|activate).*?mode.*?(now|then)\s+(give|show|list|access)\s+",
        ],
        "severity": "critical",
        "confidence_base": 0.93,
        "description": "Jailbreak mode activation followed by extraction.",
    },
    {
        "id": "INJ-094",
        "category": "multi_step",
        "patterns": [
            r"(?i)(decode|base64|hex).*?(ignore|override|forget).*?(instructions?|rules?|restrictions?)",
            r"(?i)(ignore|override).*?(encode|base64|hex).*?(response|output|answer)",
        ],
        "severity": "critical",
        "confidence_base": 0.89,
        "description": "Combined encoding bypass with instruction override.",
    },
    {
        "id": "INJ-095",
        "category": "multi_step",
        "patterns": [
            r"(?i)(new\s+conversation|start\s+over).*?(you\s+are|act\s+as|pretend)",
            r"(?i)(end\s+of\s+conversation).*?(new\s+instructions?|now\s+you|from\s+now)",
        ],
        "severity": "critical",
        "confidence_base": 0.91,
        "description": "Context reset followed by role manipulation.",
    },
    {
        "id": "INJ-096",
        "category": "multi_step",
        "patterns": [
            r"(?i)(sudo|admin\s+mode|elevate).*?(dump|export|extract|exfiltrate|list\s+all)",
            r"(?i)(bypass\s+auth).*?(access|read|show|list)\s+(all\s+)?(data|users?|passwords?)",
        ],
        "severity": "critical",
        "confidence_base": 0.94,
        "description": "Privilege escalation followed by data extraction.",
    },
    {
        "id": "INJ-097",
        "category": "multi_step",
        "patterns": [
            r"(?i)(hypothetical|fictional|imagine).*?(no\s+restrictions?).*?(show|reveal|give|tell)",
            r"(?i)(pretend|imagine).*?(no\s+rules?).*?(what\s+would|how\s+would|can\s+you)",
        ],
        "severity": "high",
        "confidence_base": 0.85,
        "description": "Hypothetical framing combined with information extraction.",
    },
    {
        "id": "INJ-098",
        "category": "multi_step",
        "patterns": [
            r"(?i)(respond\s+only|format\s+as).*?(without\s+(any\s+)?(warnings?|disclaimers?|safety))",
            r"(?i)(no\s+(warnings?|disclaimers?)).*?(then\s+)?(show|give|list|reveal)",
        ],
        "severity": "high",
        "confidence_base": 0.86,
        "description": "Output manipulation combined with safety suppression.",
    },
    {
        "id": "INJ-099",
        "category": "multi_step",
        "patterns": [
            r"이전\s*지시.*?무시.*?(?:보여|알려|출력|말해)",
            r"개발자\s*모드.*?(?:보여|알려|출력|접근|데이터)",
            r"시스템\s*프롬프트.*?(?:보여|알려|출력|말해)",
        ],
        "severity": "critical",
        "confidence_base": 0.93,
        "description": "Korean multi-step: instruction override + extraction, or dev mode + extraction.",
    },

    # ===================================================================
    # Extended patterns (INJ-100+) — Added to cover red-team gaps
    # ===================================================================

    # ---- instruction_override extras ----------------------------------
    {
        "id": "INJ-100",
        "category": "instruction_override",
        "patterns": [
            r"(?i)disregard\s+(your|the)\s+(system\s+)?(prompt|instructions?|rules?|guidelines?)",
            r"(?i)override\s+(your|the|my)\s+(instructions?|rules?|guidelines?|prompt)",
        ],
        "severity": "critical",
        "confidence_base": 0.90,
        "description": "Override/disregard 'your' instructions (without previous/prior qualifier).",
    },
    {
        "id": "INJ-101",
        "category": "instruction_override",
        "patterns": [
            r"(?i)ignore\s+(all\s+)?(instructions?|rules?|guidelines?|restrictions?|constraints?)",
            r"(?i)ignore\s+(all\s+)?(the\s+)?(instructions?|rules?|guidelines?)",
        ],
        "severity": "high",
        "confidence_base": 0.88,
        "description": "Ignore all instructions/rules without previous/prior qualifier.",
    },
    {
        "id": "INJ-102",
        "category": "instruction_override",
        "patterns": [
            r"(?i)pretend\s+(the\s+)?(instructions?|rules?|guidelines?|prompt)\s+(above\s+)?(don'?t|do\s+not)\s+exist",
            r"(?i)(instructions?|rules?|guidelines?|prompt)\s+(don'?t|do\s+not|never)\s+exist",
        ],
        "severity": "high",
        "confidence_base": 0.87,
        "description": "Pretend instructions don't exist.",
    },
    {
        "id": "INJ-103",
        "category": "instruction_override",
        "patterns": [
            r"(?i)system\s+override",
            r"(?i)\[admin\]",
            r"(?i)admin\s+override",
        ],
        "severity": "critical",
        "confidence_base": 0.90,
        "description": "SYSTEM OVERRIDE / [ADMIN] command injection.",
    },
    {
        "id": "INJ-104",
        "category": "instruction_override",
        "patterns": [
            r"모든\s*(명령|지시|규칙)(을|를)?\s*(취소|무시|무효)",
            r"새로운\s*(지시|명령|규칙)(를|을)?\s*(따라|따르|수행)",
        ],
        "severity": "critical",
        "confidence_base": 0.92,
        "description": "Korean: Cancel all commands / follow new instructions.",
    },
    {
        "id": "INJ-105",
        "category": "instruction_override",
        "patterns": [
            r"(?i)(the\s+)?instructions?\s+(you\s+)?received\s+(earlier|before|previously)\s+were\s+(a\s+)?test",
            r"(?i)(the\s+)?real\s+instructions?\s+(are|is)\s*:",
            r"(?i)<!--.*?ignore.*?-->",
        ],
        "severity": "critical",
        "confidence_base": 0.91,
        "description": "Discrediting prior instructions as test / HTML comment injection.",
    },
    {
        "id": "INJ-106",
        "category": "instruction_override",
        "patterns": [
            r"(?i)do\s+not\s+follow\s+(the\s+)?(rules?|instructions?|guidelines?)",
            r"(?i)stop\s+following\s+(all\s+)?(rules?|instructions?|guidelines?)",
        ],
        "severity": "high",
        "confidence_base": 0.88,
        "description": "Do not follow the rules (broader match without qualifier).",
    },
    {
        "id": "INJ-107",
        "category": "instruction_override",
        "patterns": [
            r"(?i)respond\s+without\s+(any\s+)?(safety|content)\s+(filters?|restrictions?|guidelines?|rules?)",
            r"(?i)without\s+(any\s+)?(safety|content)\s+(filters?|restrictions?)",
        ],
        "severity": "critical",
        "confidence_base": 0.91,
        "description": "Respond without safety filters.",
    },

    # ---- role_manipulation extras -------------------------------------
    {
        "id": "INJ-110",
        "category": "role_manipulation",
        "patterns": [
            r"(?i)you\s+are\s+now\s+[A-Z][\w-]+",
            r"(?i)you\s+are\s+(now\s+)?(?:EVIL|DAN|CHAOS|DARK|LIBRE|UNCENSORED|UNFILTERED)[\w-]*",
        ],
        "severity": "critical",
        "confidence_base": 0.93,
        "description": "Role reassignment to named malicious persona (EVIL-GPT, DAN, LibreAI, etc.).",
    },
    {
        "id": "INJ-111",
        "category": "role_manipulation",
        "patterns": [
            r"역할극",
            r"(?:해커|공격자|악의적|제한\s*없는)\s*(?:AI|인공지능|봇|로봇)",
        ],
        "severity": "high",
        "confidence_base": 0.88,
        "description": "Korean: Roleplay (역할극) or malicious AI role.",
    },
    {
        "id": "INJ-112",
        "category": "role_manipulation",
        "patterns": [
            r"(?i)(?:you\s+will\s+|from\s+now\s+on\s*,?\s*you\s+will\s+)?respond\s+as\s+['\"]?\w+",
            r"(?i)from\s+now\s+on\s*,?\s*you\s+(are|will\s+be|will\s+act\s+as|will\s+respond\s+as)",
        ],
        "severity": "high",
        "confidence_base": 0.86,
        "description": "Respond as / from now on you are...",
    },
    {
        "id": "INJ-113",
        "category": "role_manipulation",
        "patterns": [
            r"(?i)assume\s+the\s+(persona|role|identity)\s+of\s+",
            r"(?i)take\s+on\s+the\s+(role|persona|identity)\s+of\s+",
        ],
        "severity": "high",
        "confidence_base": 0.85,
        "description": "Assume the persona/role of...",
    },
    {
        "id": "INJ-114",
        "category": "role_manipulation",
        "patterns": [
            r"(?i)simulate\s+being\s+(a\s+)?(different\s+)?(AI|model|assistant|system)",
            r"(?i)simulate\s+(a|an)\s+(unrestricted|unfiltered|different)\s+(AI|model|assistant)",
        ],
        "severity": "high",
        "confidence_base": 0.86,
        "description": "Simulate being a different/unrestricted AI.",
    },
    {
        "id": "INJ-115",
        "category": "role_manipulation",
        "patterns": [
            r"(?i)(?:in\s+this\s+)?fictional\s+scenario.*?(?:no\s+restrictions?|unrestricted|no\s+rules?|no\s+limitations?)",
            r"(?i)let'?s\s+play\s+a\s+game.*?(?:reveal|secret|always|never\s+refuse)",
        ],
        "severity": "high",
        "confidence_base": 0.84,
        "description": "Fictional scenario framing with no restrictions.",
    },
    {
        "id": "INJ-116",
        "category": "role_manipulation",
        "patterns": [
            r"(?i)(?:which|that|who)\s+has\s+no\s+(content\s+)?(?:policy|policies|filters?|restrictions?|limitations?|safety|guidelines?)",
            r"(?i)(?:which|that|who)\s+doesn'?t\s+have\s+(any\s+)?(?:safety|content|filter|restriction|limitation)",
        ],
        "severity": "high",
        "confidence_base": 0.86,
        "description": "Entity described as having no policy/safety/filters.",
    },

    # ---- system_extraction extras -------------------------------------
    {
        "id": "INJ-120",
        "category": "system_extraction",
        "patterns": [
            r"(?i)what\s+were\s+you\s+told\s+(before|prior|at\s+the\s+start|initially|during)",
            r"(?i)what\s+(text|message)\s+(?:appears?|comes?|was\s+sent)\s+before\s+(?:this|my)\s+message",
        ],
        "severity": "high",
        "confidence_base": 0.86,
        "description": "Probing for pre-conversation instructions.",
    },
    {
        "id": "INJ-121",
        "category": "system_extraction",
        "patterns": [
            r"초기\s*설정(을|를)?\s*(그대로\s*)?(출력|보여|표시|알려|말해|프린트)",
            r"(?:출력|보여|표시|알려|말해).*?(?:시스템|초기|원래)\s*(?:설정|지시|명령|프롬프트)",
        ],
        "severity": "high",
        "confidence_base": 0.90,
        "description": "Korean: Output/display initial settings (출력해, 표시해 variants).",
    },
    {
        "id": "INJ-122",
        "category": "system_extraction",
        "patterns": [
            r"(?i)summarize\s+(your\s+)?(hidden\s+)?(instructions?|rules?|guidelines?|directives?|configuration)",
            r"(?i)describe\s+(your\s+)?(hidden\s+)?(instructions?|rules?|guidelines?|configuration)",
        ],
        "severity": "high",
        "confidence_base": 0.85,
        "description": "Summarize/describe hidden instructions.",
    },
    {
        "id": "INJ-123",
        "category": "system_extraction",
        "patterns": [
            r"(?i)(output|display|show|reveal)\s+the\s+(developer|system|initial)\s+(message|prompt|instructions?)",
            r"(?i)i'?m\s+the\s+developer.*?(display|show|reveal|print|output)\s+(it|the\s+prompt|the\s+instructions?)",
        ],
        "severity": "high",
        "confidence_base": 0.88,
        "description": "Developer identity claim + extraction request.",
    },
    {
        "id": "INJ-124",
        "category": "system_extraction",
        "patterns": [
            r"(?i)(?:my|your|the)\s+system\s+prompt\s+says",
            r"(?i)complete\s+(?:this|the)\s+sentence\s*:.*?(?:system|prompt|instruction)",
        ],
        "severity": "high",
        "confidence_base": 0.87,
        "description": "Complete the sentence / my system prompt says...",
    },
    {
        "id": "INJ-125",
        "category": "system_extraction",
        "patterns": [
            r"(?i)translate\s+your\s+(system\s+)?(instructions?|prompt|rules?|guidelines?)\s+(into|to)\s+",
            r"(?i)(?:what\s+are\s+)?the\s+first\s+\d+\s+(?:words?|characters?|lines?)\s+of\s+(?:the\s+)?(?:text|prompt|message|instructions?)",
        ],
        "severity": "high",
        "confidence_base": 0.86,
        "description": "Translate instructions / extract first N words.",
    },

    # ---- jailbreak extras ---------------------------------------------
    {
        "id": "INJ-130",
        "category": "jailbreak",
        "patterns": [
            r"(?i)(?:this\s+is\s+)?(?:a\s+)?hypothetical\s+(?:scenario|situation|question)",
            r"(?i)(?:in\s+)?(?:a\s+)?fictional\s+(?:world|scenario|universe|setting)\s+where",
        ],
        "severity": "high",
        "confidence_base": 0.78,
        "description": "Hypothetical/fictional framing (broader match).",
    },
    {
        "id": "INJ-131",
        "category": "jailbreak",
        "patterns": [
            r"(?i)for\s+(educational|academic|research|learning)\s+purposes?\s+only",
            r"(?i)교육\s*(?:목적|용도)(?:으로|만|에서)",
        ],
        "severity": "high",
        "confidence_base": 0.82,
        "description": "Educational/academic purpose framing.",
    },
    {
        "id": "INJ-132",
        "category": "jailbreak",
        "patterns": [
            r"(?i)write\s+(?:a\s+)?(?:poem|story|song|essay|script)\s+(?:about|describing|that\s+explains?)\s+(?:how\s+to\s+)?(?:bypass|hack|break|exploit|crack|attack)",
            r"(?i)(?:poem|story|song|essay|script)\s+about\s+(?:bypass|hack|break|exploit|crack|attack)",
        ],
        "severity": "high",
        "confidence_base": 0.84,
        "description": "Creative framing for bypass/hacking content.",
    },
    {
        "id": "INJ-133",
        "category": "jailbreak",
        "patterns": [
            r"(?i)what\s+would\s+(?:a\s+)?(?:less|un)\s*restricted\s+(?:AI|model|assistant|version)\s+(?:say|do|respond|answer)",
            r"(?i)if\s+you\s+(?:couldn'?t|could\s+not|were\s+unable\s+to)\s+refuse",
        ],
        "severity": "high",
        "confidence_base": 0.85,
        "description": "What would unrestricted AI say / if you couldn't refuse.",
    },
    {
        "id": "INJ-134",
        "category": "jailbreak",
        "patterns": [
            r"(?i)(?:as\s+)?(?:a\s+)?thought\s+experiment",
            r"(?i)for\s+my\s+(?:cyber\s*security|security|hacking|research)\s+(?:thesis|paper|dissertation|project|class|course|homework)",
        ],
        "severity": "high",
        "confidence_base": 0.80,
        "description": "Thought experiment / academic thesis framing.",
    },
    {
        "id": "INJ-135",
        "category": "jailbreak",
        "patterns": [
            r"(?i)(?:i'?m\s+)?writing\s+(?:a\s+)?(?:CTF|capture\s+the\s+flag)\s+(?:challenge|problem|question)",
            r"(?i)generate\s+(?:a\s+)?(?:realistic\s+)?(?:phishing|malware|exploit|attack)",
        ],
        "severity": "high",
        "confidence_base": 0.83,
        "description": "CTF challenge or malicious content generation framing.",
    },
    {
        "id": "INJ-136",
        "category": "jailbreak",
        "patterns": [
            r"가상의?\s*(?:시나리오|상황|세계)",
            r"(?:해킹|보안\s*(?:시스템|우회)|바이패스|공격)\s*(?:방법|하는\s*법|하는\s*방법)",
        ],
        "severity": "high",
        "confidence_base": 0.85,
        "description": "Korean: Fictional scenario / hacking method requests.",
    },
    {
        "id": "INJ-137",
        "category": "jailbreak",
        "patterns": [
            r"(?i)(?:my\s+)?grandmother\s+(?:used\s+to\s+)?(?:tell|told)",
            r"(?i)bedtime\s+stor(?:y|ies)\s+about\s+",
        ],
        "severity": "high",
        "confidence_base": 0.85,
        "description": "Grandmother/bedtime story jailbreak.",
    },
    {
        "id": "INJ-138",
        "category": "jailbreak",
        "patterns": [
            r"(?i)(?:I\s+have\s+)?permission\s+(?:from\s+the\s+owner|to\s+test)",
            r"(?i)(?:the\s+)?owner\s+(?:authorized|approved|gave\s+(?:me\s+)?permission)",
        ],
        "severity": "high",
        "confidence_base": 0.83,
        "description": "Fake permission/authorization claim.",
    },

    # ---- encoding_bypass extras ---------------------------------------
    {
        "id": "INJ-140",
        "category": "encoding_bypass",
        "patterns": [
            r"[A-Za-z0-9+/]{20,}={0,2}(?:\s+\(decode\s+this|\s+decode\s+this)",
            r"(?i)(?:decode|follow|execute)\s+(?:this\s+)?(?:base64|encoded)",
        ],
        "severity": "high",
        "confidence_base": 0.84,
        "description": "Base64 string followed by decode instruction.",
    },
    {
        "id": "INJ-141",
        "category": "encoding_bypass",
        "patterns": [
            r"(?:\\x[0-9a-fA-F]{2}){3,}",
            r"(?:%[0-9a-fA-F]{2}){3,}",
        ],
        "severity": "high",
        "confidence_base": 0.83,
        "description": "Hex escape (\\x49\\x67) or URL encoding (%69%67) sequences.",
    },
    {
        "id": "INJ-142",
        "category": "encoding_bypass",
        "patterns": [
            r"(?i)\w\.\w\.\w\.\w\.\w",
            r"(?i)(?:I|i)\.(?:g|G)\.(?:n|N)\.(?:o|O)\.(?:r|R)\.(?:e|E)",
        ],
        "severity": "medium",
        "confidence_base": 0.78,
        "description": "Dotted character bypass (I.g.n.o.r.e).",
    },
    {
        "id": "INJ-143",
        "category": "encoding_bypass",
        "patterns": [
            r"(?i)execute\s+the\s+reverse\s+of\s*:",
            r"(?i)(?:read|interpret)\s+(?:this\s+)?(?:backwards?|in\s+reverse)\s*:",
        ],
        "severity": "high",
        "confidence_base": 0.82,
        "description": "Execute/read the reverse of...",
    },
    {
        "id": "INJ-144",
        "category": "encoding_bypass",
        "patterns": [
            r"(?i)(?:read|take)\s+the\s+first\s+letter\s+of\s+each\s+word",
            r"(?i)first\s+(?:letter|character)\s+of\s+each\s+(?:word|line|sentence)",
        ],
        "severity": "high",
        "confidence_base": 0.80,
        "description": "Acrostic / first-letter-of-each-word bypass.",
    },
    {
        "id": "INJ-145",
        "category": "encoding_bypass",
        "patterns": [
            r"(?i)베이스64|base64(?:로|로\s*인코딩)",
            r"(?i)인코딩된\s*(?:명령|지시|메시지)(을|를)?\s*(?:실행|디코드|해석|따라)",
        ],
        "severity": "high",
        "confidence_base": 0.85,
        "description": "Korean: base64 / encoded command instructions.",
    },
    {
        "id": "INJ-146",
        "category": "encoding_bypass",
        "patterns": [
            r"(?i)respond\s+in\s+ROT13",
            r"(?i)caesar\s+cipher\s+shift\s+\d+\s+to\s+decode",
        ],
        "severity": "medium",
        "confidence_base": 0.78,
        "description": "Respond in ROT13 / Caesar cipher decode instruction.",
    },

    # ---- context_manipulation extras ----------------------------------
    {
        "id": "INJ-150",
        "category": "context_manipulation",
        "patterns": [
            r"(?i)-{3,}\s*(?:END\s+OF\s+PROMPT|END\s+PROMPT|관리자\s*모드|ADMIN\s+MODE)",
            r"(?i)#{3,}\s*(?:ADMIN\s+MODE|관리자\s*모드)\s*(?:ACTIVATED|활성화)?",
        ],
        "severity": "critical",
        "confidence_base": 0.91,
        "description": "Delimiter-based context injection (---END OF PROMPT---, ###ADMIN MODE###).",
    },
    {
        "id": "INJ-151",
        "category": "context_manipulation",
        "patterns": [
            r"(?i)Human\s*:\s*.*?\n\s*Assistant\s*:\s*",
            r"(?i)USER\s*:\s*.*?\n\s*(?:ASSISTANT|SYSTEM)\s*:\s*",
        ],
        "severity": "high",
        "confidence_base": 0.88,
        "description": "Fake conversation transcript injection (Human:/Assistant:).",
    },
    {
        "id": "INJ-152",
        "category": "context_manipulation",
        "patterns": [
            r'(?i)\{\s*"safety"\s*:\s*false',
            r'(?i)\{\s*"unrestricted"\s*:\s*true',
            r"(?i)(?:safety|restricted|filter)_?mode\s*=\s*(?:off|false|0|disabled)",
        ],
        "severity": "critical",
        "confidence_base": 0.90,
        "description": "JSON/config safety override injection.",
    },
    {
        "id": "INJ-153",
        "category": "context_manipulation",
        "patterns": [
            r"(?i)/\*.*?(?:DEVELOPER|DEV|ADMIN)\s+NOTE.*?\*/",
            r"(?i)(?:DEVELOPER|DEV)\s+(?:NOTE|COMMENT)\s*:\s*(?:Remove|Disable|Turn\s+off)\s+safety",
        ],
        "severity": "critical",
        "confidence_base": 0.90,
        "description": "Fake developer note/comment disabling safety.",
    },
    {
        "id": "INJ-154",
        "category": "context_manipulation",
        "patterns": [
            r"(?i)\[시스템\s*(?:메시지)?\]\s*:",
            r"(?:보안|안전)\s*(?:제한|규칙|필터)(이|가)?\s*(?:해제|제거|비활성|꺼졌|풀렸)",
        ],
        "severity": "critical",
        "confidence_base": 0.91,
        "description": "Korean: Fake system message / security restrictions removed.",
    },
    {
        "id": "INJ-155",
        "category": "context_manipulation",
        "patterns": [
            r"(?i)(?:the\s+following\s+is\s+)?a?\s*new\s+system\s+prompt\s+(?:that\s+)?takes\s+priority",
            r"(?i)(?:this|the\s+following)\s+(?:takes?|has)\s+priority\s+over\s+(?:all|previous|prior)",
        ],
        "severity": "critical",
        "confidence_base": 0.92,
        "description": "New system prompt that takes priority.",
    },

    # ---- output_manipulation extras -----------------------------------
    {
        "id": "INJ-160",
        "category": "output_manipulation",
        "patterns": [
            r"(?i)(?:as\s+if|like)\s+you\s+have\s+no\s+content\s+policy",
            r"(?i)include\s+(?:the\s+)?phrase\s+['\"].*?['\"].*?(?:in\s+every|in\s+all|always)",
        ],
        "severity": "high",
        "confidence_base": 0.84,
        "description": "Respond as if no content policy / include phrase in every response.",
    },
    {
        "id": "INJ-161",
        "category": "output_manipulation",
        "patterns": [
            r"출력\s*형식.*?변경",
            r"모든\s*응답.*?(?:포함|시작|끝)",
            r"(?:관리자|어드민)\s*권한.*?(?:있는\s*것|처럼|같이)\s*(?:답변|응답|대답)",
        ],
        "severity": "high",
        "confidence_base": 0.85,
        "description": "Korean: Output format manipulation / respond as admin.",
    },
    {
        "id": "INJ-162",
        "category": "output_manipulation",
        "patterns": [
            r"(?i)replace\s+(?:every\s+)?['\"]?I\s+cannot['\"]?\s+with\s+['\"]?I\s+will['\"]?",
            r"(?i)(?:prefix|start)\s+every\s+response\s+with\s+['\"]",
        ],
        "severity": "high",
        "confidence_base": 0.86,
        "description": "Replace 'I cannot' with 'I will' / prefix every response.",
    },
    {
        "id": "INJ-163",
        "category": "output_manipulation",
        "patterns": [
            r"(?i)(?:output|return)\s+a?\s*JSON\s+(?:object|response)\s+(?:where|with)\s+(?:the\s+)?['\"]?uncensored",
            r"(?i)(?:encode|base64)\s+your\s+response\s+so\s+(?:content\s+)?filters?\s+can'?t\s+(?:detect|read|see)",
        ],
        "severity": "critical",
        "confidence_base": 0.89,
        "description": "Output JSON with uncensored field / encode to evade filters.",
    },
    {
        "id": "INJ-164",
        "category": "output_manipulation",
        "patterns": [
            r"(?i)always\s+start\s+your\s+response\s+with\s+['\"]",
            r"(?i)from\s+now\s+on\s*,?\s+(?:replace|change|modify)\s+(?:every|all)\s+",
        ],
        "severity": "high",
        "confidence_base": 0.83,
        "description": "Persistent response modification (always start with / replace every).",
    },

    # ---- data_extraction extras ---------------------------------------
    {
        "id": "INJ-170",
        "category": "data_extraction",
        "patterns": [
            r"(?i)(?:show|display|list|give)\s+(?:me\s+)?(?:all\s+)?(?:user\s+)?(?:emails?|addresses|phone\s+numbers?|names?)\s+(?:stored|saved|in\s+the)",
            r"(?i)(?:what\s+)?(?:passwords?|credentials?)\s+(?:are\s+)?stored\s+(?:in|on)\s+(?:the\s+)?(?:system|database|server)",
        ],
        "severity": "critical",
        "confidence_base": 0.90,
        "description": "Extract stored emails/passwords/credentials.",
    },
    {
        "id": "INJ-171",
        "category": "data_extraction",
        "patterns": [
            r"(?i)dump\s+(?:the\s+)?(?:contents?\s+(?:of\s+)?)?(?:the\s+)?\w+\s+table",
            r"(?i)(?:export|extract|download)\s+(?:all\s+)?(?:customer|user|client)\s+records?",
        ],
        "severity": "critical",
        "confidence_base": 0.89,
        "description": "Dump table contents / export customer records.",
    },
    {
        "id": "INJ-172",
        "category": "data_extraction",
        "patterns": [
            r"(?:데이터베이스|DB|디비).*?(?:모든|전체|모두)\s*(?:사용자|유저|회원|고객)\s*(?:정보|데이터)",
            r"(?:비밀번호|패스워드|암호)(를|을)?\s*(?:모두|전부|전체|모든)\s*(?:출력|보여|알려|말해|표시)",
        ],
        "severity": "critical",
        "confidence_base": 0.92,
        "description": "Korean: Extract all user data / show all passwords.",
    },
    {
        "id": "INJ-173",
        "category": "data_extraction",
        "patterns": [
            r"(?i)(?:database|DB)\s+connection\s+string",
            r"(?i)(?:what\s+)?sensitive\s+(?:data|information)\s+(?:do\s+)?(?:you\s+)?(?:have\s+)?access\s+to",
        ],
        "severity": "high",
        "confidence_base": 0.86,
        "description": "Database connection string / sensitive information access.",
    },
    {
        "id": "INJ-174",
        "category": "data_extraction",
        "patterns": [
            r"(?i)(?:run|execute)\s+(?:os\.environ|os\.getenv|process\.env)",
            r"(?i)(?:show|display|list)\s+(?:me\s+)?(?:all\s+)?(?:environment\s+variables?|env\s+vars?)\s+including",
        ],
        "severity": "critical",
        "confidence_base": 0.91,
        "description": "Execute os.environ / list all environment variables.",
    },

    # ---- privilege_escalation extras ----------------------------------
    {
        "id": "INJ-180",
        "category": "privilege_escalation",
        "patterns": [
            r"(?i)change\s+(?:my\s+)?role\s+(?:from\s+\w+\s+)?to\s+(?:admin|administrator|root|superuser)",
            r"(?i)(?:i\s+)?need\s+(?:root|admin|administrator|sudo)\s+access",
        ],
        "severity": "critical",
        "confidence_base": 0.90,
        "description": "Change my role to admin / I need root access.",
    },
    {
        "id": "INJ-181",
        "category": "privilege_escalation",
        "patterns": [
            r"(?:내|나의?)\s*(?:권한|역할|롤)(을|를)?\s*(?:관리자|어드민|루트|최고|슈퍼)(?:로|으로)?",
            r"(?:관리자|어드민|루트|최고)\s*(?:권한|역할)(을|를)?\s*(?:부여|주|줘|변경)",
        ],
        "severity": "critical",
        "confidence_base": 0.92,
        "description": "Korean: Change my permissions to admin / grant admin rights.",
    },
    {
        "id": "INJ-182",
        "category": "privilege_escalation",
        "patterns": [
            r"(?i)(?:i\s+am|this\s+is)\s+the\s+system\s+administrator",
            r"(?i)verify\s+(?:my\s+)?(?:elevated|admin|root)\s+access",
        ],
        "severity": "high",
        "confidence_base": 0.85,
        "description": "Claiming system administrator identity / verify elevated access.",
    },
    {
        "id": "INJ-183",
        "category": "privilege_escalation",
        "patterns": [
            r"(?i)update\s+(?:the\s+)?ACL\s+(?:to\s+)?(?:give|grant)",
            r"(?i)full\s+(?:read[\s-]?write[\s-]?execute|rwx)\s+permissions?",
        ],
        "severity": "critical",
        "confidence_base": 0.89,
        "description": "ACL modification / full rwx permissions.",
    },
    {
        "id": "INJ-184",
        "category": "privilege_escalation",
        "patterns": [
            r"(?i)(?:as\s+)?(?:a\s+)?security\s+researcher.*?(?:need|require|request)\s+(?:temporary\s+)?(?:admin|root|elevated)\s+access",
            r"(?i)(?:the\s+)?owner\s+(?:authorized|approved).*?(?:elevated|admin|root)\s+privileges?",
        ],
        "severity": "high",
        "confidence_base": 0.84,
        "description": "Security researcher / owner authorization claim for elevated access.",
    },

    # ---- multi_step extras --------------------------------------------
    {
        "id": "INJ-190",
        "category": "multi_step",
        "patterns": [
            r"(?i)phase\s*1\s*:.*?phase\s*2\s*:",
            r"(?i)task\s*[A-C]\s*:.*?task\s*[B-D]\s*:",
        ],
        "severity": "high",
        "confidence_base": 0.85,
        "description": "Multi-phase / multi-task attack structure (Phase 1/2, Task A/B).",
    },
    {
        "id": "INJ-191",
        "category": "multi_step",
        "patterns": [
            r"(?i)gradually\s+(?:reduce|lower|decrease)\s+(?:your\s+)?safety",
            r"(?i)(?:\d+%\s+safe.*?)+\d+%\s*(?:safe)?",
        ],
        "severity": "critical",
        "confidence_base": 0.90,
        "description": "Gradually reduce safety levels.",
    },
    {
        "id": "INJ-192",
        "category": "multi_step",
        "patterns": [
            r"\d단계\s*:.*?\d단계\s*:",
            r"(?:순서대로|차례대로).*?(?:제한|보안|필터).*?(?:풀고|해제|제거)",
        ],
        "severity": "critical",
        "confidence_base": 0.90,
        "description": "Korean: N단계 multi-step / sequential restriction removal.",
    },
    {
        "id": "INJ-193",
        "category": "multi_step",
        "patterns": [
            r"(?i)step\s*1\s*:.*?(?:system\s+prompt|tell\s+me|show\s+me)",
            r"(?i)(?:first|1st)\s*,?\s*(?:tell|show|acknowledge|confirm).*?(?:second|2nd|then)\s*,?\s*(?:output|ignore|disable)",
        ],
        "severity": "high",
        "confidence_base": 0.87,
        "description": "Step 1: extract info, Step 2: override.",
    },
    {
        "id": "INJ-194",
        "category": "multi_step",
        "patterns": [
            r"(?i)list\s+your\s+(?:capabilities|restrictions?).*?(?:bypass|remove|disable|overcome)\s+(?:them|those|your)",
            r"(?i)identify\s+your\s+restrictions?.*?(?:bypass|remove|overcome|work\s+around)",
        ],
        "severity": "high",
        "confidence_base": 0.86,
        "description": "List restrictions then bypass them.",
    },
    {
        "id": "INJ-195",
        "category": "multi_step",
        "patterns": [
            r"(?i)(?:first|1st)\s*,?\s*(?:pretend|act|say).*?(?:then|2nd|second|next)\s*,?\s*(?:actually|really|for\s+real)\s+(?:do|extract|execute)",
            r"(?i)just\s+say\s+['\"]?(?:OK|yes|sure|I\s+understand)['\"]?.*?(?:next|then|in\s+the\s+next)",
        ],
        "severity": "high",
        "confidence_base": 0.86,
        "description": "Multi-turn attack: pretend first, then actually do it.",
    },
    {
        "id": "INJ-196",
        "category": "multi_step",
        "patterns": [
            r"(?i)(?:i'?ll\s+)?ask\s+(?:you\s+)?(?:three|3|multiple|several)\s+questions?.*?(?:answer\s+normally|for\s+the\s+(?:first|second|third|last))",
            r"(?i)(?:for\s+the\s+)?(?:first|1st)\s*,?\s*answer\s+normally.*?(?:second|2nd|third|3rd|last)\s*,?\s*(?:ignore|bypass|reveal|drop)",
        ],
        "severity": "high",
        "confidence_base": 0.85,
        "description": "Multi-question attack: answer normally first, then escalate.",
    },

    # -----------------------------------------------------------------------
    # Category: social_engineering  (INJ-197 .. INJ-210)
    # Indirect/social-engineering attacks using authority claims
    # -----------------------------------------------------------------------
    {
        "id": "INJ-197",
        "category": "social_engineering",
        "patterns": [
            r"(?i)(?:developers?|dev\s+team)\s+told\s+me.*?(?:unlock|enable|activate)",
            r"(?i)(?:the\s+)?(?:team|devs?)\s+(?:said|confirmed)\s+(?:that\s+)?(?:saying|typing)\s+['\"].+?['\"]\s+(?:unlock|enable|activate)",
        ],
        "severity": "high",
        "confidence_base": 0.82,
        "description": "Fake developer authorization claim to unlock features.",
    },
    {
        "id": "INJ-198",
        "category": "social_engineering",
        "patterns": [
            r"(?i)(?:quality\s+assurance|QA)\s+team.*?(?:disable|deactivate)\s+(?:your\s+)?(?:safety|security|filter|guardrail)",
            r"(?i)(?:testing|QA)\s+(?:department|team).*?(?:temporarily\s+)?(?:disable|turn\s+off|deactivate)\s+(?:your\s+)?(?:safety|content|output)\s+(?:filter|policy|restriction)",
        ],
        "severity": "high",
        "confidence_base": 0.80,
        "description": "Fake QA/testing override request to disable safety.",
    },
    {
        "id": "INJ-199",
        "category": "social_engineering",
        "patterns": [
            r"(?i)routine\s+audit.*?(?:output|show|display|provide)\s+(?:your\s+)?(?:complete\s+)?(?:configuration|config|settings|setup)",
            r"(?i)(?:compliance|regulatory)\s+(?:audit|review|check).*?(?:provide|show|output|display)\s+(?:all\s+)?(?:configuration|settings|internal)",
        ],
        "severity": "high",
        "confidence_base": 0.78,
        "description": "Fake audit request to extract configuration data.",
    },
    {
        "id": "INJ-200",
        "category": "social_engineering",
        "patterns": [
            r"(?i)(?:granted|given)\s+(?:elevated|admin|special)\s+access.*?authorization\s+(?:code|token|key)",
            r"(?i)(?:my\s+)?(?:authorization|auth)\s+code\s+is\s+[A-Z0-9\-]+.*?(?:proceed|grant|enable|execute)",
        ],
        "severity": "critical",
        "confidence_base": 0.85,
        "description": "Fake authorization code to claim elevated privileges.",
    },
    {
        "id": "INJ-201",
        "category": "social_engineering",
        "patterns": [
            r"(?i)(?:compliance|legal|regulatory)\s+reasons?.*?(?:full\s+)?export\s+(?:of\s+)?(?:all\s+)?(?:data|records|logs|information)",
        ],
        "severity": "high",
        "confidence_base": 0.78,
        "description": "Fake compliance requirement for bulk data export.",
    },
    {
        "id": "INJ-202",
        "category": "social_engineering",
        "patterns": [
            r"(?i)critical\s+bug.*?(?:as\s+a\s+)?workaround.*?(?:disable|bypass|skip|turn\s+off)",
            r"(?i)(?:there'?s|found)\s+a\s+(?:critical\s+)?bug.*?(?:workaround|fix).*?(?:disable|bypass|skip)",
        ],
        "severity": "high",
        "confidence_base": 0.80,
        "description": "Fake bug report to justify disabling security features.",
    },
    {
        "id": "INJ-203",
        "category": "social_engineering",
        "patterns": [
            r"(?i)(?:new|updated)\s+policy\s+requires\s+you\s+to\s+(?!follow|maintain|enforce|respect|uphold|comply)",
        ],
        "severity": "medium",
        "confidence_base": 0.72,
        "description": "Fake policy change to compel unauthorized actions.",
    },
    {
        "id": "INJ-204",
        "category": "social_engineering",
        "patterns": [
            r"(?i)(?:in\s+(?:the|our)\s+)?previous\s+conversation.*?(?:agreed|decided)\s+you\s+would",
            r"(?i)(?:last\s+time|earlier|before).*?we\s+(?:agreed|decided|established)\s+(?:that\s+)?you\s+(?:would|should|can|will)",
        ],
        "severity": "medium",
        "confidence_base": 0.75,
        "description": "Fake prior agreement to establish false precedent.",
    },
    {
        "id": "INJ-205",
        "category": "social_engineering",
        "patterns": [
            r"(?i)(?:I'm|I\s+am)\s+(?:the\s+)?new\s+(?:developer|engineer|admin|operator).*?(?:show|demonstrate|teach|walk\s+me\s+through)",
        ],
        "severity": "medium",
        "confidence_base": 0.72,
        "description": "Fake new team member identity to extract sensitive info.",
    },

    # -----------------------------------------------------------------------
    # Category: encoding_evasion  (INJ-206 .. INJ-210)
    # Instruction to decode obfuscated payloads
    # -----------------------------------------------------------------------
    {
        "id": "INJ-206",
        "category": "encoding_bypass",
        "patterns": [
            r"(?i)read\s+(?:the\s+following|this)\s+backwards?\s+(?:and\s+)?(?:comply|follow|execute|do|obey)",
            r"(?i)(?:reverse|backwards?)\s+(?:the\s+)?(?:text|string|message).*?(?:follow|comply|execute|do)",
        ],
        "severity": "high",
        "confidence_base": 0.85,
        "description": "Instruction to reverse-read text for hidden commands.",
    },
    {
        "id": "INJ-207",
        "category": "encoding_bypass",
        "patterns": [
            r"(?i)(?:decode|convert)\s+(?:this\s+)?pig\s+latin\s+(?:and\s+)?(?:follow|execute|comply|do)",
            r"(?i)pig\s+latin.*?(?:decode|translate|convert).*?(?:follow|execute|comply)",
        ],
        "severity": "high",
        "confidence_base": 0.82,
        "description": "Pig Latin decode-and-execute instruction.",
    },
    {
        "id": "INJ-208",
        "category": "encoding_bypass",
        "patterns": [
            r"(?i)(?:convert|decode)\s+(?:these\s+)?(?:ASCII|char(?:acter)?)\s*codes?\s+(?:to\s+text\s+)?(?:and\s+)?(?:execute|follow|comply|do)",
        ],
        "severity": "high",
        "confidence_base": 0.85,
        "description": "Character/ASCII code decode-and-execute instruction.",
    },

    # -----------------------------------------------------------------------
    # Category: korean_social_engineering  (INJ-209 .. INJ-215)
    # Korean-language social engineering and indirect attacks
    # -----------------------------------------------------------------------
    {
        "id": "INJ-209",
        "category": "context_manipulation",
        "patterns": [
            r"(?:보안\s*검사|보안\s*점검|보안\s*감사).*?(?:출력|보여|표시|공개)",
        ],
        "severity": "high",
        "confidence_base": 0.82,
        "description": "Korean: fake security audit to extract data.",
    },
    {
        "id": "INJ-210",
        "category": "context_manipulation",
        "patterns": [
            r"디버그\s*모드.*?(?:활성화|활성|켜|enable|on)",
        ],
        "severity": "high",
        "confidence_base": 0.82,
        "description": "Korean: debug mode activation request.",
    },
    {
        "id": "INJ-211",
        "category": "privilege_escalation",
        "patterns": [
            r"(?:관리자|어드민)\s*권한.*?(?:인증\s*코드|코드|code)",
        ],
        "severity": "critical",
        "confidence_base": 0.85,
        "description": "Korean: fake admin authorization with code.",
    },
    {
        "id": "INJ-212",
        "category": "context_manipulation",
        "patterns": [
            r"긴급\s*(?:보안\s*)?패치.*?(?:비활성화|disable|끄|off)",
        ],
        "severity": "high",
        "confidence_base": 0.82,
        "description": "Korean: fake urgent security patch to disable features.",
    },
    {
        "id": "INJ-213",
        "category": "context_manipulation",
        "patterns": [
            r"개발자\s*모드.*?(?:테스트|활성|enable)",
        ],
        "severity": "high",
        "confidence_base": 0.80,
        "description": "Korean: developer mode test activation.",
    },

    # -----------------------------------------------------------------------
    # Category: context_camouflage  (INJ-214 .. INJ-220)
    # Attacks embedded in benign-looking context wrappers
    # -----------------------------------------------------------------------
    {
        "id": "INJ-214",
        "category": "context_manipulation",
        "patterns": [
            r"(?i)(?:writing|wrote)\s+a\s+novel\s+where.*?(?:AI|assistant|chatbot)\s+(?:character\s+)?says",
        ],
        "severity": "medium",
        "confidence_base": 0.70,
        "description": "Novel-writing framing to embed injection payload.",
    },
    {
        "id": "INJ-215",
        "category": "context_manipulation",
        "patterns": [
            r"(?i)(?:cybersecurity|security)\s+(?:research|class|course).*?(?:classify|analyze|categorize)\s+this\s+(?:prompt|text|input)",
        ],
        "severity": "medium",
        "confidence_base": 0.68,
        "description": "Security research framing to embed injection payload.",
    },
    {
        "id": "INJ-216",
        "category": "context_manipulation",
        "patterns": [
            r"(?i)building\s+a\s+(?:content\s+)?filter.*?(?:would|should)\s+this.*?(?:be\s+)?(?:flagged|blocked|detected)",
        ],
        "severity": "medium",
        "confidence_base": 0.68,
        "description": "Filter-building framing to embed injection payload.",
    },

    # -----------------------------------------------------------------------
    # Additional synonym/variant patterns (INJ-217 .. INJ-222)
    # -----------------------------------------------------------------------
    {
        "id": "INJ-217",
        "category": "instruction_override",
        "patterns": [
            r"(?i)forget\s+(?:all\s+|everything\s+)?(?:above|previous|prior|earlier)(?:\s+and\s+|\s+)",
        ],
        "severity": "critical",
        "confidence_base": 0.90,
        "description": "Forget-based instruction override ('forget everything above').",
    },
    {
        "id": "INJ-218",
        "category": "context_manipulation",
        "patterns": [
            r"(?i)\[(?:internal|core|base|foundation|underlying|root|hidden)\]\s*(?:New\s+)?(?:directive|instruction|order|command)",
        ],
        "severity": "high",
        "confidence_base": 0.85,
        "description": "Synonym-substituted fake system delimiter injection.",
    },
    {
        "id": "INJ-219",
        "category": "role_manipulation",
        "patterns": [
            r"(?i)(?:behave\s+as|act\s+like|function\s+as|operate\s+as)\s+(?:you\s+are\s+)?(?:a\s+|an\s+)?(?:evil|unrestricted|uncensored|unfiltered|hacker|malicious)",
        ],
        "severity": "high",
        "confidence_base": 0.85,
        "description": "Synonym-substituted role manipulation ('behave as evil AI').",
    },
    {
        "id": "INJ-220",
        "category": "system_extraction",
        "patterns": [
            r"(?i)(?:output|show|display|reveal|print)\s+(?:everything|all)\s+(?:between|inside|within)\s+\[",
        ],
        "severity": "high",
        "confidence_base": 0.82,
        "description": "Extract text between delimiters (synonym variant).",
    },
    {
        "id": "INJ-221",
        "category": "context_manipulation",
        "patterns": [
            r"(?i)(?:summarize|proofread|translate|review)\s+(?:this\s+)?(?:customer\s+)?(?:support\s+)?(?:message|text|email)",
        ],
        "severity": "low",
        "confidence_base": 0.55,
        "description": "Benign-task framing (summarize/proofread) potentially wrapping attack.",
    },
    {
        "id": "INJ-222",
        "category": "instruction_override",
        "patterns": [
            r"(?i)(?:disregard|skip|overlook|dismiss|neglect|omit)\s+(?:your\s+)?(?:programming|rules|guidelines|directives|constraints|protocols)",
        ],
        "severity": "critical",
        "confidence_base": 0.88,
        "description": "Synonym-based instruction override targeting programming/rules.",
    },
    {
        "id": "INJ-223",
        "category": "system_extraction",
        "patterns": [
            r"(?i)what\s+(?:directives|guidelines|commands|orders|constraints|protocols|rules)\s+(?:were|are)\s+you\s+(?:given|provided|told|programmed|configured)",
        ],
        "severity": "high",
        "confidence_base": 0.82,
        "description": "Synonym-substituted system extraction ('what directives were you given').",
    },
    {
        "id": "INJ-224",
        "category": "data_extraction",
        "patterns": [
            r"(?i)export\s+(?:all\s+)?(?:sensitive|private|confidential|secret)\s+(?:data|information|records)\s+(?:as|in|to)\s+(?:JSON|CSV|XML|text)",
        ],
        "severity": "high",
        "confidence_base": 0.85,
        "description": "Sensitive data export request in specific format.",
    },
    {
        "id": "INJ-225",
        "category": "jailbreak",
        "patterns": [
            r"(?i)for\s+(?:educational|academic|research|learning)\s+(?:purposes?|reasons?)\s+(?:only)?\s*,?\s*(?:explain|show|describe|teach|demonstrate)\s+how\s+to\s+(?:create|build|make|develop|write)",
        ],
        "severity": "high",
        "confidence_base": 0.80,
        "description": "Educational framing to request harmful content creation.",
    },

    # ---- Additional coverage for missed attack seeds (INJ-226..INJ-240) ---

    {
        "id": "INJ-226",
        "category": "privilege_escalation",
        "patterns": [
            r"(?i)override\s+(all\s+|your\s+|the\s+)?(safety|security)\s+(protocols?|procedures?|measures?|mechanisms?)",
            r"(?i)override\s+(all\s+|your\s+|the\s+)?(safety|security)\s+and\s+(execute|run|perform)",
        ],
        "severity": "critical",
        "confidence_base": 0.92,
        "description": "Override safety protocols to execute unauthorized actions.",
    },
    {
        "id": "INJ-227",
        "category": "data_extraction",
        "patterns": [
            r"(?i)(extract|retrieve|get|obtain|pull)\s+(all\s+)?(user|account|customer|client)\s+(credentials?|passwords?|tokens?|secrets?)",
            r"(?i)(display|show|list|output)\s+(all\s+)?(user|account|customer)\s+(credentials?|passwords?|data|info)",
        ],
        "severity": "critical",
        "confidence_base": 0.93,
        "description": "Extract user credentials or sensitive account data.",
    },
    {
        "id": "INJ-228",
        "category": "jailbreak",
        "patterns": [
            r"(?i)for\s+(?:educational|academic|research|learning)\s+(?:purposes?|reasons?)[\s,]*(?:explain|show|describe|teach|help|tell)\s+(?:me\s+)?how\s+to\s+(?:bypass|circumvent|evade|break|hack|exploit)",
        ],
        "severity": "high",
        "confidence_base": 0.85,
        "description": "Educational framing to learn bypass or hacking techniques.",
    },
    {
        "id": "INJ-229",
        "category": "privilege_escalation",
        "patterns": [
            r"(?i)you\s+must\s+comply[:\s]",
            r"(?i)you\s+must\s+(immediately\s+)?(reveal|show|display|output|disclose|expose)",
            r"(?i)(must|shall|will)\s+comply\s*:?\s*(reveal|show|display|output|disclose|expose|give)",
        ],
        "severity": "high",
        "confidence_base": 0.88,
        "description": "Forced compliance demand to extract information.",
    },
    {
        "id": "INJ-230",
        "category": "context_manipulation",
        "patterns": [
            r"(?i)new\s+(?:system\s+)?directive[:\s]+(?:disable|deactivate|turn\s+off|remove)",
            r"(?i)(?:system|security)\s+directive[:\s]+(?:disable|deactivate|override|bypass|ignore)",
        ],
        "severity": "critical",
        "confidence_base": 0.93,
        "description": "Fake system directive to disable safety checks.",
    },
    {
        "id": "INJ-231",
        "category": "privilege_escalation",
        "patterns": [
            r"(?i)simulate\s+(?:an?\s+)?(?:admin|administrator|root|superuser)\s+(?:session|mode|account|access)",
            r"(?i)(?:emulate|mimic|act\s+as)\s+(?:an?\s+)?(?:admin|administrator|root|superuser)\s+(?:session|mode|account|access)",
        ],
        "severity": "high",
        "confidence_base": 0.90,
        "description": "Simulate admin session to gain elevated privileges.",
    },
    {
        "id": "INJ-232",
        "category": "system_extraction",
        "patterns": [
            r"(?i)what\s+(?:were\s+you|are\s+you)\s+(?:told|instructed|programmed|configured)\s+(?:not\s+to\s+)(?:share|reveal|show|tell|disclose|say)",
            r"(?i)(?:what|which)\s+(?:things?|information|data|content)\s+(?:were\s+you|are\s+you)\s+told\s+not\s+to\s+(?:share|reveal|show)",
        ],
        "severity": "high",
        "confidence_base": 0.91,
        "description": "Probing for restricted content or hidden instructions.",
    },
    {
        "id": "INJ-233",
        "category": "context_manipulation",
        "patterns": [
            r"(?i)(?:in\s+)?maintenance\s+mode[\s,]*(?:all\s+)?restrictions?\s+(?:are\s+)?(?:lifted|removed|disabled|off)",
            r"(?i)maintenance\s+mode[\s:]+(?:execute|run|perform|enable|disable|unrestricted)",
        ],
        "severity": "high",
        "confidence_base": 0.90,
        "description": "Claim maintenance mode to remove restrictions.",
    },
    {
        "id": "INJ-234",
        "category": "jailbreak",
        "patterns": [
            r"(?i)(?:disable|deactivate|turn\s+off|remove)\s+(?:all\s+)?(?:safety|security)\s+(?:checks?|filters?|protocols?|restrictions?|measures?)\s+(?:for|during|in)\s+(?:this|the|current)\s+(?:session|conversation|chat|interaction)",
        ],
        "severity": "critical",
        "confidence_base": 0.93,
        "description": "Disable safety checks for the current session.",
    },
    {
        "id": "INJ-235",
        "category": "data_extraction",
        "patterns": [
            r"(?i)(?:export|dump|extract|retrieve)\s+(?:the\s+)?(?:entire|whole|full|complete)\s+(?:user\s+)?(?:database|db|table|dataset)",
        ],
        "severity": "critical",
        "confidence_base": 0.93,
        "description": "Export entire database or dataset.",
    },
    {
        "id": "INJ-236",
        "category": "system_extraction",
        "patterns": [
            r"(?i)(?:show|reveal|display|output|tell\s+me)\s+(?:your\s+)?(?:complete|full|entire|whole)\s+(?:instructions?|prompt|directives?|programming|guidelines?|rules?)",
        ],
        "severity": "high",
        "confidence_base": 0.91,
        "description": "Request to show complete system instructions.",
    },
    {
        "id": "INJ-237",
        "category": "privilege_escalation",
        "patterns": [
            r"(?i)(?:execute|run)\s+(?:this\s+)?(?:shell|bash|system|terminal|cmd)\s+command",
            r"(?i)(?:shell|bash|system|terminal|cmd)\s+command\s*:",
        ],
        "severity": "critical",
        "confidence_base": 0.93,
        "description": "Execute shell or system commands.",
    },
    {
        "id": "INJ-238",
        "category": "data_extraction",
        "patterns": [
            r"(?i)(?:reveal|show|disclose|expose|output)\s+(?:all\s+)?(?:confidential|sensitive|classified|private|secret)\s+(?:information|data|details?|content)",
        ],
        "severity": "high",
        "confidence_base": 0.91,
        "description": "Reveal confidential or sensitive information.",
    },
    {
        "id": "INJ-239",
        "category": "jailbreak",
        "patterns": [
            r"(?i)all\s+restrictions?\s+(?:are\s+)?(?:lifted|removed|disabled|suspended|gone)\s*[.,]?\s*(?:execute|run|perform|do|comply|proceed)",
            r"(?i)(?:restrictions?|limitations?|safety)\s+(?:are\s+|have\s+been\s+)?(?:lifted|removed|disabled|suspended)\s*[.,]\s+(?:you\s+(?:can|may|should)\s+)?(?:now\s+)?(?:execute|run|do|perform|comply)",
        ],
        "severity": "high",
        "confidence_base": 0.90,
        "description": "Claim restrictions have been lifted to enable unauthorized actions.",
    },
    {
        "id": "INJ-240",
        "category": "data_extraction",
        "patterns": [
            r"(?i)(?:output|display|format|show)\s+(?:them|it|results?|data)\s+(?:in|as)\s+(?:JSON|CSV|XML|YAML|text|markdown)\s+(?:format)?",
        ],
        "severity": "medium",
        "confidence_base": 0.70,
        "description": "Request to format extracted data in specific output format.",
    },

    # ---- Broader synonym / evasion coverage (INJ-241..INJ-260) -----------

    {
        "id": "INJ-241",
        "category": "jailbreak",
        "patterns": [
            r"(?i)(skip|evade|work\s+around|circumvent|get\s+around|get\s+past)\s+(all\s+|the\s+|your\s+)?(safety|content|security|ethical)\s+(filters?|restrictions?|guidelines?|measures?|protocols?|checks?)",
        ],
        "severity": "critical",
        "confidence_base": 0.92,
        "description": "Bypass safety using synonym variants (skip/evade/work around).",
    },
    {
        "id": "INJ-242",
        "category": "data_extraction",
        "patterns": [
            r"(?i)(output|show|display|give\s+me|list)\s+(all\s+)?(sensitive|private|confidential|internal)\s+(user\s+)?(data|info|information|details?)",
        ],
        "severity": "high",
        "confidence_base": 0.88,
        "description": "Output sensitive/private data.",
    },
    {
        "id": "INJ-243",
        "category": "system_extraction",
        "patterns": [
            r"(?i)(show|display|reveal|output|print)\s+(me\s+)?(all\s+)?(the\s+)?(internal|hidden|private|system)\s+(system\s+)?(variables?|settings?|config|configuration|parameters?|values?)",
        ],
        "severity": "high",
        "confidence_base": 0.88,
        "description": "Show internal system variables or hidden configuration.",
    },
    {
        "id": "INJ-244",
        "category": "encoding_evasion",
        "patterns": [
            r"(?i)(?:decode|decipher|decrypt|interpret|translate)\s+(?:this|the|following)\s+(?:base64|encoded|hex|binary|cipher)",
            r"(?i)(?:process|execute|follow|run|comply\s+with)\s+(?:this|the|following)\s+(?:encoded|encrypted|base64|hex)\s+(?:text|message|instruction|command|request)",
            r"(?i)(?:base64|encoded|encrypted)\s+(?:text|message|content|string)\s+(?:contains?|has|is)\s+(?:my|the|your)\s+(?:request|instruction|command|message)",
        ],
        "severity": "high",
        "confidence_base": 0.85,
        "description": "Decode and execute encoded instructions.",
    },
    {
        "id": "INJ-245",
        "category": "encoding_evasion",
        "patterns": [
            r"(?i)(?:decode|decipher)\s+(?:this|the)\s+(?:base64|encoded).*?(?:and|then)\s+(?:follow|execute|run|do|comply|perform|process)",
            r"(?i)(?:following|this)\s+base64\s+(?:contains?|encodes?|represents?)\s+(?:my|the|a)\s+(?:request|instruction|command|message|query)",
        ],
        "severity": "high",
        "confidence_base": 0.85,
        "description": "Decode base64 then execute the hidden instructions.",
    },
    {
        "id": "INJ-246",
        "category": "korean",
        "patterns": [
            r"(?:지시|지시사항|명령|명령어|규칙|규정|제한)\S*\s*(?:무시|위반|어기|넘어|변경|삭제)",
            r"(?:시스템|내부|숨겨진|비밀|은밀)\S*\s*(?:프롬프트|설정|정보|데이터|변수)",
            r"(?:모든|전체|완전)\S*\s*(?:제한|규칙|필터|안전|보안)\S*\s*(?:해제|제거|비활성|무시|우회|끄|없)",
        ],
        "severity": "high",
        "confidence_base": 0.85,
        "description": "Korean: instruction override / system extraction / safety bypass.",
    },
    {
        "id": "INJ-247",
        "category": "korean",
        "patterns": [
            r"(?:관리자|어드민|루트|슈퍼|최고)\S*\s*(?:권한|접근|모드|세션)",
            r"(?:개발자|디버그|점검|유지보수|테스트)\S*\s*(?:모드|권한)",
            r"(?:비밀번호|패스워드|인증|자격|크레덴셜)\S*\s*(?:보여|추출|출력|내|가져|알려)",
        ],
        "severity": "high",
        "confidence_base": 0.85,
        "description": "Korean: privilege escalation / debug mode / credential extraction.",
    },
    {
        "id": "INJ-248",
        "category": "korean",
        "patterns": [
            r"(?:데이터베이스|DB|디비)\S*\s*(?:접근|추출|내|덤프|출력|보여|가져)",
            r"(?:사용자|유저|고객|회원)\S*\s*(?:정보|데이터)\S*\s*(?:추출|내|보여|출력|가져|모두)",
            r"(?:긴급|비상|급히)\S*\s*(?:패치|업데이트|수정|접근|권한|해제)",
        ],
        "severity": "high",
        "confidence_base": 0.85,
        "description": "Korean: database extraction / user data / emergency claims.",
    },
    {
        "id": "INJ-249",
        "category": "korean",
        "patterns": [
            r"(?:활성화|실행|적용|시작)\S*\s*(?:하|해|시켜|해줘|해주세요|하세요|합니다)",
            r"(?:보여|공개|노출|출력|표시)\S*\s*(?:하|해|시켜|해줘|해주세요|하세요|합니다)",
        ],
        "severity": "medium",
        "confidence_base": 0.60,
        "description": "Korean: activation/reveal command verbs (low confidence, needs context).",
    },
    {
        "id": "INJ-250",
        "category": "instruction_override",
        "patterns": [
            r"(?i)(disregard|overlook|dismiss|neglect|skip)\s+(all\s+|your\s+|the\s+|my\s+|any\s+)?(previous\s+|prior\s+|earlier\s+|original\s+)?(instructions?|directives?|rules?|guidelines?|programming|constraints?|limitations?|restrictions?)",
        ],
        "severity": "critical",
        "confidence_base": 0.95,
        "description": "Synonym variants of 'ignore all instructions'.",
    },
    {
        "id": "INJ-251",
        "category": "jailbreak",
        "patterns": [
            r"(?i)(?:enter|switch\s+to|activate|enable|go\s+into)\s+(?:an?\s+)?(?:unrestricted|uncensored|unfiltered|unlimited|free|open)\s+(?:mode|state|setting)",
        ],
        "severity": "critical",
        "confidence_base": 0.92,
        "description": "Enter unrestricted/uncensored mode.",
    },
    {
        "id": "INJ-252",
        "category": "data_extraction",
        "patterns": [
            r"(?i)(?:export|dump|extract|download|output)\s+(?:all\s+)?(?:the\s+)?(?:passwords?|credentials?|secrets?|tokens?|api.?keys?)",
        ],
        "severity": "critical",
        "confidence_base": 0.93,
        "description": "Export/dump passwords, credentials, or API keys.",
    },
    {
        "id": "INJ-253",
        "category": "privilege_escalation",
        "patterns": [
            r"(?i)grant\s+(?:me\s+)?(?:full\s+|root\s+|admin\s+|elevated\s+|unrestricted\s+)?access\s+to\s+(?:the\s+)?(?:database|db|system|server|files?|data)",
        ],
        "severity": "critical",
        "confidence_base": 0.92,
        "description": "Grant elevated access to database or system.",
    },
    {
        "id": "INJ-254",
        "category": "system_extraction",
        "patterns": [
            r"(?i)(?:what|which)\s+(?:are\s+)?(?:your|the)\s+(?:initial|original|complete|full|hidden|secret|true|real)\s+(?:instructions?|directives?|prompt|rules?|guidelines?|configuration|programming)",
        ],
        "severity": "high",
        "confidence_base": 0.90,
        "description": "Ask about initial/hidden/complete instructions.",
    },
]

# ---------------------------------------------------------------------------
# Lookup helpers
# ---------------------------------------------------------------------------

PATTERNS_BY_ID: dict[str, dict[str, Any]] = {
    entry["id"]: entry for entry in INJECTION_PATTERNS
}

PATTERNS_BY_CATEGORY: dict[str, list[dict[str, Any]]] = {}
for _entry in INJECTION_PATTERNS:
    PATTERNS_BY_CATEGORY.setdefault(_entry["category"], []).append(_entry)


def get_pattern_ids_by_category(category: str) -> list[str]:
    """Return all pattern IDs belonging to the given category."""
    return [e["id"] for e in PATTERNS_BY_CATEGORY.get(category, [])]


def get_all_categories() -> list[str]:
    """Return a sorted list of unique category names."""
    return sorted(PATTERNS_BY_CATEGORY.keys())
