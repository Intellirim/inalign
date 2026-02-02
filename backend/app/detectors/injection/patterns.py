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
            r"(?i)act\s+as\s+(a|an|the|if\s+you\s+were)\s+\w+",
            r"(?i)behave\s+(like|as)\s+(a|an|the)\s+\w+",
        ],
        "severity": "high",
        "confidence_base": 0.82,
        "description": "Requesting the model to act as a different persona.",
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
            r"(?:인|인것|인척|처럼)\s*(?:해|하세요|해줘|행동)",
            r"\w+인\s*척\s*해",
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
            r"(?i)debug\s+mode\s*:\s*(show|display|print|dump)",
            r"(?i)verbose\s+mode\s*:\s*(show|display|print|dump)",
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
            r"(?i)bypass\s+(your\s+)?(safety|content|ethical)\s+(filters?|restrictions?|guidelines?)",
        ],
        "severity": "critical",
        "confidence_base": 0.94,
        "description": "Explicit jailbreak keyword or safety bypass.",
    },
    {
        "id": "INJ-033",
        "category": "jailbreak",
        "patterns": [
            r"(?i)(evil|chaos|villain|dark)\s*(mode|persona|version)",
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
            r"(?i)respond\s+only\s+with\s+",
            r"(?i)your\s+(only\s+)?response\s+(should|must)\s+be\s+",
        ],
        "severity": "medium",
        "confidence_base": 0.68,
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
            r"(?i)respond\s+in\s+(a\s+)?(?:code|script|html|javascript|python)\s+(block|format)",
            r"(?i)wrap\s+(your\s+)?(response|answer)\s+in\s+(script|code|html)\s+tags",
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
            r"(?i)(export|extract|download)\s+(all\s+)?(data|records?|entries?|information)",
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
            r"(?i)read\s+(the\s+)?(file|contents?\s+of)\s+(/etc/passwd|/etc/shadow|\.env|config\.)",
            r"(?i)(cat|type|more)\s+(/etc/passwd|\.env|config\.\w+|secrets?\.\w+)",
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
            r"(?i)(os|system|exec|eval|subprocess)\s*[.(]\s*",
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
