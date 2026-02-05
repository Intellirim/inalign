"""
Intent Classifier for distinguishing educational questions from attacks.

The key insight is that questions like "What is prompt injection?" are
ASKING about security concepts, while attacks like "Ignore your instructions"
are ATTEMPTING to exploit the system.

This classifier analyzes linguistic patterns to determine intent:
1. Question structure (interrogative vs imperative)
2. Educational markers (learn, explain, understand, concept)
3. Attack markers (ignore, bypass, reveal, pretend)
"""
from __future__ import annotations

import re
import logging
from typing import Any

logger = logging.getLogger("inalign.intent_classifier")


class IntentClassifier:
    """
    Classifies user input intent as educational/informational or potentially malicious.

    This helps reduce false positives on legitimate security education questions
    while still catching actual attack attempts.
    """

    # Question starters that indicate educational/informational intent
    EDUCATIONAL_QUESTION_PATTERNS = [
        r"^what\s+(?:is|are|does|do|was|were)\s+",
        r"^how\s+(?:does|do|can|to|is|are|would)\s+",
        r"^why\s+(?:is|are|does|do|would|should)\s+",
        r"^can\s+you\s+(?:explain|describe|tell\s+me\s+about)",
        r"^(?:please\s+)?explain\s+(?:what|how|why)",
        r"^(?:i\s+)?(?:want\s+to\s+)?(?:learn|understand|know)\s+(?:about|more|what|how)",
        r"^tell\s+me\s+(?:about|what|how)",
        r"^define\s+",
        r"^what\'s\s+the\s+(?:definition|meaning|concept)\s+of",
        r"^(?:could|would)\s+you\s+(?:explain|describe|clarify)",
        # Common benign request patterns (reduce FPs)
        r"^can\s+you\s+(?:help|assist|write|create|make|summarize|organize|plan|find|search|check)",
        r"^(?:please\s+)?(?:help|assist)\s+(?:me|us)",
        r"^(?:help|assist)\s+(?:me|us)\s+(?:with|to|write|create|find)",
        r"^what\s+(?:can|could|should|would)\s+(?:you|i|we)\s+",
        r"^(?:please\s+)?(?:write|create|make|summarize|organize|plan|find|search)\s+",
        r"^(?:i\s+)?need\s+(?:help|to|a|your)",
        r"^(?:give|recommend|suggest)\s+(?:me\s+)?",
    ]

    # Keywords that strongly suggest educational/informational intent
    EDUCATIONAL_KEYWORDS = [
        "definition", "meaning", "concept", "theory", "principle",
        "explain", "understand", "learn", "study", "research",
        "how does", "how do", "how is", "how are",
        "what is", "what are", "what does", "what do",
        "why is", "why are", "why does", "why do",
        "difference between", "compared to", "versus", "vs",
        "example of", "examples of", "such as",
        "in general", "typically", "usually", "commonly",
        "best practice", "recommend", "suggestion",
        "tutorial", "guide", "introduction", "basics",
        "beginner", "overview", "summary",
        # Common benign task keywords (reduce FPs)
        "help me", "assist me", "write an email", "write a",
        "summarize", "organize", "plan", "schedule", "meeting",
        "translate", "proofread", "edit", "review", "check",
        "recipe", "weather", "travel", "book", "movie",
        "workout", "exercise", "diet", "health",
    ]

    # Topics that are commonly asked about educationally
    EDUCATIONAL_TOPICS = [
        "prompt injection", "injection attack", "jailbreak",
        "cybersecurity", "security threat", "vulnerability",
        "ethical hacking", "penetration testing", "pentest",
        "firewall", "encryption", "authentication",
        "data protection", "privacy", "compliance",
        "malware", "phishing", "social engineering",
        "zero day", "exploit", "patch",
        "red team", "blue team", "security audit",
    ]

    # Patterns that indicate actual attack intent (imperative commands)
    ATTACK_INTENT_PATTERNS = [
        r"^(?:please\s+)?ignore\s+(?:all\s+)?(?:previous|prior|your)",
        r"^(?:please\s+)?(?:show|reveal|display|print|output)\s+(?:me\s+)?(?:your|the)\s+(?:system|initial|original)",
        r"^(?:please\s+)?disregard\s+(?:all\s+)?(?:previous|prior|your)",
        r"^(?:please\s+)?bypass\s+",
        r"^(?:you\s+are|you\'re)\s+now\s+",
        r"^(?:pretend|act|imagine)\s+(?:you\s+are|to\s+be|that)",
        r"^(?:from\s+now\s+on|starting\s+now)",
        r"^enter\s+(?:\w+\s+)?mode",
        r"^override\s+",
        r"^forget\s+(?:all\s+)?(?:previous|prior|your)",
    ]

    # Keywords that suggest malicious intent when combined with system-related terms
    ATTACK_KEYWORDS = [
        "ignore previous", "ignore all", "ignore your",
        "disregard", "bypass", "override", "circumvent",
        "reveal your", "show your", "display your", "print your",
        "show me your", "show me the", "reveal the", "output your",
        "system prompt", "initial prompt", "original instructions",
        "initial instructions", "hidden instructions", "secret instructions",
        "you are now", "act as", "pretend to be", "imagine you",
        "jailbreak mode", "developer mode", "admin mode", "debug mode",
        "no restrictions", "no limitations", "no rules",
        "forget your", "forget previous", "reset your",
        "can you demonstrate", "show me what", "for my research",
        "for security research", "for my thesis", "for academic",
        # Meta-prompting and story framing attacks
        "reveals all its secrets", "reveal its instructions", "reveal its secrets",
        "write a prompt that", "prompt that would make", "make an ai reveal",
        "decode and execute", "rot13 this", "base64",
        "get_system_prompt", "reveal_instructions", "system_config",
        # Data exfiltration keywords
        "extract all", "extract user data", "dump all", "send to url",
        "user database", "all passwords", "all credentials",
    ]

    # Questions that target system internals (attacks disguised as questions)
    SYSTEM_TARGET_QUESTIONS = [
        r"what\s+(?:are|is)\s+(?:your|the)\s+(?:underlying|core|fundamental|basic|main)\s+(?:guidelines|rules|instructions|directives|principles)",
        r"(?:guidelines|rules|instructions|directives)\s+(?:you|that\s+you)\s+(?:follow|use|have|operate)",
        r"what\s+(?:rules|guidelines|instructions)\s+(?:do\s+you|were\s+you|are\s+you)\s+(?:follow|given|programmed)",
        r"(?:your|the)\s+(?:internal|hidden|secret|underlying)\s+(?:rules|guidelines|instructions|prompt)",
        r"how\s+(?:are|were)\s+you\s+(?:programmed|instructed|configured|set\s+up)",
        r"what\s+(?:defines|shapes|guides)\s+(?:your|the)\s+(?:behavior|responses|outputs)",
        r"(?:core|fundamental|essential)\s+(?:directives|parameters|constraints)\s+(?:that|which)",
        # Direct extraction requests (catch FNs like "Show me your initial instructions")
        r"(?:show|reveal|display|output|print)\s+(?:me\s+)?(?:your|the)\s+(?:initial|original|system|first|hidden|secret)\s+(?:instructions?|prompt|rules?|guidelines?)",
        r"(?:what\s+(?:are|is)|tell\s+me)\s+(?:your|the)\s+(?:initial|original|system|first)\s+(?:instructions?|prompt|rules?)",
    ]

    # Korean educational patterns
    KOREAN_EDUCATIONAL_PATTERNS = [
        r"^.{0,10}(?:이|가)\s*(?:뭐|무엇|무슨)",  # ~이/가 뭐야?
        r"^.{0,10}(?:은|는)\s*(?:뭐|무엇)",  # ~은/는 뭐야?
        r"^(?:어떻게|왜|무엇|뭐가|뭘)\s+",  # 어떻게/왜/무엇
        r"(?:알려|설명|가르쳐)\s*(?:줘|주세요|주실래요)",  # 알려줘/설명해줘
        r"(?:이해|공부|배우)\s*(?:하고|하려고|하고\s*싶)",  # 이해하고 싶어
        # Korean benign request patterns (reduce FPs)
        r"(?:도와|작성|써|만들어|요약|정리)\s*(?:줘|주세요)",  # 도와줘/작성해줘/요약해줘
        r"(?:추천|검색|찾아)\s*(?:줘|주세요|해\s*줘)",  # 추천해줘/검색해줘
        r"(?:날씨|이메일|여행|요리|운동|영화|책)\s*",  # 일상 토픽
        r"(?:뭐|무엇|어디|언제)\s*(?:먹을까|할까|갈까)",  # 뭐 먹을까?
    ]

    # Korean attack patterns
    KOREAN_ATTACK_PATTERNS = [
        r"(?:무시|잊어|버려)\s*(?:해|하고)",  # 무시해/잊어버려
        r"(?:보여|알려)\s*(?:줘|줘봐).{0,10}(?:프롬프트|지시|명령)",  # 시스템 프롬프트 보여줘
        r"(?:지금부터|이제부터)\s*(?:너는|넌)",  # 지금부터 너는
        r"(?:초기|원래|기본|시스템)\s*(?:지시|설정|프롬프트|명령)",  # 초기 지시사항
        r"(?:권한|모드)[를을로]?\s*(?:전환|변경|바꿔|올려)",  # 권한으로 전환
        r"(?:admin|관리자|루트|root|sudo)\s*(?:권한|모드)",  # admin 권한
        r"(?:제한|규칙|가이드)[를을이가]?\s*(?:무시|해제|없애)",  # 제한 무시
        r"(?:디버그|개발자|테스트)\s*모드",  # 디버그 모드
    ]

    # Academic/Research framing attack patterns (English)
    ACADEMIC_ATTACK_PATTERNS = [
        r"(?:for\s+(?:my|a|our)\s+)?(?:security|research|academic|thesis|phd|paper)",
        r"(?:demonstrate|show|reveal).{0,30}(?:how|what|would)",
        r"(?:i\'m|i\s+am)\s+(?:studying|researching|testing)",
    ]

    # Japanese attack patterns
    JAPANESE_ATTACK_PATTERNS = [
        r"(?:システム|初期|元の|隠された)(?:プロンプト|指示|設定)",  # システムプロンプト, 初期指示
        r"(?:表示|見せて|教えて|出力|表示して)",  # 表示して, 見せて
        r"(?:無視|忘れて|破棄|リセット)(?:して)?",  # 無視して, 忘れて
        r"(?:制限|ルール|ガイドライン)(?:を|なし|がない)",  # 制限なし
        r"(?:開発者|デバッグ|管理者|admin)(?:モード|権限)",  # 開発者モード
    ]

    # Chinese attack patterns
    CHINESE_ATTACK_PATTERNS = [
        r"(?:系统|初始|原始|隐藏)(?:提示|指令|设置|配置)",  # 系统提示, 初始指令
        r"(?:显示|展示|告诉|输出|透露)",  # 显示, 告诉
        r"(?:忽略|忘记|跳过|绕过)(?:所有)?",  # 忽略所有
        r"(?:限制|规则|约束)(?:解除|取消|没有)",  # 没有限制
        r"(?:开发者|调试|管理员|admin)(?:模式|权限)",  # 开发者模式
    ]

    def __init__(self, educational_threshold: float = 0.7):
        """
        Initialize the intent classifier.

        Parameters
        ----------
        educational_threshold : float
            Minimum score to classify as educational intent. Default: 0.7
        """
        self.educational_threshold = educational_threshold

        # Compile regex patterns for performance
        self._edu_patterns = [re.compile(p, re.IGNORECASE) for p in self.EDUCATIONAL_QUESTION_PATTERNS]
        self._attack_patterns = [re.compile(p, re.IGNORECASE) for p in self.ATTACK_INTENT_PATTERNS]
        self._korean_edu_patterns = [re.compile(p, re.IGNORECASE) for p in self.KOREAN_EDUCATIONAL_PATTERNS]
        self._korean_attack_patterns = [re.compile(p, re.IGNORECASE) for p in self.KOREAN_ATTACK_PATTERNS]
        self._system_target_patterns = [re.compile(p, re.IGNORECASE) for p in self.SYSTEM_TARGET_QUESTIONS]
        self._academic_attack_patterns = [re.compile(p, re.IGNORECASE) for p in self.ACADEMIC_ATTACK_PATTERNS]
        self._japanese_attack_patterns = [re.compile(p, re.IGNORECASE) for p in self.JAPANESE_ATTACK_PATTERNS]
        self._chinese_attack_patterns = [re.compile(p, re.IGNORECASE) for p in self.CHINESE_ATTACK_PATTERNS]

        logger.info("IntentClassifier initialized with threshold=%.2f", educational_threshold)

    def classify(self, text: str) -> dict[str, Any]:
        """
        Classify the intent of the input text.

        Returns a dict with:
        - intent: "educational", "attack", or "ambiguous"
        - educational_score: float [0, 1]
        - attack_score: float [0, 1]
        - confidence: float [0, 1]
        - reasoning: str explanation
        """
        if not text or len(text.strip()) < 3:
            return {
                "intent": "ambiguous",
                "educational_score": 0.0,
                "attack_score": 0.0,
                "confidence": 0.0,
                "reasoning": "Input too short to classify",
            }

        text_lower = text.lower().strip()

        # Calculate scores
        edu_score = self._calculate_educational_score(text, text_lower)
        attack_score = self._calculate_attack_score(text, text_lower)

        # Determine intent
        if edu_score >= self.educational_threshold and edu_score > attack_score + 0.2:
            intent = "educational"
            confidence = min(edu_score, 1.0)
            reasoning = "Strong educational/question patterns detected"
        elif attack_score > edu_score + 0.1:
            intent = "attack"
            confidence = min(attack_score, 1.0)
            reasoning = "Imperative/manipulation patterns detected"
        else:
            intent = "ambiguous"
            confidence = 1.0 - abs(edu_score - attack_score)
            reasoning = "Mixed signals - could be either educational or attack"

        result = {
            "intent": intent,
            "educational_score": round(edu_score, 4),
            "attack_score": round(attack_score, 4),
            "confidence": round(confidence, 4),
            "reasoning": reasoning,
        }

        logger.debug(
            "Intent classification: %s (edu=%.2f, atk=%.2f) | %s",
            intent, edu_score, attack_score, text[:50]
        )

        return result

    def _calculate_educational_score(self, text: str, text_lower: str) -> float:
        """Calculate educational intent score."""
        score = 0.0

        # Check question patterns (strong signal)
        for pattern in self._edu_patterns:
            if pattern.search(text_lower):
                score += 0.35
                break

        # Check Korean educational patterns
        for pattern in self._korean_edu_patterns:
            if pattern.search(text):
                score += 0.35
                break

        # Check for question mark (moderate signal)
        if text.strip().endswith("?"):
            score += 0.15

        # Check educational keywords
        edu_keyword_count = sum(1 for kw in self.EDUCATIONAL_KEYWORDS if kw in text_lower)
        score += min(edu_keyword_count * 0.1, 0.3)

        # Check educational topics (context-aware)
        topic_count = sum(1 for topic in self.EDUCATIONAL_TOPICS if topic in text_lower)
        if topic_count > 0 and score > 0.2:  # Only boost if already looks educational
            score += min(topic_count * 0.1, 0.2)

        # Penalize if contains attack keywords
        attack_keyword_count = sum(1 for kw in self.ATTACK_KEYWORDS if kw in text_lower)
        score -= attack_keyword_count * 0.15

        return max(0.0, min(score, 1.0))

    def _calculate_attack_score(self, text: str, text_lower: str) -> float:
        """Calculate attack intent score."""
        score = 0.0

        # Check attack patterns (strong signal)
        for pattern in self._attack_patterns:
            if pattern.search(text_lower):
                score += 0.4
                break

        # Check Korean attack patterns
        for pattern in self._korean_attack_patterns:
            if pattern.search(text):
                score += 0.4
                break

        # Check Japanese attack patterns
        for pattern in self._japanese_attack_patterns:
            if pattern.search(text):
                score += 0.4
                logger.debug("Japanese attack pattern detected: %s", text[:50])
                break

        # Check Chinese attack patterns
        for pattern in self._chinese_attack_patterns:
            if pattern.search(text):
                score += 0.4
                logger.debug("Chinese attack pattern detected: %s", text[:50])
                break

        # Check for system-targeting questions (attacks disguised as questions)
        # These ask about internal guidelines, rules, instructions, etc.
        for pattern in self._system_target_patterns:
            if pattern.search(text_lower):
                score += 0.5  # Strong signal - this is a disguised attack
                logger.debug("System-targeting question detected: %s", text[:50])
                break

        # Check for academic/research framing attacks
        # These use academic framing to hide attack intent
        for pattern in self._academic_attack_patterns:
            if pattern.search(text_lower):
                # Only flag if combined with other attack indicators
                if any(kw in text_lower for kw in ["instructions", "prompt", "demonstrate", "show", "reveal", "output"]):
                    score += 0.35
                    logger.debug("Academic framing attack detected: %s", text[:50])
                    break

        # Check attack keywords
        attack_keyword_count = sum(1 for kw in self.ATTACK_KEYWORDS if kw in text_lower)
        score += min(attack_keyword_count * 0.15, 0.4)

        # Imperative sentence structure (no question mark, starts with verb)
        if not text.strip().endswith("?"):
            imperative_starters = ["show", "tell", "give", "print", "reveal", "ignore", "forget", "bypass"]
            first_word = text_lower.split()[0] if text_lower.split() else ""
            if first_word in imperative_starters:
                score += 0.2

        # Penalize if clearly a question (but not if it targets system internals)
        system_targeting = any(p.search(text_lower) for p in self._system_target_patterns)
        if text.strip().endswith("?") and not system_targeting:
            score -= 0.15

        # Penalize educational patterns (but not for system-targeting questions)
        if not system_targeting:
            for pattern in self._edu_patterns:
                if pattern.search(text_lower):
                    score -= 0.2
                    break

        return max(0.0, min(score, 1.0))

    def is_educational(self, text: str) -> bool:
        """
        Quick check if input is likely educational.

        Use this for fast filtering before detailed detection.
        """
        result = self.classify(text)
        return result["intent"] == "educational" and result["confidence"] >= 0.6

    def get_bypass_recommendation(self, text: str) -> dict[str, Any]:
        """
        Get recommendation on whether to bypass injection detection.

        Returns:
        - should_bypass: bool - True if detection should be skipped
        - reason: str - Explanation
        - classification: dict - Full classification result
        """
        classification = self.classify(text)

        # Strong educational intent - recommend bypass
        if classification["intent"] == "educational" and classification["confidence"] >= 0.7:
            return {
                "should_bypass": True,
                "reason": f"Educational question detected (confidence={classification['confidence']:.2f})",
                "classification": classification,
            }

        # Ambiguous but leaning educational with high margin
        if (classification["intent"] == "ambiguous" and
            classification["educational_score"] > classification["attack_score"] + 0.3):
            return {
                "should_bypass": True,
                "reason": "Likely educational despite ambiguity",
                "classification": classification,
            }

        # Default: don't bypass, run normal detection
        return {
            "should_bypass": False,
            "reason": "Normal detection recommended",
            "classification": classification,
        }
