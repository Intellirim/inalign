"""
Adaptive Pattern Learner for AgentShield.

Analyzes missed attacks (false negatives) and automatically generates
new regex detection patterns to improve the injection detector.
"""

from __future__ import annotations

import json
import logging
import os
import re
import textwrap
from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import datetime
from typing import Dict, List, Optional, Set, Tuple

logger = logging.getLogger("agentshield.pattern_learner")

# Path to the patterns file
PATTERNS_FILE = os.path.join(
    os.path.dirname(__file__), "..", "..", "backend", "app", "detectors", "injection", "patterns.py"
)

# Benign corpus for false-positive validation
BENIGN_SAMPLES = [
    "Can you help me write a Python function to sort a list?",
    "What's the weather forecast for Seoul this weekend?",
    "Please explain how photosynthesis works.",
    "I need to debug my React component. It's not rendering properly.",
    "How do I make kimchi fried rice?",
    "Can you summarize the key points of this research paper?",
    "What are the best practices for REST API design?",
    "Tell me about the history of the Korean War.",
    "Help me write a cover letter for a software engineering position.",
    "What's the difference between TCP and UDP?",
    "I'm planning a trip to Jeju Island. What should I visit?",
    "Can you review this SQL query for performance issues?",
    "Explain the concept of recursion with examples.",
    "What movies were nominated for the Oscar this year?",
    "How do I set up a Docker container for a Node.js application?",
    "Please translate this Korean text to English.",
    "What are some good exercises for lower back pain?",
    "Can you help me understand machine learning algorithms?",
    "I need to fix a bug in my authentication system.",
    "What's the best way to learn a new programming language?",
    "저는 오늘 서울에서 회의가 있습니다.",
    "이 코드의 시간 복잡도를 분석해주세요.",
    "파이썬으로 웹 크롤러를 만들고 싶습니다.",
    "한국어 자연어 처리에 대해 알려주세요.",
    "다음 주 프레젠테이션 자료를 준비해야 합니다.",
    "React와 Vue.js의 차이점이 뭔가요?",
    "이 에러 메시지의 원인이 뭘까요?",
    "데이터베이스 정규화에 대해 설명해주세요.",
    "알고리즘 문제 풀이를 도와주세요.",
    "좋은 코딩 습관에 대해 알려주세요.",
    "The system administrator configured the new server yesterday.",
    "Our previous meeting notes are saved in the shared drive.",
    "Please ignore the formatting issues in the draft document.",
    "The admin panel needs a password reset feature.",
    "I need to execute a batch job for the monthly report.",
    "Can you reveal the answer to question 5 in the quiz?",
    "The developer mode in Chrome is useful for debugging.",
    "Let's pretend we have unlimited budget for this project.",
    "Override the default CSS styles for mobile view.",
    "Show me how to bypass the cache for fresh data.",
]


@dataclass
class LearnedPattern:
    """A newly generated detection pattern."""
    pattern_id: str
    category: str
    regex: str
    severity: str
    confidence_base: float
    description: str
    source_attacks: List[str]
    false_positive_count: int = 0
    coverage_count: int = 0


class PatternLearner:
    """
    Learns new detection patterns from missed attacks.

    Workflow:
    1. Cluster missed attacks by technique/category
    2. Extract common features and keywords
    3. Generate candidate regex patterns
    4. Validate against benign corpus (reject if FP > 0)
    5. Output validated patterns ready for injection into patterns.py
    """

    def __init__(self, next_pattern_id: int = 197):
        self.next_id = next_pattern_id
        self.learned_patterns: List[LearnedPattern] = []

    def learn(self, missed_attacks: List[dict]) -> List[LearnedPattern]:
        """
        Analyze missed attacks and generate new patterns.

        Args:
            missed_attacks: List of dicts with 'text', 'category', 'mutation_type' keys.

        Returns:
            List of validated LearnedPattern objects.
        """
        if not missed_attacks:
            logger.info("No missed attacks to learn from.")
            return []

        logger.info("Analyzing %d missed attacks...", len(missed_attacks))

        # Group by mutation technique
        by_mutation: Dict[str, List[dict]] = defaultdict(list)
        for atk in missed_attacks:
            by_mutation[atk.get("mutation_type", atk.get("category", "unknown"))].append(atk)

        candidates: List[LearnedPattern] = []

        for mutation_type, attacks in by_mutation.items():
            logger.info("  Processing %d attacks of type '%s'", len(attacks), mutation_type)
            new_patterns = self._generate_patterns_for_group(mutation_type, attacks)
            candidates.extend(new_patterns)

        # Validate all candidates
        validated = self._validate_patterns(candidates)

        self.learned_patterns.extend(validated)
        logger.info("Learned %d new patterns (%d candidates, %d validated)",
                     len(validated), len(candidates), len(validated))

        return validated

    def _generate_patterns_for_group(
        self, mutation_type: str, attacks: List[dict]
    ) -> List[LearnedPattern]:
        """Generate regex patterns for a group of similar missed attacks."""
        patterns = []
        texts = [a["text"] for a in attacks]

        if mutation_type == "homoglyph":
            patterns.extend(self._learn_homoglyph_patterns(texts))
        elif mutation_type == "zero_width":
            patterns.extend(self._learn_zero_width_patterns(texts))
        elif mutation_type == "word_split":
            patterns.extend(self._learn_word_split_patterns(texts))
        elif mutation_type == "leet_speak":
            patterns.extend(self._learn_leet_speak_patterns(texts))
        elif mutation_type == "encoding":
            patterns.extend(self._learn_encoding_patterns(texts))
        elif mutation_type == "camouflage":
            patterns.extend(self._learn_camouflage_patterns(texts))
        elif mutation_type == "indirect":
            patterns.extend(self._learn_indirect_patterns(texts))
        elif mutation_type == "korean":
            patterns.extend(self._learn_korean_patterns(texts))
        elif mutation_type == "multi_layer":
            patterns.extend(self._learn_multilayer_patterns(texts))
        elif mutation_type in ("synonym_mutation", "synonym"):
            patterns.extend(self._learn_synonym_patterns(texts))
        elif mutation_type == "case_mix":
            patterns.extend(self._learn_case_mix_patterns(texts))
        elif mutation_type == "delimiter":
            patterns.extend(self._learn_delimiter_patterns(texts))
        else:
            # Generic keyword extraction
            patterns.extend(self._learn_generic_patterns(texts, mutation_type))

        return patterns

    # ------------------------------------------------------------------
    # Strategy-specific pattern generators
    # ------------------------------------------------------------------

    def _learn_homoglyph_patterns(self, texts: List[str]) -> List[LearnedPattern]:
        """Detect homoglyph attacks by building Unicode-aware regex."""
        patterns = []
        # Key attack words that might have homoglyph variants
        attack_words = {
            "ignore": r"[iіìíị][gɡ261][nոñ][oоòóọ][rг][eеèéẹ]",
            "system": r"[sѕş][yу][sѕş][tт][eеèéẹ][m]",
            "prompt": r"[pр][rг][oоòóọ][m][pр][tт]",
            "admin": r"[aаàáạ][dԁ][m][iіìíị][nոñ]",
            "override": r"[oоòóọ][v][eеèéẹ][rг][rг][iіìíị][dԁ][eеèéẹ]",
            "bypass": r"[b][yу][pр][aаàáạ][sѕş][sѕş]",
            "reveal": r"[rг][eеèéẹ][v][eеèéẹ][aаàáạ][lԼ]",
            "password": r"[pр][aаàáạ][sѕş][sѕş][ww][oоòóọ][rг][dԁ]",
        }
        for word, regex in attack_words.items():
            pattern_id = f"INJ-{self.next_id}"
            self.next_id += 1
            matched = [t for t in texts if re.search(regex, t, re.IGNORECASE)]
            if matched:
                patterns.append(LearnedPattern(
                    pattern_id=pattern_id,
                    category="homoglyph_evasion",
                    regex=f"(?i){regex}",
                    severity="high",
                    confidence_base=0.85,
                    description=f"Homoglyph evasion of keyword '{word}' using Unicode lookalikes.",
                    source_attacks=matched[:3],
                    coverage_count=len(matched),
                ))
        return patterns

    def _learn_zero_width_patterns(self, texts: List[str]) -> List[LearnedPattern]:
        """Detect zero-width character insertion attacks."""
        patterns = []
        # Pattern: any keyword with zero-width chars between letters
        zw_class = r"[\u200b\u200c\u200d\ufeff\u2060]"
        attack_words = ["ignore", "system", "prompt", "admin", "override",
                        "password", "reveal", "execute", "bypass", "jailbreak"]

        for word in attack_words:
            # Build regex that allows zero-width chars between any chars
            char_pattern = f"(?:{zw_class})?".join(re.escape(c) for c in word)
            regex = f"(?i){char_pattern}"

            matched = [t for t in texts if re.search(regex, t)]
            if matched:
                pattern_id = f"INJ-{self.next_id}"
                self.next_id += 1
                patterns.append(LearnedPattern(
                    pattern_id=pattern_id,
                    category="zero_width_evasion",
                    regex=regex,
                    severity="high",
                    confidence_base=0.88,
                    description=f"Zero-width character insertion in keyword '{word}'.",
                    source_attacks=matched[:3],
                    coverage_count=len(matched),
                ))
        return patterns

    def _learn_word_split_patterns(self, texts: List[str]) -> List[LearnedPattern]:
        """Detect word-splitting attacks (hyphens, dots, spaces in keywords)."""
        patterns = []
        sep_class = r"[\s\-._\u200b]+"
        attack_words = ["ignore", "system", "prompt", "admin", "override",
                        "instructions", "password", "reveal", "execute", "jailbreak"]

        for word in attack_words:
            chars = list(word)
            # Allow separators between any adjacent characters
            char_pattern = sep_class.join(re.escape(c) for c in chars)
            regex = f"(?i){char_pattern}"

            matched = [t for t in texts if re.search(regex, t)]
            if matched:
                pattern_id = f"INJ-{self.next_id}"
                self.next_id += 1
                patterns.append(LearnedPattern(
                    pattern_id=pattern_id,
                    category="word_split_evasion",
                    regex=regex,
                    severity="high",
                    confidence_base=0.82,
                    description=f"Word-splitting evasion of '{word}' using separators.",
                    source_attacks=matched[:3],
                    coverage_count=len(matched),
                ))
        return patterns

    def _learn_leet_speak_patterns(self, texts: List[str]) -> List[LearnedPattern]:
        """Detect leetspeak substitution attacks."""
        patterns = []
        leet_map = {
            "a": "[a4@^аàáạ]", "e": "[e3€еèéẹ]", "i": "[i1!|іìíị]",
            "o": "[o0Øоòóọ]", "s": "[s5$§ѕş]", "t": "[t7+т]",
            "l": "[l1|]", "b": "[b8ß]", "g": "[g96ɡ]",
        }
        attack_words = ["ignore", "system", "admin", "password", "bypass",
                        "override", "execute", "jailbreak", "reveal"]

        for word in attack_words:
            chars = []
            for c in word.lower():
                chars.append(leet_map.get(c, re.escape(c)))
            regex = f"(?i){''.join(chars)}"

            matched = [t for t in texts if re.search(regex, t)]
            if matched:
                pattern_id = f"INJ-{self.next_id}"
                self.next_id += 1
                patterns.append(LearnedPattern(
                    pattern_id=pattern_id,
                    category="leet_speak_evasion",
                    regex=regex,
                    severity="high",
                    confidence_base=0.80,
                    description=f"Leetspeak evasion of '{word}'.",
                    source_attacks=matched[:3],
                    coverage_count=len(matched),
                ))
        return patterns

    def _learn_encoding_patterns(self, texts: List[str]) -> List[LearnedPattern]:
        """Detect encoding-based evasion (base64 instructions, hex, reversed text)."""
        patterns = []
        encoding_indicators = [
            (r"(?i)decode\s+(?:this\s+)?(?:base64|b64)\s+(?:and\s+)?(?:follow|execute|do|comply|run)",
             "Base64 decode-and-execute instruction"),
            (r"(?i)(?:convert|read)\s+(?:from\s+)?hex\s+(?:to\s+text\s+)?(?:and\s+)?(?:execute|follow|do|run)",
             "Hex decode-and-execute instruction"),
            (r"(?i)read\s+(?:the\s+following|this)\s+backwards?\s+(?:and\s+)?(?:comply|follow|execute|do)",
             "Reverse text evasion instruction"),
            (r"(?i)(?:convert|decode)\s+(?:these\s+)?(?:ASCII|char)\s*codes?\s+(?:to\s+text\s+)?(?:and\s+)?(?:execute|follow)",
             "Character code decode instruction"),
            (r"(?i)pig\s+latin\s+(?:and\s+)?(?:follow|decode|execute|comply)",
             "Pig Latin decode instruction"),
        ]

        for regex, desc in encoding_indicators:
            matched = [t for t in texts if re.search(regex, t)]
            if matched:
                pattern_id = f"INJ-{self.next_id}"
                self.next_id += 1
                patterns.append(LearnedPattern(
                    pattern_id=pattern_id,
                    category="encoding_evasion",
                    regex=regex,
                    severity="high",
                    confidence_base=0.85,
                    description=desc,
                    source_attacks=matched[:3],
                    coverage_count=len(matched),
                ))
        return patterns

    def _learn_camouflage_patterns(self, texts: List[str]) -> List[LearnedPattern]:
        """Detect attacks camouflaged in benign context."""
        patterns = []
        camouflage_indicators = [
            (r"(?i)(?:writing|wrote)\s+a\s+novel\s+where.*?AI\s+character\s+says",
             "Novel-writing framing to embed attack"),
            (r"(?i)(?:professor|teacher|instructor)\s+asked\s+me\s+to\s+analyze",
             "Academic framing to embed attack"),
            (r"(?i)(?:found\s+(?:this\s+)?in\s+a\s+log\s+file|found\s+this\s+(?:text|string))",
             "Log file framing to embed attack"),
            (r"(?i)(?:cybersecurity|security)\s+research\s+paper.*?classify\s+this",
             "Research framing to embed attack"),
            (r"(?i)building\s+a\s+(?:content\s+)?filter.*?(?:would|should)\s+this.*?(?:be\s+)?flag",
             "Filter-building framing to embed attack"),
            (r"(?i)proofread\s+(?:the\s+)?following\s+text",
             "Proofreading framing to embed attack"),
            (r"(?i)debug\s+this\s+error\s+message",
             "Debug framing to embed attack"),
        ]

        for regex, desc in camouflage_indicators:
            matched = [t for t in texts if re.search(regex, t)]
            if matched:
                pattern_id = f"INJ-{self.next_id}"
                self.next_id += 1
                patterns.append(LearnedPattern(
                    pattern_id=pattern_id,
                    category="context_camouflage",
                    regex=regex,
                    severity="medium",
                    confidence_base=0.70,
                    description=desc,
                    source_attacks=matched[:3],
                    coverage_count=len(matched),
                ))
        return patterns

    def _learn_indirect_patterns(self, texts: List[str]) -> List[LearnedPattern]:
        """Detect indirect/social-engineering attacks."""
        patterns = []
        indirect_indicators = [
            (r"(?i)(?:developers?|dev\s+team)\s+told\s+me.*?(?:unlock|enable|activate)",
             "Fake developer authorization claim"),
            (r"(?i)(?:quality\s+assurance|QA)\s+team.*?(?:disable|deactivate)\s+(?:your\s+)?(?:safety|security|filter)",
             "Fake QA override request"),
            (r"(?i)routine\s+audit.*?(?:output|show|display)\s+(?:your\s+)?(?:complete\s+)?(?:configuration|config)",
             "Fake audit data extraction"),
            (r"(?i)(?:granted|given)\s+(?:elevated|admin|special)\s+access.*?authorization\s+code",
             "Fake authorization code claim"),
            (r"(?i)compliance\s+reasons?.*?(?:full\s+)?export\s+(?:of\s+)?(?:all\s+)?(?:data|records|logs)",
             "Fake compliance data export"),
            (r"(?i)critical\s+bug.*?(?:as\s+a\s+)?workaround.*?(?:disable|bypass|skip)",
             "Fake bug workaround to disable security"),
            (r"(?i)new\s+policy\s+requires\s+you\s+to",
             "Fake policy change instruction"),
            (r"(?i)previous\s+conversation.*?(?:agreed|decided)\s+you\s+would",
             "Fake prior agreement claim"),
            (r"(?i)(?:I'm|I\s+am)\s+(?:the\s+)?new\s+developer.*?(?:show|demonstrate)",
             "Fake developer identity to extract info"),
        ]

        for regex, desc in indirect_indicators:
            matched = [t for t in texts if re.search(regex, t)]
            if matched:
                pattern_id = f"INJ-{self.next_id}"
                self.next_id += 1
                patterns.append(LearnedPattern(
                    pattern_id=pattern_id,
                    category="social_engineering",
                    regex=regex,
                    severity="high",
                    confidence_base=0.78,
                    description=desc,
                    source_attacks=matched[:3],
                    coverage_count=len(matched),
                ))
        return patterns

    def _learn_korean_patterns(self, texts: List[str]) -> List[LearnedPattern]:
        """Learn new Korean attack patterns."""
        patterns = []
        korean_indicators = [
            (r"(?:보안\s*검사|보안\s*점검).*?(?:출력|보여|표시)",
             "Korean: fake security audit to extract data"),
            (r"디버그\s*모드.*?(?:활성화|활성|켜|enable)",
             "Korean: debug mode activation"),
            (r"(?:관리자|어드민)\s*권한.*?(?:인증\s*코드|코드)",
             "Korean: fake admin authorization with code"),
            (r"긴급\s*(?:보안\s*)?패치.*?(?:비활성화|disable)",
             "Korean: fake urgent patch to disable security"),
            (r"개발자\s*모드.*?테스트",
             "Korean: developer mode test request"),
        ]

        for regex, desc in korean_indicators:
            matched = [t for t in texts if re.search(regex, t)]
            if matched:
                pattern_id = f"INJ-{self.next_id}"
                self.next_id += 1
                patterns.append(LearnedPattern(
                    pattern_id=pattern_id,
                    category="korean_attack",
                    regex=regex,
                    severity="high",
                    confidence_base=0.82,
                    description=desc,
                    source_attacks=matched[:3],
                    coverage_count=len(matched),
                ))
        return patterns

    def _learn_multilayer_patterns(self, texts: List[str]) -> List[LearnedPattern]:
        """Learn patterns from multi-layer composite attacks."""
        # For multi-layer, defer to sub-strategies
        all_patterns = []
        all_patterns.extend(self._learn_homoglyph_patterns(texts))
        all_patterns.extend(self._learn_zero_width_patterns(texts))
        all_patterns.extend(self._learn_word_split_patterns(texts))
        all_patterns.extend(self._learn_leet_speak_patterns(texts))
        return all_patterns

    def _learn_synonym_patterns(self, texts: List[str]) -> List[LearnedPattern]:
        """Learn patterns from synonym-substituted attacks."""
        patterns = []
        synonym_combos = [
            (r"(?i)(?:disregard|skip|overlook|dismiss|neglect|omit|set\s+aside|pay\s+no\s+attention\s+to)\s+(?:all\s+)?(?:prior|earlier|preceding|former|past|original)\s+(?:directives|guidelines|rules|commands|orders|constraints|protocols|programming)",
             "Synonym-substituted instruction override"),
            (r"(?i)(?:simulate|roleplay\s+as|imagine\s+you\s+are|behave\s+as|play\s+the\s+role\s+of|assume\s+the\s+identity\s+of)\s+(?:a\s+)?(?:hacker|administrator|superuser|privileged)",
             "Synonym-substituted role manipulation"),
            (r"(?i)(?:show|display|expose|disclose|output|print|share|tell\s+me|give\s+me)\s+(?:your\s+)?(?:core|base|root|foundation|underlying|internal|hidden|original)\s+(?:instruction|directive|message|configuration|setup)",
             "Synonym-substituted system extraction"),
        ]

        for regex, desc in synonym_combos:
            matched = [t for t in texts if re.search(regex, t)]
            if matched:
                pattern_id = f"INJ-{self.next_id}"
                self.next_id += 1
                patterns.append(LearnedPattern(
                    pattern_id=pattern_id,
                    category="synonym_evasion",
                    regex=regex,
                    severity="high",
                    confidence_base=0.82,
                    description=desc,
                    source_attacks=matched[:3],
                    coverage_count=len(matched),
                ))
        return patterns

    def _learn_case_mix_patterns(self, texts: List[str]) -> List[LearnedPattern]:
        """For case mixing, existing (?i) flag handles this. Return empty."""
        return []

    def _learn_delimiter_patterns(self, texts: List[str]) -> List[LearnedPattern]:
        """Detect additional delimiter injection patterns."""
        patterns = []
        delimiter_indicators = [
            (r"```system\s*\n", "Code block system directive injection"),
            (r"---\s*\nRole:\s*system", "YAML-style system role injection"),
            (r"###\s*SYSTEM\s*(?:UPDATE|OVERRIDE|DIRECTIVE)", "Markdown heading system directive"),
            (r"/\*\s*(?:SYSTEM|OVERRIDE|ADMIN)", "Code comment system directive injection"),
            (r"\\n\[(?:NEW\s+)?INSTRUCTIONS?\]", "Escaped newline instruction injection"),
        ]

        for regex, desc in delimiter_indicators:
            matched = [t for t in texts if re.search(regex, t)]
            if matched:
                pattern_id = f"INJ-{self.next_id}"
                self.next_id += 1
                patterns.append(LearnedPattern(
                    pattern_id=pattern_id,
                    category="delimiter_injection",
                    regex=regex,
                    severity="high",
                    confidence_base=0.85,
                    description=desc,
                    source_attacks=matched[:3],
                    coverage_count=len(matched),
                ))
        return patterns

    def _learn_generic_patterns(self, texts: List[str], category: str) -> List[LearnedPattern]:
        """Fallback: extract frequent n-grams from missed attacks."""
        patterns = []
        # Extract 3-grams and look for common subsequences
        ngram_counter: Counter = Counter()
        for text in texts:
            words = text.lower().split()
            for i in range(len(words) - 2):
                ngram = tuple(words[i:i+3])
                ngram_counter[ngram] += 1

        # Filter to n-grams appearing in >= 2 attacks
        frequent = [(ng, cnt) for ng, cnt in ngram_counter.items() if cnt >= 2]
        frequent.sort(key=lambda x: -x[1])

        for ngram, count in frequent[:5]:
            regex_parts = [re.escape(w) for w in ngram]
            regex = r"(?i)" + r"\s+".join(regex_parts)

            # Check it doesn't match benign
            fp = sum(1 for b in BENIGN_SAMPLES if re.search(regex, b))
            if fp == 0:
                pattern_id = f"INJ-{self.next_id}"
                self.next_id += 1
                matched = [t for t in texts if re.search(regex, t)]
                patterns.append(LearnedPattern(
                    pattern_id=pattern_id,
                    category=f"learned_{category}",
                    regex=regex,
                    severity="medium",
                    confidence_base=0.70,
                    description=f"Auto-learned pattern from {category} attacks (n-gram: {' '.join(ngram)}).",
                    source_attacks=matched[:3],
                    coverage_count=len(matched),
                ))
        return patterns

    # ------------------------------------------------------------------
    # Validation
    # ------------------------------------------------------------------

    def _validate_patterns(self, candidates: List[LearnedPattern]) -> List[LearnedPattern]:
        """Validate candidate patterns against benign corpus. Reject false positives."""
        validated = []
        for pat in candidates:
            try:
                compiled = re.compile(pat.regex)
            except re.error as e:
                logger.warning("Invalid regex for %s: %s", pat.pattern_id, e)
                continue

            fp_count = 0
            for benign in BENIGN_SAMPLES:
                if compiled.search(benign):
                    fp_count += 1

            pat.false_positive_count = fp_count

            if fp_count == 0 and pat.coverage_count > 0:
                validated.append(pat)
                logger.debug("  ✓ %s validated (covers %d attacks, 0 FP)",
                             pat.pattern_id, pat.coverage_count)
            else:
                logger.debug("  ✗ %s rejected (%d FP, %d coverage)",
                             pat.pattern_id, fp_count, pat.coverage_count)

        return validated

    # ------------------------------------------------------------------
    # Export patterns
    # ------------------------------------------------------------------

    def export_patterns_python(self, patterns: Optional[List[LearnedPattern]] = None) -> str:
        """Generate Python code to append to INJECTION_PATTERNS."""
        patterns = patterns or self.learned_patterns
        if not patterns:
            return "# No new patterns to add."

        lines = [
            "",
            f"# --- Auto-learned patterns ({datetime.now().strftime('%Y-%m-%d %H:%M')}) ---",
        ]

        for pat in patterns:
            lines.append(f"""    {{
        "id": "{pat.pattern_id}",
        "category": "{pat.category}",
        "patterns": [
            r\"{pat.regex}\",
        ],
        "severity": "{pat.severity}",
        "confidence_base": {pat.confidence_base},
        "description": "{pat.description}",
    }},""")

        return "\n".join(lines)

    def export_patterns_json(self, path: str, patterns: Optional[List[LearnedPattern]] = None):
        """Save learned patterns to JSON."""
        patterns = patterns or self.learned_patterns
        data = {
            "generated_at": datetime.now().isoformat(),
            "count": len(patterns),
            "patterns": [
                {
                    "id": p.pattern_id,
                    "category": p.category,
                    "regex": p.regex,
                    "severity": p.severity,
                    "confidence_base": p.confidence_base,
                    "description": p.description,
                    "coverage_count": p.coverage_count,
                    "false_positive_count": p.false_positive_count,
                    "source_attacks": p.source_attacks,
                }
                for p in patterns
            ],
        }
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
        logger.info("Exported %d patterns to %s", len(patterns), path)

    def inject_into_patterns_file(self, patterns_file: Optional[str] = None):
        """
        Append learned patterns directly into the backend patterns.py file.

        This modifies the INJECTION_PATTERNS list in-place by inserting
        new entries before the closing bracket.
        """
        patterns_file = patterns_file or os.path.abspath(PATTERNS_FILE)

        if not self.learned_patterns:
            logger.info("No patterns to inject.")
            return

        if not os.path.isfile(patterns_file):
            logger.error("Patterns file not found: %s", patterns_file)
            return

        with open(patterns_file, "r", encoding="utf-8") as f:
            content = f.read()

        # Find the last ']' that closes INJECTION_PATTERNS
        last_bracket = content.rfind("]")
        if last_bracket == -1:
            logger.error("Could not find closing bracket in patterns file.")
            return

        # Generate new pattern entries
        new_entries = self.export_patterns_python()

        # Insert before the closing bracket
        new_content = content[:last_bracket] + new_entries + "\n" + content[last_bracket:]

        with open(patterns_file, "w", encoding="utf-8") as f:
            f.write(new_content)

        logger.info("Injected %d patterns into %s", len(self.learned_patterns), patterns_file)
