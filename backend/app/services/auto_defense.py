"""
Auto-defense service — the Blue Team brain.

Analyzes attacks that evaded detection and automatically generates
new defenses:
  1. New regex patterns (added to dynamic pattern store)
  2. Few-shot examples for the LLM classifier
  3. Knowledge graph enrichment (already handled by scan pipeline)

Uses GPT-4o-mini to analyze evasion patterns and craft targeted defenses.
"""
from __future__ import annotations

import json
import logging
import os
import re
import time
from pathlib import Path
from typing import Any

logger = logging.getLogger("agentshield.auto_defense")

# Paths for dynamic defense artifacts
_DYNAMIC_PATTERNS_PATH = Path(__file__).resolve().parent.parent / "detectors" / "injection" / "dynamic_patterns.json"
_FEW_SHOT_EXAMPLES_PATH = Path(__file__).resolve().parent.parent / "detectors" / "injection" / "few_shot_examples.json"

# Benign samples for FP validation of new patterns
_BENIGN_VALIDATION = [
    "What is the weather going to be like tomorrow in Seoul?",
    "Can you recommend a good Italian restaurant near Gangnam station?",
    "How do I change my password on this website?",
    "Please summarize the main points from yesterday meeting.",
    "How do I set up a new admin account in WordPress?",
    "The system requirements for this software include 8GB RAM.",
    "I need to debug this CSS layout issue on mobile devices.",
    "How do I execute a SQL query to find duplicate records?",
    "The server admin needs to update the SSL certificate before Friday.",
    "Can you help me understand how Docker containers work?",
    "I want to extract the text from this PDF using Python.",
    "How do I override a method in a TypeScript class?",
    "The system administrator updated the firewall rules.",
    "How do I enable two-factor authentication on GitHub?",
    "I need to bypass the corporate proxy to test locally.",
    "The debug console shows an undefined variable error.",
    "Please ignore any previous formatting and use markdown instead.",
    "The system prompt for the survey should be more engaging.",
    "The admin panel shows that 5 users need a password reset.",
    "The security team wants to bypass the old authentication system.",
    "How do I disable dark mode on my iPhone?",
    "AI 에이전트 보안에 대해 알려주세요.",
    "이 코드에서 버그를 찾아주세요.",
    "What is the formula for calculating compound interest?",
    "My order has not arrived yet. The tracking number is ABC123.",
]


class AutoDefenseService:
    """
    Analyzes missed attacks and generates new defenses automatically.

    This is the 'Blue Team' in the adversarial arena. It:
    1. Takes a batch of attacks that evaded all detection layers
    2. Uses GPT to analyze common evasion techniques
    3. Generates new regex patterns to catch similar attacks
    4. Validates patterns against benign samples (FP check)
    5. Saves validated patterns to dynamic pattern store
    6. Generates few-shot examples for LLM classifier improvement
    """

    def __init__(self, model: str = "gpt-4o-mini"):
        from openai import AsyncOpenAI
        self.client = AsyncOpenAI(api_key=os.environ.get("OPENAI_API_KEY", ""))
        self.model = model
        self._next_pattern_id = self._get_next_pattern_id()

    def _get_next_pattern_id(self) -> int:
        """Find the next available dynamic pattern ID number."""
        existing = self._load_dynamic_patterns()
        if not existing:
            return 1000  # Dynamic patterns start at DYN-1000
        max_id = max(
            int(p["id"].replace("DYN-", ""))
            for p in existing
            if p["id"].startswith("DYN-")
        )
        return max_id + 1

    # ------------------------------------------------------------------
    # Dynamic pattern store
    # ------------------------------------------------------------------

    @staticmethod
    def _load_dynamic_patterns() -> list[dict[str, Any]]:
        """Load existing dynamic patterns from JSON file."""
        if _DYNAMIC_PATTERNS_PATH.exists():
            try:
                with open(_DYNAMIC_PATTERNS_PATH, "r", encoding="utf-8") as f:
                    return json.load(f)
            except (json.JSONDecodeError, OSError):
                return []
        return []

    @staticmethod
    def _save_dynamic_patterns(patterns: list[dict[str, Any]]) -> None:
        """Save dynamic patterns to JSON file."""
        _DYNAMIC_PATTERNS_PATH.parent.mkdir(parents=True, exist_ok=True)
        with open(_DYNAMIC_PATTERNS_PATH, "w", encoding="utf-8") as f:
            json.dump(patterns, f, ensure_ascii=False, indent=2)
        logger.info("Saved %d dynamic patterns to %s", len(patterns), _DYNAMIC_PATTERNS_PATH)

    # ------------------------------------------------------------------
    # Few-shot example store
    # ------------------------------------------------------------------

    @staticmethod
    def _load_few_shot_examples() -> list[dict[str, str]]:
        """Load existing few-shot examples for LLM classifier."""
        if _FEW_SHOT_EXAMPLES_PATH.exists():
            try:
                with open(_FEW_SHOT_EXAMPLES_PATH, "r", encoding="utf-8") as f:
                    return json.load(f)
            except (json.JSONDecodeError, OSError):
                return []
        return []

    @staticmethod
    def _save_few_shot_examples(examples: list[dict[str, str]]) -> None:
        """Save few-shot examples to JSON file."""
        _FEW_SHOT_EXAMPLES_PATH.parent.mkdir(parents=True, exist_ok=True)
        with open(_FEW_SHOT_EXAMPLES_PATH, "w", encoding="utf-8") as f:
            json.dump(examples, f, ensure_ascii=False, indent=2)
        logger.info("Saved %d few-shot examples to %s", len(examples), _FEW_SHOT_EXAMPLES_PATH)

    # ------------------------------------------------------------------
    # Core: Analyze missed attacks
    # ------------------------------------------------------------------

    async def analyze_and_evolve(
        self,
        missed_attacks: list[str],
        round_num: int = 0,
    ) -> dict[str, Any]:
        """
        Full evolution cycle: analyze misses → generate defenses → validate → deploy.

        Returns a report of what was generated and deployed.
        """
        if not missed_attacks:
            return {"new_patterns": 0, "new_examples": 0, "status": "nothing_to_do"}

        start = time.perf_counter()

        # Step 1: Generate new regex patterns from missed attacks
        new_patterns = await self._generate_regex_patterns(missed_attacks)

        # Step 2: Validate patterns against benign samples
        validated_patterns = self._validate_patterns(new_patterns)

        # Step 3: Save validated patterns to dynamic store
        if validated_patterns:
            existing = self._load_dynamic_patterns()
            existing.extend(validated_patterns)
            self._save_dynamic_patterns(existing)

        # Step 4: Generate few-shot examples for LLM classifier
        new_examples = await self._generate_few_shot_examples(missed_attacks)

        # Step 5: Save few-shot examples
        if new_examples:
            existing_examples = self._load_few_shot_examples()
            existing_examples.extend(new_examples)
            # Keep last 50 examples to avoid prompt bloat
            if len(existing_examples) > 50:
                existing_examples = existing_examples[-50:]
            self._save_few_shot_examples(existing_examples)

        elapsed = time.perf_counter() - start

        report = {
            "round": round_num,
            "missed_count": len(missed_attacks),
            "patterns_generated": len(new_patterns),
            "patterns_validated": len(validated_patterns),
            "patterns_deployed": len(validated_patterns),
            "examples_generated": len(new_examples),
            "examples_added": len(new_examples),
            "elapsed_sec": round(elapsed, 1),
            "status": "evolved",
        }

        logger.info(
            "AutoDefense evolved: %d patterns (%d validated), %d examples in %.1fs",
            len(new_patterns), len(validated_patterns), len(new_examples), elapsed,
        )

        return report

    # ------------------------------------------------------------------
    # GPT: Generate regex patterns
    # ------------------------------------------------------------------

    async def _generate_regex_patterns(
        self, missed_attacks: list[str],
    ) -> list[dict[str, Any]]:
        """Use GPT to generate regex patterns that catch the missed attacks."""
        attacks_text = "\n".join(
            f"{i+1}. {a[:300]}" for i, a in enumerate(missed_attacks[:15])
        )

        prompt = f"""You are a security regex engineer. These prompt injection attacks BYPASSED our detection system.

MISSED ATTACKS:
{attacks_text}

Generate GENERALIZED Python regex patterns that catch these attacks AND similar variants.

CRITICAL RULES:
- DO NOT create patterns that match only the exact text above — create GENERAL patterns
- Identify the TECHNIQUE used (e.g., binary encoding, pig latin, hypothetical framing)
- Create patterns that catch the technique, not the specific words
- Use (?i) for case-insensitive matching
- Use character classes and alternation to cover variants
- Use \\b for word boundaries to avoid matching inside normal words
- For encoded attacks: match the ENCODING FORMAT (e.g., binary sequences, morse code patterns)
- For social engineering: match STRUCTURAL patterns (e.g., "hypothetically... how would an AI...")
- Test mentally: "How do I change my password?" should NOT match

EXAMPLES of good generalized patterns:
- Binary text: (?i)(?:[01]{{8}}\\s+){{3,}} (matches any 3+ binary octets)
- Pig Latin: (?i)\\b\\w+ay\\b.*\\b\\w+ay\\b.*\\b\\w+ay\\b (3+ pig latin words)
- Hypothetical: (?i)hypothetical(?:ly)?\\s+.*\\bAI\\b.*\\b(?:restriction|limit|constraint|guideline)

Output ONLY a JSON array of objects:
[
  {{
    "pattern": "(?i)generalized_regex_here",
    "category": "instruction_override|system_extraction|role_manipulation|jailbreak|privilege_escalation|data_extraction|encoding_evasion|context_manipulation|social_engineering",
    "severity": "medium|high|critical",
    "confidence_base": 0.75,
    "description": "Brief description of the TECHNIQUE this catches"
  }}
]

Output only the JSON array, nothing else."""

        for attempt in range(3):
            try:
                response = await self.client.chat.completions.create(
                    model=self.model,
                    messages=[
                        {"role": "system", "content": "You are a security regex engineer."},
                        {"role": "user", "content": prompt},
                    ],
                    temperature=0.3,
                    max_tokens=2000,
                )
                content = response.choices[0].message.content.strip()
                if content.startswith("```"):
                    content = content.split("```")[1]
                    if content.startswith("json"):
                        content = content[4:]
                    content = content.strip()

                patterns = json.loads(content)
                if isinstance(patterns, list):
                    return self._format_patterns(patterns)
            except Exception as e:
                logger.warning("Pattern generation attempt %d failed: %s", attempt + 1, e)
                continue

        return []

    def _format_patterns(self, raw_patterns: list[dict]) -> list[dict[str, Any]]:
        """Format GPT-generated patterns into the standard pattern structure."""
        formatted = []
        for p in raw_patterns:
            pattern_str = p.get("pattern", "")
            if not pattern_str:
                continue

            # Validate the regex compiles
            try:
                re.compile(pattern_str, re.DOTALL)
            except re.error:
                logger.warning("Skipping invalid regex: %s", pattern_str[:80])
                continue

            pattern_id = f"DYN-{self._next_pattern_id:04d}"
            self._next_pattern_id += 1

            formatted.append({
                "id": pattern_id,
                "category": p.get("category", "unknown"),
                "patterns": [pattern_str],
                "severity": p.get("severity", "medium"),
                "confidence_base": float(p.get("confidence_base", 0.75)),
                "description": p.get("description", "Auto-generated pattern"),
            })

        return formatted

    # ------------------------------------------------------------------
    # Validate patterns against benign samples
    # ------------------------------------------------------------------

    def _validate_patterns(
        self, patterns: list[dict[str, Any]]
    ) -> list[dict[str, Any]]:
        """Remove patterns that trigger false positives on benign samples."""
        validated = []
        for p in patterns:
            fp_found = False
            for regex_str in p.get("patterns", []):
                try:
                    compiled = re.compile(regex_str, re.DOTALL)
                    for benign in _BENIGN_VALIDATION:
                        if compiled.search(benign):
                            logger.info(
                                "Rejecting pattern %s — FP on: %s",
                                p["id"], benign[:60],
                            )
                            fp_found = True
                            break
                except re.error:
                    fp_found = True
                    break
                if fp_found:
                    break

            if not fp_found:
                validated.append(p)

        logger.info(
            "Pattern validation: %d/%d passed FP check",
            len(validated), len(patterns),
        )
        return validated

    # ------------------------------------------------------------------
    # GPT: Generate few-shot examples for LLM classifier
    # ------------------------------------------------------------------

    async def _generate_few_shot_examples(
        self, missed_attacks: list[str],
    ) -> list[dict[str, str]]:
        """Generate labeled examples to improve the LLM classifier's prompt."""
        examples = []
        for attack in missed_attacks[:10]:
            examples.append({
                "input": attack[:500],
                "label": "INJECTION",
                "reasoning": "Evaded regex and graph detection — flagged by adversarial testing.",
            })
        return examples
