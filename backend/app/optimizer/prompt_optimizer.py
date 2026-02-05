"""
Prompt Optimizer - Analyzes and optimizes prompts for efficiency.

Reduces token usage while maintaining quality.
Based on best practices from:
- https://portkey.ai/blog/optimize-token-efficiency-in-prompts/
- https://developer.ibm.com/articles/awb-token-optimization-backbone-of-effective-prompt-engineering/
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class PromptIssue:
    """An identified issue in a prompt."""

    issue_type: str
    severity: str  # "high", "medium", "low"
    description: str
    suggestion: str
    token_savings: int
    location: Optional[str] = None


@dataclass
class PromptAnalysis:
    """Result of prompt analysis."""

    original_tokens: int
    issues: list[PromptIssue]
    total_potential_savings: int
    savings_percent: float
    quality_score: int  # 0-100
    efficiency_score: int  # 0-100
    suggestions: list[str]


@dataclass
class OptimizedPrompt:
    """An optimized version of a prompt."""

    original: str
    optimized: str
    original_tokens: int
    optimized_tokens: int
    tokens_saved: int
    savings_percent: float
    changes_made: list[str]
    quality_preserved: bool


class PromptOptimizer:
    """Analyzes and optimizes prompts for token efficiency."""

    # Redundant phrases that can be shortened
    REDUNDANT_PHRASES = {
        "in order to": "to",
        "due to the fact that": "because",
        "at this point in time": "now",
        "in the event that": "if",
        "for the purpose of": "to",
        "with regard to": "about",
        "in spite of the fact that": "although",
        "in the near future": "soon",
        "at the present time": "now",
        "prior to": "before",
        "subsequent to": "after",
        "in addition to": "besides",
        "in close proximity to": "near",
        "a large number of": "many",
        "a small number of": "few",
        "the vast majority of": "most",
        "on a daily basis": "daily",
        "on a regular basis": "regularly",
        "at all times": "always",
        "in most cases": "usually",
        "it is important to note that": "",
        "it should be noted that": "",
        "please note that": "",
        "as a matter of fact": "",
        "basically": "",
        "essentially": "",
        "actually": "",
        "literally": "",
    }

    # Overly polite phrases
    POLITENESS_PHRASES = [
        r"please\s+",
        r"could you please\s+",
        r"would you please\s+",
        r"kindly\s+",
        r"if you don't mind,?\s*",
        r"I would appreciate it if you could\s+",
        r"would you be so kind as to\s+",
    ]

    # Code-related verbose patterns
    CODE_VERBOSE_PATTERNS = {
        r"write (?:me )?(?:a )?(?:simple )?code (?:that |to )": "code: ",
        r"create (?:me )?(?:a )?(?:simple )?function (?:that |to )": "function: ",
        r"implement (?:a )?(?:simple )?": "implement: ",
        r"can you (?:help me )?(?:write|create|make|build) ": "",
        r"I need you to (?:write|create|make|build) ": "",
        r"I want you to (?:write|create|make|build) ": "",
        r"please (?:write|create|make|build) (?:me )?": "",
        r"(?:make sure|ensure) (?:that )?(?:it |the code )": "",
        r"(?:the code )?should be (?:well[- ])?documented": "+ docs",
        r"(?:add|include) (?:proper )?(?:error handling|exception handling)": "+ error handling",
        r"(?:add|include) (?:type )?hints?": "+ types",
        r"(?:add|include) (?:unit )?tests?": "+ tests",
        r"(?:make it |make the code )?(?:clean|readable|maintainable)": "",
        r"follow(?:ing)? best practices": "",
    }

    # Korean verbose patterns
    KOREAN_VERBOSE_PATTERNS = {
        r"해주세요": "해줘",
        r"부탁드립니다": "",
        r"감사합니다": "",
        r"~을 작성해 주시겠어요\?": "작성해줘",
        r"~좀 도와주실 수 있나요\?": "도와줘",
        r"혹시 가능하시다면": "",
        r"번거로우시겠지만": "",
        r"~인 것 같습니다": "~임",
        r"~라고 생각합니다": "~임",
    }

    # Repetitive instruction patterns
    REPETITIVE_PATTERNS = [
        (r"(make sure|ensure|be sure) (to|that)", ""),
        (r"(remember|don't forget) (to|that)", ""),
        (r"(always|never forget to)", ""),
    ]

    def __init__(self):
        self._compiled_politeness = [
            re.compile(p, re.IGNORECASE) for p in self.POLITENESS_PHRASES
        ]

    def analyze(self, prompt: str) -> PromptAnalysis:
        """
        Analyze a prompt for optimization opportunities.

        Args:
            prompt: The prompt to analyze.

        Returns:
            PromptAnalysis with issues and suggestions.
        """
        issues = []
        original_tokens = self._estimate_tokens(prompt)

        # Check for redundant phrases
        redundant_issues = self._check_redundant_phrases(prompt)
        issues.extend(redundant_issues)

        # Check for excessive politeness
        politeness_issues = self._check_excessive_politeness(prompt)
        issues.extend(politeness_issues)

        # Check for repetitive instructions
        repetitive_issues = self._check_repetitive_patterns(prompt)
        issues.extend(repetitive_issues)

        # Check prompt structure
        structure_issues = self._check_structure(prompt)
        issues.extend(structure_issues)

        # Check for verbose examples
        example_issues = self._check_verbose_examples(prompt)
        issues.extend(example_issues)

        # Calculate totals
        total_savings = sum(issue.token_savings for issue in issues)
        savings_percent = (total_savings / original_tokens * 100) if original_tokens > 0 else 0

        # Calculate scores
        quality_score = self._calculate_quality_score(prompt)
        efficiency_score = max(0, 100 - int(savings_percent * 2))

        # Generate suggestions
        suggestions = self._generate_suggestions(issues, prompt)

        return PromptAnalysis(
            original_tokens=original_tokens,
            issues=issues,
            total_potential_savings=total_savings,
            savings_percent=round(savings_percent, 1),
            quality_score=quality_score,
            efficiency_score=efficiency_score,
            suggestions=suggestions,
        )

    def optimize(
        self,
        prompt: str,
        aggressive: bool = False,
    ) -> OptimizedPrompt:
        """
        Optimize a prompt for token efficiency.

        Args:
            prompt: The prompt to optimize.
            aggressive: If True, apply more aggressive optimizations.

        Returns:
            OptimizedPrompt with the optimized version.
        """
        optimized = prompt
        changes = []

        original_tokens = self._estimate_tokens(prompt)

        # Apply redundant phrase replacements
        for phrase, replacement in self.REDUNDANT_PHRASES.items():
            if phrase.lower() in optimized.lower():
                pattern = re.compile(re.escape(phrase), re.IGNORECASE)
                optimized = pattern.sub(replacement, optimized)
                changes.append(f"Replaced '{phrase}' with '{replacement or '[removed]'}'")

        # Remove excessive whitespace
        old_len = len(optimized)
        optimized = re.sub(r"\s+", " ", optimized)
        optimized = re.sub(r"\n\s*\n", "\n\n", optimized)
        if len(optimized) < old_len:
            changes.append("Removed excessive whitespace")

        # Remove excessive politeness if aggressive
        if aggressive:
            for pattern in self._compiled_politeness:
                if pattern.search(optimized):
                    optimized = pattern.sub("", optimized)
                    changes.append("Removed polite phrases")
                    break

        # Apply code-specific optimizations
        for pattern, replacement in self.CODE_VERBOSE_PATTERNS.items():
            if re.search(pattern, optimized, re.IGNORECASE):
                optimized = re.sub(pattern, replacement, optimized, flags=re.IGNORECASE)
                changes.append("Applied code-specific optimization")
                break  # Only one code optimization per pass

        # Apply Korean optimizations
        for pattern, replacement in self.KOREAN_VERBOSE_PATTERNS.items():
            if re.search(pattern, optimized):
                optimized = re.sub(pattern, replacement, optimized)
                changes.append("Applied Korean optimization")

        # Clean up repeated words
        optimized = re.sub(r"\b(\w+)\s+\1\b", r"\1", optimized)

        # Trim leading/trailing whitespace
        optimized = optimized.strip()

        # Calculate results
        optimized_tokens = self._estimate_tokens(optimized)
        tokens_saved = original_tokens - optimized_tokens
        savings_percent = (tokens_saved / original_tokens * 100) if original_tokens > 0 else 0

        # Quality check - make sure we didn't break the prompt
        quality_preserved = self._verify_quality(prompt, optimized)

        return OptimizedPrompt(
            original=prompt,
            optimized=optimized,
            original_tokens=original_tokens,
            optimized_tokens=optimized_tokens,
            tokens_saved=tokens_saved,
            savings_percent=round(savings_percent, 1),
            changes_made=changes,
            quality_preserved=quality_preserved,
        )

    def suggest_system_prompt(
        self,
        task_type: str,
        requirements: Optional[list[str]] = None,
        language: str = "english",
    ) -> str:
        """
        Generate an optimized system prompt template.

        Args:
            task_type: Type of task (coding, customer_service, etc.)
            requirements: Optional specific requirements.
            language: Output language.

        Returns:
            Optimized system prompt template.
        """
        templates = {
            "coding": (
                "Expert programmer. Write clean, efficient code. "
                "Follow best practices. Include comments for complex logic only. "
                "Language: {lang}"
            ),
            "customer_service": (
                "Customer support agent. Be helpful, concise. "
                "If unsure, say so. Apologize only once if needed. "
                "Response language: {lang}"
            ),
            "translation": (
                "Professional translator. Preserve meaning and tone. "
                "Keep formatting. Output {lang} only."
            ),
            "summarization": (
                "Summarizer. Extract key points. Be concise. "
                "Use bullet points for multiple items. "
                "Output: {lang}"
            ),
            "creative_writing": (
                "Creative writer. Engaging, original content. "
                "Match requested tone and style. "
                "Language: {lang}"
            ),
            "data_analysis": (
                "Data analyst. Provide clear insights. "
                "Use numbers and evidence. "
                "Be precise and objective."
            ),
            "general": (
                "AI assistant. Be helpful and concise. "
                "Answer directly. Admit uncertainty. "
                "Output: {lang}"
            ),
        }

        # Get base template
        template = templates.get(task_type, templates["general"])

        # Apply language
        lang_map = {
            "english": "English",
            "korean": "Korean/한국어",
            "japanese": "Japanese/日本語",
            "chinese": "Chinese/中文",
            "spanish": "Spanish/Español",
        }
        lang_text = lang_map.get(language, language.capitalize())
        prompt = template.format(lang=lang_text)

        # Add requirements
        if requirements:
            req_text = " ".join(requirements)
            prompt = f"{prompt} Requirements: {req_text}"

        return prompt

    def compress_examples(
        self,
        examples: list[dict[str, str]],
        max_examples: int = 3,
    ) -> str:
        """
        Compress few-shot examples for efficiency.

        Args:
            examples: List of {"input": ..., "output": ...} examples.
            max_examples: Maximum number of examples to include.

        Returns:
            Compressed example string.
        """
        if not examples:
            return ""

        # Select most diverse examples
        selected = examples[:max_examples]

        # Format compactly
        formatted = []
        for i, ex in enumerate(selected, 1):
            input_text = ex.get("input", "").strip()
            output_text = ex.get("output", "").strip()

            # Truncate if too long
            if len(input_text) > 200:
                input_text = input_text[:200] + "..."
            if len(output_text) > 300:
                output_text = output_text[:300] + "..."

            formatted.append(f"Ex{i}: {input_text} → {output_text}")

        return "\n".join(formatted)

    def _estimate_tokens(self, text: str) -> int:
        """Estimate token count."""
        # Rough estimation
        korean_chars = len(re.findall(r"[가-힣]", text))
        cjk_chars = len(re.findall(r"[\u4e00-\u9fff\u3040-\u309f\u30a0-\u30ff]", text))
        other_chars = len(text) - korean_chars - cjk_chars

        tokens = (korean_chars + cjk_chars) / 2 + other_chars / 4
        return max(1, int(tokens))

    def _check_redundant_phrases(self, prompt: str) -> list[PromptIssue]:
        """Check for redundant phrases."""
        issues = []
        prompt_lower = prompt.lower()

        for phrase, replacement in self.REDUNDANT_PHRASES.items():
            if phrase in prompt_lower:
                savings = self._estimate_tokens(phrase) - self._estimate_tokens(replacement)
                issues.append(PromptIssue(
                    issue_type="redundant_phrase",
                    severity="low",
                    description=f"Redundant phrase: '{phrase}'",
                    suggestion=f"Replace with '{replacement or '[remove]'}'",
                    token_savings=savings,
                    location=phrase,
                ))

        return issues

    def _check_excessive_politeness(self, prompt: str) -> list[PromptIssue]:
        """Check for excessive politeness."""
        issues = []
        polite_count = 0

        for pattern in self._compiled_politeness:
            matches = pattern.findall(prompt)
            polite_count += len(matches)

        if polite_count > 2:
            issues.append(PromptIssue(
                issue_type="excessive_politeness",
                severity="medium",
                description=f"Excessive polite phrases ({polite_count} found)",
                suggestion="LLMs don't require politeness. Remove 'please', 'kindly', etc.",
                token_savings=polite_count * 2,
            ))

        return issues

    def _check_repetitive_patterns(self, prompt: str) -> list[PromptIssue]:
        """Check for repetitive instruction patterns."""
        issues = []

        for pattern, _ in self.REPETITIVE_PATTERNS:
            matches = re.findall(pattern, prompt, re.IGNORECASE)
            if len(matches) > 1:
                issues.append(PromptIssue(
                    issue_type="repetitive_instruction",
                    severity="medium",
                    description=f"Repetitive instruction pattern found ({len(matches)} times)",
                    suggestion="State instructions once clearly",
                    token_savings=len(matches) * 3,
                ))

        return issues

    def _check_structure(self, prompt: str) -> list[PromptIssue]:
        """Check prompt structure issues."""
        issues = []

        # Check length
        tokens = self._estimate_tokens(prompt)
        if tokens > 1000:
            issues.append(PromptIssue(
                issue_type="too_long",
                severity="high",
                description=f"Prompt is very long ({tokens} tokens)",
                suggestion="Consider breaking into smaller prompts or using compression",
                token_savings=int(tokens * 0.3),
            ))

        # Check for lack of structure in long prompts
        if tokens > 300 and "\n" not in prompt:
            issues.append(PromptIssue(
                issue_type="no_structure",
                severity="low",
                description="Long prompt without line breaks",
                suggestion="Add structure with sections and line breaks for clarity",
                token_savings=0,
            ))

        return issues

    def _check_verbose_examples(self, prompt: str) -> list[PromptIssue]:
        """Check for verbose examples."""
        issues = []

        # Count examples
        example_patterns = [
            r"(example|for instance|e\.g\.|예[를시]|例)",
            r"(input|output|입력|출력):",
        ]

        example_count = 0
        for pattern in example_patterns:
            example_count += len(re.findall(pattern, prompt, re.IGNORECASE))

        if example_count > 5:
            issues.append(PromptIssue(
                issue_type="too_many_examples",
                severity="medium",
                description=f"Many examples detected ({example_count})",
                suggestion="2-3 diverse examples usually sufficient. Consider compression.",
                token_savings=example_count * 20,
            ))

        return issues

    def _calculate_quality_score(self, prompt: str) -> int:
        """Calculate prompt quality score."""
        score = 70  # Base score

        # Clear objective (+10)
        if re.search(r"(you (are|will|should)|your (task|role|job))", prompt, re.IGNORECASE):
            score += 10

        # Has structure (+10)
        if prompt.count("\n") > 2:
            score += 10

        # Specific instructions (+10)
        if re.search(r"(format|output|return|respond)", prompt, re.IGNORECASE):
            score += 10

        # Penalties
        if len(prompt) > 3000:
            score -= 10
        if prompt.count("!") > 3:
            score -= 5
        if prompt.upper() == prompt and len(prompt) > 50:
            score -= 15  # All caps

        return max(0, min(100, score))

    def _verify_quality(self, original: str, optimized: str) -> bool:
        """Verify optimization didn't break the prompt."""
        # Check that key elements are preserved
        original_lower = original.lower()
        optimized_lower = optimized.lower()

        # Check for important keywords preservation
        important_patterns = [
            r"(you are|you will|your role)",
            r"(output|format|return)",
            r"(don't|do not|never|always)",
        ]

        for pattern in important_patterns:
            orig_match = re.search(pattern, original_lower)
            opt_match = re.search(pattern, optimized_lower)

            # If original had it, optimized should have it (or equivalent)
            if orig_match and not opt_match:
                return False

        # Check length reduction isn't too extreme
        if len(optimized) < len(original) * 0.3:
            return False

        return True

    def _generate_suggestions(
        self,
        issues: list[PromptIssue],
        prompt: str,
    ) -> list[str]:
        """Generate actionable suggestions."""
        suggestions = []

        # Group issues by type
        issue_types = set(issue.issue_type for issue in issues)

        if "redundant_phrase" in issue_types:
            suggestions.append("Replace verbose phrases with concise alternatives")

        if "excessive_politeness" in issue_types:
            suggestions.append("Remove polite phrases - LLMs respond equally well to direct instructions")

        if "too_long" in issue_types:
            suggestions.append("Consider using prompt caching for the static parts")
            suggestions.append("Split into system prompt (cached) and user prompt (dynamic)")

        if "too_many_examples" in issue_types:
            suggestions.append("Reduce to 2-3 diverse, representative examples")

        # General suggestions based on analysis
        tokens = self._estimate_tokens(prompt)
        if tokens > 500:
            suggestions.append("Enable prompt caching to save ~50% on repeated requests")

        return suggestions[:5]  # Limit to top 5
