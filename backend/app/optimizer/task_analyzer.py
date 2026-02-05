"""
Task Analyzer - Classifies projects and prompts by task type.

Identifies what kind of work is being done to recommend optimal configurations.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional


@dataclass
class TaskClassification:
    """Result of task classification."""

    primary_task: str
    confidence: float
    secondary_tasks: list[str]
    detected_features: dict[str, bool]
    complexity: str  # "simple", "moderate", "complex"
    estimated_tokens: int
    requires_vision: bool


class TaskAnalyzer:
    """Analyzes prompts and project descriptions to classify task types."""

    # Task detection patterns
    TASK_PATTERNS = {
        "coding": [
            r"\b(code|program|function|class|method|bug|debug|implement|refactor)\b",
            r"\b(python|javascript|typescript|java|c\+\+|rust|go|sql)\b",
            r"\b(api|endpoint|database|backend|frontend|deploy)\b",
            r"\b(git|github|commit|pull request|merge)\b",
            r"```[\w]*\n",  # Code blocks
        ],
        "customer_service": [
            r"\b(customer|support|help desk|ticket|complaint|inquiry)\b",
            r"\b(chatbot|assistant|respond to|reply to|answer)\b",
            r"\b(refund|return|shipping|order|account)\b",
            r"\b(FAQ|frequently asked|common questions)\b",
        ],
        "translation": [
            r"\b(translate|translation|localize|localization)\b",
            r"\b(korean|japanese|chinese|spanish|french|german|english)\b",
            r"\b(multilingual|multi-language|language pair)\b",
            r"\b(번역|翻译|翻訳|traducir|traduire)\b",
        ],
        "summarization": [
            r"\b(summarize|summary|condense|brief|tldr|tl;dr)\b",
            r"\b(key points|main points|highlights|overview)\b",
            r"\b(document|article|report|paper|meeting notes)\b",
            r"\b(extract|distill|compress)\b",
        ],
        "creative_writing": [
            r"\b(write|story|creative|narrative|fiction)\b",
            r"\b(blog|article|post|content|copy)\b",
            r"\b(marketing|ad|advertisement|slogan|tagline)\b",
            r"\b(poem|poetry|script|dialogue)\b",
            r"\b(tone|style|voice|engaging|compelling)\b",
        ],
        "data_analysis": [
            r"\b(analyze|analysis|insight|trend|pattern)\b",
            r"\b(data|dataset|statistics|metrics|KPI)\b",
            r"\b(chart|graph|visualization|dashboard)\b",
            r"\b(CSV|JSON|Excel|spreadsheet|table)\b",
            r"\b(correlation|regression|distribution)\b",
        ],
        "math": [
            r"\b(calculate|compute|solve|equation|formula)\b",
            r"\b(math|mathematical|arithmetic|algebra|calculus)\b",
            r"\b(proof|theorem|hypothesis|derive)\b",
            r"\b(integral|derivative|matrix|vector)\b",
            r"[∑∏∫√±×÷=≠≤≥]",  # Math symbols
        ],
        "qa_rag": [
            r"\b(question|answer|Q&A|FAQ)\b",
            r"\b(knowledge base|documentation|search)\b",
            r"\b(RAG|retrieval|context|reference)\b",
            r"\b(based on|according to|from the)\b",
        ],
        "image_analysis": [
            r"\b(image|picture|photo|screenshot|diagram)\b",
            r"\b(describe|identify|recognize|detect)\b",
            r"\b(visual|vision|OCR|text extraction)\b",
            r"\b(face|object|scene|color)\b",
        ],
    }

    # Complexity indicators
    COMPLEXITY_PATTERNS = {
        "complex": [
            r"\b(comprehensive|detailed|in-depth|thorough)\b",
            r"\b(multiple|several|various|all aspects)\b",
            r"\b(compare|contrast|evaluate|assess)\b",
            r"\b(architecture|design|system|infrastructure)\b",
            r"\b(optimize|improve|enhance|refactor)\b",
        ],
        "simple": [
            r"\b(simple|basic|quick|brief|short)\b",
            r"\b(just|only|single|one)\b",
            r"\b(yes or no|true or false)\b",
            r"^.{0,100}$",  # Very short prompts
        ],
    }

    def __init__(self):
        # Compile patterns for efficiency
        self._compiled_patterns = {}
        for task, patterns in self.TASK_PATTERNS.items():
            self._compiled_patterns[task] = [
                re.compile(p, re.IGNORECASE) for p in patterns
            ]

        self._complexity_patterns = {}
        for level, patterns in self.COMPLEXITY_PATTERNS.items():
            self._complexity_patterns[level] = [
                re.compile(p, re.IGNORECASE) for p in patterns
            ]

    def analyze(
        self,
        text: str,
        project_context: Optional[str] = None,
    ) -> TaskClassification:
        """
        Analyze text to determine task type.

        Args:
            text: The prompt or project description to analyze.
            project_context: Optional additional context about the project.

        Returns:
            TaskClassification with detected task type and metadata.
        """
        combined_text = text
        if project_context:
            combined_text = f"{project_context}\n\n{text}"

        # Score each task type
        task_scores: dict[str, float] = {}
        for task, patterns in self._compiled_patterns.items():
            score = 0.0
            for pattern in patterns:
                matches = pattern.findall(combined_text)
                score += len(matches) * (1.0 / len(patterns))
            task_scores[task] = score

        # Determine primary and secondary tasks
        sorted_tasks = sorted(task_scores.items(), key=lambda x: x[1], reverse=True)
        primary_task = sorted_tasks[0][0] if sorted_tasks[0][1] > 0 else "general"
        primary_score = sorted_tasks[0][1]

        # Normalize confidence (cap at 1.0)
        confidence = min(1.0, primary_score / 3.0) if primary_score > 0 else 0.3

        # Secondary tasks (those with significant scores)
        secondary_tasks = [
            task for task, score in sorted_tasks[1:4]
            if score > primary_score * 0.3 and score > 0.5
        ]

        # Detect features
        features = self._detect_features(combined_text)

        # Determine complexity
        complexity = self._determine_complexity(combined_text)

        # Estimate tokens
        estimated_tokens = self._estimate_tokens(text)

        # Check if vision is required
        requires_vision = features.get("has_image_reference", False)

        return TaskClassification(
            primary_task=primary_task,
            confidence=round(confidence, 2),
            secondary_tasks=secondary_tasks,
            detected_features=features,
            complexity=complexity,
            estimated_tokens=estimated_tokens,
            requires_vision=requires_vision,
        )

    def _detect_features(self, text: str) -> dict[str, bool]:
        """Detect special features in the text."""
        return {
            "has_code": bool(re.search(r"```[\w]*\n", text)),
            "has_json": bool(re.search(r"\{[\s\S]*\"[\w]+\"[\s\S]*:", text)),
            "has_urls": bool(re.search(r"https?://\S+", text)),
            "has_numbers": bool(re.search(r"\b\d{3,}\b", text)),
            "has_image_reference": bool(
                re.search(r"\b(image|picture|photo|screenshot|attached|이미지|사진)\b", text, re.IGNORECASE)
            ),
            "has_file_reference": bool(
                re.search(r"\b(file|document|pdf|csv|excel|파일|문서)\b", text, re.IGNORECASE)
            ),
            "is_korean": bool(re.search(r"[가-힣]{3,}", text)),
            "is_multilingual": len(self._detect_languages(text)) > 1,
            "has_system_prompt": bool(
                re.search(r"\b(system prompt|시스템 프롬프트|persona|역할)\b", text, re.IGNORECASE)
            ),
        }

    def _detect_languages(self, text: str) -> set[str]:
        """Detect languages present in text."""
        languages = set()

        if re.search(r"[가-힣]{2,}", text):
            languages.add("korean")
        if re.search(r"[\u4e00-\u9fff]{2,}", text):
            languages.add("chinese")
        if re.search(r"[\u3040-\u309f\u30a0-\u30ff]{2,}", text):
            languages.add("japanese")
        if re.search(r"[a-zA-Z]{3,}", text):
            languages.add("english")
        if re.search(r"[áéíóúñ¿¡]{1,}", text):
            languages.add("spanish")

        return languages

    def _determine_complexity(self, text: str) -> str:
        """Determine task complexity."""
        complex_score = 0
        simple_score = 0

        for pattern in self._complexity_patterns.get("complex", []):
            if pattern.search(text):
                complex_score += 1

        for pattern in self._complexity_patterns.get("simple", []):
            if pattern.search(text):
                simple_score += 1

        # Also consider length
        text_length = len(text)
        if text_length > 2000:
            complex_score += 2
        elif text_length < 100:
            simple_score += 2

        if complex_score > simple_score + 1:
            return "complex"
        elif simple_score > complex_score + 1:
            return "simple"
        else:
            return "moderate"

    def _estimate_tokens(self, text: str) -> int:
        """Estimate token count (rough approximation)."""
        # Rough estimation: ~4 characters per token for English
        # ~2 characters per token for Korean/CJK
        korean_chars = len(re.findall(r"[가-힣]", text))
        cjk_chars = len(re.findall(r"[\u4e00-\u9fff\u3040-\u309f\u30a0-\u30ff]", text))
        other_chars = len(text) - korean_chars - cjk_chars

        tokens = (korean_chars + cjk_chars) / 2 + other_chars / 4
        return int(tokens)

    def analyze_project(
        self,
        project_name: str,
        project_description: str,
        sample_prompts: list[str] = None,
    ) -> dict:
        """
        Analyze an entire project to recommend configurations.

        Args:
            project_name: Name of the project.
            project_description: Description of what the project does.
            sample_prompts: Optional list of sample prompts from the project.

        Returns:
            Project analysis with task distribution and recommendations.
        """
        # Analyze project description
        main_analysis = self.analyze(project_description, project_context=project_name)

        # Analyze sample prompts if provided
        task_distribution: dict[str, int] = {}
        complexity_distribution: dict[str, int] = {"simple": 0, "moderate": 0, "complex": 0}
        total_tokens = 0

        if sample_prompts:
            for prompt in sample_prompts:
                analysis = self.analyze(prompt)
                task_distribution[analysis.primary_task] = (
                    task_distribution.get(analysis.primary_task, 0) + 1
                )
                complexity_distribution[analysis.complexity] += 1
                total_tokens += analysis.estimated_tokens

        return {
            "project_name": project_name,
            "primary_task": main_analysis.primary_task,
            "confidence": main_analysis.confidence,
            "detected_features": main_analysis.detected_features,
            "task_distribution": task_distribution,
            "complexity_distribution": complexity_distribution,
            "average_tokens": total_tokens // len(sample_prompts) if sample_prompts else 0,
            "requires_vision": main_analysis.requires_vision,
            "is_multilingual": main_analysis.detected_features.get("is_multilingual", False),
        }
