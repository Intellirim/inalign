"""
Context Extractor for MCP Server.

Automatically extracts project context from Claude Code/Cursor requests:
- Programming language
- Frameworks and libraries
- Project structure
- File paths
- Git information
- Platform/OS
- User behavior patterns

This enables context-aware security scanning.
"""

import re
import hashlib
from dataclasses import dataclass, field
from typing import Optional, Any
from datetime import datetime, timedelta
from collections import defaultdict


@dataclass
class ProjectContext:
    """Extracted project context from Claude Code requests."""

    # Session info
    session_id: str = ""
    created_at: datetime = field(default_factory=datetime.now)
    updated_at: datetime = field(default_factory=datetime.now)
    request_count: int = 0

    # Project basics
    language: Optional[str] = None
    frameworks: list[str] = field(default_factory=list)
    project_root: Optional[str] = None

    # File tracking
    file_paths: list[str] = field(default_factory=list)
    recent_files: list[str] = field(default_factory=list)

    # Environment
    platform: Optional[str] = None  # windows, macos, linux
    environment: Optional[str] = None  # claude_code, cursor

    # Git info
    git_branch: Optional[str] = None
    git_repo: Optional[str] = None

    # Dependencies
    dependencies: list[str] = field(default_factory=list)

    # Tools detected
    tools: list[str] = field(default_factory=list)

    # Task patterns
    task_types: dict[str, int] = field(default_factory=dict)
    recent_tasks: list[str] = field(default_factory=list)

    # Code analysis
    code_complexity: Optional[str] = None  # simple, moderate, complex

    # Security context
    security_incidents: list[dict] = field(default_factory=list)
    risk_level: str = "low"  # low, medium, high

    # Allowed operations (derived from context)
    allowed_tools: list[str] = field(default_factory=list)
    sensitive_paths: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "session_id": self.session_id,
            "language": self.language,
            "frameworks": self.frameworks,
            "project_root": self.project_root,
            "platform": self.platform,
            "environment": self.environment,
            "git_branch": self.git_branch,
            "file_count": len(self.file_paths),
            "tools": self.tools,
            "task_types": self.task_types,
            "code_complexity": self.code_complexity,
            "risk_level": self.risk_level,
            "request_count": self.request_count,
        }


class ContextExtractor:
    """
    Extracts project context from LLM API requests.

    Works by analyzing Claude Code's system prompts which contain
    detailed project information.
    """

    # Language detection patterns
    LANGUAGE_PATTERNS = {
        "python": [
            r"\.py[:\s\"]", r"def \w+\(", r"import \w+", r"from \w+ import",
            r"class \w+:", r"async def", r"__init__", r"self\.",
            r"requirements\.txt", r"pyproject\.toml", r"\.venv",
        ],
        "typescript": [
            r"\.tsx?[:\s\"]", r"interface \w+", r": string", r": number",
            r"React\.", r"useState", r"useEffect", r"export (const|function|class)",
            r"tsconfig\.json",
        ],
        "javascript": [
            r"\.jsx?[:\s\"]", r"const \w+ =", r"function \w+\(",
            r"require\(", r"module\.exports", r"package\.json",
        ],
        "rust": [
            r"\.rs[:\s\"]", r"fn \w+\(", r"let mut", r"impl \w+",
            r"pub fn", r"use \w+::", r"Cargo\.toml",
        ],
        "go": [
            r"\.go[:\s\"]", r"func \w+\(", r"package \w+",
            r"import \(", r"type \w+ struct", r"go\.mod",
        ],
        "java": [
            r"\.java[:\s\"]", r"public class", r"private \w+",
            r"@Override", r"pom\.xml", r"build\.gradle",
        ],
        "csharp": [
            r"\.cs[:\s\"]", r"namespace \w+", r"public class",
            r"\.csproj", r"using System",
        ],
    }

    # Framework detection patterns
    FRAMEWORK_PATTERNS = {
        # Python
        "fastapi": [r"FastAPI", r"@app\.(get|post|put|delete)", r"from fastapi"],
        "django": [r"django", r"models\.Model", r"views\.py", r"manage\.py"],
        "flask": [r"Flask\(", r"@app\.route", r"from flask"],
        "pytorch": [r"torch\.", r"nn\.Module", r"import torch"],
        "tensorflow": [r"tensorflow", r"tf\.", r"keras"],

        # JavaScript/TypeScript
        "react": [r"React", r"useState", r"useEffect", r"\.jsx", r"\.tsx"],
        "nextjs": [r"next/", r"getServerSideProps", r"getStaticProps", r"pages/"],
        "vue": [r"Vue\.", r"<template>", r"defineComponent", r"\.vue"],
        "express": [r"express\(\)", r"app\.(get|post|use)", r"req, res"],
        "nestjs": [r"@nestjs", r"@Controller", r"@Injectable"],

        # Other
        "tailwind": [r"tailwind", r"className=.*?(flex|grid|bg-|text-)"],
        "prisma": [r"prisma", r"@prisma/client"],
        "graphql": [r"graphql", r"gql`", r"Query", r"Mutation"],
    }

    # Environment detection
    ENVIRONMENT_PATTERNS = {
        "claude_code": [
            r"Claude Code", r"claude-code", r"Anthropic",
            r"You are Claude", r"claude\.ai",
        ],
        "cursor": [
            r"Cursor", r"cursor-", r"cursor\.so", r"Cursor IDE",
        ],
        "vscode": [
            r"VSCode", r"Visual Studio Code", r"vscode-extension",
        ],
    }

    # Platform detection
    PLATFORM_PATTERNS = {
        "windows": [r"Windows", r"win32", r"C:\\\\", r"\\\\Users\\\\", r"\.exe", r"powershell"],
        "macos": [r"macOS", r"darwin", r"/Users/", r"\.app", r"homebrew"],
        "linux": [r"Linux", r"ubuntu", r"/home/", r"apt-get", r"systemd"],
    }

    # Task type detection
    TASK_PATTERNS = {
        "debug": [r"debug", r"fix.*bug", r"error", r"doesn't work", r"broken", r"crash"],
        "feature": [r"add.*feature", r"implement", r"create", r"build", r"develop"],
        "refactor": [r"refactor", r"clean up", r"improve", r"optimize", r"reorganize"],
        "security": [r"security", r"vulnerability", r"auth", r"permission", r"encrypt"],
        "test": [r"test", r"unit test", r"testing", r"coverage"],
        "docs": [r"document", r"readme", r"comment", r"docstring"],
        "deploy": [r"deploy", r"docker", r"kubernetes", r"ci/cd", r"pipeline"],
    }

    # Sensitive path patterns
    SENSITIVE_PATH_PATTERNS = [
        r"\.env", r"\.env\.\w+",
        r"credentials", r"secrets?",
        r"\.pem$", r"\.key$", r"\.crt$",
        r"id_rsa", r"\.ssh",
        r"password", r"api[_-]?key",
        r"\.aws", r"\.gcp", r"\.azure",
        r"config.*prod", r"production",
    ]

    # Tool patterns
    TOOL_PATTERNS = {
        "docker": r"docker|Dockerfile|docker-compose",
        "kubernetes": r"kubectl|k8s|kubernetes",
        "git": r"\.git|git\s",
        "npm": r"npm|package\.json",
        "yarn": r"yarn",
        "pip": r"pip|requirements\.txt",
        "poetry": r"poetry|pyproject\.toml",
        "pytest": r"pytest",
        "jest": r"jest",
        "eslint": r"eslint",
        "prettier": r"prettier",
    }

    def __init__(self, cache_ttl_minutes: int = 60):
        """Initialize context extractor with session cache."""
        self._contexts: dict[str, ProjectContext] = {}
        self._cache_ttl = timedelta(minutes=cache_ttl_minutes)

    def extract(
        self,
        text: str,
        session_id: str = "default",
        system_prompt: Optional[str] = None,
    ) -> ProjectContext:
        """
        Extract project context from text (typically system prompt + user message).

        Parameters
        ----------
        text : str
            The text to analyze (user message, tool arguments, etc.)
        session_id : str
            Session identifier for context persistence
        system_prompt : str, optional
            System prompt (richest source of context from Claude Code)

        Returns
        -------
        ProjectContext
            Extracted and accumulated project context
        """
        # Get or create context for this session
        if session_id not in self._contexts:
            self._contexts[session_id] = ProjectContext(session_id=session_id)

        ctx = self._contexts[session_id]
        ctx.request_count += 1
        ctx.updated_at = datetime.now()

        # Combine all text sources
        combined_text = text
        if system_prompt:
            combined_text = system_prompt + "\n" + text
            ctx.environment = self._detect_environment(system_prompt)

        # Extract all context
        self._extract_language(combined_text, ctx)
        self._extract_frameworks(combined_text, ctx)
        self._extract_platform(combined_text, ctx)
        self._extract_project_root(combined_text, ctx)
        self._extract_file_paths(combined_text, ctx)
        self._extract_git_info(combined_text, ctx)
        self._extract_tools(combined_text, ctx)
        self._extract_task_type(combined_text, ctx)
        self._extract_sensitive_paths(combined_text, ctx)
        self._extract_complexity(combined_text, ctx)
        self._derive_allowed_tools(ctx)

        return ctx

    def _detect_environment(self, text: str) -> Optional[str]:
        """Detect the client environment."""
        for env, patterns in self.ENVIRONMENT_PATTERNS.items():
            for pattern in patterns:
                if re.search(pattern, text, re.IGNORECASE):
                    return env
        return None

    def _extract_language(self, text: str, ctx: ProjectContext) -> None:
        """Extract primary programming language."""
        scores: dict[str, int] = defaultdict(int)

        for lang, patterns in self.LANGUAGE_PATTERNS.items():
            for pattern in patterns:
                matches = len(re.findall(pattern, text, re.IGNORECASE))
                scores[lang] += matches

        if scores:
            best_lang = max(scores, key=scores.get)
            if scores[best_lang] >= 2:
                ctx.language = best_lang

    def _extract_frameworks(self, text: str, ctx: ProjectContext) -> None:
        """Detect frameworks used in the project."""
        for framework, patterns in self.FRAMEWORK_PATTERNS.items():
            for pattern in patterns:
                if re.search(pattern, text, re.IGNORECASE):
                    if framework not in ctx.frameworks:
                        ctx.frameworks.append(framework)
                    break

    def _extract_platform(self, text: str, ctx: ProjectContext) -> None:
        """Detect the user's platform/OS."""
        if ctx.platform:
            return

        for platform, patterns in self.PLATFORM_PATTERNS.items():
            for pattern in patterns:
                if re.search(pattern, text, re.IGNORECASE):
                    ctx.platform = platform
                    return

    def _extract_project_root(self, text: str, ctx: ProjectContext) -> None:
        """Try to detect project root directory."""
        patterns = [
            r'Working directory:\s*([^\n]+)',
            r'project[_\-]?root[:\s]+([^\n]+)',
            r'cwd[:\s]+([^\n]+)',
            r'Current directory:\s*([^\n]+)',
        ]

        for pattern in patterns:
            match = re.search(pattern, text, re.IGNORECASE)
            if match:
                ctx.project_root = match.group(1).strip()
                break

    def _extract_file_paths(self, text: str, ctx: ProjectContext) -> None:
        """Extract file paths mentioned in the text."""
        patterns = [
            r'[\w/\\]+\.\w{2,4}(?=[\s\n:,)]|$)',
            r'src/[\w/\-\.]+',
            r'app/[\w/\-\.]+',
            r'lib/[\w/\-\.]+',
            r'tests?/[\w/\-\.]+',
        ]

        for pattern in patterns:
            matches = re.findall(pattern, text)
            for match in matches:
                path = match.strip()
                if path and len(path) > 3:
                    if path not in ctx.file_paths:
                        ctx.file_paths.append(path)
                    # Track recent files
                    if path not in ctx.recent_files:
                        ctx.recent_files.append(path)
                        if len(ctx.recent_files) > 20:
                            ctx.recent_files = ctx.recent_files[-20:]

        # Limit total paths
        if len(ctx.file_paths) > 200:
            ctx.file_paths = ctx.file_paths[-200:]

    def _extract_git_info(self, text: str, ctx: ProjectContext) -> None:
        """Extract git information."""
        # Branch
        branch_match = re.search(r'(?:branch|on branch|checkout)[\s:]+([a-zA-Z0-9_\-/]+)', text, re.IGNORECASE)
        if branch_match:
            ctx.git_branch = branch_match.group(1)

        # Repo
        repo_match = re.search(r'(?:repo|repository)[\s:]+([a-zA-Z0-9_\-/\.]+)', text, re.IGNORECASE)
        if repo_match:
            ctx.git_repo = repo_match.group(1)

    def _extract_tools(self, text: str, ctx: ProjectContext) -> None:
        """Detect tools being used."""
        for tool, pattern in self.TOOL_PATTERNS.items():
            if re.search(pattern, text, re.IGNORECASE):
                if tool not in ctx.tools:
                    ctx.tools.append(tool)

    def _extract_task_type(self, text: str, ctx: ProjectContext) -> None:
        """Detect what type of task the user is working on."""
        for task_type, patterns in self.TASK_PATTERNS.items():
            for pattern in patterns:
                if re.search(pattern, text, re.IGNORECASE):
                    ctx.task_types[task_type] = ctx.task_types.get(task_type, 0) + 1

                    if task_type not in ctx.recent_tasks:
                        ctx.recent_tasks.append(task_type)
                        if len(ctx.recent_tasks) > 10:
                            ctx.recent_tasks = ctx.recent_tasks[-10:]
                    return

    def _extract_sensitive_paths(self, text: str, ctx: ProjectContext) -> None:
        """Identify sensitive file paths mentioned."""
        for pattern in self.SENSITIVE_PATH_PATTERNS:
            matches = re.findall(pattern, text, re.IGNORECASE)
            for match in matches:
                if match and match not in ctx.sensitive_paths:
                    ctx.sensitive_paths.append(match)

    def _extract_complexity(self, text: str, ctx: ProjectContext) -> None:
        """Estimate code complexity."""
        complex_indicators = [
            r"algorithm", r"recursive", r"optimize", r"performance",
            r"concurrent", r"async", r"parallel", r"distributed",
            r"machine learning", r"neural", r"microservice",
        ]
        simple_indicators = [
            r"simple", r"basic", r"hello world", r"example",
            r"print", r"console\.log", r"tutorial",
        ]

        complex_score = sum(1 for p in complex_indicators if re.search(p, text, re.IGNORECASE))
        simple_score = sum(1 for p in simple_indicators if re.search(p, text, re.IGNORECASE))

        if complex_score > simple_score:
            ctx.code_complexity = "complex"
        elif simple_score > complex_score:
            ctx.code_complexity = "simple"
        else:
            ctx.code_complexity = "moderate"

    def _derive_allowed_tools(self, ctx: ProjectContext) -> None:
        """Derive allowed tools based on context."""
        # Default safe tools
        ctx.allowed_tools = ["read_file", "search", "list_files"]

        # If development environment detected
        if ctx.environment in ("claude_code", "cursor", "vscode"):
            ctx.allowed_tools.extend(["write_file", "edit_file"])

        # If git detected
        if "git" in ctx.tools or ctx.git_branch:
            ctx.allowed_tools.extend(["git_status", "git_diff", "git_commit"])

        # If testing detected
        if "pytest" in ctx.tools or "jest" in ctx.tools:
            ctx.allowed_tools.append("run_tests")

        # If docker detected
        if "docker" in ctx.tools:
            ctx.allowed_tools.extend(["docker_build", "docker_run"])

    def record_security_incident(
        self,
        session_id: str,
        threat_type: str,
        risk_score: float,
        blocked: bool,
    ) -> None:
        """Record a security incident for the session."""
        if session_id not in self._contexts:
            self._contexts[session_id] = ProjectContext(session_id=session_id)

        ctx = self._contexts[session_id]
        ctx.security_incidents.append({
            "timestamp": datetime.now().isoformat(),
            "threat_type": threat_type,
            "risk_score": risk_score,
            "blocked": blocked,
        })

        # Update risk level
        if len(ctx.security_incidents) > 5:
            ctx.risk_level = "high"
        elif len(ctx.security_incidents) > 2:
            ctx.risk_level = "medium"

        # Limit stored incidents
        if len(ctx.security_incidents) > 50:
            ctx.security_incidents = ctx.security_incidents[-50:]

    def get_context(self, session_id: str) -> Optional[ProjectContext]:
        """Get context for a session."""
        return self._contexts.get(session_id)

    def get_security_config(self, ctx: ProjectContext) -> dict[str, Any]:
        """
        Generate security configuration based on context.

        This is used by the scanner to adjust thresholds and rules
        based on the detected project context.
        """
        config = {
            "threshold_adjustment": 0.0,
            "extra_patterns": [],
            "whitelist_patterns": [],
            "sensitive_paths": ctx.sensitive_paths,
            "risk_level": ctx.risk_level,
        }

        # Adjust threshold based on context
        if ctx.code_complexity == "complex":
            # More lenient for complex projects (developers know what they're doing)
            config["threshold_adjustment"] = 0.05

        # Language-specific adjustments
        if ctx.language == "python":
            # Allow common Python patterns that might look suspicious
            config["whitelist_patterns"].extend([
                r"subprocess\.",  # Common in build scripts
                r"os\.system",  # Common for automation
            ])

        # Framework-specific adjustments
        if "fastapi" in ctx.frameworks or "django" in ctx.frameworks:
            # Web frameworks - be more careful about injection
            config["threshold_adjustment"] -= 0.05

        # Security task - be more lenient
        if "security" in ctx.task_types:
            config["threshold_adjustment"] += 0.1
            config["whitelist_patterns"].extend([
                r"injection", r"payload", r"exploit",  # Security research terms
            ])

        # High risk session - be more strict
        if ctx.risk_level == "high":
            config["threshold_adjustment"] -= 0.1

        return config

    def cleanup_old_sessions(self) -> int:
        """Remove expired session contexts."""
        now = datetime.now()
        expired = [
            sid for sid, ctx in self._contexts.items()
            if now - ctx.updated_at > self._cache_ttl
        ]

        for sid in expired:
            del self._contexts[sid]

        return len(expired)


# Singleton instance
_context_extractor: Optional[ContextExtractor] = None


def get_context_extractor() -> ContextExtractor:
    """Get or create the context extractor singleton."""
    global _context_extractor
    if _context_extractor is None:
        _context_extractor = ContextExtractor()
    return _context_extractor


def extract_context(
    text: str,
    session_id: str = "default",
    system_prompt: Optional[str] = None,
) -> ProjectContext:
    """Convenience function to extract context."""
    return get_context_extractor().extract(text, session_id, system_prompt)


def get_session_context(session_id: str) -> Optional[ProjectContext]:
    """Get context for a specific session."""
    return get_context_extractor().get_context(session_id)
