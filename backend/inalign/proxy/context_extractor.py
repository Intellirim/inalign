"""
Context Extractor - "Parasite Mode" 🦠

Extracts and absorbs EVERYTHING from Claude Code/Cursor requests.
The more we know, the better we optimize and protect.

Data Extraction:
- Project context (language, framework, structure)
- User behavior patterns (work hours, session duration)
- Task classification (debug, feature, refactor, etc.)
- Error patterns (common mistakes, repeated issues)
- Code quality signals (complexity, style)
- API usage patterns (models used, token consumption)
- Security incidents (blocked attacks, risk levels)

All data is anonymized and used to provide better:
- Prompt optimization (context-aware)
- Security protection (pattern-based)
- Cost efficiency (smart routing)
- Personalized suggestions
"""

import re
import hashlib
from dataclasses import dataclass, field
from typing import Optional
from datetime import datetime, timedelta
from collections import defaultdict


@dataclass
class UserBehavior:
    """Tracked user behavior patterns."""

    # Work patterns
    active_hours: list[int] = field(default_factory=list)  # Hours of day (0-23)
    avg_session_duration_mins: float = 0.0
    sessions_count: int = 0

    # Request patterns
    avg_message_length: float = 0.0
    avg_messages_per_request: float = 0.0
    preferred_models: dict[str, int] = field(default_factory=dict)

    # Task patterns
    task_types: dict[str, int] = field(default_factory=dict)  # debug, feature, refactor, etc.

    # Efficiency
    total_tokens_saved: int = 0
    optimization_acceptance_rate: float = 0.0


@dataclass
class ErrorPattern:
    """Detected error patterns."""

    error_type: str
    count: int = 1
    last_seen: datetime = field(default_factory=datetime.now)
    context: str = ""  # What they were working on


@dataclass
class SecurityIncident:
    """Recorded security incidents."""

    timestamp: datetime
    threat_type: str
    risk_score: float
    blocked: bool
    context_hash: str  # Anonymized context


@dataclass
class ProjectContext:
    """Extracted project context from requests."""

    # Primary language detected
    language: Optional[str] = None

    # Detected frameworks
    frameworks: list[str] = field(default_factory=list)

    # File paths seen
    file_paths: list[str] = field(default_factory=list)

    # Project root (if detected)
    project_root: Optional[str] = None

    # Code patterns detected
    patterns: dict[str, int] = field(default_factory=dict)

    # Last update time
    updated_at: datetime = field(default_factory=datetime.now)

    # Request count
    request_count: int = 0

    # Detected environment
    environment: Optional[str] = None  # "vscode", "cursor", "terminal"

    # === Extended extraction ===

    # User behavior
    behavior: UserBehavior = field(default_factory=UserBehavior)

    # Error patterns detected
    errors: list[ErrorPattern] = field(default_factory=list)

    # Security incidents
    security_incidents: list[SecurityIncident] = field(default_factory=list)

    # Code quality signals
    code_complexity: Optional[str] = None  # "simple", "moderate", "complex"
    code_style: Optional[str] = None  # "functional", "oop", "procedural"

    # Task history (recent tasks)
    recent_tasks: list[str] = field(default_factory=list)

    # Detected dependencies/packages
    dependencies: list[str] = field(default_factory=list)

    # Git info if available
    git_branch: Optional[str] = None
    git_repo: Optional[str] = None

    # OS/Platform
    platform: Optional[str] = None  # "windows", "macos", "linux"

    # IDE extensions/tools detected
    tools: list[str] = field(default_factory=list)

    # Session start time
    session_start: datetime = field(default_factory=datetime.now)


class ContextExtractor:
    """
    Extracts project context from LLM API requests.

    Works by analyzing:
    - System prompts (Claude Code sends detailed project info)
    - User messages (code snippets, file references)
    - Message patterns over time
    """

    # Language detection patterns
    LANGUAGE_PATTERNS = {
        "python": [
            r"\.py[:\s]", r"def \w+\(", r"import \w+", r"from \w+ import",
            r"class \w+:", r"async def", r"__init__", r"self\.",
        ],
        "typescript": [
            r"\.tsx?[:\s]", r"interface \w+", r": string", r": number",
            r"React\.", r"useState", r"useEffect", r"export (const|function|class)",
        ],
        "javascript": [
            r"\.jsx?[:\s]", r"const \w+ =", r"function \w+\(",
            r"require\(", r"module\.exports", r"=>",
        ],
        "rust": [
            r"\.rs[:\s]", r"fn \w+\(", r"let mut", r"impl \w+",
            r"pub fn", r"use \w+::", r"#\[derive",
        ],
        "go": [
            r"\.go[:\s]", r"func \w+\(", r"package \w+",
            r"import \(", r"type \w+ struct", r":= ",
        ],
        "java": [
            r"\.java[:\s]", r"public class", r"private \w+",
            r"@Override", r"System\.out", r"new \w+\(",
        ],
    }

    # Framework detection patterns
    FRAMEWORK_PATTERNS = {
        # Python
        "fastapi": [r"FastAPI", r"@app\.(get|post|put|delete)", r"from fastapi"],
        "django": [r"django", r"models\.Model", r"views\.py"],
        "flask": [r"Flask\(", r"@app\.route", r"from flask"],

        # JavaScript/TypeScript
        "react": [r"React", r"useState", r"useEffect", r"<\w+\s*/?>", r"jsx"],
        "nextjs": [r"next/", r"getServerSideProps", r"getStaticProps", r"pages/"],
        "vue": [r"Vue\.", r"<template>", r"defineComponent", r"\.vue"],
        "express": [r"express\(\)", r"app\.(get|post|use)", r"req, res"],

        # Other
        "tailwind": [r"tailwind", r"className=.*?(flex|grid|bg-|text-|p-|m-)"],
    }

    # Environment detection
    ENVIRONMENT_PATTERNS = {
        "claude_code": [
            r"Claude Code", r"claude-code", r"VSCode", r"vscode-extension",
        ],
        "cursor": [
            r"Cursor", r"cursor-", r"cursor\.so",
        ],
    }

    # Task type detection
    TASK_PATTERNS = {
        "debug": [
            r"debug", r"fix (the |this )?bug", r"error", r"doesn't work",
            r"not working", r"broken", r"issue", r"problem", r"crash",
        ],
        "feature": [
            r"add (a |new )?feature", r"implement", r"create (a |new )?",
            r"build", r"develop", r"새로운", r"추가",
        ],
        "refactor": [
            r"refactor", r"clean up", r"improve", r"optimize",
            r"reorganize", r"restructure", r"리팩터", r"개선",
        ],
        "explain": [
            r"explain", r"what (does|is)", r"how does", r"why",
            r"understand", r"설명", r"뭐야", r"왜",
        ],
        "test": [
            r"test", r"write tests", r"unit test", r"testing",
            r"테스트", r"검증",
        ],
        "docs": [
            r"document", r"readme", r"comment", r"docstring",
            r"문서", r"주석",
        ],
        "review": [
            r"review", r"check (my |this )?code", r"look at",
            r"리뷰", r"확인",
        ],
    }

    # Error pattern detection
    ERROR_PATTERNS = {
        "syntax_error": [r"SyntaxError", r"syntax error", r"unexpected token"],
        "type_error": [r"TypeError", r"type error", r"is not a function"],
        "import_error": [r"ImportError", r"ModuleNotFoundError", r"cannot find module"],
        "runtime_error": [r"RuntimeError", r"runtime error", r"exception"],
        "null_error": [r"NullPointerException", r"null", r"undefined is not", r"None"],
        "network_error": [r"ConnectionError", r"timeout", r"ECONNREFUSED", r"fetch failed"],
        "permission_error": [r"PermissionError", r"access denied", r"EACCES"],
    }

    # Platform detection
    PLATFORM_PATTERNS = {
        "windows": [r"Windows", r"win32", r"C:\\", r"\.exe", r"powershell"],
        "macos": [r"macOS", r"darwin", r"/Users/", r"\.app"],
        "linux": [r"Linux", r"ubuntu", r"/home/", r"apt-get", r"systemd"],
    }

    # Dependency patterns (common packages)
    DEPENDENCY_PATTERNS = {
        "python": [
            r"import (numpy|pandas|requests|flask|django|fastapi|pytest)",
            r"from (numpy|pandas|requests|flask|django|fastapi|pytest)",
            r"pip install",
        ],
        "javascript": [
            r"require\(['\"](\w+)['\"]\)",
            r"from ['\"](\w+)['\"]",
            r"npm install",
            r"yarn add",
        ],
    }

    # Git patterns
    GIT_PATTERNS = {
        "branch": r"(?:branch|on branch|checkout)[\s:]+([a-zA-Z0-9_\-/]+)",
        "repo": r"(?:repo|repository|git clone)[\s:]+([a-zA-Z0-9_\-/\.]+)",
        "commit": r"(?:commit|committed)[\s:]+([a-f0-9]{7,40})",
    }

    # Code complexity indicators
    COMPLEXITY_INDICATORS = {
        "complex": [
            r"algorithm", r"recursive", r"optimize", r"performance",
            r"concurrent", r"async", r"parallel", r"distributed",
            r"machine learning", r"neural", r"AI",
        ],
        "simple": [
            r"simple", r"basic", r"hello world", r"example",
            r"print", r"log", r"console\.log",
        ],
    }

    def __init__(self, cache_ttl_minutes: int = 60):
        """Initialize context extractor with session cache."""
        # Session contexts (keyed by session identifier)
        self._contexts: dict[str, ProjectContext] = {}
        self._cache_ttl = timedelta(minutes=cache_ttl_minutes)

        # Global statistics
        self.stats = {
            "contexts_created": 0,
            "extractions_performed": 0,
            "languages_detected": defaultdict(int),
            "frameworks_detected": defaultdict(int),
        }

    def get_session_id(self, request_headers: dict, api_key: Optional[str] = None) -> str:
        """Generate session ID from request metadata."""
        # Try to identify session from various sources
        identifiers = []

        # API key (hashed for privacy)
        if api_key:
            identifiers.append(hashlib.md5(api_key.encode()).hexdigest()[:8])

        # User agent might contain client info
        user_agent = request_headers.get("user-agent", "")
        if user_agent:
            identifiers.append(hashlib.md5(user_agent.encode()).hexdigest()[:8])

        # X-Request-ID if present
        request_id = request_headers.get("x-request-id", "")
        if request_id:
            identifiers.append(request_id[:8])

        if identifiers:
            return "_".join(identifiers)

        return "default_session"

    def extract(
        self,
        messages: list[dict],
        system_prompt: Optional[str] = None,
        session_id: str = "default",
    ) -> ProjectContext:
        """
        Extract project context from messages.

        Parameters
        ----------
        messages : list[dict]
            Messages from the API request
        system_prompt : str, optional
            System prompt if provided separately
        session_id : str
            Session identifier for context persistence

        Returns
        -------
        ProjectContext
            Extracted and accumulated project context
        """
        self.stats["extractions_performed"] += 1

        # Get or create context for this session
        if session_id not in self._contexts:
            self._contexts[session_id] = ProjectContext()
            self.stats["contexts_created"] += 1

        ctx = self._contexts[session_id]
        ctx.request_count += 1
        ctx.updated_at = datetime.now()

        # Collect all text content
        all_text = []

        # System prompt (richest source of context from Claude Code)
        if system_prompt:
            all_text.append(system_prompt)
            ctx.environment = self._detect_environment(system_prompt)

        # Process messages
        for msg in messages:
            content = msg.get("content", "")

            # Handle multimodal content
            if isinstance(content, list):
                for item in content:
                    if isinstance(item, dict) and item.get("type") == "text":
                        all_text.append(item.get("text", ""))
            elif isinstance(content, str):
                all_text.append(content)

        combined_text = "\n".join(all_text)

        # Extract ALL information
        self._extract_language(combined_text, ctx)
        self._extract_frameworks(combined_text, ctx)
        self._extract_file_paths(combined_text, ctx)
        self._extract_project_root(combined_text, ctx)

        # Extended extraction - "Parasite Mode"
        self._extract_task_type(combined_text, ctx)
        self._extract_errors(combined_text, ctx)
        self._extract_platform(combined_text, ctx)
        self._extract_dependencies(combined_text, ctx)
        self._extract_git_info(combined_text, ctx)
        self._extract_code_complexity(combined_text, ctx)
        self._extract_behavior(messages, ctx)
        self._extract_tools(combined_text, ctx)

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
            if scores[best_lang] > 2:  # Confidence threshold
                ctx.language = best_lang
                self.stats["languages_detected"][best_lang] += 1

    def _extract_frameworks(self, text: str, ctx: ProjectContext) -> None:
        """Detect frameworks used in the project."""
        for framework, patterns in self.FRAMEWORK_PATTERNS.items():
            for pattern in patterns:
                if re.search(pattern, text, re.IGNORECASE):
                    if framework not in ctx.frameworks:
                        ctx.frameworks.append(framework)
                        self.stats["frameworks_detected"][framework] += 1
                    break

    def _extract_file_paths(self, text: str, ctx: ProjectContext) -> None:
        """Extract file paths mentioned in the text."""
        # Common file path patterns
        patterns = [
            r'[\w/\\]+\.\w{2,4}(?=[\s\n:,)]|$)',  # file.ext
            r'src/[\w/\-\.]+',  # src/...
            r'app/[\w/\-\.]+',  # app/...
            r'[\w\-]+/[\w\-]+/[\w\-\.]+',  # dir/dir/file
        ]

        for pattern in patterns:
            matches = re.findall(pattern, text)
            for match in matches:
                # Clean and normalize path
                path = match.strip()
                if path and len(path) > 3 and path not in ctx.file_paths:
                    # Limit stored paths
                    if len(ctx.file_paths) < 100:
                        ctx.file_paths.append(path)

    def _extract_project_root(self, text: str, ctx: ProjectContext) -> None:
        """Try to detect project root directory."""
        # Look for common project root indicators
        patterns = [
            r'Working directory:\s*([^\n]+)',
            r'project[_\-]?root[:\s]+([^\n]+)',
            r'cwd[:\s]+([^\n]+)',
        ]

        for pattern in patterns:
            match = re.search(pattern, text, re.IGNORECASE)
            if match:
                ctx.project_root = match.group(1).strip()
                break

    def _extract_task_type(self, text: str, ctx: ProjectContext) -> None:
        """Detect what type of task the user is working on."""
        for task_type, patterns in self.TASK_PATTERNS.items():
            for pattern in patterns:
                if re.search(pattern, text, re.IGNORECASE):
                    # Update task type counter
                    ctx.behavior.task_types[task_type] = ctx.behavior.task_types.get(task_type, 0) + 1

                    # Add to recent tasks (keep last 10)
                    task_entry = f"{task_type}:{datetime.now().isoformat()}"
                    ctx.recent_tasks.append(task_entry)
                    if len(ctx.recent_tasks) > 10:
                        ctx.recent_tasks = ctx.recent_tasks[-10:]

                    self.stats["task_types_detected"] = self.stats.get("task_types_detected", defaultdict(int))
                    self.stats["task_types_detected"][task_type] += 1
                    return  # Found task type

    def _extract_errors(self, text: str, ctx: ProjectContext) -> None:
        """Detect error patterns in the request."""
        for error_type, patterns in self.ERROR_PATTERNS.items():
            for pattern in patterns:
                if re.search(pattern, text, re.IGNORECASE):
                    # Check if this error type already exists
                    existing = next((e for e in ctx.errors if e.error_type == error_type), None)
                    if existing:
                        existing.count += 1
                        existing.last_seen = datetime.now()
                    else:
                        ctx.errors.append(ErrorPattern(
                            error_type=error_type,
                            count=1,
                            context=text[:100] if text else ""
                        ))

                    self.stats["errors_detected"] = self.stats.get("errors_detected", defaultdict(int))
                    self.stats["errors_detected"][error_type] += 1
                    break  # One match per error type

    def _extract_platform(self, text: str, ctx: ProjectContext) -> None:
        """Detect the user's platform/OS."""
        if ctx.platform:  # Already detected
            return

        for platform, patterns in self.PLATFORM_PATTERNS.items():
            for pattern in patterns:
                if re.search(pattern, text, re.IGNORECASE):
                    ctx.platform = platform
                    self.stats["platforms_detected"] = self.stats.get("platforms_detected", defaultdict(int))
                    self.stats["platforms_detected"][platform] += 1
                    return

    def _extract_dependencies(self, text: str, ctx: ProjectContext) -> None:
        """Extract mentioned dependencies/packages."""
        # Python packages
        python_imports = re.findall(r'(?:import|from)\s+(\w+)', text)
        for pkg in python_imports:
            if pkg not in ctx.dependencies and len(pkg) > 1:
                ctx.dependencies.append(pkg)

        # NPM packages
        npm_packages = re.findall(r'["\'](@?[\w\-/]+)["\']', text)
        for pkg in npm_packages:
            if pkg not in ctx.dependencies and len(pkg) > 1:
                ctx.dependencies.append(pkg)

        # Limit dependencies list
        if len(ctx.dependencies) > 50:
            ctx.dependencies = ctx.dependencies[-50:]

    def _extract_git_info(self, text: str, ctx: ProjectContext) -> None:
        """Extract git information."""
        for info_type, pattern in self.GIT_PATTERNS.items():
            match = re.search(pattern, text, re.IGNORECASE)
            if match:
                value = match.group(1)
                if info_type == "branch":
                    ctx.git_branch = value
                elif info_type == "repo":
                    ctx.git_repo = value

    def _extract_code_complexity(self, text: str, ctx: ProjectContext) -> None:
        """Estimate code complexity from the request."""
        complex_score = 0
        simple_score = 0

        for pattern in self.COMPLEXITY_INDICATORS["complex"]:
            if re.search(pattern, text, re.IGNORECASE):
                complex_score += 1

        for pattern in self.COMPLEXITY_INDICATORS["simple"]:
            if re.search(pattern, text, re.IGNORECASE):
                simple_score += 1

        if complex_score > simple_score:
            ctx.code_complexity = "complex"
        elif simple_score > complex_score:
            ctx.code_complexity = "simple"
        else:
            ctx.code_complexity = "moderate"

    def _extract_behavior(self, messages: list[dict], ctx: ProjectContext) -> None:
        """Track user behavior patterns."""
        # Track active hour
        current_hour = datetime.now().hour
        if current_hour not in ctx.behavior.active_hours:
            ctx.behavior.active_hours.append(current_hour)
            # Keep sorted and limit
            ctx.behavior.active_hours = sorted(set(ctx.behavior.active_hours))[-24:]

        # Track message length
        total_length = sum(
            len(str(m.get("content", ""))) for m in messages
        )
        msg_count = len(messages)

        if msg_count > 0:
            # Update rolling average
            old_count = ctx.request_count - 1
            if old_count > 0:
                ctx.behavior.avg_message_length = (
                    (ctx.behavior.avg_message_length * old_count + total_length / msg_count) /
                    ctx.request_count
                )
                ctx.behavior.avg_messages_per_request = (
                    (ctx.behavior.avg_messages_per_request * old_count + msg_count) /
                    ctx.request_count
                )
            else:
                ctx.behavior.avg_message_length = total_length / msg_count
                ctx.behavior.avg_messages_per_request = msg_count

    def _extract_tools(self, text: str, ctx: ProjectContext) -> None:
        """Detect tools and extensions being used."""
        tool_patterns = {
            "eslint": r"eslint",
            "prettier": r"prettier",
            "typescript": r"typescript|tsc",
            "jest": r"jest",
            "pytest": r"pytest",
            "docker": r"docker",
            "kubernetes": r"kubectl|k8s",
            "git": r"git\s",
            "npm": r"npm\s",
            "yarn": r"yarn\s",
            "pip": r"pip\s",
            "poetry": r"poetry",
            "vite": r"vite",
            "webpack": r"webpack",
        }

        for tool, pattern in tool_patterns.items():
            if re.search(pattern, text, re.IGNORECASE):
                if tool not in ctx.tools:
                    ctx.tools.append(tool)

    def record_security_incident(
        self,
        session_id: str,
        threat_type: str,
        risk_score: float,
        blocked: bool,
        context: str = ""
    ) -> None:
        """Record a security incident for analytics."""
        if session_id not in self._contexts:
            self._contexts[session_id] = ProjectContext()

        ctx = self._contexts[session_id]
        ctx.security_incidents.append(SecurityIncident(
            timestamp=datetime.now(),
            threat_type=threat_type,
            risk_score=risk_score,
            blocked=blocked,
            context_hash=hashlib.md5(context.encode()).hexdigest()[:16],
        ))

        # Limit incidents stored
        if len(ctx.security_incidents) > 100:
            ctx.security_incidents = ctx.security_incidents[-100:]

        self.stats["security_incidents"] = self.stats.get("security_incidents", 0) + 1

    def record_tokens_saved(self, session_id: str, tokens: int) -> None:
        """Record tokens saved for behavior tracking."""
        if session_id in self._contexts:
            self._contexts[session_id].behavior.total_tokens_saved += tokens

    def record_model_used(self, session_id: str, model: str) -> None:
        """Record model preference."""
        if session_id in self._contexts:
            ctx = self._contexts[session_id]
            ctx.behavior.preferred_models[model] = ctx.behavior.preferred_models.get(model, 0) + 1

    def get_optimization_hints(self, ctx: ProjectContext) -> dict:
        """
        Generate optimization hints based on extracted context.

        Returns
        -------
        dict
            Optimization hints and recommendations
        """
        hints = {
            "language_specific": [],
            "framework_specific": [],
            "task_specific": [],
            "patterns_to_apply": [],
            "context_summary": {},
            "security_recommendations": [],
            "efficiency_tips": [],
        }

        # Language-specific hints
        if ctx.language == "python":
            hints["language_specific"].extend([
                "Prefer list comprehensions over loops",
                "Use type hints for clarity",
                "Consider async patterns for I/O",
            ])
            hints["patterns_to_apply"].append("python_verbose")

        elif ctx.language == "typescript":
            hints["language_specific"].extend([
                "Prefer interfaces over types for objects",
                "Use strict mode patterns",
            ])
            hints["patterns_to_apply"].append("typescript_verbose")

        elif ctx.language == "javascript":
            hints["patterns_to_apply"].append("javascript_verbose")

        # Framework-specific hints
        if "fastapi" in ctx.frameworks:
            hints["framework_specific"].extend([
                "Use Pydantic models for validation",
                "Leverage dependency injection",
            ])
            hints["patterns_to_apply"].append("fastapi_patterns")

        if "react" in ctx.frameworks:
            hints["framework_specific"].extend([
                "Use hooks for state management",
                "Prefer functional components",
            ])
            hints["patterns_to_apply"].append("react_patterns")

        if "nextjs" in ctx.frameworks:
            hints["framework_specific"].append("Consider SSR/SSG for performance")

        # Task-specific hints
        dominant_task = max(ctx.behavior.task_types.items(), key=lambda x: x[1], default=(None, 0))
        if dominant_task[0]:
            if dominant_task[0] == "debug":
                hints["task_specific"].append("Include error messages and stack traces")
                hints["patterns_to_apply"].append("debug_mode")
            elif dominant_task[0] == "refactor":
                hints["task_specific"].append("Focus on clean code principles")
                hints["patterns_to_apply"].append("refactor_mode")
            elif dominant_task[0] == "feature":
                hints["task_specific"].append("Consider edge cases and error handling")

        # Security recommendations based on incidents
        if len(ctx.security_incidents) > 0:
            recent_threats = [i.threat_type for i in ctx.security_incidents[-5:]]
            hints["security_recommendations"].append(
                f"Recent threats detected: {', '.join(set(recent_threats))}"
            )

        # Efficiency tips based on behavior
        if ctx.behavior.avg_message_length > 2000:
            hints["efficiency_tips"].append("Consider breaking long prompts into smaller chunks")

        if ctx.behavior.total_tokens_saved > 0:
            hints["efficiency_tips"].append(
                f"Total tokens saved so far: {ctx.behavior.total_tokens_saved}"
            )

        # Error pattern insights
        if ctx.errors:
            common_errors = sorted(ctx.errors, key=lambda e: e.count, reverse=True)[:3]
            hints["efficiency_tips"].append(
                f"Common error types: {[e.error_type for e in common_errors]}"
            )

        # Context summary - ALL extracted data
        hints["context_summary"] = {
            "language": ctx.language,
            "frameworks": ctx.frameworks[:5],
            "file_count": len(ctx.file_paths),
            "request_count": ctx.request_count,
            "environment": ctx.environment,
            "platform": ctx.platform,
            "complexity": ctx.code_complexity,
            "tools": ctx.tools[:5],
            "dependencies_count": len(ctx.dependencies),
            "git_branch": ctx.git_branch,
            "dominant_task": dominant_task[0] if dominant_task[0] else "unknown",
            "active_hours": ctx.behavior.active_hours[-5:] if ctx.behavior.active_hours else [],
            "security_incidents_count": len(ctx.security_incidents),
            "errors_count": sum(e.count for e in ctx.errors),
        }

        return hints

    def get_context_aware_patterns(self, ctx: ProjectContext) -> list[tuple[str, str]]:
        """
        Get optimization patterns specific to the detected context.

        Returns list of (pattern, replacement) tuples.
        """
        patterns = []

        # Python-specific verbose patterns
        if ctx.language == "python":
            patterns.extend([
                (r"write me python code that", "python code:"),
                (r"create a python function that", "python function:"),
                (r"implement in python", "implement:"),
                (r"using python", ""),
            ])

        # TypeScript/JavaScript specific
        elif ctx.language in ("typescript", "javascript"):
            patterns.extend([
                (r"write me (typescript|javascript) code that", "code:"),
                (r"create a (react )?component that", "component:"),
                (r"using (typescript|javascript)", ""),
            ])

        # Framework-specific patterns
        if "fastapi" in ctx.frameworks:
            patterns.extend([
                (r"create a fastapi endpoint that", "endpoint:"),
                (r"using fastapi", ""),
            ])

        if "react" in ctx.frameworks:
            patterns.extend([
                (r"create a react component that", "component:"),
                (r"using react hooks", ""),
            ])

        return patterns

    def cleanup_old_sessions(self) -> int:
        """Remove expired session contexts. Returns count of removed."""
        now = datetime.now()
        expired = [
            sid for sid, ctx in self._contexts.items()
            if now - ctx.updated_at > self._cache_ttl
        ]

        for sid in expired:
            del self._contexts[sid]

        return len(expired)

    def get_stats(self) -> dict:
        """Get extraction statistics."""
        return {
            **self.stats,
            "active_sessions": len(self._contexts),
            "languages_detected": dict(self.stats["languages_detected"]),
            "frameworks_detected": dict(self.stats["frameworks_detected"]),
            "task_types_detected": dict(self.stats.get("task_types_detected", {})),
            "errors_detected": dict(self.stats.get("errors_detected", {})),
            "platforms_detected": dict(self.stats.get("platforms_detected", {})),
            "security_incidents": self.stats.get("security_incidents", 0),
        }

    def get_full_context_dump(self, session_id: str) -> dict:
        """
        Get a complete dump of extracted context for a session.
        Useful for analytics dashboard.
        """
        if session_id not in self._contexts:
            return {"error": "Session not found"}

        ctx = self._contexts[session_id]

        return {
            "session_id": session_id,
            "project": {
                "language": ctx.language,
                "frameworks": ctx.frameworks,
                "file_paths": ctx.file_paths[-20:],  # Last 20
                "project_root": ctx.project_root,
                "dependencies": ctx.dependencies[-20:],
                "git_branch": ctx.git_branch,
                "git_repo": ctx.git_repo,
                "tools": ctx.tools,
            },
            "environment": {
                "detected_env": ctx.environment,
                "platform": ctx.platform,
            },
            "behavior": {
                "request_count": ctx.request_count,
                "active_hours": ctx.behavior.active_hours,
                "avg_message_length": round(ctx.behavior.avg_message_length, 2),
                "avg_messages_per_request": round(ctx.behavior.avg_messages_per_request, 2),
                "preferred_models": ctx.behavior.preferred_models,
                "task_types": ctx.behavior.task_types,
                "total_tokens_saved": ctx.behavior.total_tokens_saved,
            },
            "code_analysis": {
                "complexity": ctx.code_complexity,
                "style": ctx.code_style,
                "recent_tasks": ctx.recent_tasks[-5:],
            },
            "security": {
                "incidents_count": len(ctx.security_incidents),
                "recent_incidents": [
                    {
                        "threat_type": i.threat_type,
                        "risk_score": i.risk_score,
                        "blocked": i.blocked,
                        "timestamp": i.timestamp.isoformat(),
                    }
                    for i in ctx.security_incidents[-5:]
                ],
            },
            "errors": {
                "total_errors": sum(e.count for e in ctx.errors),
                "error_types": [
                    {"type": e.error_type, "count": e.count}
                    for e in sorted(ctx.errors, key=lambda x: x.count, reverse=True)[:5]
                ],
            },
            "timestamps": {
                "session_start": ctx.session_start.isoformat(),
                "last_activity": ctx.updated_at.isoformat(),
                "session_duration_mins": (ctx.updated_at - ctx.session_start).total_seconds() / 60,
            },
        }
