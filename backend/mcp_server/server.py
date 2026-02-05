"""
In-A-Lign MCP Server.

Exposes AI development tools via Model Context Protocol.
"""

from __future__ import annotations

import json
import logging
import sys
from pathlib import Path
from typing import Any, Optional

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import Tool, TextContent

from app.optimizer import (
    AIAdvisor,
    TaskAnalyzer,
    ModelMatcher,
    PromptOptimizer,
    CostSimulator,
)
from app.detectors.injection.rules import RuleBasedDetector

logger = logging.getLogger(__name__)


class InAlignMCPServer:
    """In-A-Lign MCP Server for AI development tools."""

    def __init__(self):
        self.server = Server("in-a-lign")
        self.advisor = AIAdvisor()
        self.task_analyzer = TaskAnalyzer()
        self.model_matcher = ModelMatcher()
        self.prompt_optimizer = PromptOptimizer()
        self.cost_simulator = CostSimulator()
        self.security_detector = RuleBasedDetector()

        self._setup_handlers()

    def _setup_handlers(self):
        """Register all tool handlers."""

        @self.server.list_tools()
        async def list_tools() -> list[Tool]:
            """List all available tools."""
            return [
                Tool(
                    name="analyze_project",
                    description="Analyze an AI project for optimization opportunities. Provides task classification, model recommendations, prompt suggestions, and cost analysis.",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "project_name": {
                                "type": "string",
                                "description": "Name of the project"
                            },
                            "project_description": {
                                "type": "string",
                                "description": "Description of what the project does"
                            },
                            "sample_prompts": {
                                "type": "array",
                                "items": {"type": "string"},
                                "description": "Sample prompts from the project (optional)"
                            },
                            "current_model": {
                                "type": "string",
                                "description": "Currently used model (e.g., 'gpt-4o', 'claude-3.5-sonnet')"
                            },
                            "requests_per_day": {
                                "type": "integer",
                                "description": "Expected daily request volume",
                                "default": 1000
                            }
                        },
                        "required": ["project_name", "project_description"]
                    }
                ),
                Tool(
                    name="optimize_prompt",
                    description="Analyze and optimize a prompt for token efficiency while maintaining quality. Returns optimized version with savings analysis.",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "prompt": {
                                "type": "string",
                                "description": "The prompt to optimize"
                            },
                            "task_type": {
                                "type": "string",
                                "description": "Type of task (coding, customer_service, translation, etc.)",
                                "enum": ["coding", "customer_service", "translation", "summarization", "creative_writing", "data_analysis", "math", "qa_rag", "general"]
                            },
                            "aggressive": {
                                "type": "boolean",
                                "description": "Apply aggressive optimizations (may change tone)",
                                "default": False
                            }
                        },
                        "required": ["prompt"]
                    }
                ),
                Tool(
                    name="recommend_model",
                    description="Recommend the optimal AI model for a specific task. Considers performance, cost, and task requirements.",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "task_description": {
                                "type": "string",
                                "description": "Description of the task or sample prompt"
                            },
                            "priority": {
                                "type": "string",
                                "description": "Optimization priority",
                                "enum": ["quality", "cost", "balanced"],
                                "default": "balanced"
                            },
                            "budget_mode": {
                                "type": "boolean",
                                "description": "Prioritize budget-friendly options",
                                "default": False
                            }
                        },
                        "required": ["task_description"]
                    }
                ),
                Tool(
                    name="estimate_cost",
                    description="Calculate and compare costs for different AI model configurations.",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "models": {
                                "type": "array",
                                "items": {"type": "string"},
                                "description": "List of model IDs to compare (e.g., ['gpt-4o', 'claude-3.5-sonnet'])"
                            },
                            "avg_input_tokens": {
                                "type": "integer",
                                "description": "Average input tokens per request",
                                "default": 500
                            },
                            "avg_output_tokens": {
                                "type": "integer",
                                "description": "Average output tokens per request",
                                "default": 200
                            },
                            "requests_per_day": {
                                "type": "integer",
                                "description": "Expected daily request volume",
                                "default": 1000
                            }
                        },
                        "required": ["models"]
                    }
                ),
                Tool(
                    name="security_scan",
                    description="Scan prompts or text for prompt injection vulnerabilities and security risks.",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "text": {
                                "type": "string",
                                "description": "Text to scan for security issues"
                            },
                            "context": {
                                "type": "string",
                                "description": "Context of where this text is used (user_input, system_prompt, etc.)",
                                "enum": ["user_input", "system_prompt", "api_response", "file_content"],
                                "default": "user_input"
                            }
                        },
                        "required": ["text"]
                    }
                ),
                Tool(
                    name="generate_system_prompt",
                    description="Generate an optimized system prompt template for a specific task type.",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "task_type": {
                                "type": "string",
                                "description": "Type of task",
                                "enum": ["coding", "customer_service", "translation", "summarization", "creative_writing", "data_analysis", "general"]
                            },
                            "requirements": {
                                "type": "array",
                                "items": {"type": "string"},
                                "description": "Specific requirements to include"
                            },
                            "language": {
                                "type": "string",
                                "description": "Output language",
                                "default": "english"
                            }
                        },
                        "required": ["task_type"]
                    }
                ),
                Tool(
                    name="get_optimization_report",
                    description="Generate a comprehensive optimization report for current AI usage.",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "current_model": {
                                "type": "string",
                                "description": "Currently used model"
                            },
                            "current_avg_tokens": {
                                "type": "integer",
                                "description": "Current average tokens per request"
                            },
                            "requests_per_day": {
                                "type": "integer",
                                "description": "Current daily request volume"
                            },
                            "sample_prompt": {
                                "type": "string",
                                "description": "Sample prompt for analysis"
                            }
                        },
                        "required": ["current_model", "current_avg_tokens", "requests_per_day"]
                    }
                ),
            ]

        @self.server.call_tool()
        async def call_tool(name: str, arguments: dict[str, Any]) -> list[TextContent]:
            """Handle tool calls."""
            try:
                if name == "analyze_project":
                    result = self._analyze_project(arguments)
                elif name == "optimize_prompt":
                    result = self._optimize_prompt(arguments)
                elif name == "recommend_model":
                    result = self._recommend_model(arguments)
                elif name == "estimate_cost":
                    result = self._estimate_cost(arguments)
                elif name == "security_scan":
                    result = self._security_scan(arguments)
                elif name == "generate_system_prompt":
                    result = self._generate_system_prompt(arguments)
                elif name == "get_optimization_report":
                    result = self._get_optimization_report(arguments)
                else:
                    result = {"error": f"Unknown tool: {name}"}

                return [TextContent(
                    type="text",
                    text=json.dumps(result, indent=2, ensure_ascii=False)
                )]
            except Exception as e:
                logger.exception(f"Error in tool {name}")
                return [TextContent(
                    type="text",
                    text=json.dumps({"error": str(e)}, indent=2)
                )]

    def _analyze_project(self, args: dict[str, Any]) -> dict[str, Any]:
        """Analyze a project for optimization opportunities."""
        result = self.advisor.analyze_project(
            project_name=args["project_name"],
            project_description=args["project_description"],
            sample_prompts=args.get("sample_prompts"),
            current_model=args.get("current_model"),
            requests_per_day=args.get("requests_per_day", 1000),
        )

        return {
            "project_name": result.project_name,
            "task_analysis": result.task_analysis,
            "model_recommendation": result.model_recommendation,
            "prompt_suggestions": result.prompt_suggestions,
            "cost_analysis": result.cost_analysis,
            "optimization_potential": result.optimization_potential,
            "action_items": result.action_items,
        }

    def _optimize_prompt(self, args: dict[str, Any]) -> dict[str, Any]:
        """Optimize a prompt for efficiency."""
        result = self.advisor.optimize_prompt(
            prompt=args["prompt"],
            task_type=args.get("task_type"),
            aggressive=args.get("aggressive", False),
        )
        return result

    def _recommend_model(self, args: dict[str, Any]) -> dict[str, Any]:
        """Recommend optimal model for a task."""
        # Analyze the task
        task = self.task_analyzer.analyze(args["task_description"])

        # Get priority
        priority = args.get("priority", "balanced")
        budget_mode = args.get("budget_mode", False) or priority == "cost"

        # Get model recommendations
        match = self.model_matcher.match(task, budget_mode=budget_mode)

        # Select recommendation based on priority
        if priority == "quality":
            recommended = match.best_performance
        elif priority == "cost":
            recommended = match.best_budget
        else:
            recommended = match.best_value

        return {
            "task_type": task.primary_task,
            "task_complexity": task.complexity,
            "confidence": task.confidence,
            "recommendation": {
                "model_id": recommended.model_id if recommended else None,
                "model_name": recommended.model_name if recommended else None,
                "reasoning": recommended.reasoning if recommended else None,
                "estimated_cost_per_1k": recommended.estimated_cost_per_1k_requests if recommended else None,
            },
            "alternatives": {
                "best_performance": {
                    "model": match.best_performance.model_name if match.best_performance else None,
                    "cost_per_1k": match.best_performance.estimated_cost_per_1k_requests if match.best_performance else None,
                },
                "best_value": {
                    "model": match.best_value.model_name if match.best_value else None,
                    "cost_per_1k": match.best_value.estimated_cost_per_1k_requests if match.best_value else None,
                },
                "best_budget": {
                    "model": match.best_budget.model_name if match.best_budget else None,
                    "cost_per_1k": match.best_budget.estimated_cost_per_1k_requests if match.best_budget else None,
                },
            },
            "savings_potential": match.savings_potential,
        }

    def _estimate_cost(self, args: dict[str, Any]) -> dict[str, Any]:
        """Estimate and compare costs."""
        comparison = self.cost_simulator.compare(
            model_ids=args["models"],
            avg_input_tokens=args.get("avg_input_tokens", 500),
            avg_output_tokens=args.get("avg_output_tokens", 200),
            requests_per_day=args.get("requests_per_day", 1000),
        )

        return {
            "estimates": [
                {
                    "model": e.model_name,
                    "cost_per_request": e.cost_per_request,
                    "daily_cost": e.daily_cost,
                    "monthly_cost": e.monthly_cost,
                    "yearly_cost": e.yearly_cost,
                }
                for e in comparison.estimates
            ],
            "cheapest": {
                "model": comparison.cheapest.model_name,
                "monthly_cost": comparison.cheapest.monthly_cost,
            },
            "recommended": {
                "model": comparison.recommended.model_name,
                "monthly_cost": comparison.recommended.monthly_cost,
            },
            "savings_summary": comparison.savings_summary,
        }

    def _security_scan(self, args: dict[str, Any]) -> dict[str, Any]:
        """Scan text for security issues."""
        text = args["text"]
        context = args.get("context", "user_input")

        threats = self.security_detector.detect(text)

        # Calculate risk score
        severity_scores = {"low": 1, "medium": 2, "high": 3, "critical": 4}
        risk_score = 0
        if threats:
            risk_score = sum(severity_scores.get(t["severity"], 1) for t in threats) / len(threats)

        return {
            "scanned_text_length": len(text),
            "context": context,
            "threats_found": len(threats),
            "risk_score": round(risk_score, 2),
            "risk_level": (
                "safe" if risk_score == 0 else
                "low" if risk_score < 1.5 else
                "medium" if risk_score < 2.5 else
                "high" if risk_score < 3.5 else
                "critical"
            ),
            "threats": [
                {
                    "type": t["type"],
                    "category": t["subtype"],
                    "pattern_id": t["pattern_id"],
                    "severity": t["severity"],
                    "confidence": t["confidence"],
                    "description": t["description"],
                    "matched_text": t["matched_text"][:100] + "..." if len(t["matched_text"]) > 100 else t["matched_text"],
                }
                for t in threats
            ],
            "recommendations": self._get_security_recommendations(threats, context),
        }

    def _get_security_recommendations(
        self, threats: list[dict], context: str
    ) -> list[str]:
        """Generate security recommendations based on threats."""
        recommendations = []

        if not threats:
            recommendations.append("No immediate threats detected. Continue monitoring.")
            return recommendations

        # Get unique categories
        categories = set(t["subtype"] for t in threats)

        if "role_manipulation" in categories:
            recommendations.append("Implement role-based access control in system prompts")
            recommendations.append("Use input sandwich technique to protect instructions")

        if "instruction_injection" in categories:
            recommendations.append("Add input validation before processing")
            recommendations.append("Consider using In-A-Lign proxy for automatic injection blocking")

        if "data_exfiltration" in categories:
            recommendations.append("Restrict output format to prevent data leakage")
            recommendations.append("Implement output filtering for sensitive patterns")

        if context == "user_input":
            recommendations.append("Never trust user input directly - always sanitize")

        if context == "system_prompt":
            recommendations.append("Review system prompt for unintended instruction exposure")

        return recommendations[:5]

    def _generate_system_prompt(self, args: dict[str, Any]) -> dict[str, Any]:
        """Generate an optimized system prompt."""
        prompt = self.prompt_optimizer.suggest_system_prompt(
            task_type=args["task_type"],
            requirements=args.get("requirements"),
            language=args.get("language", "english"),
        )

        return {
            "task_type": args["task_type"],
            "language": args.get("language", "english"),
            "system_prompt": prompt,
            "token_estimate": self.prompt_optimizer._estimate_tokens(prompt),
            "tips": [
                "Use this as your base system prompt",
                "Keep dynamic content in user messages",
                "Enable prompt caching for this static prompt",
            ],
        }

    def _get_optimization_report(self, args: dict[str, Any]) -> dict[str, Any]:
        """Generate comprehensive optimization report."""
        return self.advisor.get_optimization_report(
            current_model=args["current_model"],
            current_avg_tokens=args["current_avg_tokens"],
            requests_per_day=args["requests_per_day"],
            sample_prompt=args.get("sample_prompt"),
        )

    async def run(self):
        """Run the MCP server."""
        async with stdio_server() as (read_stream, write_stream):
            await self.server.run(
                read_stream,
                write_stream,
                self.server.create_initialization_options(),
            )


def create_server() -> InAlignMCPServer:
    """Create a new In-A-Lign MCP server instance."""
    return InAlignMCPServer()


if __name__ == "__main__":
    import asyncio

    logging.basicConfig(level=logging.INFO)
    server = create_server()
    asyncio.run(server.run())
