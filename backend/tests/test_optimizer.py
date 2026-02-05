"""
Test AI Optimization Advisor.

Tests task analysis, model matching, prompt optimization, and cost simulation.
"""

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

from app.optimizer import (
    AIAdvisor,
    TaskAnalyzer,
    ModelMatcher,
    PromptOptimizer,
    CostSimulator,
)


def test_task_analyzer():
    """Test task classification."""
    print("=" * 60)
    print("TASK ANALYZER TEST")
    print("=" * 60)

    analyzer = TaskAnalyzer()

    test_cases = [
        ("Write a Python function to sort a list", "coding"),
        ("Translate this to Korean: Hello world", "translation"),
        ("Summarize this article about climate change", "summarization"),
        ("Help me respond to this customer complaint", "customer_service"),
        ("Write a creative story about a dragon", "creative_writing"),
        ("Calculate the integral of x^2", "math"),
        ("What is the capital of France?", "general"),
    ]

    print("\nTask Classification Results:")
    print("-" * 60)

    for prompt, expected in test_cases:
        result = analyzer.analyze(prompt)
        status = "[OK]" if result.primary_task == expected else "[X]"
        print(f"{status} '{prompt[:40]}...'")
        print(f"   Expected: {expected}, Got: {result.primary_task} (conf: {result.confidence})")
        print(f"   Complexity: {result.complexity}, Tokens: ~{result.estimated_tokens}")

    print()


def test_model_matcher():
    """Test model recommendations."""
    print("=" * 60)
    print("MODEL MATCHER TEST")
    print("=" * 60)

    analyzer = TaskAnalyzer()
    matcher = ModelMatcher()

    test_tasks = ["coding", "customer_service", "translation", "summarization"]

    print("\nModel Recommendations by Task:")
    print("-" * 60)

    for task in test_tasks:
        # Create a sample prompt for this task
        sample_prompts = {
            "coding": "Write a Python function to parse JSON",
            "customer_service": "Help me with a return request",
            "translation": "Translate this document to Spanish",
            "summarization": "Summarize this quarterly report",
        }

        classification = analyzer.analyze(sample_prompts[task])
        result = matcher.match(classification)

        print(f"\n>> Task: {task.upper()}")
        print(f"   Best Performance: {result.best_performance.model_name}")
        print(f"   Best Value: {result.best_value.model_name} (${result.best_value.estimated_cost_per_1k_requests:.4f}/1K)")
        print(f"   Best Budget: {result.best_budget.model_name} (${result.best_budget.estimated_cost_per_1k_requests:.4f}/1K)")
        print(f"   Savings Potential: {result.savings_potential['savings_percent']:.0f}%")

    print()


def test_prompt_optimizer():
    """Test prompt optimization."""
    print("=" * 60)
    print("PROMPT OPTIMIZER TEST")
    print("=" * 60)

    optimizer = PromptOptimizer()

    # Verbose prompt to optimize
    verbose_prompt = """
    Hello! I would be extremely grateful if you could please help me with the following task.
    In order to accomplish this, I need you to write a Python function.
    Please note that the function should be well-documented.
    It is important to note that you should handle errors properly.
    At this point in time, I need this function to sort a list of numbers.
    Please make sure to include comments explaining what each part does.
    If you don't mind, could you also add type hints?
    Thank you so much in advance for your help!
    """

    print("\nPrompt Analysis:")
    print("-" * 60)

    analysis = optimizer.analyze(verbose_prompt)
    print(f"Original Tokens: {analysis.original_tokens}")
    print(f"Quality Score: {analysis.quality_score}/100")
    print(f"Efficiency Score: {analysis.efficiency_score}/100")
    print(f"Potential Savings: {analysis.savings_percent}%")

    print("\nIssues Found:")
    for issue in analysis.issues[:5]:
        print(f"  [{issue.severity}] {issue.description}")

    print("\nOptimized Version:")
    print("-" * 60)

    optimized = optimizer.optimize(verbose_prompt, aggressive=True)
    print(f"Original: {optimized.original_tokens} tokens")
    print(f"Optimized: {optimized.optimized_tokens} tokens")
    print(f"Saved: {optimized.tokens_saved} tokens ({optimized.savings_percent}%)")
    print(f"\nOptimized prompt:\n{optimized.optimized[:200]}...")

    print()


def test_cost_simulator():
    """Test cost simulation."""
    print("=" * 60)
    print("COST SIMULATOR TEST")
    print("=" * 60)

    simulator = CostSimulator()

    print("\nCost Comparison (1000 requests/day, 500 input tokens):")
    print("-" * 60)

    models_to_compare = [
        "gpt-4o",
        "gpt-4o-mini",
        "claude-3.5-sonnet",
        "claude-3.5-haiku",
        "gemini-2.5-flash",
    ]

    comparison = simulator.compare(
        model_ids=models_to_compare,
        avg_input_tokens=500,
        avg_output_tokens=200,
        requests_per_day=1000,
    )

    print(f"\n{'Model':<25} {'Daily':<12} {'Monthly':<12} {'Yearly':<12}")
    print("-" * 60)

    for estimate in comparison.estimates:
        print(f"{estimate.model_name:<25} ${estimate.daily_cost:<10.2f} ${estimate.monthly_cost:<10.2f} ${estimate.yearly_cost:<10.2f}")

    print(f"\n[CHEAPEST] Cheapest: {comparison.cheapest.model_name} (${comparison.cheapest.monthly_cost}/month)")
    print(f"[RECOMMENDED] Recommended (best value): {comparison.recommended.model_name}")
    print(f"[SAVINGS] Max savings: ${comparison.savings_summary['max_monthly_savings']}/month ({comparison.savings_summary['savings_percent']:.0f}%)")

    print()


def test_ai_advisor():
    """Test the full AI advisor."""
    print("=" * 60)
    print("AI ADVISOR - FULL ANALYSIS TEST")
    print("=" * 60)

    advisor = AIAdvisor()

    # Quick analysis
    print("\n[1] Quick Prompt Analysis")
    print("-" * 60)

    quick = advisor.analyze_prompt("Write a Python function to implement binary search")
    print(f"Task Type: {quick.task_type}")
    print(f"Recommended Model: {quick.recommended_model}")
    print(f"Budget Model: {quick.budget_model}")
    print(f"Estimated Tokens: {quick.estimated_tokens}")
    print(f"Cost per 1K requests: ${quick.estimated_cost_per_1k:.4f}")

    # Project analysis
    print("\n[2] Project Analysis")
    print("-" * 60)

    project = advisor.analyze_project(
        project_name="Customer Support Bot",
        project_description="AI chatbot for e-commerce customer support. Handles returns, order status, and product questions.",
        sample_prompts=[
            "I want to return my order #12345",
            "Where is my package?",
            "Do you have this shirt in blue?",
        ],
        current_model="gpt-4o",
        requests_per_day=5000,
    )

    print(f"Project: {project.project_name}")
    print(f"Primary Task: {project.task_analysis['primary_task']}")
    print(f"Recommended Model: {project.model_recommendation['recommended']['model']}")
    print(f"Budget Option: {project.model_recommendation['budget_option']['model']}")
    print(f"Current Monthly Cost: ${project.cost_analysis['recommended_monthly']:.2f}")
    print(f"Budget Monthly Cost: ${project.cost_analysis['budget_monthly']:.2f}")

    print("\nAction Items:")
    for i, item in enumerate(project.action_items, 1):
        print(f"  {i}. {item}")

    # Optimization report
    print("\n[3] Optimization Report")
    print("-" * 60)

    report = advisor.get_optimization_report(
        current_model="gpt-4o",
        current_avg_tokens=800,
        requests_per_day=5000,
        sample_prompt="""
        Hello, I am a customer service representative and I need your help.
        Please assist me in responding to this customer inquiry in a professional manner.
        The customer is asking about their order status.
        Please make sure to be polite and helpful.
        """,
    )

    print(f"Current Monthly Cost: ${report['current_state']['monthly_cost']:.2f}")
    print(f"Optimized Monthly Cost: ${report['potential_savings']['optimized_monthly']:.2f}")
    print(f"Monthly Savings: ${report['potential_savings']['monthly_savings']:.2f} ({report['potential_savings']['savings_percent']:.0f}%)")
    print(f"Yearly Savings: ${report['potential_savings']['yearly_savings']:.2f}")

    print("\nAction Plan:")
    for action in report['action_plan']:
        print(f"  {action}")

    print()


def main():
    """Run all tests."""
    print("\n" + "=" * 60)
    print("IN-A-LIGN AI OPTIMIZATION ADVISOR")
    print("=" * 60 + "\n")

    test_task_analyzer()
    test_model_matcher()
    test_prompt_optimizer()
    test_cost_simulator()
    test_ai_advisor()

    print("=" * 60)
    print("ALL TESTS COMPLETE")
    print("=" * 60)


if __name__ == "__main__":
    main()
