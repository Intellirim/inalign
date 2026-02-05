# -*- coding: utf-8 -*-
"""Test optimization features: PromptOptimizer + EfficiencyEngine"""
import sys
sys.path.insert(0, ".")

from app.optimizer.prompt_optimizer import PromptOptimizer
from app.efficiency.engine import EfficiencyEngine, ComplexityAnalyzer

def test_prompt_optimizer():
    print("=" * 60)
    print("PROMPT OPTIMIZER TEST")
    print("=" * 60)

    optimizer = PromptOptimizer()

    # Test cases: verbose prompts in multiple languages
    tests = [
        (
            "English Verbose",
            "Please could you kindly write me a simple code that is well-documented and follow best practices in order to sort a list of numbers. Make sure that it is clean and readable. I would appreciate it if you could add proper error handling.",
        ),
        (
            "Korean Verbose",
            "혹시 가능하시다면 정렬 알고리즘을 작성해 주시겠어요? 번거로우시겠지만 에러 처리도 부탁드립니다. 감사합니다.",
        ),
        (
            "Efficient (baseline)",
            "Write Python sorting function with error handling",
        ),
    ]

    for name, prompt in tests:
        analysis = optimizer.analyze(prompt)
        result = optimizer.optimize(prompt, aggressive=True)

        print(f"\n[{name}]")
        print(f"  Original:  {result.original_tokens} tokens")
        print(f"  Optimized: {result.optimized_tokens} tokens")
        print(f"  Saved:     {result.tokens_saved} tokens ({result.savings_percent}%)")
        print(f"  Quality:   {analysis.quality_score}/100")
        print(f"  Efficiency: {analysis.efficiency_score}/100")
        if result.changes_made:
            print(f"  Changes:   {len(result.changes_made)} optimizations applied")

    return True


def test_complexity_analyzer():
    print("\n" + "=" * 60)
    print("COMPLEXITY ANALYZER TEST")
    print("=" * 60)

    analyzer = ComplexityAnalyzer()

    tests = [
        ("Simple Query", "What is Python?"),
        ("Simple Translation", "Translate hello to Korean"),
        ("Medium Coding", "Write a function to calculate fibonacci numbers"),
        ("Complex Analysis", "Analyze the architectural patterns in this codebase, explain the design decisions, compare different approaches, and provide comprehensive recommendations for optimization"),
        ("Complex Debug", "Debug this code step by step and explain why the race condition occurs"),
    ]

    for name, query in tests:
        result = analyzer.analyze(query)
        print(f"\n[{name}]")
        print(f"  Query: {query[:50]}...")
        print(f"  Score: {result['score']:.2f}")
        print(f"  Tier:  {result['tier'].upper()}")

    return True


def test_efficiency_engine():
    print("\n" + "=" * 60)
    print("EFFICIENCY ENGINE TEST")
    print("=" * 60)

    engine = EfficiencyEngine(
        enable_caching=True,
        enable_routing=True,
    )

    # Simulate some requests
    requests = [
        ("What is Python?", "simple"),
        ("Write a sorting algorithm", "medium"),
        ("Analyze this complex system architecture", "complex"),
        ("What is Python?", "cached"),  # Should be cached
    ]

    print("\n[Request Routing & Caching]")
    for query, expected_type in requests:
        result = engine.optimize_request(query)

        if result["cached"]:
            status = "CACHED"
            model = result["model"]
        else:
            status = "ROUTED"
            model = result["model"]
            # Simulate recording response
            engine.record_response(
                query=query,
                response="Test response",
                model=model,
                input_tokens=100,
                output_tokens=200,
            )

        print(f"  {expected_type.upper():8} -> {status:7} -> {model}")

    # Get stats
    stats = engine.get_stats()
    print("\n[Statistics]")
    print(f"  Total requests:   {stats['usage']['total_requests']}")
    print(f"  Cached requests:  {stats['usage']['cached_requests']}")
    print(f"  Cache hit rate:   {stats['usage']['cache_hit_rate']}")
    print(f"  Cost actual:      {stats['usage']['cost']['actual']}")
    print(f"  Cost saved:       {stats['usage']['cost']['saved']}")

    return True


def test_smart_routing():
    print("\n" + "=" * 60)
    print("SMART MODEL ROUTING TEST")
    print("=" * 60)

    from app.efficiency.engine import SmartRouter

    router = SmartRouter({
        "simple": "gpt-4o-mini",
        "medium": "gpt-4o",
        "complex": "claude-3-5-sonnet",
    })

    tests = [
        "What is 2+2?",
        "Write Python code to parse JSON",
        "Analyze the performance bottlenecks in this distributed system, explain the CAP theorem implications, and provide a comprehensive refactoring plan",
    ]

    print("\n[Model Selection]")
    for query in tests:
        result = router.route(query)
        cost_mini = router.estimate_cost("gpt-4o-mini", 1000, 500)
        cost_4o = router.estimate_cost("gpt-4o", 1000, 500)
        cost_selected = router.estimate_cost(result["model"], 1000, 500)

        print(f"\n  Query: {query[:40]}...")
        print(f"  Selected: {result['model']} (tier: {result['analysis']['tier']})")
        print(f"  Cost comparison (1K in, 500 out):")
        print(f"    - gpt-4o-mini: ${cost_mini:.4f}")
        print(f"    - gpt-4o:      ${cost_4o:.4f}")
        print(f"    - Selected:    ${cost_selected:.4f}")

    return True


if __name__ == "__main__":
    print("\n" + "=" * 60)
    print("IN-A-LIGN OPTIMIZATION TEST SUITE")
    print("=" * 60)

    results = []

    try:
        results.append(("Prompt Optimizer", test_prompt_optimizer()))
    except Exception as e:
        print(f"ERROR: {e}")
        results.append(("Prompt Optimizer", False))

    try:
        results.append(("Complexity Analyzer", test_complexity_analyzer()))
    except Exception as e:
        print(f"ERROR: {e}")
        results.append(("Complexity Analyzer", False))

    try:
        results.append(("Efficiency Engine", test_efficiency_engine()))
    except Exception as e:
        print(f"ERROR: {e}")
        results.append(("Efficiency Engine", False))

    try:
        results.append(("Smart Routing", test_smart_routing()))
    except Exception as e:
        print(f"ERROR: {e}")
        results.append(("Smart Routing", False))

    print("\n" + "=" * 60)
    print("FINAL RESULTS")
    print("=" * 60)

    all_passed = True
    for name, passed in results:
        status = "OK" if passed else "FAIL"
        print(f"  {name}: {status}")
        if not passed:
            all_passed = False

    if all_passed:
        print("\n*** ALL OPTIMIZATION TESTS PASSED ***")
    else:
        print("\n*** SOME TESTS FAILED ***")
