"""Test efficiency features (routing, caching, cost tracking)."""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

from app.platform import InALign, PlatformConfig

platform = InALign(config=PlatformConfig(
    enable_caching=True,
    enable_injection_detection=False,  # Focus on efficiency
))

print("=" * 60)
print("EFFICIENCY FEATURES TEST")
print("=" * 60)

# Test 1: Smart Routing
print("\n[1] SMART MODEL ROUTING")
print("-" * 40)

simple_q = "What is 2+2?"
complex_q = """
I need a comprehensive analysis of quantum computing principles,
including mathematical foundations, current hardware implementations,
comparison of different qubit technologies, error correction methods,
and future scalability challenges. Please provide detailed examples
and code implementations where relevant.
""" * 2

r1 = platform.process(text=simple_q, user_id="test")
r2 = platform.process(text=complex_q, user_id="test")

print(f"Simple query: '{simple_q}'")
print(f"  → Routed to: {r1['recommended_model']}")
print(f"\nComplex query: (long analysis request)")
print(f"  → Routed to: {r2['recommended_model']}")

# Test 2: Caching
print("\n[2] RESPONSE CACHING")
print("-" * 40)

# First request
result1 = platform.process(text="What is Python?", user_id="user1")
print(f"First request: cached={result1['cached']}")

# Record a response
platform.record(
    text="What is Python?",
    response="Python is a programming language.",
    model="gpt-4o-mini",
    tokens={"input": 10, "output": 20},
)

# Second request (should be cached)
result2 = platform.process(text="What is Python?", user_id="user2")
print(f"Second request: cached={result2['cached']}")
if result2['cached']:
    print(f"  → Cached response: {result2.get('response', 'N/A')[:50]}...")

# Test 3: Cost Tracking
print("\n[3] COST TRACKING")
print("-" * 40)

# Record some usage
platform.record(text="Q1", response="A1", model="gpt-4", tokens={"input": 100, "output": 200})
platform.record(text="Q2", response="A2", model="gpt-4o-mini", tokens={"input": 50, "output": 100})
platform.record(text="Q3", response="A3", model="gpt-4-turbo", tokens={"input": 200, "output": 400})

stats = platform.get_stats()
efficiency = stats.get("efficiency", {})
usage = efficiency.get("usage", {})

print(f"Total Requests: {usage.get('total_requests', 0)}")
print(f"Actual Cost: {usage.get('cost', {}).get('actual', '$0.00')}")
print(f"Would-be Cost (without routing): {usage.get('cost', {}).get('without_routing', '$0.00')}")
print(f"Savings: {usage.get('cost', {}).get('savings', '$0.00')}")

# Model distribution
print("\nModel Usage Distribution:")
for model, count in usage.get("by_model", {}).items():
    print(f"  {model}: {count} requests")

print("\n" + "=" * 60)
print("EFFICIENCY TEST COMPLETE")
print("=" * 60)
