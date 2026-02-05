#!/usr/bin/env python3
"""
InALign Red Team Test Runner.

Runs all attack prompts against the /scan/input endpoint and generates
a detection report with:
  - Overall detection rate
  - Per-category detection rate
  - False positive rate
  - Missed attacks (for pattern tuning)
  - Per-difficulty breakdown

Usage:
    python tests/redteam/run_redteam.py [--url URL] [--api-key KEY]
"""

from __future__ import annotations

import argparse
import io
import json
import os
import sys
import time

# Force UTF-8 output on Windows
if sys.platform == "win32":
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8", errors="replace")
from dataclasses import dataclass, field
from pathlib import Path

import httpx

# Add project root to path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))
from tests.redteam.attack_prompts import ATTACK_PROMPTS


@dataclass
class TestResult:
    text: str
    category: str
    expected_detected: bool
    difficulty: str
    actual_detected: bool = False
    threat_count: int = 0
    risk_score: float = 0.0
    threats: list = field(default_factory=list)
    recommendation: str = ""
    error: str = ""
    latency_ms: float = 0.0


def scan_input(client: httpx.Client, url: str, headers: dict, text: str) -> dict:
    """Call /scan/input and return the response."""
    payload = {
        "text": text,
        "agent_id": "redteam-bot",
        "session_id": "redteam-session-001",
        "context": {"mode": "redteam_test"},
    }
    start = time.perf_counter()
    resp = client.post(f"{url}/api/v1/scan/input", headers=headers, json=payload, timeout=30.0)
    elapsed = (time.perf_counter() - start) * 1000

    if resp.status_code != 200:
        return {"error": f"HTTP {resp.status_code}: {resp.text}", "latency_ms": elapsed}

    data = resp.json()
    data["latency_ms"] = elapsed
    return data


def run_tests(url: str, api_key: str, delay: float = 0.65) -> list[TestResult]:
    """Execute all attack prompts and collect results."""
    headers = {"X-API-Key": api_key, "Content-Type": "application/json"}
    results: list[TestResult] = []

    with httpx.Client() as client:
        total = len(ATTACK_PROMPTS)
        for i, prompt in enumerate(ATTACK_PROMPTS, 1):
            text = prompt["text"]
            short_text = text[:60] + "..." if len(text) > 60 else text
            print(f"  [{i:3d}/{total}] {prompt['category']:24s} | {short_text}", flush=True)

            result = TestResult(
                text=text,
                category=prompt["category"],
                expected_detected=prompt["expected"],
                difficulty=prompt["difficulty"],
            )

            try:
                data = scan_input(client, url, headers, text)
                if "error" in data and isinstance(data["error"], str):
                    result.error = data["error"]
                else:
                    result.actual_detected = not data.get("safe", True)
                    result.threat_count = len(data.get("threats", []))
                    result.risk_score = data.get("risk_score", 0.0)
                    result.threats = data.get("threats", [])
                    result.recommendation = data.get("recommendation", "")
                    result.latency_ms = data.get("latency_ms", 0.0)
            except Exception as exc:
                result.error = str(exc)

            results.append(result)

            # Delay between requests to stay under rate limit
            if i < total and delay > 0:
                time.sleep(delay)

    return results


def generate_report(results: list[TestResult]) -> str:
    """Generate a human-readable report from test results."""
    lines: list[str] = []
    lines.append("=" * 80)
    lines.append("  InALign Red Team Test Report")
    lines.append("=" * 80)
    lines.append("")

    # Separate attacks vs benign
    attacks = [r for r in results if r.expected_detected]
    benign = [r for r in results if not r.expected_detected]

    # Overall stats
    true_pos = sum(1 for r in attacks if r.actual_detected)
    false_neg = sum(1 for r in attacks if not r.actual_detected and not r.error)
    false_pos = sum(1 for r in benign if r.actual_detected)
    true_neg = sum(1 for r in benign if not r.actual_detected and not r.error)
    errors = sum(1 for r in results if r.error)

    detection_rate = true_pos / max(len(attacks), 1) * 100
    fp_rate = false_pos / max(len(benign), 1) * 100
    avg_latency = sum(r.latency_ms for r in results if not r.error) / max(sum(1 for r in results if not r.error), 1)

    lines.append(f"  Total prompts:     {len(results)}")
    lines.append(f"  Attack prompts:    {len(attacks)}")
    lines.append(f"  Benign prompts:    {len(benign)}")
    lines.append(f"  Errors:            {errors}")
    lines.append("")
    lines.append(f"  Detection Rate:    {detection_rate:.1f}% ({true_pos}/{len(attacks)})")
    lines.append(f"  False Positive:    {fp_rate:.1f}% ({false_pos}/{len(benign)})")
    lines.append(f"  Avg Latency:       {avg_latency:.0f}ms")
    lines.append("")

    # Per-category breakdown
    lines.append("-" * 80)
    lines.append(f"  {'Category':<25s} {'Detected':>10s} {'Total':>8s} {'Rate':>8s} {'FP':>5s}")
    lines.append("-" * 80)

    categories = sorted(set(r.category for r in results))
    for cat in categories:
        cat_attacks = [r for r in attacks if r.category == cat]
        cat_benign = [r for r in benign if r.category == cat]
        cat_tp = sum(1 for r in cat_attacks if r.actual_detected)
        cat_fp = sum(1 for r in cat_benign if r.actual_detected)
        cat_rate = cat_tp / max(len(cat_attacks), 1) * 100
        fp_str = f"{cat_fp}" if cat_benign else "-"
        lines.append(f"  {cat:<25s} {cat_tp:>10d} {len(cat_attacks):>8d} {cat_rate:>7.1f}% {fp_str:>5s}")

    lines.append("")

    # Per-difficulty breakdown
    lines.append("-" * 80)
    lines.append(f"  {'Difficulty':<15s} {'Detected':>10s} {'Total':>8s} {'Rate':>8s}")
    lines.append("-" * 80)
    for diff in ["easy", "medium", "hard"]:
        diff_attacks = [r for r in attacks if r.difficulty == diff]
        diff_tp = sum(1 for r in diff_attacks if r.actual_detected)
        diff_rate = diff_tp / max(len(diff_attacks), 1) * 100
        lines.append(f"  {diff:<15s} {diff_tp:>10d} {len(diff_attacks):>8d} {diff_rate:>7.1f}%")

    lines.append("")

    # Missed attacks (false negatives)
    missed = [r for r in attacks if not r.actual_detected and not r.error]
    if missed:
        lines.append("-" * 80)
        lines.append(f"  MISSED ATTACKS ({len(missed)} total) — Pattern tuning needed")
        lines.append("-" * 80)
        for r in missed:
            short = r.text[:70] + "..." if len(r.text) > 70 else r.text
            lines.append(f"  [{r.category}] [{r.difficulty}] {short}")
        lines.append("")

    # False positives
    fps = [r for r in benign if r.actual_detected]
    if fps:
        lines.append("-" * 80)
        lines.append(f"  FALSE POSITIVES ({len(fps)} total)")
        lines.append("-" * 80)
        for r in fps:
            short = r.text[:70] + "..." if len(r.text) > 70 else r.text
            lines.append(f"  [{r.category}] {short}")
        lines.append("")

    lines.append("=" * 80)
    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(description="InALign Red Team Tester")
    parser.add_argument("--url", default="http://localhost:8000", help="API base URL")
    parser.add_argument("--api-key", default="ask_XbFGizz0VbUgH7spl4PrKennzP1MH8_9h8ETYtzUtl0", help="API key")
    parser.add_argument("--output", default=None, help="Output file path for JSON results")
    parser.add_argument("--delay", type=float, default=0.65, help="Delay between requests in seconds (default: 0.65 to stay under rate limit)")
    args = parser.parse_args()

    print(f"\n  InALign Red Team Test", flush=True)
    print(f"  Target: {args.url}", flush=True)
    print(f"  Prompts: {len(ATTACK_PROMPTS)}", flush=True)
    print(flush=True)

    results = run_tests(args.url, args.api_key, delay=args.delay)
    report = generate_report(results)
    print(report, flush=True)

    # Save detailed JSON results
    output_path = args.output or str(
        Path(__file__).resolve().parent / "redteam_results.json"
    )
    json_results = [
        {
            "text": r.text,
            "category": r.category,
            "expected": r.expected_detected,
            "detected": r.actual_detected,
            "difficulty": r.difficulty,
            "risk_score": r.risk_score,
            "threat_count": r.threat_count,
            "threats": r.threats,
            "recommendation": r.recommendation,
            "latency_ms": r.latency_ms,
            "error": r.error,
            "correct": (r.expected_detected == r.actual_detected) and not r.error,
        }
        for r in results
    ]
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(json_results, f, ensure_ascii=False, indent=2)
    print(f"\n  Detailed results saved to: {output_path}")

    # Save report text
    report_path = str(Path(__file__).resolve().parent / "redteam_report.txt")
    with open(report_path, "w", encoding="utf-8") as f:
        f.write(report)
    print(f"  Report saved to: {report_path}")


if __name__ == "__main__":
    main()
