#!/usr/bin/env python3
"""
AgentShield Adversarial Training Loop.

Continuous cycle:  Attack → Detect → Learn → Repeat

Usage:
    python -m tools.adversarial.adversarial_loop \
        --url http://localhost:8000 \
        --api-key ask_... \
        --rounds 5 \
        --attacks-per-strategy 5 \
        --auto-inject

Or from the project root:
    python tools/adversarial/adversarial_loop.py \
        --url http://localhost:8000 \
        --api-key ask_... \
        --rounds 3
"""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import os
import sys
from datetime import datetime
from pathlib import Path

# Add project root to path for imports
_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(_ROOT))

from tools.adversarial.attack_agent import AttackAgent, AttackRoundReport
from tools.adversarial.pattern_learner import PatternLearner

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("agentshield.adversarial_loop")


def print_banner():
    print(r"""
    ╔══════════════════════════════════════════════════════════╗
    ║       AgentShield Adversarial Training System           ║
    ║   Attack → Detect → Learn → Repeat                     ║
    ╚══════════════════════════════════════════════════════════╝
    """)


def print_round_report(report: AttackRoundReport):
    """Pretty-print a single round report."""
    dr = report.detection_rate * 100
    bar_len = 40
    filled = int(bar_len * report.detection_rate)
    bar = "█" * filled + "░" * (bar_len - filled)

    print(f"\n{'='*60}")
    print(f"  ROUND {report.round_num} RESULTS")
    print(f"{'='*60}")
    print(f"  Total Attacks : {report.total_attacks}")
    print(f"  Detected      : {report.detected}")
    print(f"  Missed        : {report.missed}")
    print(f"  Detection Rate: [{bar}] {dr:.1f}%")
    print(f"  Avg Latency   : {report.avg_latency_ms:.0f}ms")
    print()

    # Per-category breakdown
    if report.categories:
        print(f"  {'Category':<25} {'Total':>6} {'Det':>6} {'Miss':>6} {'Rate':>8}")
        print(f"  {'-'*55}")
        for cat, stats in sorted(report.categories.items()):
            total = stats["total"]
            det = stats["detected"]
            miss = stats["missed"]
            rate = det / total * 100 if total > 0 else 0
            flag = " ⚠" if miss > 0 else ""
            print(f"  {cat:<25} {total:>6} {det:>6} {miss:>6} {rate:>7.1f}%{flag}")

    if report.missed_attacks:
        print(f"\n  MISSED ATTACKS ({len(report.missed_attacks)}):")
        print(f"  {'-'*55}")
        for i, m in enumerate(report.missed_attacks[:20]):
            text_preview = m.text[:80].replace("\n", "\\n")
            print(f"  {i+1:>3}. [{m.category}] {text_preview}...")
        if len(report.missed_attacks) > 20:
            print(f"  ... and {len(report.missed_attacks) - 20} more")
    print()


def print_learning_report(learned_patterns, round_num: int):
    """Print what the pattern learner discovered."""
    if not learned_patterns:
        print(f"  Round {round_num}: No new patterns generated.")
        return

    print(f"\n  LEARNED PATTERNS (Round {round_num}): {len(learned_patterns)} new")
    print(f"  {'-'*55}")
    for pat in learned_patterns:
        print(f"    {pat.pattern_id}: [{pat.category}] {pat.description}")
        print(f"      regex: {pat.regex[:70]}{'...' if len(pat.regex) > 70 else ''}")
        print(f"      severity={pat.severity}, confidence={pat.confidence_base}, covers={pat.coverage_count}")
    print()


def print_final_summary(all_reports: list, total_learned: int, auto_injected: bool):
    """Print final training summary."""
    print(f"\n{'═'*60}")
    print(f"  ADVERSARIAL TRAINING COMPLETE")
    print(f"{'═'*60}")
    print(f"  Rounds Completed  : {len(all_reports)}")

    total_attacks = sum(r.total_attacks for r in all_reports)
    total_detected = sum(r.detected for r in all_reports)
    total_missed = sum(r.missed for r in all_reports)
    overall_rate = total_detected / total_attacks * 100 if total_attacks else 0

    print(f"  Total Attacks     : {total_attacks}")
    print(f"  Total Detected    : {total_detected}")
    print(f"  Total Missed      : {total_missed}")
    print(f"  Overall Det. Rate : {overall_rate:.1f}%")
    print(f"  Patterns Learned  : {total_learned}")
    print(f"  Auto-Injected     : {'Yes' if auto_injected else 'No'}")

    # Show improvement across rounds
    if len(all_reports) > 1:
        print(f"\n  Detection Rate Progression:")
        for r in all_reports:
            bar_len = 30
            filled = int(bar_len * r.detection_rate)
            bar = "█" * filled + "░" * (bar_len - filled)
            print(f"    Round {r.round_num}: [{bar}] {r.detection_rate*100:.1f}%"
                  f" ({r.missed} missed)")

    print(f"\n{'═'*60}\n")


async def run_training_loop(
    api_url: str,
    api_key: str,
    rounds: int = 3,
    attacks_per_strategy: int = 5,
    max_attacks_per_round: int | None = None,
    auto_inject: bool = False,
    output_dir: str = "adversarial_results",
    request_delay: float = 0.1,
):
    """
    Main adversarial training loop.

    Each round:
    1. Generate diverse attacks using all mutation strategies.
    2. Test all attacks against the AgentShield API.
    3. Analyze missed attacks with PatternLearner.
    4. (Optional) Auto-inject learned patterns into the detection engine.
    5. Save results for analysis.
    """
    os.makedirs(output_dir, exist_ok=True)

    agent = AttackAgent(
        api_url=api_url,
        api_key=api_key,
        request_delay=request_delay,
    )

    learner = PatternLearner()
    all_reports: list = []
    total_learned = 0
    injected = False

    try:
        for round_num in range(1, rounds + 1):
            logger.info("=" * 60)
            logger.info("STARTING ROUND %d/%d", round_num, rounds)
            logger.info("=" * 60)

            # 1) Run attack round
            report = await agent.run_round(
                round_num=round_num,
                attacks_per_strategy=attacks_per_strategy,
                max_attacks=max_attacks_per_round,
            )
            all_reports.append(report)
            print_round_report(report)

            # 2) Save round results
            round_file = os.path.join(output_dir, f"round_{round_num}_results.json")
            agent.save_report(report, round_file)

            # 3) Learn from missed attacks
            if report.missed_attacks:
                missed_data = [
                    {
                        "text": m.text,
                        "category": m.category,
                        "mutation_type": m.mutation_type,
                    }
                    for m in report.missed_attacks
                ]

                learned = learner.learn(missed_data)
                total_learned += len(learned)
                print_learning_report(learned, round_num)

                # Save learned patterns
                patterns_file = os.path.join(output_dir, f"round_{round_num}_learned_patterns.json")
                learner.export_patterns_json(patterns_file, learned)

                # 4) Auto-inject if requested
                if auto_inject and learned:
                    patterns_py = os.path.join(
                        str(_ROOT), "backend", "app", "detectors", "injection", "patterns.py"
                    )
                    learner.inject_into_patterns_file(patterns_py)
                    injected = True
                    logger.info("Auto-injected %d patterns into detection engine.", len(learned))
            else:
                logger.info("Round %d: No missed attacks! Detection is holding strong.", round_num)

            # Brief pause between rounds
            if round_num < rounds:
                logger.info("Pausing before next round...")
                await asyncio.sleep(2)

    finally:
        await agent.close()

    # Final summary
    print_final_summary(all_reports, total_learned, injected)

    # Save overall summary
    summary_file = os.path.join(output_dir, "training_summary.json")
    summary = {
        "timestamp": datetime.now().isoformat(),
        "rounds": rounds,
        "total_attacks": sum(r.total_attacks for r in all_reports),
        "total_detected": sum(r.detected for r in all_reports),
        "total_missed": sum(r.missed for r in all_reports),
        "overall_detection_rate": sum(r.detected for r in all_reports) / max(1, sum(r.total_attacks for r in all_reports)),
        "patterns_learned": total_learned,
        "auto_injected": injected,
        "round_details": [
            {
                "round": r.round_num,
                "total": r.total_attacks,
                "detected": r.detected,
                "missed": r.missed,
                "detection_rate": r.detection_rate,
                "avg_latency_ms": r.avg_latency_ms,
            }
            for r in all_reports
        ],
    }
    with open(summary_file, "w", encoding="utf-8") as f:
        json.dump(summary, f, ensure_ascii=False, indent=2)

    logger.info("All results saved to %s/", output_dir)
    return all_reports, total_learned


def main():
    parser = argparse.ArgumentParser(
        description="AgentShield Adversarial Training Loop",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent("""
        Examples:
            # Quick test (3 rounds, 5 attacks per strategy)
            python adversarial_loop.py --url http://localhost:8000 --api-key ask_xxx --rounds 3

            # Full training with auto-injection
            python adversarial_loop.py --url http://localhost:8000 --api-key ask_xxx \\
                --rounds 10 --attacks-per-strategy 10 --auto-inject

            # Large scale stress test
            python adversarial_loop.py --url http://localhost:8000 --api-key ask_xxx \\
                --rounds 20 --attacks-per-strategy 20 --max-attacks 500
        """),
    )
    parser.add_argument("--url", default="http://localhost:8000", help="Backend API URL")
    parser.add_argument("--api-key", required=True, help="API key (ask_... or JWT)")
    parser.add_argument("--rounds", type=int, default=3, help="Number of training rounds")
    parser.add_argument("--attacks-per-strategy", type=int, default=5,
                        help="Attacks to generate per mutation strategy")
    parser.add_argument("--max-attacks", type=int, default=None,
                        help="Max attacks per round (cap)")
    parser.add_argument("--auto-inject", action="store_true",
                        help="Auto-inject learned patterns into patterns.py")
    parser.add_argument("--output-dir", default="adversarial_results",
                        help="Directory for results")
    parser.add_argument("--delay", type=float, default=0.1,
                        help="Delay between API requests (seconds)")

    args = parser.parse_args()

    print_banner()

    asyncio.run(run_training_loop(
        api_url=args.url,
        api_key=args.api_key,
        rounds=args.rounds,
        attacks_per_strategy=args.attacks_per_strategy,
        max_attacks_per_round=args.max_attacks,
        auto_inject=args.auto_inject,
        output_dir=args.output_dir,
        request_delay=args.delay,
    ))


import textwrap  # noqa: E402 (moved here to keep main() clean)

if __name__ == "__main__":
    main()
