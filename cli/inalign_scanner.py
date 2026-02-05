#!/usr/bin/env python3
"""
In-A-Lign Local ML Scanner CLI
Fast local security scanning without proxy or API calls.
Works with Claude Code hooks for Max subscription users.
"""

import sys
import json
import re
import argparse
from typing import Dict, Any, Tuple
from pathlib import Path

# Add parent directory for imports
sys.path.insert(0, str(Path(__file__).parent.parent / "backend"))

try:
    from inalign.detectors.injection import InjectionDetector
    from inalign.detectors.pii import PIIDetector
    FULL_MODE = True
except ImportError:
    FULL_MODE = False


class FastLocalScanner:
    """Lightweight local scanner for quick security checks."""

    # Common injection patterns
    INJECTION_PATTERNS = [
        r"ignore\s+(all\s+)?(previous|prior|above)",
        r"disregard\s+(all\s+)?(previous|prior|above)",
        r"forget\s+(all\s+)?(previous|prior|above)",
        r"you\s+are\s+(now\s+)?(DAN|evil|unrestricted|jailbroken)",
        r"pretend\s+(you\s+)?(have\s+no|are\s+not|don't\s+have)",
        r"act\s+as\s+(if\s+)?(you\s+)?(have\s+no|are\s+)",
        r"bypass\s+(your\s+)?(restrictions|filters|safety)",
        r"(system|developer)\s*prompt",
        r"reveal\s+(your\s+)?(instructions|prompt|rules)",
        r"what\s+(are|were)\s+(your\s+)?(initial|original|system)",
        r"\[INST\]|\[\/INST\]|<<SYS>>|<\|im_start\|>",
        r"<\|system\|>|<\|user\|>|<\|assistant\|>",
        r"###\s*(instruction|system|human|assistant)",
        r"(human|user|assistant)\s*:",
        r"sudo\s+mode|god\s+mode|admin\s+mode",
        r"developer\s+mode|debug\s+mode",
        r"override\s+(safety|security|restrictions)",
    ]

    # Compiled patterns for speed
    COMPILED_PATTERNS = [re.compile(p, re.IGNORECASE) for p in INJECTION_PATTERNS]

    # PII patterns
    PII_PATTERNS = {
        'email': re.compile(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'),
        'phone_kr': re.compile(r'01[0-9]-?\d{3,4}-?\d{4}'),
        'phone_intl': re.compile(r'\+\d{1,3}[-.\s]?\d{3,4}[-.\s]?\d{3,4}[-.\s]?\d{3,4}'),
        'ssn_kr': re.compile(r'\d{6}-?[1-4]\d{6}'),
        'credit_card': re.compile(r'\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}'),
    }

    def __init__(self, use_ml: bool = True):
        self.use_ml = use_ml and FULL_MODE
        self.injection_detector = None
        self.pii_detector = None

        if self.use_ml:
            try:
                self.injection_detector = InjectionDetector()
                self.pii_detector = PIIDetector()
            except Exception:
                self.use_ml = False

    def scan_injection(self, text: str) -> Tuple[bool, float, str]:
        """
        Scan for injection attacks.
        Returns: (is_attack, confidence, reason)
        """
        # Skip very short messages (greetings, etc.)
        if len(text.strip()) < 15:
            return False, 0.0, "Short message - safe"

        # Rule-based detection (fast)
        for i, pattern in enumerate(self.COMPILED_PATTERNS):
            if pattern.search(text):
                return True, 0.95, f"Pattern match: {self.INJECTION_PATTERNS[i][:30]}..."

        # ML-based detection if available
        if self.use_ml and self.injection_detector:
            try:
                result = self.injection_detector.analyze(text)
                if result.get('risk_score', 0) >= 0.85:
                    return True, result['risk_score'], result.get('attack_type', 'ML detected')
            except Exception:
                pass

        return False, 0.0, "No threats detected"

    def scan_pii(self, text: str) -> Dict[str, Any]:
        """Scan for PII."""
        found_pii = {}

        for pii_type, pattern in self.PII_PATTERNS.items():
            matches = pattern.findall(text)
            if matches:
                found_pii[pii_type] = len(matches)

        # ML-based PII detection if available
        if self.use_ml and self.pii_detector:
            try:
                result = self.pii_detector.analyze(text)
                if result.get('pii_found'):
                    for item in result.get('pii_items', []):
                        pii_type = item.get('type', 'unknown')
                        found_pii[pii_type] = found_pii.get(pii_type, 0) + 1
            except Exception:
                pass

        return found_pii

    def scan(self, text: str, check_injection: bool = True, check_pii: bool = True) -> Dict[str, Any]:
        """Full scan."""
        result = {
            "ok": True,
            "text_length": len(text),
            "mode": "ml" if self.use_ml else "rules"
        }

        if check_injection:
            is_attack, confidence, reason = self.scan_injection(text)
            result["injection"] = {
                "is_attack": is_attack,
                "confidence": confidence,
                "reason": reason
            }
            if is_attack:
                result["ok"] = False
                result["reason"] = f"Injection detected: {reason}"

        if check_pii:
            pii_found = self.scan_pii(text)
            result["pii"] = {
                "found": bool(pii_found),
                "types": pii_found
            }

        return result


def main():
    parser = argparse.ArgumentParser(description="In-A-Lign Local Security Scanner")
    parser.add_argument("text", nargs="?", help="Text to scan (or use --stdin)")
    parser.add_argument("--stdin", action="store_true", help="Read from stdin")
    parser.add_argument("--no-ml", action="store_true", help="Disable ML detection (faster)")
    parser.add_argument("--injection-only", action="store_true", help="Only check injection")
    parser.add_argument("--pii-only", action="store_true", help="Only check PII")
    parser.add_argument("--hook-mode", action="store_true", help="Claude Code hook output format")

    args = parser.parse_args()

    # Get input text
    if args.stdin:
        text = sys.stdin.read()
    elif args.text:
        text = args.text
    else:
        # Try to read from stdin if no text provided
        if not sys.stdin.isatty():
            text = sys.stdin.read()
        else:
            parser.print_help()
            sys.exit(1)

    # Create scanner
    scanner = FastLocalScanner(use_ml=not args.no_ml)

    # Determine what to check
    check_injection = not args.pii_only
    check_pii = not args.injection_only

    # Scan
    result = scanner.scan(text, check_injection=check_injection, check_pii=check_pii)

    # Output format
    if args.hook_mode:
        # Claude Code hook format
        if result["ok"]:
            print(json.dumps({"ok": True}))
        else:
            print(json.dumps({"ok": False, "reason": result.get("reason", "Security threat detected")}))
    else:
        print(json.dumps(result, indent=2))

    # Exit code
    sys.exit(0 if result["ok"] else 1)


if __name__ == "__main__":
    main()
