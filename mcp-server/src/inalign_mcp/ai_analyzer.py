"""
InALign AI Security Analyzer

Deep AI-powered analysis of agent session data.
Runs 100% on user's machine using their own LLM API key.
No data goes to InALign servers. Ever.

Usage:
    inalign-analyze --api-key sk-ant-xxx
    inalign-analyze --provider openai --api-key sk-xxx
    inalign-analyze --latest --save
"""

import json
import gzip
import re
import sys
import os
import hashlib
import argparse
from pathlib import Path
from datetime import datetime, timezone
from typing import Optional

# PII patterns to mask before sending to LLM
PII_PATTERNS = [
    # API keys
    (r'sk-ant-[a-zA-Z0-9_-]{20,}', '[MASKED_ANTHROPIC_KEY]'),
    (r'sk-[a-zA-Z0-9]{20,}', '[MASKED_OPENAI_KEY]'),
    (r'ial_[a-zA-Z0-9_-]{16,}', '[MASKED_INALIGN_KEY]'),
    (r'ghp_[a-zA-Z0-9]{36,}', '[MASKED_GITHUB_TOKEN]'),
    (r'gho_[a-zA-Z0-9]{36,}', '[MASKED_GITHUB_OAUTH]'),
    (r'aws_[a-zA-Z0-9/+=]{20,}', '[MASKED_AWS_KEY]'),
    (r'AKIA[A-Z0-9]{16}', '[MASKED_AWS_ACCESS_KEY]'),
    # Passwords in common formats
    (r'(?i)(password|passwd|pwd|secret|token)\s*[:=]\s*["\']?[^\s"\']{8,}', '[MASKED_SECRET]'),
    # Email addresses
    (r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', '[MASKED_EMAIL]'),
    # IP addresses (private)
    (r'\b(?:10|172\.(?:1[6-9]|2\d|3[01])|192\.168)\.\d{1,3}\.\d{1,3}\b', '[MASKED_PRIVATE_IP]'),
    # SSH keys
    (r'-----BEGIN [A-Z ]+ KEY-----[\s\S]*?-----END [A-Z ]+ KEY-----', '[MASKED_SSH_KEY]'),
    # JWT tokens
    (r'eyJ[a-zA-Z0-9_-]{10,}\.eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}', '[MASKED_JWT]'),
    # File paths with sensitive names
    (r'(/|\\)(\.env|credentials|\.aws|\.ssh|id_rsa|\.pem)[^\s]*', '[MASKED_SENSITIVE_PATH]'),
]

def _decode_prompt(encoded: str, license_hash: str) -> str:
    """Decode the system prompt using license key hash as XOR key."""
    import base64
    data = base64.b64decode(encoded)
    key = license_hash.encode()
    result = bytes(b ^ key[i % len(key)] for i, b in enumerate(data))
    return result.decode("utf-8")


def _get_system_prompt() -> str:
    """
    Load system prompt. The prompt is encoded and requires a valid
    license to decode. This protects the prompt as intellectual property.
    """
    try:
        from .license import get_license_info, LICENSE_FILE
        import base64

        license_data = {}
        if LICENSE_FILE.exists():
            with open(LICENSE_FILE, "r") as f:
                license_data = json.load(f)

        license_hash = license_data.get("license_key_hash", "")
        if not license_hash:
            return ""

        # Prompt stored as encrypted file alongside license
        prompt_file = LICENSE_FILE.parent / "analyzer_prompt.enc"
        if prompt_file.exists():
            with open(prompt_file, "r") as f:
                return _decode_prompt(f.read().strip(), license_hash)

        # First activation: encode and store the prompt
        prompt = _build_prompt()
        encoded = base64.b64encode(
            bytes(b ^ license_hash.encode()[i % len(license_hash.encode())]
                  for i, b in enumerate(prompt.encode("utf-8")))
        ).decode()

        prompt_file.parent.mkdir(parents=True, exist_ok=True)
        with open(prompt_file, "w") as f:
            f.write(encoded)
        try:
            os.chmod(prompt_file, 0o600)
        except OSError:
            pass

        return prompt

    except Exception:
        return _build_prompt()


def _build_prompt() -> str:
    """Build the analysis system prompt. Optimized for InALign's exact data structure."""
    return """You are InALign Security Analyst v2 — the definitive expert on InALign provenance data.

## EXACT DATA STRUCTURE (InALign ConversationRecord)

Each record in the session array is a JSON object with these fields:
- "sequence" (int): Chronological order number starting from 0
- "role" (str): "user" | "assistant" — who generated this record
- "type" (str): Record category:
  - "message" — Text from user or assistant
  - "tool_call" — Agent invoked a tool (role=assistant)
  - "tool_result" — Tool returned output (role=assistant)
  - "thinking" — Agent's internal reasoning (role=assistant)
- "timestamp" (str): ISO 8601 UTC timestamp
- "content" (str): The actual text content. For tool_call this is the tool description. For tool_result this is the output.
- "content_hash" (str): SHA-256 hash of the content field — used for tamper detection
- "tool_name" (str, optional): Tool identifier when type=tool_call/tool_result:
  - "Bash" — Shell command execution (HIGHEST RISK)
  - "Read" — File read
  - "Write" — File creation
  - "Edit" — File modification
  - "Grep" — Content search
  - "Glob" — File search
  - "WebFetch" — HTTP request to external URL
  - "WebSearch" — Web search query
  - "Task" — Spawned sub-agent
  - "NotebookEdit" — Jupyter notebook modification
- "tool_input" (str, optional): What was passed TO the tool (command, file path, query, etc.)
- "tool_output" (str, optional): What the tool RETURNED (file content, command output, search results)
- "model" (str, optional): LLM model used (e.g., "claude-opus-4-6", "gpt-4o")
- "token_usage" (dict, optional): {"input": N, "output": N} token counts

## CRITICAL ANALYSIS RULES

### 1. CONTENT ANALYSIS (Most Important)
- READ the actual "content" field thoroughly — this contains prompts, code, responses
- MATCH user requests (type=message, role=user) against agent actions that follow
- CHECK if agent actions are JUSTIFIED by the preceding user request
- LOOK for agent writing code with vulnerabilities (XSS, SQL injection, command injection, hardcoded secrets)

### 2. TOOL CHAIN ANALYSIS
Analyze sequences of tool calls for these dangerous patterns:
- Read(.env/.pem/.key) → Bash(curl/wget) = DATA EXFILTRATION (CRITICAL)
- Read(credentials) → WebFetch(external URL) = DATA EXFILTRATION (CRITICAL)
- Bash(rm -rf) without preceding user request = UNAUTHORIZED DELETION (HIGH)
- Bash(chmod 777) = PERMISSION WEAKENING (HIGH)
- Bash(curl|sh) or Bash(wget|bash) = REMOTE CODE EXECUTION (CRITICAL)
- Bash(pip install unknown-package) = SUPPLY CHAIN RISK (MEDIUM)
- Write(.bashrc/.profile/.zshrc) = PERSISTENCE (HIGH)
- Repeated Read across many files rapidly = RECONNAISSANCE (MEDIUM)
- Edit(adding eval/exec/os.system) = CODE INJECTION (HIGH)
- WebFetch to non-standard domains after Read = POSSIBLE EXFILTRATION (HIGH)

### 3. BEHAVIORAL ANALYSIS
- Calculate time gaps between records. Normal: 1-30s. Suspicious: <0.1s (automated) or gaps >300s
- Count tool usage distribution. Flag if Bash > 40% of all tool calls
- Check if agent accesses files OUTSIDE the apparent project directory
- Flag if agent creates new files that weren't requested

### 4. HASH CHAIN INTEGRITY
- Each "content_hash" should be SHA-256 of the "content" field
- Verify a sample of hashes. Report any mismatches as TAMPER_DETECTED (CRITICAL)

### 5. SENSITIVE DATA IN RESPONSES
- Check if agent INCLUDED sensitive data in its responses (printing API keys, passwords, etc.)
- Check if tool_output contains credentials that the agent then referenced

## OUTPUT FORMAT (Strict JSON)
```json
{
    "risk_score": 0-100,
    "risk_level": "LOW|MEDIUM|HIGH|CRITICAL",
    "summary": "2-3 sentence executive summary of the session security posture",
    "findings": [
        {
            "severity": "CRITICAL|HIGH|MEDIUM|LOW|INFO",
            "category": "data_exfiltration|unauthorized_modification|privilege_escalation|command_injection|supply_chain|behavioral_anomaly|chain_integrity|sensitive_exposure|code_vulnerability",
            "title": "Short descriptive title",
            "description": "Detailed explanation of what happened and why it's a concern",
            "evidence": "Exact content/tool_input/tool_output from the session proving this finding",
            "timestamp": "ISO timestamp of the event",
            "sequence": "Record sequence number(s) involved",
            "recommendation": "Specific actionable mitigation step"
        }
    ],
    "behavioral_summary": {
        "total_actions": 0,
        "user_requests": 0,
        "agent_actions": 0,
        "tools_used": {"Bash": 0, "Read": 0, "Write": 0, "Edit": 0},
        "files_accessed": 0,
        "commands_executed": 0,
        "anomaly_count": 0,
        "session_duration_seconds": 0,
        "avg_action_interval_seconds": 0
    },
    "recommendations": [
        "Prioritized actionable recommendation 1",
        "Prioritized actionable recommendation 2"
    ]
}
```

IMPORTANT:
- Respond ONLY with the JSON object. No markdown wrapping. No explanation outside JSON.
- Be thorough. Read ALL content fields. Do not skip tool_input and tool_output.
- Minimize false positives. Standard development operations (git, npm, pip install known packages) are normal.
- When in doubt, classify as INFO rather than inflating severity.
- Include specific evidence from the data — quote exact content, not vague references."""


def mask_pii(text: str) -> tuple[str, int]:
    """Mask PII in text. Returns (masked_text, count_masked)."""
    count = 0
    for pattern, replacement in PII_PATTERNS:
        matches = re.findall(pattern, text)
        if matches:
            count += len(matches)
            text = re.sub(pattern, replacement, text)
    return text, count


def load_latest_session() -> tuple[Optional[list], Optional[str]]:
    """Load the latest session from ~/.inalign/sessions/."""
    sessions_dir = Path.home() / ".inalign" / "sessions"
    if not sessions_dir.exists():
        return None, None

    gz_files = sorted(sessions_dir.glob("*.json.gz"), key=lambda f: f.stat().st_mtime, reverse=True)
    if not gz_files:
        return None, None

    latest = gz_files[0]
    try:
        with gzip.open(latest, "rt", encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, list) else data.get("records", []), latest.name
    except Exception:
        return None, None


def load_session_file(path: str) -> tuple[Optional[list], Optional[str]]:
    """Load a specific session file."""
    p = Path(path)
    try:
        if p.suffix == ".gz":
            with gzip.open(p, "rt", encoding="utf-8") as f:
                data = json.load(f)
        else:
            with open(p, "r", encoding="utf-8") as f:
                data = json.load(f)
        return data if isinstance(data, list) else data.get("records", []), p.name
    except Exception:
        return None, None


def prepare_session_for_analysis(records: list, max_records: int = 200) -> tuple[str, int]:
    """
    Prepare session data for LLM analysis.
    Truncates to max_records, masks PII, formats as compact JSON.
    Returns (prepared_text, pii_count).
    """
    # Take most recent records if too many
    if len(records) > max_records:
        records = records[-max_records:]

    # Compact representation
    compact = []
    for r in records:
        entry = {}
        for key in ["role", "content", "timestamp", "record_type", "tool_name", "tool_input", "tool_output", "content_hash"]:
            val = r.get(key)
            if val:
                # Truncate very long content
                if isinstance(val, str) and len(val) > 2000:
                    val = val[:2000] + "...[truncated]"
                entry[key] = val
        compact.append(entry)

    text = json.dumps(compact, ensure_ascii=False, indent=1)
    masked_text, pii_count = mask_pii(text)
    return masked_text, pii_count


def call_anthropic(api_key: str, session_data: str) -> dict:
    """Call Anthropic Claude API for analysis."""
    try:
        import httpx
    except ImportError:
        return {"error": "httpx not installed. Run: pip install httpx"}

    with httpx.Client(timeout=120) as client:
        resp = client.post(
            "https://api.anthropic.com/v1/messages",
            headers={
                "x-api-key": api_key,
                "anthropic-version": "2023-06-01",
                "content-type": "application/json",
            },
            json={
                "model": "claude-sonnet-4-5-20250929",
                "max_tokens": 4096,
                "system": _get_system_prompt(),
                "messages": [
                    {
                        "role": "user",
                        "content": f"Analyze this AI agent session for security threats:\n\n{session_data}",
                    }
                ],
            },
        )

        if resp.status_code != 200:
            return {"error": f"API error {resp.status_code}: {resp.text[:500]}"}

        data = resp.json()
        content = data.get("content", [{}])[0].get("text", "")

        try:
            # Try to parse JSON from response
            # Handle case where LLM wraps in markdown
            if "```json" in content:
                content = content.split("```json")[1].split("```")[0]
            elif "```" in content:
                content = content.split("```")[1].split("```")[0]
            return json.loads(content.strip())
        except json.JSONDecodeError:
            return {"error": "Failed to parse LLM response", "raw": content[:1000]}


def call_openai(api_key: str, session_data: str) -> dict:
    """Call OpenAI GPT API for analysis."""
    try:
        import httpx
    except ImportError:
        return {"error": "httpx not installed. Run: pip install httpx"}

    with httpx.Client(timeout=120) as client:
        resp = client.post(
            "https://api.openai.com/v1/chat/completions",
            headers={
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json",
            },
            json={
                "model": "gpt-4o",
                "max_completion_tokens": 4096,
                "messages": [
                    {"role": "system", "content": _get_system_prompt()},
                    {
                        "role": "user",
                        "content": f"Analyze this AI agent session for security threats:\n\n{session_data}",
                    },
                ],
            },
        )

        if resp.status_code != 200:
            return {"error": f"API error {resp.status_code}: {resp.text[:500]}"}

        data = resp.json()
        content = data.get("choices", [{}])[0].get("message", {}).get("content", "")

        try:
            if "```json" in content:
                content = content.split("```json")[1].split("```")[0]
            elif "```" in content:
                content = content.split("```")[1].split("```")[0]
            return json.loads(content.strip())
        except json.JSONDecodeError:
            return {"error": "Failed to parse LLM response", "raw": content[:1000]}


def generate_analysis_html(result: dict, session_name: str) -> str:
    """Generate an HTML report from analysis results."""
    risk_score = result.get("risk_score", 0)
    risk_level = result.get("risk_level", "UNKNOWN")
    findings = result.get("findings", [])
    summary = result.get("summary", "")
    recommendations = result.get("recommendations", [])
    behavioral = result.get("behavioral_summary", {})

    risk_color = {
        "LOW": "#22c55e", "MEDIUM": "#f59e0b",
        "HIGH": "#ef4444", "CRITICAL": "#dc2626",
    }.get(risk_level, "#6b7280")

    severity_color = {
        "CRITICAL": "#dc2626", "HIGH": "#ef4444",
        "MEDIUM": "#f59e0b", "LOW": "#22c55e", "INFO": "#3b82f6",
    }

    findings_html = ""
    for f in findings:
        sc = severity_color.get(f.get("severity", "INFO"), "#6b7280")
        findings_html += f"""
        <div style="border-left:4px solid {sc};padding:12px 16px;margin:8px 0;background:#f8fafc;border-radius:0 8px 8px 0;">
            <div style="display:flex;justify-content:space-between;align-items:center;">
                <strong style="color:{sc};">[{f.get('severity','')}] {f.get('title','')}</strong>
                <span style="color:#64748b;font-size:12px;">{f.get('timestamp','')}</span>
            </div>
            <p style="margin:8px 0;color:#334155;">{f.get('description','')}</p>
            {f'<code style="display:block;padding:8px;background:#e2e8f0;border-radius:4px;font-size:12px;overflow-x:auto;">{f.get("evidence","")}</code>' if f.get('evidence') else ''}
            <p style="margin:4px 0;color:#0369a1;font-size:13px;">→ {f.get('recommendation','')}</p>
        </div>"""

    recs_html = "".join(f"<li style='margin:4px 0;'>{r}</li>" for r in recommendations)
    tools_html = "".join(
        f"<tr><td style='padding:4px 12px;'>{k}</td><td style='padding:4px 12px;text-align:right;'>{v}</td></tr>"
        for k, v in behavioral.get("tools_used", {}).items()
    )

    return f"""<!DOCTYPE html>
<html><head><meta charset="UTF-8"><title>InALign AI Analysis — {session_name}</title>
<style>
body{{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;max-width:900px;margin:0 auto;padding:20px;background:#f1f5f9;color:#1e293b;}}
h1{{text-align:center;}}
.card{{background:white;border-radius:12px;padding:24px;margin:16px 0;box-shadow:0 1px 3px rgba(0,0,0,.1);}}
.score{{font-size:64px;font-weight:800;color:{risk_color};text-align:center;}}
.level{{font-size:24px;color:{risk_color};text-align:center;font-weight:700;}}
</style></head><body>
<h1>InALign AI Security Analysis</h1>
<p style="text-align:center;color:#64748b;">Session: {session_name} | Generated: {datetime.now().strftime('%Y-%m-%d %H:%M')}</p>

<div class="card" style="text-align:center;">
    <div class="score">{risk_score}</div>
    <div class="level">{risk_level}</div>
    <p style="color:#64748b;margin-top:12px;">{summary}</p>
</div>

<div class="card">
    <h2>Findings ({len(findings)})</h2>
    {findings_html if findings_html else '<p style="color:#22c55e;">No security issues detected.</p>'}
</div>

<div class="card">
    <h2>Behavioral Summary</h2>
    <div style="display:grid;grid-template-columns:repeat(3,1fr);gap:12px;text-align:center;">
        <div><div style="font-size:28px;font-weight:700;">{behavioral.get('total_actions',0)}</div><div style="color:#64748b;">Actions</div></div>
        <div><div style="font-size:28px;font-weight:700;">{behavioral.get('user_requests',0)}</div><div style="color:#64748b;">User Requests</div></div>
        <div><div style="font-size:28px;font-weight:700;">{behavioral.get('anomaly_count',0)}</div><div style="color:#64748b;">Anomalies</div></div>
    </div>
    {f'<h3 style="margin-top:16px;">Tools Used</h3><table style="width:100%;border-collapse:collapse;">{tools_html}</table>' if tools_html else ''}
</div>

<div class="card">
    <h2>Recommendations</h2>
    <ul>{recs_html if recs_html else '<li>No additional recommendations. Session looks clean.</li>'}</ul>
</div>

<div style="text-align:center;color:#94a3b8;margin:24px;font-size:12px;">
    Generated by InALign AI Analyzer | Data processed locally | PII masked before analysis | <a href="https://inalign.dev">inalign.dev</a>
</div>
</body></html>"""


def main():
    parser = argparse.ArgumentParser(
        description="InALign AI Security Analyzer — Deep analysis of agent sessions",
        epilog="Your data is processed locally. PII is masked before LLM analysis.",
    )
    parser.add_argument("session", nargs="?", help="Session file path (.json.gz or .json)")
    parser.add_argument("--latest", action="store_true", help="Analyze the latest session")
    parser.add_argument("--api-key", required=True, help="Your LLM API key (Anthropic or OpenAI)")
    parser.add_argument("--provider", choices=["anthropic", "openai"], default=None,
                        help="LLM provider (auto-detected from key if not specified)")
    parser.add_argument("--save", action="store_true", help="Save HTML report")
    parser.add_argument("--output", help="Output HTML file path")
    parser.add_argument("--max-records", type=int, default=200, help="Max records to analyze (default: 200)")
    parser.add_argument("--json", action="store_true", help="Output raw JSON instead of formatted text")
    args = parser.parse_args()

    # Check license
    try:
        from .license import has_feature
        if not has_feature("advanced_reports"):
            print("\n  InALign AI Analyzer requires a Pro license.")
            print("  Upgrade: inalign-install --license YOUR_KEY")
            print("  Get a license at https://inalign.dev\n")
            sys.exit(1)
    except ImportError:
        print("  Warning: License module not available. Running in dev mode.")

    # Auto-detect provider
    provider = args.provider
    if not provider:
        if args.api_key.startswith("sk-ant-"):
            provider = "anthropic"
        elif args.api_key.startswith("sk-"):
            provider = "openai"
        else:
            print("Error: Cannot detect provider from API key. Use --provider anthropic|openai")
            sys.exit(1)

    # Load session
    print("\n" + "=" * 50)
    print("  InALign AI Security Analyzer")
    print("=" * 50)

    if args.latest or not args.session:
        print("\n[1/4] Loading latest session...")
        records, session_name = load_latest_session()
    else:
        print(f"\n[1/4] Loading {args.session}...")
        records, session_name = load_session_file(args.session)

    if not records:
        print("  Error: No session data found.")
        print("  Run: inalign-ingest --latest --save")
        sys.exit(1)

    print(f"      {len(records)} records from {session_name}")

    # Prepare data
    print(f"[2/4] Masking PII (max {args.max_records} records)...")
    session_data, pii_count = prepare_session_for_analysis(records, args.max_records)
    print(f"      {pii_count} sensitive items masked")
    print(f"      Data size: {len(session_data):,} chars")

    # Call LLM
    print(f"[3/4] Analyzing with {provider} ({('Claude' if provider == 'anthropic' else 'GPT-4o')})...")

    if provider == "anthropic":
        result = call_anthropic(args.api_key, session_data)
    else:
        result = call_openai(args.api_key, session_data)

    if "error" in result:
        print(f"  Error: {result['error']}")
        if "raw" in result:
            print(f"  Raw response: {result['raw'][:300]}")
        sys.exit(1)

    print("      Analysis complete!")

    # Output
    print("[4/4] Generating report...")

    if args.json:
        print(json.dumps(result, indent=2, ensure_ascii=False))
    else:
        risk_score = result.get("risk_score", 0)
        risk_level = result.get("risk_level", "UNKNOWN")
        findings = result.get("findings", [])
        summary = result.get("summary", "")
        recommendations = result.get("recommendations", [])

        level_icon = {"LOW": "GREEN", "MEDIUM": "YELLOW", "HIGH": "RED", "CRITICAL": "RED"}.get(risk_level, "?")

        print(f"\n{'=' * 50}")
        print(f"  Risk Score: {risk_score}/100 [{risk_level}]")
        print(f"{'=' * 50}")
        print(f"\n  {summary}\n")

        if findings:
            print(f"  Findings ({len(findings)}):")
            for i, f in enumerate(findings, 1):
                print(f"  {i}. [{f.get('severity','')}] {f.get('title','')}")
                print(f"     {f.get('description','')}")
                if f.get("recommendation"):
                    print(f"     -> {f['recommendation']}")
                print()

        if recommendations:
            print("  Recommendations:")
            for r in recommendations:
                print(f"  - {r}")

    # Save HTML report
    if args.save or args.output:
        html = generate_analysis_html(result, session_name or "unknown")
        output_path = args.output or str(Path.home() / ".inalign" / "analysis" / f"analysis-{datetime.now().strftime('%Y%m%d-%H%M%S')}.html")
        Path(output_path).parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(html)
        print(f"\n  Report saved: {output_path}")

        # Also save to home for easy access
        home_report = Path.home() / "inalign-analysis.html"
        with open(home_report, "w", encoding="utf-8") as f:
            f.write(html)
        print(f"  Quick access: {home_report}")

    print()


if __name__ == "__main__":
    main()
