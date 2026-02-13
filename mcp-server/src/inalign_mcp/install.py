#!/usr/bin/env python3
"""
InALign MCP Server Installer

One-command setup for Claude Code integration.
Usage:
  inalign-install --local           # Free, local-only
  inalign-install --license KEY     # Pro/Enterprise with license key
  inalign-install --uninstall       # Remove InALign
"""

import os
import sys
import json
import subprocess
import platform
import shutil
from pathlib import Path


def get_claude_settings_path():
    """Get the Claude settings.json path based on OS."""
    return Path.home() / ".claude" / "settings.json"


def get_python_path():
    """Get the current Python executable path."""
    return sys.executable


def install(local: bool = False, license_key: str = None):
    """Install InALign MCP server for Claude Code."""

    print("\n" + "="*50)
    print("  InALign MCP Server Installer")
    print("="*50 + "\n")

    if license_key:
        print("  Mode: PRO (license key activation)\n")
    else:
        print("  Mode: LOCAL (free, SQLite storage)\n")

    python = get_python_path()

    # 1. Ensure inalign-mcp is installed
    print("[1/6] Checking inalign-mcp package...")
    try:
        import inalign_mcp as _pkg
        print(f"      Already installed: {_pkg.__file__}")
    except ImportError:
        print("      Installing from PyPI...")
        ret = subprocess.run(
            [python, "-m", "pip", "install", "inalign-mcp", "--upgrade", "-q"],
            capture_output=True, text=True,
        )
        if ret.returncode != 0:
            print(f"      ERROR: pip install failed ({ret.returncode})")
            if ret.stderr:
                print(f"      {ret.stderr.strip()[:200]}")
            sys.exit(1)
        print("      Done!")

    # 2. Create ~/.inalign directory
    print("[2/6] Creating data directories...")
    inalign_dir = Path.home() / ".inalign"
    sessions_dir = inalign_dir / "sessions"
    inalign_dir.mkdir(parents=True, exist_ok=True)
    sessions_dir.mkdir(parents=True, exist_ok=True)
    print(f"      {inalign_dir}")
    print(f"      {sessions_dir}")

    # 3. Activate license (if provided)
    if license_key:
        print("[3/6] Activating license key...")
        try:
            from inalign_mcp.license import activate_license, get_license_info
            result = activate_license(license_key)
            if result["success"]:
                info = get_license_info()
                print(f"      Plan: {info['plan'].upper()}")
                print(f"      Features: {len(info['features'])} unlocked")
            else:
                print(f"      Warning: {result.get('error', 'Activation failed')}")
                print("      Continuing with free plan. You can retry later.")
        except Exception as e:
            print(f"      Warning: License activation failed ({e})")
            print("      Continuing with free plan.")
    else:
        print("[3/6] License: Free plan (upgrade anytime at inalign.dev)")

    # 4. Update Claude settings.json (MCP server + auto-report hook)
    settings_path = get_claude_settings_path()
    settings_path.parent.mkdir(parents=True, exist_ok=True)

    print(f"[4/6] Updating {settings_path}...")

    # Load existing settings or create new
    if settings_path.exists():
        with open(settings_path) as f:
            settings = json.load(f)
    else:
        settings = {}

    if "mcpServers" not in settings:
        settings["mcpServers"] = {}

    # MCP server config (no API key needed, everything is local)
    mcp_config = {
        "command": python,
        "args": ["-m", "inalign_mcp.server"],
    }

    settings["mcpServers"]["inalign"] = mcp_config

    # Add session-end hook for automatic report generation
    if "hooks" not in settings:
        settings["hooks"] = {}
    if "Stop" not in settings["hooks"]:
        settings["hooks"]["Stop"] = []

    # Check if inalign hook already exists
    hook_exists = any(
        "inalign-ingest" in str(h.get("command", ""))
        for hook_group in settings["hooks"].get("Stop", [])
        for h in hook_group.get("hooks", [])
    )

    if not hook_exists:
        settings["hooks"]["Stop"].append({
            "matcher": "",
            "hooks": [{
                "type": "command",
                "command": f"{python} -m inalign_mcp.session_ingest --latest --save"
            }]
        })

    with open(settings_path, "w") as f:
        json.dump(settings, f, indent=2)
    print("      Done!")

    # 5. Create CLAUDE.md template
    claude_md_path = Path.home() / "CLAUDE.md"

    print(f"[5/6] Creating {claude_md_path}...")

    claude_md_content = """# Claude Code Instructions

## InALign Integration

IMPORTANT: At the start of EVERY conversation, call the `mcp__inalign__record_user_command` tool to record the user's request. This is required for audit logging.

Example:
- User says: "Help me fix this bug"
- First action: Call record_user_command with the user's request
- Then: Proceed with the task
"""

    if not claude_md_path.exists():
        with open(claude_md_path, "w") as f:
            f.write(claude_md_content)
        print("      Done!")
    else:
        print("      CLAUDE.md already exists, skipping...")

    # 6. Verify MCP server can start
    print("[6/6] Verifying MCP server...")
    test = subprocess.run(
        [python, "-c", "from inalign_mcp.server import server; print('OK')"],
        capture_output=True, text=True, timeout=10,
    )
    if test.returncode == 0 and "OK" in test.stdout:
        print("      Server verified!")
    else:
        print("      Warning: Server import check failed, but may still work at runtime")

    # Success message
    print("\n" + "="*50)
    print("  Installation Complete!")
    print("="*50)

    if license_key:
        print(f"""
Mode: PRO (license activated)
Database: {inalign_dir / 'provenance.db'}
License: {inalign_dir / 'license.json'}

Your data stays 100% on your machine. No telemetry.

Next Steps:
1. Restart Claude Code (close and reopen terminal/VSCode)
2. Start using Claude Code normally
3. All actions recorded with SHA-256 hash chains
4. Pro features unlocked (advanced reports, custom policies, etc.)

Auto-report: Session reports auto-saved to ~/.inalign/sessions/
Manual: inalign-ingest --latest --save
""")
    else:
        print(f"""
Mode: FREE (local SQLite storage)
Database: {inalign_dir / 'provenance.db'}

Your data stays 100% on your machine. No telemetry.

Next Steps:
1. Restart Claude Code (close and reopen terminal/VSCode)
2. Start using Claude Code normally
3. All actions recorded with SHA-256 hash chains

Auto-report: Session reports auto-saved to ~/.inalign/sessions/
Manual: inalign-ingest --latest --save

Upgrade: inalign-install --license YOUR_KEY
Get a license at https://inalign.dev
""")


def activate(license_key: str):
    """Activate or update a license key without full reinstall."""
    print("\n" + "="*50)
    print("  InALign License Activation")
    print("="*50 + "\n")

    try:
        from inalign_mcp.license import activate_license, get_license_info
        result = activate_license(license_key)
        if result["success"]:
            info = get_license_info()
            print(f"  Plan: {info['plan'].upper()}")
            print(f"  Status: {info['status']}")
            print(f"  Features: {', '.join(info['features'])}")
            print(f"\n  License saved to ~/.inalign/license.json")
            print(f"  Restart Claude Code to apply changes.")
        else:
            print(f"  Error: {result.get('error', 'Activation failed')}")
            sys.exit(1)
    except Exception as e:
        print(f"  Error: {e}")
        sys.exit(1)


def show_license():
    """Show current license status."""
    try:
        from inalign_mcp.license import get_license_info
        info = get_license_info()
        print(f"\n  Plan: {info['plan'].upper()}")
        print(f"  Status: {info['status']}")
        if info.get('license_prefix'):
            print(f"  License: {info['license_prefix']}")
        print(f"  Features: {', '.join(info['features'])}")
        limits = info.get('limits', {})
        print(f"  Actions/month: {limits.get('actions_per_month', '?')}")
        print(f"  Retention: {limits.get('retention_days', '?')} days")
        print(f"  Max agents: {limits.get('max_agents', '?')}")
    except Exception as e:
        print(f"  Error: {e}")


def uninstall():
    """Remove InALign configuration."""
    print("\nUninstalling InALign...")

    # Remove license
    license_path = Path.home() / ".inalign" / "license.json"
    if license_path.exists():
        license_path.unlink()
        print(f"Removed {license_path}")

    # Remove env file
    env_path = Path.home() / ".inalign.env"
    if env_path.exists():
        env_path.unlink()
        print(f"Removed {env_path}")

    # Remove from Claude settings
    settings_path = get_claude_settings_path()
    if settings_path.exists():
        with open(settings_path) as f:
            settings = json.load(f)

        if "mcpServers" in settings and "inalign" in settings["mcpServers"]:
            del settings["mcpServers"]["inalign"]
            with open(settings_path, "w") as f:
                json.dump(settings, f, indent=2)
            print(f"Removed inalign from {settings_path}")

    print("Uninstall complete!")
    print("Note: Audit data preserved at ~/.inalign/ (delete manually if needed)")


def main():
    """CLI entry point."""
    if len(sys.argv) < 2:
        print("Usage:")
        print("  Install:     inalign-install --local")
        print("  With license: inalign-install --license YOUR_KEY")
        print("  Activate:    inalign-install --activate YOUR_KEY")
        print("  Status:      inalign-install --status")
        print("  Uninstall:   inalign-install --uninstall")
        sys.exit(1)

    arg = sys.argv[1]

    if arg == "--uninstall":
        uninstall()
    elif arg == "--local":
        install(local=True)
    elif arg == "--license":
        if len(sys.argv) < 3:
            print("Error: License key required. Usage: inalign-install --license YOUR_KEY")
            sys.exit(1)
        install(license_key=sys.argv[2])
    elif arg == "--activate":
        if len(sys.argv) < 3:
            print("Error: License key required. Usage: inalign-install --activate YOUR_KEY")
            sys.exit(1)
        activate(sys.argv[2])
    elif arg == "--status":
        show_license()
    else:
        # Backward compatibility: treat as API key
        install(license_key=arg)


if __name__ == "__main__":
    main()
