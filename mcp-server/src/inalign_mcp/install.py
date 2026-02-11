#!/usr/bin/env python3
"""
InALign MCP Server Installer

One-command setup for Claude Code integration.
Usage: python install.py YOUR_API_KEY
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


def install(api_key: str = None, local: bool = False):
    """Install InALign MCP server for Claude Code."""

    print("\n" + "="*50)
    print("  InALign MCP Server Installer")
    print("="*50 + "\n")

    if local:
        print("  Mode: LOCAL (SQLite persistent storage, no API key needed)\n")
    else:
        # Validate API key format
        if not api_key or not api_key.startswith("ial_"):
            print("Error: Invalid API key format. Should start with 'ial_'")
            print("Hint: Use --local for local-only mode (no API key needed)")
            sys.exit(1)

    python = get_python_path()

    # 1. Ensure inalign-mcp is installed
    print("[1/4] Checking inalign-mcp package...")
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

    # 2. Update Claude settings.json
    settings_path = get_claude_settings_path()
    settings_path.parent.mkdir(parents=True, exist_ok=True)

    print(f"[2/4] Updating {settings_path}...")

    # Load existing settings or create new
    if settings_path.exists():
        with open(settings_path) as f:
            settings = json.load(f)
    else:
        settings = {}

    if "mcpServers" not in settings:
        settings["mcpServers"] = {}

    # Use pip-installed package directly (no PYTHONPATH needed)
    mcp_config = {
        "command": python,
        "args": ["-m", "inalign_mcp.server"],
    }

    if not local and api_key:
        mcp_config["env"] = {"API_KEY": api_key}

        # Create ~/.inalign.env for API mode
        env_path = Path.home() / ".inalign.env"
        api_url = os.getenv("INALIGN_API_URL", "https://api.inalign.ai")
        env_content = f"API_KEY={api_key}\nAPI_URL={api_url}\n"
        with open(env_path, "w") as f:
            f.write(env_content)

    settings["mcpServers"]["inalign"] = mcp_config

    with open(settings_path, "w") as f:
        json.dump(settings, f, indent=2)
    print("      Done!")

    # 3. Create CLAUDE.md template
    claude_md_path = Path.home() / "CLAUDE.md"

    print(f"[3/4] Creating {claude_md_path}...")

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

    # 4. Verify MCP server can start
    print("[4/4] Verifying MCP server...")
    test_env = dict(os.environ)
    if api_key:
        test_env["API_KEY"] = api_key
    test = subprocess.run(
        [python, "-c", "from inalign_mcp.server import server; print('OK')"],
        capture_output=True, text=True, timeout=10,
        env=test_env,
    )
    if test.returncode == 0 and "OK" in test.stdout:
        print("      Server verified!")
    else:
        print("      Warning: Server import check failed, but may still work at runtime")

    # Success message
    print("\n" + "="*50)
    print("  Installation Complete!")
    print("="*50)

    if local:
        # Create ~/.inalign directory for SQLite storage
        inalign_dir = Path.home() / ".inalign"
        inalign_dir.mkdir(parents=True, exist_ok=True)
        print(f"      Created {inalign_dir}")

        print(f"""
Mode: LOCAL (SQLite persistent storage)
Database: {inalign_dir / 'provenance.db'}

Next Steps:
1. Restart Claude Code (close and reopen terminal/VSCode)
2. Start using Claude Code normally
3. Every agent action is recorded with SHA-256 hash chains

All audit trails are stored locally at ~/.inalign/provenance.db
and persist across sessions. No external services needed.
Use 'export_report' to generate a visual HTML audit report.

Upgrade path:
- Self-host with Neo4j for graph-based risk analysis
- Use API key for cloud-hosted governance
""")
    else:
        print(f"""
API Key: {api_key}

Next Steps:
1. Restart Claude Code (close and reopen terminal/VSCode)
2. Start using Claude Code normally
3. All agent actions are now recorded and persisted

Your audit trails are stored server-side with cryptographic
verification. Use generate_audit_report to view activity.
""")


def uninstall():
    """Remove InALign configuration."""
    print("\nUninstalling InALign...")

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


def main():
    """CLI entry point."""
    if len(sys.argv) < 2:
        print("Usage:")
        print("  Local:     inalign-install --local")
        print("  Cloud:     inalign-install YOUR_API_KEY")
        print("  Uninstall: inalign-install --uninstall")
        sys.exit(1)

    if sys.argv[1] == "--uninstall":
        uninstall()
    elif sys.argv[1] == "--local":
        install(local=True)
    else:
        install(api_key=sys.argv[1])


if __name__ == "__main__":
    main()
