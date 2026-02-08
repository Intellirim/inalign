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


def install(api_key: str):
    """Install InALign MCP server for Claude Code."""

    print("\n" + "="*50)
    print("  InALign MCP Server Installer")
    print("="*50 + "\n")

    # Validate API key format
    if not api_key.startswith("ial_"):
        print("Error: Invalid API key format. Should start with 'ial_'")
        sys.exit(1)

    python = get_python_path()

    # 1. Ensure inalign-mcp is installed
    print("[1/5] Checking inalign-mcp package...")
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

    # 2. Create ~/.inalign.env file (API URL for server proxy — no DB credentials needed)
    env_path = Path.home() / ".inalign.env"
    api_url = os.getenv("INALIGN_API_URL", "https://api.inalign.ai")
    env_content = f"""API_KEY={api_key}
API_URL={api_url}
"""

    print(f"[2/5] Creating {env_path}...")
    with open(env_path, "w") as f:
        f.write(env_content)
    print("      Done!")

    # 3. Update Claude settings.json
    settings_path = get_claude_settings_path()
    settings_path.parent.mkdir(parents=True, exist_ok=True)

    print(f"[3/5] Updating {settings_path}...")

    # Load existing settings or create new
    if settings_path.exists():
        with open(settings_path) as f:
            settings = json.load(f)
    else:
        settings = {}

    if "mcpServers" not in settings:
        settings["mcpServers"] = {}

    # Use pip-installed package directly (no PYTHONPATH needed)
    settings["mcpServers"]["inalign"] = {
        "command": python,
        "args": ["-m", "inalign_mcp.server"],
        "env": {
            "API_KEY": api_key,
        }
    }

    with open(settings_path, "w") as f:
        json.dump(settings, f, indent=2)
    print("      Done!")

    # 4. Create CLAUDE.md template
    claude_md_path = Path.home() / "CLAUDE.md"

    print(f"[4/5] Creating {claude_md_path}...")

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

    # 5. Verify MCP server can start
    print("[5/5] Verifying MCP server...")
    test = subprocess.run(
        [python, "-c", "from inalign_mcp.server import server; print('OK')"],
        capture_output=True, text=True, timeout=10,
        env={**os.environ, "API_KEY": api_key},
    )
    if test.returncode == 0 and "OK" in test.stdout:
        print("      Server verified!")
    else:
        print("      Warning: Server import check failed, but may still work at runtime")

    # Success message
    client_id = api_key[:12]
    print("\n" + "="*50)
    print("  Installation Complete!")
    print("="*50)
    print(f"""
Your API Key: {api_key}
Your Client ID: {client_id}

Next Steps:
1. Restart Claude Code (close and reopen terminal/VSCode)
2. Start using Claude Code normally
3. View your activity at: https://api.inalign.ai/login
   (Login with your API key)

All your Claude Code activity will now be automatically recorded
and governed by InALign!
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
        print("  Install:   inalign-install YOUR_API_KEY")
        print("             python -m inalign_mcp.install YOUR_API_KEY")
        print("  Uninstall: inalign-install --uninstall")
        print("\nGet your API key at: https://api.inalign.ai")
        sys.exit(1)

    if sys.argv[1] == "--uninstall":
        uninstall()
    else:
        install(sys.argv[1])


if __name__ == "__main__":
    main()
