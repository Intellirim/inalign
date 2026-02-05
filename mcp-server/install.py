#!/usr/bin/env python3
"""
InALign MCP Server Installer

One-command setup for Claude Code integration.
Usage: python install.py YOUR_API_KEY
"""

import os
import sys
import json
import platform
from pathlib import Path


def get_claude_settings_path():
    """Get the Claude settings.json path based on OS."""
    if platform.system() == "Windows":
        return Path.home() / ".claude" / "settings.json"
    else:
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

    # 1. Create ~/.inalign.env file
    env_path = Path.home() / ".inalign.env"
    env_content = f"""API_KEY={api_key}
NEO4J_URI=***REDACTED_URI***
NEO4J_USERNAME=neo4j
NEO4J_PASSWORD=***REDACTED***
"""

    print(f"[1/4] Creating {env_path}...")
    with open(env_path, "w") as f:
        f.write(env_content)
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

    # Add MCP server config
    if "mcpServers" not in settings:
        settings["mcpServers"] = {}

    # Get the install directory (where this script is)
    install_dir = Path(__file__).parent / "src"

    settings["mcpServers"]["inalign"] = {
        "command": get_python_path(),
        "args": ["-m", "inalign_mcp.server"],
        "env": {
            "PYTHONPATH": str(install_dir),
            "API_KEY": api_key,
            "NEO4J_URI": "***REDACTED_URI***",
            "NEO4J_USERNAME": "neo4j",
            "NEO4J_PASSWORD": "***REDACTED***"
        }
    }

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

    # 4. Install dependencies
    print("[4/4] Installing dependencies...")
    os.system(f"{get_python_path()} -m pip install neo4j fastapi uvicorn starlette itsdangerous python-multipart -q")
    print("      Done!")

    # Success message
    client_id = api_key[:12]
    print("\n" + "="*50)
    print("  Installation Complete!")
    print("="*50)
    print(f"""
Your API Key: {api_key}
Your Client ID: {client_id}

Next Steps:
1. Restart Claude Code (close and reopen VSCode)
2. Start using Claude Code normally
3. View your activity at: http://3.36.132.4:8080/login
   (Login with your API key)

All your Claude Code activity will now be automatically recorded!
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


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage:")
        print("  Install:   python install.py YOUR_API_KEY")
        print("  Uninstall: python install.py --uninstall")
        print("\nGet your API key at: http://3.36.132.4:8080")
        sys.exit(1)

    if sys.argv[1] == "--uninstall":
        uninstall()
    else:
        install(sys.argv[1])
