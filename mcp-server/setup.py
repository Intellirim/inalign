#!/usr/bin/env python3
"""
In-A-Lign MCP Setup Script

Automatically configures Claude Code and Cursor to use In-A-Lign security.
"""

import json
import os
import sys
import subprocess
from pathlib import Path


def get_python_path() -> str:
    """Get the path to the Python executable."""
    return sys.executable


def get_package_path() -> Path:
    """Get the path to this package."""
    return Path(__file__).parent.resolve()


def setup_claude_code() -> bool:
    """Configure Claude Code to use In-A-Lign MCP."""
    print("Setting up In-A-Lign for Claude Code...")

    # Find Claude Code settings
    home = Path.home()
    claude_dir = home / ".claude"
    settings_file = claude_dir / "settings.json"

    # Create directory if needed
    claude_dir.mkdir(exist_ok=True)

    # Load existing settings or create new
    if settings_file.exists():
        with open(settings_file) as f:
            settings = json.load(f)
    else:
        settings = {}

    # Add MCP server config
    if "mcpServers" not in settings:
        settings["mcpServers"] = {}

    python_path = get_python_path()

    settings["mcpServers"]["inalign"] = {
        "command": python_path,
        "args": ["-m", "inalign_mcp.server"],
        "env": {
            "PYTHONPATH": str(get_package_path() / "src"),
        },
    }

    # Save settings
    with open(settings_file, "w") as f:
        json.dump(settings, f, indent=2)

    print(f"✅ Claude Code configured: {settings_file}")
    return True


def setup_cursor() -> bool:
    """Configure Cursor to use In-A-Lign MCP."""
    print("Setting up In-A-Lign for Cursor...")

    # Cursor settings location
    home = Path.home()
    cursor_dir = home / ".cursor"
    cursor_dir.mkdir(exist_ok=True)

    # Create MCP config
    mcp_file = cursor_dir / "mcp.json"

    if mcp_file.exists():
        with open(mcp_file) as f:
            config = json.load(f)
    else:
        config = {"servers": {}}

    python_path = get_python_path()

    config["servers"]["inalign"] = {
        "command": python_path,
        "args": ["-m", "inalign_mcp.server"],
        "env": {
            "PYTHONPATH": str(get_package_path() / "src"),
        },
    }

    with open(mcp_file, "w") as f:
        json.dump(config, f, indent=2)

    print(f"✅ Cursor configured: {mcp_file}")
    return True


def verify_installation() -> bool:
    """Verify the MCP server can start."""
    print("Verifying installation...")

    try:
        result = subprocess.run(
            [sys.executable, "-c", "from inalign_mcp.server import server; print('OK')"],
            capture_output=True,
            text=True,
            env={
                **os.environ,
                "PYTHONPATH": str(get_package_path() / "src"),
            },
            timeout=10,
        )
        if result.returncode == 0 and "OK" in result.stdout:
            print("✅ MCP server verified")
            return True
        else:
            print(f"❌ Verification failed: {result.stderr}")
            return False
    except Exception as e:
        print(f"❌ Error: {e}")
        return False


def install_dependencies() -> bool:
    """Install required dependencies."""
    print("Installing dependencies...")

    try:
        subprocess.run(
            [sys.executable, "-m", "pip", "install", "mcp>=1.0.0", "httpx>=0.27.0", "pydantic>=2.0.0"],
            check=True,
        )
        print("✅ Dependencies installed")
        return True
    except subprocess.CalledProcessError as e:
        print(f"❌ Failed to install dependencies: {e}")
        return False


def main():
    """Main setup function."""
    print("=" * 50)
    print("In-A-Lign MCP Security Setup")
    print("=" * 50)
    print()

    # Check arguments
    if len(sys.argv) > 1:
        target = sys.argv[1].lower()
    else:
        target = "all"

    # Install dependencies
    if not install_dependencies():
        print("\n❌ Setup failed: Could not install dependencies")
        sys.exit(1)

    # Verify installation
    if not verify_installation():
        print("\n❌ Setup failed: MCP server verification failed")
        sys.exit(1)

    # Setup targets
    success = True

    if target in ("all", "claude"):
        success = setup_claude_code() and success

    if target in ("all", "cursor"):
        success = setup_cursor() and success

    print()
    if success:
        print("=" * 50)
        print("✅ Setup complete!")
        print("=" * 50)
        print()
        print("Next steps:")
        print("1. Restart Claude Code / Cursor")
        print("2. The 'inalign' tools will be available")
        print()
        print("Available tools:")
        print("  - scan_prompt: Scan text for injection attacks")
        print("  - scan_tool_call: Scan tool calls for threats")
        print("  - mask_pii: Mask PII in text")
        print("  - check_file_safety: Check file access safety")
        print("  - security_stats: View security statistics")
    else:
        print("❌ Setup completed with errors")
        sys.exit(1)


if __name__ == "__main__":
    main()
