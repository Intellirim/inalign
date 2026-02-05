"""
In-A-Lign CLI.

Command-line interface for running the In-A-Lign proxy.

Usage:
    inalign start          Start the proxy server
    inalign start --port 9000  Start on custom port
    inalign status         Check proxy status
    inalign stats          Show usage statistics
"""

import argparse
import os
import sys
import requests


def cmd_start(args):
    """Start the proxy server."""
    from inalign.proxy.server import main as start_server

    # Set environment variables from args
    os.environ["INALIGN_PROXY_PORT"] = str(args.port)
    os.environ["INALIGN_PROXY_HOST"] = args.host

    # Build argv for the server
    server_args = ["--port", str(args.port), "--host", args.host]
    if args.no_security:
        server_args.append("--no-security")
    if args.no_optimizer:
        server_args.append("--no-optimizer")
    if args.no_cache:
        server_args.append("--no-cache")

    sys.argv = ["inalign.proxy.server"] + server_args
    start_server()


def cmd_status(args):
    """Check proxy status."""
    url = f"http://localhost:{args.port}/health"
    try:
        response = requests.get(url, timeout=2)
        if response.status_code == 200:
            data = response.json()
            print(f"""
In-A-Lign Proxy Status
======================
Status: RUNNING
URL: http://localhost:{args.port}/v1

Stats:
  Total Requests: {data['stats']['total_requests']}
  Blocked: {data['stats']['blocked_requests']}
  Forwarded: {data['stats']['forwarded_requests']}
  Cached: {data['stats'].get('cached_responses', 0)}
  Tokens Saved: {data['stats'].get('tokens_saved', 0)}
""")
        else:
            print(f"Proxy returned status {response.status_code}")
    except requests.exceptions.ConnectionError:
        print(f"""
In-A-Lign Proxy Status
======================
Status: NOT RUNNING

Start with: inalign start
""")


def cmd_stats(args):
    """Show detailed statistics."""
    url = f"http://localhost:{args.port}/stats"
    try:
        response = requests.get(url, timeout=2)
        if response.status_code == 200:
            stats = response.json()

            # Calculate savings
            tokens_saved = stats.get('tokens_saved', 0)
            # Rough estimate: $0.01 per 1000 tokens average
            cost_saved = tokens_saved * 0.00001

            print(f"""
In-A-Lign Usage Statistics
==========================

Requests:
  Total:     {stats['total_requests']}
  Forwarded: {stats['forwarded_requests']}
  Blocked:   {stats['blocked_requests']}
  Cached:    {stats.get('cached_responses', 0)}

Optimization:
  Tokens Saved: {tokens_saved:,}
  Estimated Cost Saved: ${cost_saved:.4f}
  Optimizations Applied: {stats.get('optimizations_applied', 0)}

Security:
  Attacks Blocked: {stats['blocked_requests']}
  Block Rate: {(stats['blocked_requests'] / max(stats['total_requests'], 1) * 100):.1f}%
""")
        else:
            print("Failed to get stats")
    except requests.exceptions.ConnectionError:
        print("Proxy not running. Start with: inalign start")


def cmd_setup(args):
    """Show setup instructions."""
    port = args.port
    print(f"""
In-A-Lign Setup Instructions
============================

1. Start the proxy:
   $ inalign start

2. Configure your AI tool:

   [Claude Code]
   $ export ANTHROPIC_BASE_URL=http://localhost:{port}
   $ claude

   [Cursor]
   Settings > Models > OpenAI API Base URL
   Enter: http://localhost:{port}/v1

   [Python OpenAI SDK]
   import openai
   openai.api_base = "http://localhost:{port}/v1"

   [Python Anthropic SDK]
   import anthropic
   client = anthropic.Anthropic(base_url="http://localhost:{port}")

3. Use your AI tool normally - In-A-Lign works transparently!

Features:
  - Security: Blocks prompt injection attacks automatically
  - Optimization: Reduces tokens and routes to optimal models
  - Caching: Avoids redundant API calls

Dashboard: http://localhost:{port}/stats
""")


def main():
    """Main CLI entry point."""
    parser = argparse.ArgumentParser(
        prog="inalign",
        description="In-A-Lign: AI Security + Efficiency Proxy",
    )
    parser.add_argument("--version", action="version", version="In-A-Lign 0.1.0")

    subparsers = parser.add_subparsers(dest="command", help="Commands")

    # start command
    start_parser = subparsers.add_parser("start", help="Start the proxy server")
    start_parser.add_argument("--port", type=int, default=8080, help="Port to listen on")
    start_parser.add_argument("--host", default="0.0.0.0", help="Host to bind to")
    start_parser.add_argument("--no-security", action="store_true", help="Disable security")
    start_parser.add_argument("--no-optimizer", action="store_true", help="Disable optimizer")
    start_parser.add_argument("--no-cache", action="store_true", help="Disable caching")

    # status command
    status_parser = subparsers.add_parser("status", help="Check proxy status")
    status_parser.add_argument("--port", type=int, default=8080, help="Proxy port")

    # stats command
    stats_parser = subparsers.add_parser("stats", help="Show usage statistics")
    stats_parser.add_argument("--port", type=int, default=8080, help="Proxy port")

    # setup command
    setup_parser = subparsers.add_parser("setup", help="Show setup instructions")
    setup_parser.add_argument("--port", type=int, default=8080, help="Proxy port")

    args = parser.parse_args()

    if args.command == "start":
        cmd_start(args)
    elif args.command == "status":
        cmd_status(args)
    elif args.command == "stats":
        cmd_stats(args)
    elif args.command == "setup":
        cmd_setup(args)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
