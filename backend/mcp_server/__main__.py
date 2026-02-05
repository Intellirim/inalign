"""
In-A-Lign MCP Server entry point.

Run with: python -m mcp_server
"""

import asyncio
import logging

from mcp_server.server import create_server

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)


def main():
    """Run the In-A-Lign MCP server."""
    server = create_server()
    asyncio.run(server.run())


if __name__ == "__main__":
    main()
