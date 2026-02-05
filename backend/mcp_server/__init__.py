"""
In-A-Lign MCP Server.

Model Context Protocol server for AI development tools.
Provides project analysis, prompt optimization, model recommendation,
cost estimation, and security scanning capabilities.
"""

from mcp_server.server import InAlignMCPServer, create_server

__all__ = ["InAlignMCPServer", "create_server"]
