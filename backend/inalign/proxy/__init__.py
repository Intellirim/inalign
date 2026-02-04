"""
In-A-Lign Proxy Gateway.

Drop-in replacement for OpenAI/Claude API endpoints.
Just change your API base URL to use In-A-Lign protection.
"""

from inalign.proxy.server import create_proxy_app

__all__ = ["create_proxy_app"]
