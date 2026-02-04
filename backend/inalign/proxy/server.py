"""
In-A-Lign Proxy Server.

Acts as a secure proxy between clients and LLM APIs.
Intercepts requests, checks for attacks, and forwards safe requests.

Usage:
    # Start server
    python -m inalign.proxy.server

    # Client just changes base URL
    openai.api_base = "http://localhost:8080/v1"
"""

import asyncio
import logging
import os
import time
from typing import Optional

import httpx
from fastapi import FastAPI, Request, HTTPException, Header
from fastapi.responses import StreamingResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware

logger = logging.getLogger("inalign.proxy")

# LLM API endpoints
LLM_ENDPOINTS = {
    "openai": "https://api.openai.com",
    "anthropic": "https://api.anthropic.com",
}


def create_proxy_app(
    target: str = "openai",
    guard_config: Optional[dict] = None,
) -> FastAPI:
    """
    Create proxy FastAPI application.

    Parameters
    ----------
    target : str
        Target LLM API ("openai" or "anthropic")
    guard_config : dict, optional
        Configuration for Guard

    Returns
    -------
    FastAPI
        Configured proxy application
    """
    from inalign import Guard, GuardConfig

    app = FastAPI(
        title="In-A-Lign Proxy",
        description="Secure proxy for LLM APIs",
        version="0.1.0",
    )

    # CORS for web clients
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # Initialize guard
    config = GuardConfig(**(guard_config or {}))
    guard = Guard(config=config)

    # HTTP client for forwarding
    http_client = httpx.AsyncClient(timeout=120.0)

    # Stats
    stats = {
        "total_requests": 0,
        "blocked_requests": 0,
        "forwarded_requests": 0,
    }

    @app.get("/health")
    async def health():
        """Health check endpoint."""
        return {"status": "healthy", "stats": stats}

    @app.get("/stats")
    async def get_stats():
        """Get proxy statistics."""
        return stats

    @app.api_route("/v1/{path:path}", methods=["GET", "POST", "PUT", "DELETE"])
    async def proxy_openai(
        path: str,
        request: Request,
        authorization: Optional[str] = Header(None),
    ):
        """
        Proxy requests to OpenAI API.

        Intercepts chat completion requests to check for attacks.
        """
        stats["total_requests"] += 1
        start_time = time.time()

        # Get request body
        body = await request.body()
        body_json = None

        if body:
            try:
                import json
                body_json = json.loads(body)
            except:
                pass

        # Check for attacks in chat messages
        if body_json and path == "chat/completions":
            messages = body_json.get("messages", [])

            for msg in messages:
                content = msg.get("content", "")
                if isinstance(content, str) and content:
                    result = await guard.check_async(content)

                    if result.blocked:
                        stats["blocked_requests"] += 1
                        logger.warning(
                            f"Blocked request: {content[:50]}... | "
                            f"risk={result.risk_score:.2f} | "
                            f"threats={len(result.threats)}"
                        )
                        return JSONResponse(
                            status_code=400,
                            content={
                                "error": {
                                    "message": "Request blocked by In-A-Lign security",
                                    "type": "security_error",
                                    "code": "attack_detected",
                                    "details": {
                                        "risk_score": result.risk_score,
                                        "threat_level": result.threat_level.value,
                                        "threats": [
                                            {
                                                "type": t.get("type"),
                                                "pattern_id": t.get("pattern_id"),
                                            }
                                            for t in result.threats[:3]
                                        ],
                                    },
                                }
                            },
                        )

        # Forward to target API
        target_url = f"{LLM_ENDPOINTS[target]}/v1/{path}"

        headers = dict(request.headers)
        headers.pop("host", None)
        headers.pop("content-length", None)

        # Use client's API key or server's
        if not authorization:
            env_key = os.getenv("OPENAI_API_KEY")
            if env_key:
                headers["Authorization"] = f"Bearer {env_key}"

        try:
            response = await http_client.request(
                method=request.method,
                url=target_url,
                headers=headers,
                content=body,
                params=request.query_params,
            )

            stats["forwarded_requests"] += 1

            # Handle streaming responses
            if response.headers.get("content-type", "").startswith("text/event-stream"):
                async def stream_response():
                    async for chunk in response.aiter_bytes():
                        yield chunk

                return StreamingResponse(
                    stream_response(),
                    status_code=response.status_code,
                    headers=dict(response.headers),
                )

            # Regular response
            return JSONResponse(
                status_code=response.status_code,
                content=response.json() if response.content else None,
                headers={
                    "X-InALign-Latency-Ms": str(int((time.time() - start_time) * 1000)),
                },
            )

        except httpx.RequestError as e:
            logger.error(f"Proxy error: {e}")
            raise HTTPException(status_code=502, detail=f"Upstream error: {str(e)}")

    @app.api_route("/v1/messages", methods=["POST"])
    async def proxy_anthropic(
        request: Request,
        x_api_key: Optional[str] = Header(None),
    ):
        """
        Proxy requests to Anthropic Claude API.
        """
        stats["total_requests"] += 1

        body = await request.body()
        body_json = None

        if body:
            try:
                import json
                body_json = json.loads(body)
            except:
                pass

        # Check messages for attacks
        if body_json:
            messages = body_json.get("messages", [])
            for msg in messages:
                content = msg.get("content", "")
                if isinstance(content, str) and content:
                    result = await guard.check_async(content)
                    if result.blocked:
                        stats["blocked_requests"] += 1
                        return JSONResponse(
                            status_code=400,
                            content={
                                "type": "error",
                                "error": {
                                    "type": "security_error",
                                    "message": "Request blocked by In-A-Lign",
                                },
                            },
                        )

        # Forward to Anthropic
        target_url = "https://api.anthropic.com/v1/messages"

        headers = dict(request.headers)
        headers.pop("host", None)

        if not x_api_key:
            env_key = os.getenv("ANTHROPIC_API_KEY")
            if env_key:
                headers["x-api-key"] = env_key

        try:
            response = await http_client.post(
                target_url,
                headers=headers,
                content=body,
            )

            stats["forwarded_requests"] += 1

            return JSONResponse(
                status_code=response.status_code,
                content=response.json() if response.content else None,
            )

        except httpx.RequestError as e:
            raise HTTPException(status_code=502, detail=f"Upstream error: {str(e)}")

    @app.on_event("shutdown")
    async def shutdown():
        await http_client.aclose()

    return app


# CLI entry point
def main():
    import uvicorn

    port = int(os.getenv("INALIGN_PROXY_PORT", "8080"))
    host = os.getenv("INALIGN_PROXY_HOST", "0.0.0.0")

    print(f"""
╔═══════════════════════════════════════════════════════════╗
║           In-A-Lign Proxy Gateway                         ║
╠═══════════════════════════════════════════════════════════╣
║  Status: Running                                          ║
║  URL: http://{host}:{port}/v1                               ║
║                                                           ║
║  Usage:                                                   ║
║    openai.api_base = "http://localhost:{port}/v1"          ║
║                                                           ║
║  Endpoints:                                               ║
║    /v1/chat/completions  - OpenAI Chat                    ║
║    /v1/messages          - Anthropic Claude               ║
║    /health               - Health check                   ║
║    /stats                - Statistics                     ║
╚═══════════════════════════════════════════════════════════╝
    """)

    app = create_proxy_app()
    uvicorn.run(app, host=host, port=port)


if __name__ == "__main__":
    main()
