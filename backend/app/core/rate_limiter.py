"""
Redis-based sliding window rate limiter for FastAPI.
"""

import logging
import time
from typing import Annotated, Optional

from fastapi import Depends, HTTPException, Request, status
from redis.asyncio import Redis

from app.config import get_settings
from app.dependencies import get_redis

logger = logging.getLogger("agentshield.rate_limiter")


class RateLimiter:
    """Sliding-window rate limiter backed by Redis sorted sets."""

    def __init__(self, max_requests: Optional[int] = None, window_seconds: int = 60):
        self.max_requests = max_requests
        self.window_seconds = window_seconds

    async def __call__(
        self,
        request: Request,
        redis: Annotated[Redis, Depends(get_redis)],
    ) -> None:
        settings = get_settings()
        max_req = self.max_requests or settings.rate_limit_per_minute

        # Identify caller by API key header or IP
        api_key = request.headers.get("x-api-key", "")
        identifier = api_key[:16] if api_key else (request.client.host if request.client else "unknown")
        key = f"rl:{identifier}:{request.url.path}"

        now = time.time()
        window_start = now - self.window_seconds

        pipe = redis.pipeline(transaction=True)
        pipe.zremrangebyscore(key, 0, window_start)
        pipe.zadd(key, {f"{now}": now})
        pipe.zcard(key)
        pipe.expire(key, self.window_seconds + 1)
        results = await pipe.execute()

        request_count = results[2]

        # Add rate-limit headers
        request.state.rate_limit_limit = max_req
        request.state.rate_limit_remaining = max(0, max_req - request_count)

        if request_count > max_req:
            logger.warning(
                "Rate limit exceeded for %s on %s (%d/%d)",
                identifier, request.url.path, request_count, max_req,
            )
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Rate limit exceeded. Please retry later.",
                headers={
                    "Retry-After": str(self.window_seconds),
                    "X-RateLimit-Limit": str(max_req),
                    "X-RateLimit-Remaining": "0",
                },
            )


# Pre-built dependency instances
rate_limit = RateLimiter()
rate_limit_strict = RateLimiter(max_requests=20, window_seconds=60)
