"""Per-IP In-Memory Token Bucket Rate Limiter.

Prevents denial-of-service, automated scraping, and resource exhaustion
on forensic ingestion and intelligence lookup endpoints.
"""

from __future__ import annotations

import asyncio
import time
from typing import Dict, Tuple

from fastapi import HTTPException, Request, status

from backend.app.core.config import settings


class InMemoryTokenBucketLimiter:
    """Sliding-window token bucket rate limiter indexed by client IP."""

    def __init__(self, rate_per_minute: int = 60, burst_multiplier: float = 1.5) -> None:
        self.rate_per_second: float = rate_per_minute / 60.0
        self.capacity: float = rate_per_minute * burst_multiplier
        # Map: ip -> (tokens: float, last_updated: float)
        self._buckets: Dict[str, Tuple[float, float]] = {}
        self._lock = asyncio.Lock()

    def _get_client_ip(self, request: Request) -> str:
        """Extract client IP, inspecting X-Forwarded-For if available."""
        forwarded = request.headers.get("X-Forwarded-For")
        if forwarded:
            return forwarded.split(",")[0].strip()
        if request.client and request.client.host:
            return request.client.host
        return "127.0.0.1"

    async def check(self, request: Request, cost: float = 1.0) -> None:
        """Check and consume tokens for incoming request.
        Raises HTTP 429 if rate limit is exceeded.
        """
        ip = self._get_client_ip(request)
        now = time.monotonic()

        async with self._lock:
            # Clean up old entries if dictionary exceeds 10,000 entries
            if len(self._buckets) > 10000:
                stale_cutoff = now - 3600
                self._buckets = {k: v for k, v in self._buckets.items() if v[1] > stale_cutoff}

            tokens, last_updated = self._buckets.get(ip, (self.capacity, now))
            # Replenish tokens based on elapsed time
            elapsed = now - last_updated
            tokens = min(self.capacity, tokens + elapsed * self.rate_per_second)

            if tokens < cost:
                retry_after = int((cost - tokens) / self.rate_per_second) + 1
                raise HTTPException(
                    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                    detail=f"Rate limit exceeded. Too many requests from IP {ip}. Try again in {retry_after} seconds.",
                    headers={"Retry-After": str(retry_after)},
                )

            self._buckets[ip] = (tokens - cost, now)


# Global singleton instance configured from settings
limiter = InMemoryTokenBucketLimiter(rate_per_minute=settings.RATE_LIMIT_PER_MINUTE)


async def rate_limit_guard(request: Request) -> None:
    """FastAPI dependency injecting rate-limiting verification."""
    await limiter.check(request)
