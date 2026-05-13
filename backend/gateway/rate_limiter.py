"""
gateway/rate_limiter.py — Token-bucket rate limiting middleware

Supports:
- Per-user rate limiting
- Per-API-key rate limiting
- Configurable windows and limits
- In-memory store (with Redis extension path)
"""
import time
from collections import defaultdict
from typing import Dict, Tuple, Optional
from threading import Lock

from fastapi import HTTPException, Request
from loguru import logger


class TokenBucket:
    """
    Token bucket rate limiter for a single identity.
    Thread-safe with per-bucket locking.
    """

    def __init__(self, capacity: int, refill_rate: float):
        """
        Args:
            capacity: max number of tokens (= max burst)
            refill_rate: tokens added per second
        """
        self.capacity = capacity
        self.refill_rate = refill_rate
        self.tokens = float(capacity)
        self.last_refill = time.monotonic()
        self._lock = Lock()

    def consume(self, tokens: int = 1) -> Tuple[bool, float]:
        """
        Try to consume tokens.

        Returns:
            (allowed, retry_after_seconds)
        """
        with self._lock:
            now = time.monotonic()
            elapsed = now - self.last_refill
            self.tokens = min(
                self.capacity,
                self.tokens + elapsed * self.refill_rate
            )
            self.last_refill = now

            if self.tokens >= tokens:
                self.tokens -= tokens
                return True, 0.0

            # Calculate retry delay
            deficit = tokens - self.tokens
            retry_after = deficit / self.refill_rate
            return False, retry_after


class RateLimiter:
    """
    Multi-tenant rate limiter using token bucket algorithm.
    """

    def __init__(
        self,
        default_requests: int = 100,
        default_window_seconds: int = 60,
    ):
        self._buckets: Dict[str, TokenBucket] = {}
        self._default_capacity = default_requests
        self._default_refill = default_requests / default_window_seconds
        self._lock = Lock()

    def _get_or_create_bucket(
        self,
        identity: str,
        capacity: Optional[int] = None,
        window: Optional[int] = None,
    ) -> TokenBucket:
        with self._lock:
            if identity not in self._buckets:
                cap = capacity or self._default_capacity
                win = window or 60
                self._buckets[identity] = TokenBucket(cap, cap / win)
            return self._buckets[identity]

    def check(
        self,
        identity: str,
        capacity: Optional[int] = None,
        window: Optional[int] = None,
    ) -> Tuple[bool, float]:
        """
        Check if a request is allowed.

        Returns:
            (allowed, retry_after_seconds)
        """
        bucket = self._get_or_create_bucket(identity, capacity, window)
        return bucket.consume()

    def get_status(self, identity: str) -> Dict:
        """Get current token count for an identity."""
        if identity not in self._buckets:
            return {"tokens": self._default_capacity, "capacity": self._default_capacity}
        bucket = self._buckets[identity]
        return {
            "tokens": round(bucket.tokens, 2),
            "capacity": bucket.capacity,
            "utilization": round(1.0 - (bucket.tokens / bucket.capacity), 3),
        }


# Global rate limiter instance
rate_limiter = RateLimiter()


async def rate_limit_middleware(request: Request, identity: str, limit: int = 100, window: int = 60):
    """
    FastAPI dependency for rate limiting.
    Raises 429 if rate limit exceeded.
    """
    allowed, retry_after = rate_limiter.check(identity, limit, window)
    if not allowed:
        logger.warning(f"Rate limit exceeded for {identity}, retry after {retry_after:.1f}s")
        raise HTTPException(
            status_code=429,
            detail={
                "error": "Rate limit exceeded",
                "retry_after_seconds": round(retry_after, 1),
            },
            headers={"Retry-After": str(int(retry_after) + 1)},
        )
