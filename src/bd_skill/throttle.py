"""
Async rate limiter for outbound HTTP requests to Black Duck.

Uses a simple "minimum interval" strategy: each call to ``acquire()`` ensures
at least ``1 / max_rps`` seconds have elapsed since the previous request.
An asyncio lock serializes concurrent callers so only one request is
dispatched at a time, preventing bursts that could trigger Black Duck's
server-side rate limits.
"""

import asyncio
import time


class RequestThrottle:
    """Token-bucket rate limiter for outbound requests to Black Duck."""

    def __init__(self, max_rps: int = 5):
        # Minimum number of seconds that must pass between consecutive requests.
        self.min_interval = 1.0 / max_rps
        # Monotonic timestamp of the last request that was allowed through.
        self._last_request = 0.0
        # Lock ensures only one coroutine can check/update timing at a time.
        self._lock = asyncio.Lock()

    async def acquire(self):
        """Wait until enough time has elapsed, then mark the current instant."""
        async with self._lock:
            now = time.monotonic()
            wait = self.min_interval - (now - self._last_request)
            if wait > 0:
                await asyncio.sleep(wait)
            self._last_request = time.monotonic()
