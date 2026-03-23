import asyncio
import time


class RequestThrottle:
    """Token-bucket rate limiter for outbound requests to Black Duck."""

    def __init__(self, max_rps: int = 5):
        self.min_interval = 1.0 / max_rps
        self._last_request = 0.0
        self._lock = asyncio.Lock()

    async def acquire(self):
        async with self._lock:
            now = time.monotonic()
            wait = self.min_interval - (now - self._last_request)
            if wait > 0:
                await asyncio.sleep(wait)
            self._last_request = time.monotonic()
