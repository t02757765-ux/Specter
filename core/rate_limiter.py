import asyncio
import time

class RateLimiter:
    def __init__(self, rate_limit: int):
        self.rate_limit = rate_limit
        self.tokens = float(rate_limit)
        self.last_update = time.monotonic()
        self._lock = asyncio.Lock()

    async def acquire(self) -> None:
        if self.rate_limit <= 0:
            return
        async with self._lock:
            now = time.monotonic()
            elapsed = now - self.last_update
            self.last_update = now
            self.tokens = min(float(self.rate_limit), self.tokens + elapsed * self.rate_limit)
            
            if self.tokens < 1.0:
                wait_time = (1.0 - self.tokens) / float(self.rate_limit)
                await asyncio.sleep(wait_time)
                self.tokens = 0.0
            else:
                self.tokens -= 1.0
