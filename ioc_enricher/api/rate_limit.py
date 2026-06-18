"""Small thread-safe fixed-window limiter for a single API process."""

import math
import threading
import time
from collections import deque


class RateLimiter:
    """Limit requests per direct peer over a rolling time window."""

    def __init__(self, limit=60, window_seconds=60, clock=time.monotonic):
        self.limit = max(0, limit)
        self.window_seconds = max(1, window_seconds)
        self.clock = clock
        self._requests: dict[str, deque[float]] = {}
        self._lock = threading.Lock()

    def check(self, client: str) -> tuple[bool, int, int]:
        """Return allowed, remaining requests, and retry delay in seconds."""
        if self.limit == 0:
            return True, 0, 0
        now = self.clock()
        with self._lock:
            entries = self._requests.setdefault(client, deque())
            while entries and entries[0] <= now - self.window_seconds:
                entries.popleft()
            if len(entries) >= self.limit:
                retry_after = max(1, math.ceil(entries[0] + self.window_seconds - now))
                return False, 0, retry_after
            entries.append(now)
            return True, self.limit - len(entries), 0
