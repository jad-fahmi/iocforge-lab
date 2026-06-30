"""Small thread-safe rolling-window limiter with bounded per-peer state."""

import math
import threading
import time
from collections import OrderedDict, deque


class RateLimiter:
    """Limit requests per direct peer over a rolling time window."""

    def __init__(
        self,
        limit=60,
        window_seconds=60,
        clock=time.monotonic,
        max_clients=10_000,
    ):
        self.limit = max(0, limit)
        self.window_seconds = max(1, window_seconds)
        self.clock = clock
        self.max_clients = max(1, max_clients)
        self._requests: OrderedDict[str, deque[float]] = OrderedDict()
        self._overflow_requests: deque[float] = deque()
        self._lock = threading.Lock()

    def check(self, client: str) -> tuple[bool, int, int]:
        """Return allowed, remaining requests, and retry delay in seconds."""
        if self.limit == 0:
            return True, 0, 0
        now = self.clock()
        with self._lock:
            entries = self._requests.get(client)
            if entries is not None:
                self._requests.move_to_end(client)
            else:
                if len(self._requests) >= self.max_clients:
                    oldest_client, oldest_entries = next(iter(self._requests.items()))
                    self._prune(oldest_entries, now)
                    if not oldest_entries:
                        del self._requests[oldest_client]
                if len(self._requests) < self.max_clients:
                    entries = deque()
                    self._requests[client] = entries
                else:
                    entries = self._overflow_requests

            return self._check_bucket(entries, now)

    def _check_bucket(self, entries: deque[float], now: float) -> tuple[bool, int, int]:
        self._prune(entries, now)
        if len(entries) >= self.limit:
            retry_after = max(1, math.ceil(entries[0] + self.window_seconds - now))
            return False, 0, retry_after
        entries.append(now)
        return True, self.limit - len(entries), 0

    def _prune(self, entries: deque[float], now: float) -> None:
        while entries and entries[0] <= now - self.window_seconds:
            entries.popleft()
