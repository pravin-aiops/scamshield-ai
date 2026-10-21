"""A tiny in-memory sliding-window rate limiter.

It protects a single backend process (one Elastic Beanstalk instance or one
Docker container) from a client hammering the slow AI endpoint. It is not a
distributed limiter: with several instances each one counts on its own.
"""

import threading
import time
from collections import deque


class RateLimiter:
    def __init__(self, limit: int, window_seconds: float = 60.0, max_clients: int = 5000):
        self.limit = limit
        self.window = window_seconds
        self.max_clients = max_clients
        self._hits: dict[str, deque[float]] = {}
        self._lock = threading.Lock()

    @property
    def enabled(self) -> bool:
        return self.limit > 0

    def check(self, key: str, now: float | None = None) -> tuple[bool, int]:
        """Record a request. Returns (allowed, seconds_until_retry)."""
        if not self.enabled:
            return True, 0

        now = time.monotonic() if now is None else now

        with self._lock:
            hits = self._hits.setdefault(key, deque())

            while hits and now - hits[0] >= self.window:
                hits.popleft()

            if len(hits) >= self.limit:
                retry = int(self.window - (now - hits[0])) + 1
                return False, max(retry, 1)

            hits.append(now)

            if len(self._hits) > self.max_clients:
                self._prune(now)

            return True, 0

    def _prune(self, now: float) -> None:
        for client in [k for k, v in self._hits.items() if not v or now - v[-1] >= self.window]:
            del self._hits[client]
