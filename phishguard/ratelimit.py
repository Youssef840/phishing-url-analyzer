"""Tiny in-memory, per-IP rate limiter (sliding window).

Enough for a public demo without extra dependencies. State lives in the
process, so each gunicorn worker keeps its own counters.
"""

from __future__ import annotations

import threading
import time
from collections import deque


class RateLimiter:
    def __init__(self, limit: int, window: float = 60.0, max_clients: int = 10_000) -> None:
        self.limit = limit
        self.window = window
        self.max_clients = max_clients
        self._hits: dict[str, deque[float]] = {}
        self._lock = threading.Lock()

    def allow(self, key: str) -> bool:
        """Record a hit for ``key``; return False if it exceeds the limit."""
        if self.limit <= 0:
            return True
        now = time.monotonic()
        cutoff = now - self.window
        with self._lock:
            if len(self._hits) >= self.max_clients and key not in self._hits:
                self._prune(cutoff)
            hits = self._hits.setdefault(key, deque())
            while hits and hits[0] <= cutoff:
                hits.popleft()
            if len(hits) >= self.limit:
                return False
            hits.append(now)
            return True

    def _prune(self, cutoff: float) -> None:
        for key in [k for k, v in self._hits.items() if not v or v[-1] <= cutoff]:
            del self._hits[key]
