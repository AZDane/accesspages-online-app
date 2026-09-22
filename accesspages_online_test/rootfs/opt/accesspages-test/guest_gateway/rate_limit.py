from collections import defaultdict, deque
import math
from threading import Lock
from time import monotonic


class SlidingWindowRateLimiter:
    def __init__(self, limit: int, window_seconds: float):
        self.limit = limit
        self.window_seconds = window_seconds
        self._events = defaultdict(deque)
        self._lock = Lock()
        self._last_cleanup = monotonic()

    def _cleanup(self, cutoff: float) -> None:
        for key, events in list(self._events.items()):
            while events and events[0] <= cutoff:
                events.popleft()
            if not events:
                del self._events[key]

    def allow(self, key: str) -> bool:
        now = monotonic()
        cutoff = now - self.window_seconds
        with self._lock:
            if now - self._last_cleanup >= self.window_seconds:
                self._cleanup(cutoff)
                self._last_cleanup = now
            events = self._events[key]
            while events and events[0] <= cutoff:
                events.popleft()
            if len(events) >= self.limit:
                return False
            events.append(now)
            return True


class MinimumIntervalRateLimiter:
    """Bounded per-key minimum-delay enforcement with retry guidance."""

    def __init__(self, *, max_entries=10000, clock=monotonic):
        self.max_entries = max_entries
        self._clock = clock
        self._last = {}
        self._lock = Lock()

    def check(self, key: str, interval_seconds: float) -> tuple[bool, int]:
        now = self._clock()
        with self._lock:
            previous = self._last.get(key)
            if previous is not None and now - previous < interval_seconds:
                remaining = interval_seconds - (now - previous)
                return False, max(1, math.ceil(remaining))
            if len(self._last) >= self.max_entries:
                oldest = min(self._last, key=self._last.get)
                del self._last[oldest]
            self._last[key] = now
            return True, 0
