import threading
import time
from collections import deque
from collections.abc import Callable


class RateLimiter:
    def __init__(
        self, clock: Callable[[], float] = time.monotonic, max_keys: int = 10_000
    ) -> None:
        self._clock = clock
        self._max_keys = max_keys
        self._entries: dict[str, tuple[int, deque[float]]] = {}
        self._lock = threading.Lock()

    def __len__(self) -> int:
        return len(self._entries)

    def hit(self, key: str, limit: int, window_seconds: int) -> float | None:
        now = self._clock()
        with self._lock:
            _, hits = self._entries.setdefault(key, (window_seconds, deque()))
            cutoff = now - window_seconds
            while hits and hits[0] <= cutoff:
                hits.popleft()
            if len(hits) >= limit:
                return max(1.0, hits[0] + window_seconds - now)
            hits.append(now)
            if len(self._entries) > self._max_keys:
                self._purge(now)
            return None

    def _purge(self, now: float) -> None:
        expired = [
            key
            for key, (window, hits) in self._entries.items()
            if not hits or hits[-1] <= now - window
        ]
        for key in expired:
            del self._entries[key]

    def reset(self) -> None:
        with self._lock:
            self._entries.clear()