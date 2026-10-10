"""Small per-process API rate limiter; production guidance covers shared limits."""
from __future__ import annotations

import threading
import time
from collections import defaultdict, deque

from fastapi import HTTPException


class SlidingWindowLimiter:
    def __init__(self) -> None:
        self._events: dict[tuple[str, str], deque[float]] = defaultdict(deque)
        self._lock = threading.Lock()

    def check(self, owner_id: str, action: str) -> None:
        now = time.monotonic()
        if action == "create_scan":
            limit, window = 5, 60 * 60
        elif action == "ownership":
            limit, window = 12, 60 * 60
        else:
            limit, window = 120, 60
        key = (owner_id, action)
        with self._lock:
            events = self._events[key]
            while events and now - events[0] >= window:
                events.popleft()
            if len(events) >= limit:
                retry_after = max(1, int(window - (now - events[0])))
                raise HTTPException(
                    status_code=429,
                    detail="Rate limit reached; please try again later",
                    headers={"Retry-After": str(retry_after)},
                )
            events.append(now)


limiter = SlidingWindowLimiter()
