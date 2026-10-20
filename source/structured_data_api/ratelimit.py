"""滑动窗口限流。

按 key（本项目用令牌 id）维护一个时间戳队列：
  - 每次请求先剔除窗口外的旧时间戳；
  - 队列长度达到 limit 即拒绝，并给出 Retry-After（最早一条过期还需多少秒）。
滑动窗口而不是固定窗口，是为了避免"窗口边界突发双倍额度"。
"""

from __future__ import annotations

import math
import threading
from collections import deque
from dataclasses import dataclass
from typing import Any


@dataclass
class RateDecision:
    allowed: bool
    limit: int
    window_s: int
    used: int
    remaining: int
    retry_after_s: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "allowed": self.allowed,
            "limit": self.limit,
            "window_seconds": self.window_s,
            "used": self.used,
            "remaining": self.remaining,
            "retry_after_s": self.retry_after_s,
        }


class SlidingWindowLimiter:
    def __init__(self, limit: int, window_s: int, *, name: str = "default") -> None:
        if limit <= 0 or window_s <= 0:
            raise ValueError("limit 与 window_s 必须是正整数")
        self.limit = int(limit)
        self.window_s = int(window_s)
        self.name = name
        self._hits: dict[str, deque[float]] = {}
        self._lock = threading.Lock()

    def check(self, key: str, now_ts: float) -> RateDecision:
        with self._lock:
            bucket = self._hits.setdefault(key, deque())
            horizon = now_ts - self.window_s
            while bucket and bucket[0] <= horizon:
                bucket.popleft()
            used = len(bucket)
            if used >= self.limit:
                retry_after = 1
                if bucket:
                    retry_after = max(1, int(math.ceil(bucket[0] + self.window_s - now_ts)))
                return RateDecision(
                    allowed=False,
                    limit=self.limit,
                    window_s=self.window_s,
                    used=used,
                    remaining=0,
                    retry_after_s=retry_after,
                )
            bucket.append(now_ts)
            return RateDecision(
                allowed=True,
                limit=self.limit,
                window_s=self.window_s,
                used=used + 1,
                remaining=self.limit - used - 1,
                retry_after_s=0,
            )

    def used(self, key: str, now_ts: float) -> int:
        with self._lock:
            bucket = self._hits.get(key)
            if not bucket:
                return 0
            horizon = now_ts - self.window_s
            while bucket and bucket[0] <= horizon:
                bucket.popleft()
            return len(bucket)

    def reset(self, key: str | None = None) -> None:
        with self._lock:
            if key is None:
                self._hits.clear()
            else:
                self._hits.pop(key, None)


class LimiterRegistry:
    """每个令牌一个限流器：配额来自 auth.json，缺省回落 limits.json 的全局配额。"""

    def __init__(self, default_limit: int, default_window_s: int) -> None:
        self.default_limit = int(default_limit)
        self.default_window_s = int(default_window_s)
        self._limiters: dict[str, SlidingWindowLimiter] = {}
        self._lock = threading.Lock()

    def for_key(self, key: str, limit: int | None = None, window_s: int | None = None) -> SlidingWindowLimiter:
        limit = int(limit or self.default_limit)
        window_s = int(window_s or self.default_window_s)
        cache_key = f"{key}:{limit}:{window_s}"
        with self._lock:
            limiter = self._limiters.get(cache_key)
            if limiter is None:
                limiter = SlidingWindowLimiter(limit, window_s, name=key)
                self._limiters[cache_key] = limiter
            return limiter
