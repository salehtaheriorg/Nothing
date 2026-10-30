"""
core/rate_limiter.py

محدودکننده‌ی نرخ درخواست. خیلی از برنامه‌های bug bounty توی policy‌شون
یه سقف مشخص برای req/s اعلام می‌کنن (مثلاً "no more than 5 requests per
second"). رد کردن این سقف می‌تونه:
1) باعث بن‌شدن اکانتت بشه
2) در بدترین حالت شبیه یه حمله‌ی DoS واقعی به‌نظر برسه و مشکل قانونی بسازه

این کلاس یه token bucket ساده‌ست که همه‌ی Hunterها ازش استفاده می‌کنن.
"""

from __future__ import annotations
import time
import threading


class RateLimiter:
    def __init__(self, requests_per_second: float = 5.0):
        if not 0.01 <= requests_per_second <= 1000:
            raise ValueError(
                f"requests_per_second باید بین 0.01 و 1000 باشه، مقدار داده‌شده: {requests_per_second}"
            )
        self.min_interval = 1.0 / requests_per_second
        self._lock = threading.Lock()
        self._last_call = 0.0

    def wait(self):
        with self._lock:
            now = time.monotonic()
            elapsed = now - self._last_call
            sleep_for = self.min_interval - elapsed
            if sleep_for > 0:
                time.sleep(sleep_for)
            self._last_call = time.monotonic()
