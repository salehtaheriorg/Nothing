"""
core/logger.py

لاگ ساده و thread-safe. چون حالا اسکن از داشبورد وب توی یه background
thread اجرا می‌شه، نیاز داریم خروجی رو یه‌جا (فایل) جمع کنیم تا هم توی
کنسول ببینیمش هم داشبورد وب بتونه با polling نشونش بده.
"""

from __future__ import annotations
import threading
from datetime import datetime
from pathlib import Path

_lock = threading.Lock()
# مسیر مطلق بر اساس ریشه‌ی پروژه — مثل بقیه‌ی ماژول‌ها. قبلاً relative
# بود و وقتی از داشبورد (CWD = dashboard/) اجرا می‌شد، لاگ فایل زیر
# dashboard/logs/ ساخته می‌شد — جدا از فایلی که tail_log() می‌خوند.
_PROJECT_ROOT = Path(__file__).resolve().parent.parent
LOG_FILE = _PROJECT_ROOT / "logs" / "scan.log"


def log(message: str):
    LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
    line = f"[{datetime.now().strftime('%H:%M:%S')}] {message}"
    with _lock:
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(line + "\n")
    print(line)


def tail_log(n: int = 200) -> list[str]:
    if not LOG_FILE.exists():
        return []
    with _lock:
        lines = LOG_FILE.read_text(encoding="utf-8").splitlines()
    return lines[-n:]


def clear_log():
    with _lock:
        if LOG_FILE.exists():
            LOG_FILE.unlink()
