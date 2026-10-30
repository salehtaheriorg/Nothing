"""
hunters/base_hunter.py

کلاس پایه برای همه‌ی Hunterها. نکته‌ی کلیدی: متد run() هرگز مستقیم
target رو صدا نمی‌زنه — همیشه اول از self.scope.enforce() رد می‌شه.
اگه یه Hunter جدید بنویسی و این خط رو یادت بره، ScopeViolationError
هرجای دیگه که subprocess صدا زده بشه هم (در صورت استفاده‌ی درست از
enforce) جلوش رو می‌گیره.
"""

from __future__ import annotations
from abc import ABC, abstractmethod
from core.scope import ScopeGuard, ScopeViolationError
from core.task_store import TaskStore
from core.findings_store import FindingsStore
from core.rate_limiter import RateLimiter
from core.logger import log


class BaseHunter(ABC):
    name: str = "base"

    def __init__(
        self,
        scope: ScopeGuard,
        store: TaskStore,
        findings: FindingsStore | None = None,
        rate_limiter: RateLimiter | None = None,
    ):
        self.scope = scope
        self.store = store
        self.findings = findings or FindingsStore()
        self.rate_limiter = rate_limiter or RateLimiter()
        self.run_id = None

    def report_finding(self, target: str, vuln_type: str, severity: str, evidence: dict, confidence: str = "candidate"):
        """راه استاندارد ثبت یه یافته. severity: info/low/medium/high/critical"""
        fid = self.findings.add_finding(
            hunter=self.name, target=target, vuln_type=vuln_type,
            severity=severity, evidence=evidence, confidence=confidence,
        )
        marker = "🔴" if confidence == "confirmed" else "🟡"
        log(f"[{self.name}] {marker} یافته‌ی جدید ({severity}/{confidence}): {vuln_type} در {target} — id={fid}")
        return fid

    def run_next(self) -> dict | None:
        """برمی‌گردونه: نتیجه‌ی تسک (dict) اگه تسکی پردازش شد (چه موفق چه
        ناموفق)، یا None *فقط* وقتی که واقعاً هیچ تسک دیگه‌ای توی صف
        نمونده. این تمایز مهمه: قبلاً یه باگ اینجا بود که شکست یه تسک
        (مثلاً scope violation) با "صف خالیه" قاطی می‌شد و کل حلقه‌ی
        پردازش رو زودتر از موقع متوقف می‌کرد — یعنی بقیه‌ی تسک‌های معتبر
        هیچ‌وقت پردازش نمی‌شدن. حالا فقط نبود تسک باعث توقف می‌شه."""
        task = self.store.next_task(self.name)
        if task is None:
            return None  # صف واقعاً خالیه
        try:
            # این خط اجباریه - هر Hunter باید هدفش رو enforce کنه
            safe_target = self.scope.enforce(task["target"])
            result = self.execute(safe_target, task["payload"])
            self.store.complete_task(task["id"], result)
            return result
        except ScopeViolationError as e:
            self.store.fail_task(task["id"], str(e))
            log(f"[{self.name}] ⛔ {e}")
            return {"error": str(e), "scope_violation": True}
        except Exception as e:
            self.store.fail_task(task["id"], f"{type(e).__name__}: {e}")
            log(f"[{self.name}] ⚠️ تسک با خطا مواجه شد: {e}")
            return {"error": str(e)}

    @abstractmethod
    def execute(self, target: str, payload: dict) -> dict:
        """منطق واقعی هر Hunter اینجا پیاده می‌شه. target تا این نقطه
        تضمین شده که از scope enforcement عبور کرده."""
        ...
