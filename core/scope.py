"""
core/scope.py

هسته‌ی امنیتی سیستم. هیچ Hunter یا Overseer‌ای مجاز نیست مستقیم به
subprocess یا httpx/subfinder/nuclei دسترسی داشته باشه بدون عبور از
این ماژول. این عمداً از منطق LLM جداست تا هالوسینیشن یا prompt injection
نتونه scope رو دور بزنه.

اصل طراحی: "fail closed" - هر چیزی که مطمئن نیستیم مجازه، رد می‌شه.
"""

from __future__ import annotations
import json
import re
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlparse


def normalize_hostname(value: str) -> str:
    """Return a canonical hostname for scope/recon identity decisions.

    Scope entries are host-based even when the user pastes a full URL. Paths
    such as /robots.txt and /sitemap.xml must never become separate recon
    targets.
    """
    raw = (value or "").strip().lower()
    if not raw:
        return ""
    candidate = raw if "://" in raw else "http://" + raw
    try:
        parsed = urlparse(candidate)
        host = (parsed.hostname or "").rstrip(".")
        return host
    except ValueError:
        return ""


def normalize_scope_pattern(value: str) -> str:
    """Normalize a dashboard/config scope entry to a hostname pattern."""
    raw = (value or "").strip().lower()
    if not raw:
        return ""
    wildcard = raw.startswith("*.")
    base = raw[2:] if wildcard else raw
    host = normalize_hostname(base)
    if not host:
        return ""
    return f"*.{host}" if wildcard else host


class ScopeViolationError(Exception):
    """وقتی یه هدف خارج از scope درخواست بشه، این exception پرتاب می‌شه.
    این exception هیچ‌جا catch نمی‌شه و silently نادیده گرفته نمی‌شه —
    باید تا بالای stack بره و لاگ بشه."""
    pass


@dataclass(frozen=True)
class ScopeDecision:
    target: str
    allowed: bool
    reason: str


class ScopeGuard:
    def __init__(self, scope_file: str | Path):
        self.scope_file = Path(scope_file)
        if not self.scope_file.exists():
            raise FileNotFoundError(
                f"scope file پیدا نشد: {scope_file}. "
                "بدون فایل scope معتبر، سیستم اجازه‌ی اجرا نداره."
            )
        data = json.loads(self.scope_file.read_text(encoding="utf-8"))
        self.program_name: str = data.get("program_name", "unknown")
        self.in_scope: list[str] = list(dict.fromkeys(filter(None, (normalize_scope_pattern(s) for s in data.get("in_scope", [])))))
        self.out_of_scope: list[str] = list(dict.fromkeys(filter(None, (normalize_scope_pattern(s) for s in data.get("out_of_scope", [])))))

        if not self.in_scope:
            raise ValueError("لیست in_scope خالیه — این یعنی هیچ هدفی مجاز نیست.")

    @staticmethod
    def _extract_host(target: str) -> str:
        """یه URL یا domain خام رو به hostname خالص تبدیل می‌کنه."""
        target = target.strip().lower()
        if "://" not in target:
            target = "http://" + target
        parsed = urlparse(target)
        host = parsed.hostname or ""
        return host

    @staticmethod
    def _domain_matches(host: str, pattern: str, include_subdomains_by_default: bool = False) -> bool:
        """پشتیبانی از wildcard مثل *.example.com.

        include_subdomains_by_default=True یعنی حتی بدون *. هم زیردامنه‌ها
        مچ می‌شن. این فقط برای out_of_scope استفاده می‌شه: چون هدف
        out_of_scope محافظت حداکثریه، محافظه‌کارانه‌تره که پیش‌فرض شامل
        زیردامنه‌ها هم بشه (over-exclusion بی‌خطره، under-exclusion
        بی‌خطر نیست). برای in_scope این رفتار فعال نمی‌شه، چون برعکسش
        صادقه: اسکن‌کردن چیزی که نباید in-scope باشه خطرناکه."""
        if pattern.startswith("*."):
            base = pattern[2:]
            return host == base or host.endswith("." + base)
        if include_subdomains_by_default:
            return host == pattern or host.endswith("." + pattern)
        return host == pattern

    def check(self, target: str) -> ScopeDecision:
        host = self._extract_host(target)
        if not host:
            return ScopeDecision(target, False, "نتونستم hostname رو از هدف استخراج کنم")

        # اول out_of_scope چک می‌شه - همیشه اولویت با رد کردنه.
        # حتی بدون *. صریح، زیردامنه‌ها هم رد می‌شن (نگاه کن به توضیح
        # include_subdomains_by_default توی _domain_matches).
        for pattern in self.out_of_scope:
            if self._domain_matches(host, pattern, include_subdomains_by_default=True):
                return ScopeDecision(target, False, f"صراحتاً out-of-scope طبق قانون: {pattern}")

        for pattern in self.in_scope:
            if self._domain_matches(host, pattern):
                return ScopeDecision(target, True, f"مطابق با قانون in-scope: {pattern}")

        return ScopeDecision(target, False, "در هیچ قانون in_scope مطابقتی پیدا نشد")

    def enforce(self, target: str) -> str:
        """اگه مجاز باشه host رو برمی‌گردونه، وگرنه exception می‌ده.
        هر تابعی که قراره یه دامنه رو اسکن کنه باید این رو صدا بزنه."""
        decision = self.check(target)
        if not decision.allowed:
            raise ScopeViolationError(
                f"[{self.program_name}] هدف رد شد: {target} — دلیل: {decision.reason}"
            )
        return decision.target

    def filter_list(self, targets: list[str]) -> list[str]:
        """لیستی از دامنه‌ها (مثلاً خروجی subfinder) رو فیلتر می‌کنه و فقط
        مواردی که واقعاً in-scope هستن رو نگه می‌داره. موارد رد شده لاگ می‌شن."""
        allowed, rejected = [], []
        for t in targets:
            d = self.check(t)
            (allowed if d.allowed else rejected).append(t)
        if rejected:
            print(f"[scope] {len(rejected)} هدف خارج از scope فیلتر شد: {rejected[:5]}{'...' if len(rejected) > 5 else ''}")
        return allowed
