"""تست دستی سریع برای core/scope.py - بدون نیاز به شبکه یا subfinder."""
import json
import tempfile
from pathlib import Path
from core.scope import ScopeGuard, ScopeViolationError

scope_data = {
    "program_name": "test-program",
    "in_scope": ["example.com", "*.example.com"],
    "out_of_scope": ["blog.example.com"]
}

with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
    json.dump(scope_data, f)
    scope_path = f.name

guard = ScopeGuard(scope_path)

tests = [
    ("example.com", True),
    ("https://api.example.com/v1/users", True),
    ("sub.deep.example.com", True),
    ("blog.example.com", False),          # صراحتاً out_of_scope
    ("evil.com", False),                  # اصلاً توی scope نیست
    ("example.com.evil.com", False),      # trick کلاسیک - نباید match بشه
    ("notexample.com", False),
    ("BLOG.EXAMPLE.COM", False),          # حساسیت به حروف بزرگ نباید فیلتر رو دور بزنه
    ("sub.blog.example.com", False),      # زیردامنه‌ی یه out_of_scope بدون *. هم باید رد بشه (fail-safe)
]

print(f"برنامه: {guard.program_name}\n")
all_passed = True
for target, expected in tests:
    decision = guard.check(target)
    ok = decision.allowed == expected
    all_passed &= ok
    status = "✅" if ok else "❌"
    print(f"{status} {target:35s} -> allowed={decision.allowed} (انتظار: {expected}) | {decision.reason}")

print(f"\n{'همه‌ی تست‌ها پاس شدن ✅' if all_passed else 'بعضی تست‌ها fail شدن ❌'}")

# تست filter_list
print("\n--- تست filter_list ---")
mixed = ["a.example.com", "evil.com", "blog.example.com", "example.com"]
filtered = guard.filter_list(mixed)
print(f"ورودی: {mixed}")
print(f"خروجی (فقط in-scope): {filtered}")

# تست enforce - باید exception بده
print("\n--- تست enforce روی هدف خارج از scope ---")
try:
    guard.enforce("evil.com")
    print("❌ باید exception می‌داد ولی نداد!")
except ScopeViolationError as e:
    print(f"✅ به‌درستی رد شد: {e}")

Path(scope_path).unlink()
