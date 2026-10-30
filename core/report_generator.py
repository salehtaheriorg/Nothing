"""
core/report_generator.py

از روی هر finding (که با confidence مناسب و پس از بررسی دستی توسط خودت
تأیید شده) یه فایل مارک‌داون می‌سازه به سبک استاندارد گزارش‌های
HackerOne/Bugcrowd: Summary, Steps to Reproduce, Impact, Suggested Fix.

⚠️ این گزارش صرفاً یه **پیش‌نویس** هست. هیچ‌وقت مستقیم و بدون خوندن و
ویرایش دستی ارسالش نکن. اطلاعات evidence رو با policy برنامه چک کن که
همه‌چیز طبق قوانینشون باشه (بعضی برنامه‌ها می‌خوان proof-of-concept
حداقلی باشه، بعضی‌ها فرمت خاص خودشون رو دارن).
"""

from __future__ import annotations
import json
import re
from pathlib import Path
from datetime import datetime, timezone

# فقط این کاراکترها توی اسم فایل مجازن. هر چیز دیگه‌ای (شامل / \ .. و
# کاراکترهای کنترلی) با _ جایگزین می‌شه. این جلوی path traversal رو
# می‌گیره حتی اگه vuln_type از یه منبع نیمه‌قابل‌اعتماد بیاد (مثلاً
# فیلد title که template_forge_hunter از خروجی AI می‌سازه، که خودش از
# سیگنال‌های هدف اسکن‌شده -- یعنی از نظر تئوری prompt-injectable --
# تأثیر می‌گیره). این تابع مستقل از اینکه finding از کدوم هانتر اومده
# اعمال می‌شه، چون این لایه نباید به «قابل‌اعتماد بودن» هیچ هانتری متکی باشه.
_SAFE_FILENAME_CHARS = re.compile(r"[^A-Za-z0-9_-]+")


def _safe_filename_component(raw: str, max_len: int = 80) -> str:
    cleaned = _SAFE_FILENAME_CHARS.sub("_", raw).strip("_")
    if not cleaned:
        cleaned = "finding"
    return cleaned[:max_len]


TEMPLATE = """# گزارش پیش‌نویس: {vuln_type}

**هدف:** `{target}`
**شدت (severity) پیشنهادی:** {severity}
**سطح اطمینان اتوماتیک:** {confidence}
**تاریخ کشف:** {created_at}

---

## ⚠️ قبل از ارسال چک کن
- [ ] این finding رو دستی تست کردم و واقعاً reproducible هست
- [ ] هیچ داده‌ی واقعی کاربر دیگه‌ای رو بیش از حد لازم برای اثبات آسیب‌پذیری نخوندم/ذخیره نکردم
- [ ] این تست دقیقاً مطابق scope و rules-of-engagement برنامه بوده
- [ ] فرمت گزارش رو با الزامات خاص این برنامه (اگه داره) تطبیق دادم

---

## Summary
<!-- یک یا دو جمله: این آسیب‌پذیری چیه و کجا پیدا شده -->
یافته‌ای از نوع {vuln_type} در `{target}` شناسایی شد.

## Steps to Reproduce
<!-- قدم‌به‌قدم و دقیق بنویس تا triager بتونه عیناً تکرار کنه -->
1. ...
2. ...
3. ...

## Evidence (خودکار جمع‌آوری‌شده — بازبینی و پاک‌سازی کن)
```json
{evidence_json}
```

## Impact
<!-- این آسیب‌پذیری چه آسیبی می‌تونه بزنه؟ چه دسترسی/دیتایی افشا می‌شه؟ -->
...

## Suggested Fix
<!-- اختیاری ولی معمولاً امتیاز مثبت می‌گیره -->
...
"""


def generate_report(finding: dict, output_dir: str = "reports") -> str:
    out_path = Path(output_dir)
    out_path.mkdir(parents=True, exist_ok=True)

    content = TEMPLATE.format(
        vuln_type=finding["vuln_type"],
        target=finding["target"],
        severity=finding["severity"],
        confidence=finding["confidence"],
        created_at=finding["created_at"],
        evidence_json=json.dumps(json.loads(finding["evidence"]), ensure_ascii=False, indent=2),
    )

    filename = f"{finding['id'][:8]}_{_safe_filename_component(finding['vuln_type'])}.md"
    file_path = out_path / filename

    # دفاع لایه‌ی دوم: حتی بعد از sanitize بالا، مطمئن می‌شیم مسیر نهایی
    # واقعاً زیرمجموعه‌ی out_path باقی مونده قبل از نوشتن (belt-and-braces
    # در برابر هر مسیر ناشناخته‌ی دیگه‌ای که ممکنه از قلم افتاده باشه).
    resolved_out = out_path.resolve()
    resolved_file = file_path.resolve()
    if resolved_out not in resolved_file.parents and resolved_file != resolved_out:
        raise ValueError(f"مسیر گزارش نامعتبره (احتمال path traversal): {file_path}")

    file_path.write_text(content, encoding="utf-8")
    return str(file_path)


def generate_all_reports(findings: list[dict], output_dir: str = "reports") -> list[tuple[str, str]]:
    """برمی‌گردونه لیستی از (finding_id, مسیر فایل گزارش)."""
    return [(f["id"], generate_report(f, output_dir)) for f in findings]
