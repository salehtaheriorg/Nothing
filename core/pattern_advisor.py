"""
core/pattern_advisor.py

از روی یه یادداشت آموزشی (رایتاپ/تکنیک) که توی داشبورد وارد کردی، با
کمک Gemini API پیشنهاد می‌ده چه الگوها/پی‌لود/fingerprint جدیدی می‌تونه
به هانتر مربوطه اضافه بشه.

⚠️ این فقط PISHNAHAD می‌ده -- هیچ فایل کدی رو خودکار تغییر نمی‌ده.
خروجی باید دستی بررسی و (در صورت تأیید) توسط خودت به فایل مربوطه
(مثلاً hunters/secrets_hunter.py یا config/takeover_fingerprints.json)
اضافه بشه. این عمداً همین‌طوریه: محتوای یادداشت متن ورودیه (از کاربر یا
یه رایتاپ کپی‌شده) و نباید بدون بازبینی انسانی مستقیم روی رفتار یه
ابزار امنیتی تأثیر بذاره -- حتی اگه ناخواسته یه یادداشت متن گمراه‌کننده
یا دستکاری‌شده داشته باشه.
"""

from __future__ import annotations
import json

from core.llm_client import GeminiTextClient, DEFAULT_MODEL, strip_json_fences

ADVISOR_SYSTEM_PROMPT = """تو داری به یه محقق امنیتی کمک می‌کنی که از
یه رایتاپ/یادداشت آموزشی، الگوهای قابل‌اتوماسیون استخراج کنه تا به یه
ابزار اسکن آسیب‌پذیری اضافه بشن.

فقط یک آرایه‌ی JSON برگردون، هیچ توضیح اضافه‌ای نده. هر آیتم این شکل:
{"type": "regex" | "payload" | "fingerprint" | "param_name" | "note",
 "value": "...", "explanation": "چرا این پیشنهاد به این هانتر کمک می‌کنه"}

اگه یادداشت هیچ الگوی قابل‌اتوماسیونی نداشت (مثلاً فقط توضیح مفهومی یا
داستانیه، نه یه تکنیک فنی مشخص)، آرایه‌ی خالی برگردون. بیش از ۸ پیشنهاد
نده. تو فقط پیشنهاد می‌دی -- هیچ فایلی رو تغییر نمی‌دی و هیچ اجرایی
انجام نمی‌شه."""


def suggest_patterns(hunter: str, note_content: str, model: str = DEFAULT_MODEL) -> list[dict]:
    client = GeminiTextClient(model=model)
    raw = client.generate_text(
        system_prompt=ADVISOR_SYSTEM_PROMPT,
        user_content=f"هانتر هدف: {hunter}\n\nمتن یادداشت:\n{note_content[:4000]}",
        max_output_tokens=1024,
    )
    try:
        suggestions = json.loads(strip_json_fences(raw))
        if not isinstance(suggestions, list):
            return []
        return suggestions[:8]
    except json.JSONDecodeError:
        return []
