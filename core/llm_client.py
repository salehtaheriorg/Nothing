"""
core/llm_client.py

Wrapper نازک روی Gemini API (پکیج google-genai، همون SDK رسمی گوگل) که
هر سه بخشی از سیستم که به یه LLM برای متن/JSON نیاز دارن ازش استفاده
می‌کنن: Overseer.plan_next_steps، pattern_advisor.suggest_patterns، و
TemplateForgeHunter._generate_templates. قبلاً این سه فایل هرکدوم
مستقیم Anthropic client می‌ساختن؛ حالا همه از همین یه wrapper رد می‌شن
تا provider (الان: Gemini Flash) فقط توی یه فایل تعریف بشه.

چرا Gemini Flash: نسخه‌ی رایگان (از طریق Google AI Studio، بدون کارت
اعتباری) rate limit سخاوتمندی داره و برای این سه مصرف (پیشنهاد JSON
کوتاه، نه یه ایجنت کدنویسی) کاملاً کافیه.

⚠️ درباره‌ی انتخاب مدل: عمداً از alias «-latest» (مثل gemini-flash-latest)
استفاده نمی‌کنیم. طبق مستندات خود گوگل، این alias می‌تونه به یه نسخه‌ی
stable یا experimental اشاره کنه و با هر رونمایی جدید بی‌سروصدا
hot-swap می‌شه؛ عملاً هم گزارش‌های متعددی از خطای 404 غیرمنتظره بعد از
عوض شدن مدل پشت این alias ثبت شده (مثلاً issue #6010 پروژه‌ی
google/adk-python). برای یه ابزار امنیتی که planning/Template Forge
بهش تکیه می‌کنن، شکست بی‌صدا/غیرقابل‌پیش‌بینی قابل‌قبول نیست. به‌جاش
یه model ID مشخص و stable/GA رو pin می‌کنیم (پایین). اگه گوگل بعداً
همین ID رو retire کنه، طبق سیاست خودشون قبلش اطلاع‌رسانی می‌کنه -- نه
اینکه بی‌خبر پشت یه اسم دیگه عوض بشه. برای عوض کردن مدل (مثلاً بعد از
یه رونمایی جدید یا اگه این ID retire شد)، کافیه متغیر محیطی
GEMINI_MODEL رو ست کنی؛ نیازی به تغییر کد نیست.

کلید API باید توی متغیر محیطی GEMINI_API_KEY (یا GOOGLE_API_KEY) ست
شده باشه؛ همون چیزی که خود google-genai SDK هم به‌صورت پیش‌فرض دنبالش
می‌گرده. مثل قبل، داشبورد و CLI می‌تونن این متغیر رو از config/api_keys.json
ست کنن (کلید anthropic_api_key قبلی حالا gemini_api_key شده).

نکته‌ی امنیتی مهم: این wrapper هیچ اختیار اجرایی نداره -- فقط متن پس
می‌ده. هر سه caller (Overseer/PatternAdvisor/TemplateForgeHunter) خروجی
رو خودشون parse و validate می‌کنن (JSON schema، ScopeGuard، یا
validate_template) قبل از این‌که هر اثری روی سیستم بذاره. این wrapper
عمداً هیچ tool/function calling یا اجرای subprocess نداره.
"""

from __future__ import annotations
import os
import random
import time


# gemini-3.7-flash یه model ID مشخص و pin‌شده‌ست (نه alias) -- طبق
# مستندات گوگل، از ۱۳ اوت ۲۰۲۶ به‌صورت stable/GA منتشر شده و از طریق
# Google AI Studio با یه سهمیه‌ی رایگان روزانه هم در دسترسه (رایگان
# برای prototyping/تست، نه لزوماً حجم production بالا). اگه بعداً مدل
# جدیدتری اومد یا این ID retire شد، به‌جای عوض کردن این ثابت، ترجیحاً
# متغیر محیطی GEMINI_MODEL رو ست کن (پایین‌تر خونده می‌شه) -- این‌جوری
# رفتار سیستم صریح و قابل‌ردیابیه، نه یه alias که بی‌خبر عوض می‌شه.
DEFAULT_MODEL = os.environ.get("GEMINI_MODEL") or "gemini-3.7-flash"


class GeminiTextClient:
    """یه wrapper خیلی ساده: system prompt + user content بده، متن خام
    پاسخ مدل رو بگیر. caller خودش مسئول parse کردن JSON و validation
    خروجیه -- این کلاس هیچ فرضی درباره‌ی ساختار پاسخ نداره."""

    def __init__(self, model: str = DEFAULT_MODEL, api_key: str | None = None):
        self.model = model
        resolved_key = api_key or os.environ.get("GEMINI_API_KEY") or os.environ.get("GOOGLE_API_KEY")
        try:
            from google import genai
            self._client = genai.Client(api_key=resolved_key)
        except (ImportError, ModuleNotFoundError) as exc:
            raise RuntimeError(
                "google-genai is not installed. Install requirements.txt before using Gemini-backed features."
            ) from exc

    def generate_text(self, system_prompt: str, user_content: str, max_output_tokens: int = 1024) -> str:
        # Small bounded retry for transient provider failures such as 429/503.
        # Never retry parsing errors or arbitrary exceptions indefinitely.
        last_error = None
        for attempt in range(3):
            try:
                from google.genai import types
                response = self._client.models.generate_content(
                    model=self.model,
                    contents=user_content,
                    config=types.GenerateContentConfig(
                        system_instruction=system_prompt,
                        max_output_tokens=max_output_tokens,
                    ),
                )
                return response.text or ""
            except Exception as exc:
                last_error = exc
                message = str(exc).lower()
                transient = any(token in message for token in ("503", "429", "unavailable", "resource_exhausted", "timeout"))
                if not transient or attempt == 2:
                    raise
                time.sleep((2 ** attempt) + random.uniform(0.0, 0.5))
        raise last_error


def strip_json_fences(text: str) -> str:
    """با تست مستقیم پیدا شد: با اینکه توی هر سه system prompt صریح
    نوشتیم «فقط یه آرایه‌ی JSON برگردون»، Gemini بعضی‌وقتا (برخلاف Claude
    که توی این پروژه رفتارش رو ندیده بودیم) خروجی رو توی یه code fence
    مارک‌داون می‌پیچه (مثلاً ```json ... ``` یا فقط ``` ... ```). قبل از
    این فیکس، json.loads() روی این ورودی JSONDecodeError می‌داد و caller
    بی‌صدا آرایه‌ی خالی برمی‌گردوند -- یعنی یادداشت/نتیجه‌ی recon واقعاً
    پردازش شده بود ولی پیشنهاد Gemini بی‌دلیل گم می‌شد، بدون هیچ خطای
    قابل‌مشاهده‌ای برای کاربر.

    این تابع فقط پوشش code fence رو برمی‌داره -- هیچ تغییر دیگه‌ای روی
    محتوا نمی‌ده. هر سه caller (Overseer، PatternAdvisor، TemplateForge)
    قبل از json.loads() این رو صدا می‌زنن. اگه fence‌ای نبود، متن دست‌نخورده
    برمی‌گرده."""
    stripped = text.strip()
    if not stripped.startswith("```"):
        return stripped
    lines = stripped.split("\n")
    lines = lines[1:]  # خط اول: "```json" یا فقط "```"
    if lines and lines[-1].strip() == "```":
        lines = lines[:-1]
    elif lines and lines[-1].rstrip().endswith("```"):
        lines[-1] = lines[-1].rstrip()[:-3]
    return "\n".join(lines).strip()
