# Bug Bounty Multi-Agent System (Overseer/Hunter)

سیستم چندایجنتی برای اتوماسیون recon و vulnerability hunting در برنامه‌های
bug bounty **مجاز**، به‌همراه یه داشبورد مدیریتی کامل تحت وب. طراحی بر
پایه‌ی یک اصل غیرقابل‌مذاکره است:

> **scope enforcement توی کد سخت‌گیریه، نه توی prompt.**
> LLM هرگز مستقیم subprocess صدا نمی‌زنه و هرگز نمی‌تونه scope.json رو دور بزنه.

بخش «planning» تکمیلی سیستم (Overseer.plan_next_steps، پیشنهاد الگو،
و Template Forge) از **Gemini Flash** استفاده می‌کنه — یه کلید رایگان
از [Google AI Studio](https://aistudio.google.com/apikey) بگیر (بدون
کارت اعتباری) و توی `GEMINI_API_KEY` بذارش. مدل پیش‌فرض `gemini-3.7-flash`
هست (یه model ID مشخص و pin‌شده، نه alias «-latest» که بی‌خبر عوض می‌شه)؛
اگه لازم شد بعداً مدل رو عوض کنی، فقط `GEMINI_MODEL` رو ست کن — نیازی
به تغییر کد نیست.

## نصب سریع

```bash
pip install -r requirements.txt
playwright install chromium   # اختیاری، برای تأیید واقعی XSS

# ابزارهای recon و nuclei (نیاز به Go دارن)
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest

# اگر داخل venv پکیج Python `httpx` هم نصب باشد مشکلی نیست؛ ReconHunter
# نسخه‌ی ProjectDiscovery را به‌صورت خودکار تشخیص می‌دهد و ترجیحاً
# ~/go/bin/httpx را انتخاب می‌کند. برای مسیر سفارشی: 
# export PROJECTDISCOVERY_HTTPX=/path/to/projectdiscovery/httpx
go install -v github.com/projectdiscovery/katana/cmd/katana@latest
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
```

## راه‌اندازی (دو روش)

**روش ۱ — داشبورد وب (پیشنهادی، همه‌چیز از مرورگر):**
```bash
cd dashboard
python app.py
# مرورگر: http://127.0.0.1:5000
```
از داشبورد می‌تونی: دامنه‌ها رو اضافه کنی، API key بذاری، هانترها رو
روشن/خاموش کنی، و دکمه‌ی "شروع اسکن" رو بزنی. نیازی به دستکاری دستی
فایل‌های JSON نیست.

**روش ۲ — خط‌فرمان (CLI):**
```bash
cp config/scope.example.json config/scope.json       # پرش کن با scope واقعی برنامه
cp config/auth.example.json config/auth.json          # اختیاری، برای تست IDOR
cp config/settings.example.json config/settings.json  # نرخ درخواست
export GEMINI_API_KEY=...
python main.py
```

راهنمای کامل و مرحله‌به‌مرحله (از صفر تا صد، شامل هر بخش داشبورد) رو
توی فایل جدا `راهنمای_کامل_پروژه.md` بخون.

## وضعیت فعلی

| بخش | وضعیت |
|---|---|
| ScopeGuard + تست | ✅ کامل و تست‌شده |
| TaskStore / FindingsStore / RunsStore (SQLite) | ✅ کامل |
| RateLimiter | ✅ کامل |
| ReconHunter (subfinder→httpx→katana) | ✅ کامل |
| IDORHunter (broken access control + cross-account) | ✅ کامل |
| XSSHunter (reflection + تأیید با headless browser) | ✅ کامل |
| NucleiHunter (تمپلیت‌های عمومی CVE/misconfig) | ✅ کامل |
| TakeoverHunter (dangling CNAME / subdomain takeover) | ✅ کامل |
| SecretsHunter (کلید API/توکن هاردکدشده در JS و ...) | ✅ کامل |
| **CorsRedirectHunter (CORS Misconfig + Open Redirect)** | ✅ کامل — روی همون param_urls که IDOR/XSS استفاده می‌کنن |
| **SSRFHunter (Server-Side Request Forgery)** | ✅ کامل — تشخیص غیر-blind + پشتیبانی اختیاری از OOB (interactsh) |
| **TemplateForgeHunter (تولید تمپلیت Nuclei سفارشی با AI)** | ✅ کامل — validation امنیتی قوی، اجرا پیش‌فرض غیرفعال |
| **ParamMinerHunter (کشف پارامتر مخفی، سبک arjun)** | ✅ کامل — تست‌شده با ۱۵ دور تکرار، صفر false positive |
| **📚 آموزش هانترها (Knowledge Base)** | ✅ کامل — یادداشت‌های آموزشی به planning تزریق می‌شن + دکمه‌ی پیشنهاد الگو (قابل‌بررسی) |
| DiffScanHunter (اسکن افتراقی/Incremental) | ✅ کامل — هانتر هفتم |
| **داشبورد مدیریتی کامل تحت وب** | ✅ کامل |
| — شروع/توقف اسکن + لاگ زنده | ✅ |
| — مدیریت دامنه‌های مجاز (scope) | ✅ |
| — مدیریت هانترها (روشن/خاموش) | ✅ |
| — یافته‌ها + مشاهده‌ی رایتاپ | ✅ |
| — ردیاب پاداش (submission status + مبلغ) | ✅ |
| — مدیریت API Keys (masked) | ✅ |
| — چند-برنامه‌ای (ذخیره/بارگذاری چند scope) | ✅ |
| — تاریخچه‌ی اجراها | ✅ |
| — تنظیمات (rate limit) | ✅ |
| Template Forge (تولید تمپلیت Nuclei سفارشی با AI) | ✅ ساخته و تست شد |

## اصل‌های طراحی امنیتی

1. **Fail-closed**: بدون فایل scope معتبر، سیستم اصلاً اجرا نمی‌شه.
2. **Defense in depth**: خروجی هر مرحله دوباره از ScopeGuard رد می‌شه.
3. **همه‌چیز "candidate" هست تا دستی تأیید بشه**: هیچ finding به‌صورت
   خودکار "confirmed" نیست، مگر XSS با تأیید headless browser.
4. **Rate limiting همیشه فعاله**: پیش‌فرض ۵ درخواست بر ثانیه.
5. **داشبورد فقط روی 127.0.0.1**: هیچ‌وقت این پورت رو به اینترنت expose
   نکن — الان write-access کامل به سیستم و کلیدهات داره.
6. **هیچ secretی خام ذخیره نمی‌شه**: API keyها و کلیدهای پیداشده همیشه
   masked نمایش داده می‌شن.

## قدم بعدی پیشنهادی

همه‌ی آیتم‌های پیشنهادی قبلی اضافه شدن (۱۱ هانتر کامل). برای گسترش بیشتر:
- افزایش wordlist پارامترها توی ParamMinerHunter (الان ۶۱ تا، arjun کامل ۲۵هزار+ داره)
- افزودن CSRF Token validation checker
- گزارش‌دهی خودکار (submit) به HackerOne/Bugcrowd API (فعلاً فقط draft می‌سازه)


## Regression tests

```bash
python -m pytest -q test_recon_httpx.py test_recon_integration.py
python -m compileall -q .
```

تست‌های Recon بدون شبکه اجرا می‌شوند و بررسی می‌کنند که حتی با وجود `venv/bin/httpx`، باینری ProjectDiscovery انتخاب شود.

## Final release: queue & verification hardening
- Same-run task deduplication with canonical URL targets.
- Old unfinished queue entries are purged when a new scan starts.
- Findings are deduplicated by logical finding signature.
- Param Miner uses multi-sample baselines, differential checks, and repeatability before creating a candidate.
- `candidate` and `verified` remain separate states; hidden-parameter candidates are not auto-verified vulnerabilities.
- Planning retries once on transient LLM errors and rejects unsupported hunter names.
