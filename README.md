# Bug Bounty Multi-Agent System (Overseer/Hunter)

از لینک زیر نیز میتوانید راهنمای اجرا و معرفی پروژه را ببینید:
https://salehtaheriorg.github.io/Nothing

<p align="center">
  <b>🌐 Language / زبان</b><br>
  <a href="#fa">فارسی</a> · <a href="#en">English</a>
</p>

---

<a id="fa"></a>

## فارسی

سیستم چندایجنتی برای اتوماسیون recon و vulnerability hunting در برنامه‌های
bug bounty **مجاز**، به‌همراه یه داشبورد مدیریتی کامل تحت وب. طراحی بر
پایه‌ی یک اصل غیرقابل‌مذاکره است:

> [!IMPORTANT]
> **scope enforcement توی کد سخت‌گیریه، نه توی prompt.**
> LLM هرگز مستقیم subprocess صدا نمی‌زنه و هرگز نمی‌تونه scope.json رو دور بزنه.

بخش «planning» تکمیلی سیستم (Overseer.plan_next_steps، پیشنهاد الگو،
و Template Forge) از **Gemini Flash** استفاده می‌کنه — یه کلید رایگان
از [Google AI Studio](https://aistudio.google.com/apikey) بگیر (بدون
کارت اعتباری) و توی `GEMINI_API_KEY` بذارش. مدل پیش‌فرض `gemini-3.7-flash`
هست (یه model ID مشخص و pin‌شده، نه alias «-latest» که بی‌خبر عوض می‌شه)؛
اگه لازم شد بعداً مدل رو عوض کنی، فقط `GEMINI_MODEL` رو ست کن — نیازی
به تغییر کد نیست.

### نصب سریع

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

### راه‌اندازی (دو روش)

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

### وضعیت فعلی

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

### اصل‌های طراحی امنیتی

1. **Fail-closed**: بدون فایل scope معتبر، سیستم اصلاً اجرا نمی‌شه.
2. **Defense in depth**: خروجی هر مرحله دوباره از ScopeGuard رد می‌شه.
3. **همه‌چیز "candidate" هست تا دستی تأیید بشه**: هیچ finding به‌صورت
   خودکار "confirmed" نیست، مگر XSS با تأیید headless browser.
4. **Rate limiting همیشه فعاله**: پیش‌فرض ۵ درخواست بر ثانیه.
5. **داشبورد فقط روی 127.0.0.1**: هیچ‌وقت این پورت رو به اینترنت expose
   نکن — الان write-access کامل به سیستم و کلیدهات داره.
6. **هیچ secretی خام ذخیره نمی‌شه**: API keyها و کلیدهای پیداشده همیشه
   masked نمایش داده می‌شن.

> [!WARNING]
> داشبورد write-access کامل به سیستم و کلیدهات داره. هیچ‌وقت پورت اون رو به اینترنت expose نکن.

### قدم بعدی پیشنهادی

همه‌ی آیتم‌های پیشنهادی قبلی اضافه شدن (۱۱ هانتر کامل). برای گسترش بیشتر:

- افزایش wordlist پارامترها توی ParamMinerHunter (الان ۶۱ تا، arjun کامل ۲۵هزار+ داره)
- افزودن CSRF Token validation checker
- گزارش‌دهی خودکار (submit) به HackerOne/Bugcrowd API (فعلاً فقط draft می‌سازه)

### تست‌ها (Regression tests)

```bash
python -m pytest -q test_recon_httpx.py test_recon_integration.py
python -m compileall -q .
```

تست‌های Recon بدون شبکه اجرا می‌شوند و بررسی می‌کنند که حتی با وجود `venv/bin/httpx`، باینری ProjectDiscovery انتخاب شود.

### Final release: queue & verification hardening

- Same-run task deduplication with canonical URL targets.
- Old unfinished queue entries are purged when a new scan starts.
- Findings are deduplicated by logical finding signature.
- Param Miner uses multi-sample baselines, differential checks, and repeatability before creating a candidate.
- `candidate` and `verified` remain separate states; hidden-parameter candidates are not auto-verified vulnerabilities.
- Planning retries once on transient LLM errors and rejects unsupported hunter names.

<p align="right"><a href="#bug-bounty-multi-agent-system-overseerhunter">⬆ بازگشت به بالا / Back to top</a></p>

---

<a id="en"></a>

## English

A multi-agent system for automating recon and vulnerability hunting in
**authorized** bug bounty programs, shipped with a full web-based management
dashboard. It is built around one non-negotiable principle:

> [!IMPORTANT]
> **Scope enforcement lives in strict code, not in the prompt.**
> The LLM never calls a subprocess directly and can never bypass `scope.json`.

The system's supplementary "planning" layer (`Overseer.plan_next_steps`,
template suggestions, and Template Forge) uses **Gemini Flash**. Get a free
key from [Google AI Studio](https://aistudio.google.com/apikey) (no credit
card required) and set it in `GEMINI_API_KEY`. The default model is
`gemini-3.7-flash` (a specific, pinned model ID, not a "-latest" alias that
can change silently). If you want to switch models later, just set
`GEMINI_MODEL`; no code changes are needed.

### Quick install

```bash
pip install -r requirements.txt
playwright install chromium   # optional, for real XSS confirmation

# Recon tools and nuclei (require Go)
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest

# It is fine if the Python `httpx` package is also installed inside your venv;
# ReconHunter automatically detects the ProjectDiscovery version and prefers
# ~/go/bin/httpx. For a custom path:
# export PROJECTDISCOVERY_HTTPX=/path/to/projectdiscovery/httpx
go install -v github.com/projectdiscovery/katana/cmd/katana@latest
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
```

### Getting started (two ways)

**Option 1: Web dashboard (recommended, everything from the browser):**

```bash
cd dashboard
python app.py
# Browser: http://127.0.0.1:5000
```

From the dashboard you can add domains, set API keys, toggle hunters on/off,
and press the "Start scan" button. No manual editing of JSON files is needed.

**Option 2: Command line (CLI):**

```bash
cp config/scope.example.json config/scope.json       # fill in with the program's real scope
cp config/auth.example.json config/auth.json          # optional, for IDOR testing
cp config/settings.example.json config/settings.json  # request rate
export GEMINI_API_KEY=...
python main.py
```

For the complete step-by-step guide (from zero to hero, covering every
dashboard section), read the separate file `راهنمای_کامل_پروژه.md`
(Persian).

### Current status

| Component | Status |
|---|---|
| ScopeGuard + tests | ✅ Complete and tested |
| TaskStore / FindingsStore / RunsStore (SQLite) | ✅ Complete |
| RateLimiter | ✅ Complete |
| ReconHunter (subfinder→httpx→katana) | ✅ Complete |
| IDORHunter (broken access control + cross-account) | ✅ Complete |
| XSSHunter (reflection + headless-browser confirmation) | ✅ Complete |
| NucleiHunter (generic CVE/misconfig templates) | ✅ Complete |
| TakeoverHunter (dangling CNAME / subdomain takeover) | ✅ Complete |
| SecretsHunter (hardcoded API keys/tokens in JS, etc.) | ✅ Complete |
| **CorsRedirectHunter (CORS misconfig + Open Redirect)** | ✅ Complete: runs on the same param_urls used by IDOR/XSS |
| **SSRFHunter (Server-Side Request Forgery)** | ✅ Complete: non-blind detection + optional OOB support (interactsh) |
| **TemplateForgeHunter (AI-generated custom Nuclei templates)** | ✅ Complete: strong security validation, execution disabled by default |
| **ParamMinerHunter (hidden parameter discovery, arjun-style)** | ✅ Complete: tested over 15 repeated rounds, zero false positives |
| **📚 Hunter training (Knowledge Base)** | ✅ Complete: training notes are injected into planning + a reviewable "suggest template" button |
| DiffScanHunter (differential/incremental scanning) | ✅ Complete: the seventh hunter |
| **Full web-based management dashboard** | ✅ Complete |
| — Start/stop scan + live log | ✅ |
| — Authorized domain (scope) management | ✅ |
| — Hunter management (on/off) | ✅ |
| — Findings + write-up viewer | ✅ |
| — Bounty tracker (submission status + amount) | ✅ |
| — API Keys management (masked) | ✅ |
| — Multi-program (save/load multiple scopes) | ✅ |
| — Run history | ✅ |
| — Settings (rate limit) | ✅ |
| Template Forge (AI-generated custom Nuclei templates) | ✅ Built and tested |

### Security design principles

1. **Fail-closed**: without a valid scope file, the system will not run at all.
2. **Defense in depth**: the output of every stage passes through ScopeGuard again.
3. **Everything is a "candidate" until manually confirmed**: no finding is
   automatically "confirmed", except XSS verified by the headless browser.
4. **Rate limiting is always on**: default is 5 requests per second.
5. **The dashboard listens on 127.0.0.1 only**: never expose this port to the
   internet. It currently has full write access to your system and keys.
6. **No secret is stored in plaintext**: API keys and discovered keys are
   always displayed masked.

> [!WARNING]
> The dashboard has full write access to your system and keys. Never expose its port to the internet.

### Suggested next steps

All previously suggested items have been added (11 complete hunters). For
further expansion:

- Expand the parameter wordlist in ParamMinerHunter (currently 61; full arjun has 25,000+)
- Add a CSRF token validation checker
- Automatic report submission to the HackerOne/Bugcrowd API (currently only creates drafts)

### Regression tests

```bash
python -m pytest -q test_recon_httpx.py test_recon_integration.py
python -m compileall -q .
```

The Recon tests run without network access and verify that the
ProjectDiscovery binary is selected even when `venv/bin/httpx` exists.

### Final release: queue & verification hardening

- Same-run task deduplication with canonical URL targets.
- Old unfinished queue entries are purged when a new scan starts.
- Findings are deduplicated by logical finding signature.
- Param Miner uses multi-sample baselines, differential checks, and repeatability before creating a candidate.
- `candidate` and `verified` remain separate states; hidden-parameter candidates are not auto-verified vulnerabilities.
- Planning retries once on transient LLM errors and rejects unsupported hunter names.

<p align="right"><a href="#bug-bounty-multi-agent-system-overseerhunter">⬆ Back to top / بازگشت به بالا</a></p>
