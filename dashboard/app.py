"""
dashboard/app.py

داشبورد مدیریتی کامل تحت وب. برخلاف نسخه‌ی اول (که فقط read-only بود)،
این نسخه می‌تونه:
- اسکن رو شروع/متوقف کنه (core/scan_runner.py)
- دامنه‌های مجاز (scope) رو مدیریت کنه
- هانترها رو تک‌تک روشن/خاموش کنه
- API keyها و sessionهای تست رو ذخیره/نمایش (masked) کنه
- گزارش/رایتاپ هر finding رو نشون بده و وضعیت ارسال/پاداشش رو ثبت کنه
- تاریخچه‌ی اجراها و چند-برنامه‌ای (Programs) رو مدیریت کنه

⚠️ هشدار امنیتی مهم: این داشبورد write-access کامل به سیستم داره
(می‌تونه اسکن اجرا کنه، scope رو عوض کنه، API key رو ببینه/عوض کنه).
فقط روی 127.0.0.1 (لوکال) اجرا می‌شه. **هیچ‌وقت این پورت رو به اینترنت
expose نکن** (نه با 0.0.0.0، نه با port forwarding، نه با ngrok) —
هر کسی که بهش دسترسی پیدا کنه عملاً کنترل کامل ابزار امنیتی‌ت و
کلیدهات رو به دست میاره.
"""

from __future__ import annotations
import sys
import os
import json
import secrets
import shutil
from pathlib import Path
from datetime import datetime, timezone

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from flask import Flask, render_template, jsonify, request, abort

from core.task_store import TaskStore
from core.scope import normalize_scope_pattern
from core.findings_store import FindingsStore
from core.runs_store import RunsStore
from core.diff_store import DiffStore
from core.knowledge_store import KnowledgeStore
from core.logger import tail_log
from core import scan_runner

app = Flask(__name__)

# --- CSRF protection --------------------------------------------------
# این داشبورد auth/session نداره (عمداً -- یه ابزار لوکال تک‌کاربره‌ست)،
# ولی همین یعنی هر endpoint تغییردهنده‌ای (POST) بدون این لایه در برابر
# CSRF کور آسیب‌پذیره: یه تب دیگه‌ی مرورگر که یه صفحه‌ی مخرب باز کرده،
# می‌تونه یه POST ساده (بدون نیاز به preflight چون Content-Type رو
# text/plain می‌ذاره) به مثلاً /api/scope/domain/add بزنه و یه دامنه‌ی
# دلخواه رو به in_scope اضافه کنه، بعد /api/scan/start رو صدا بزنه --
# یعنی ابزار امنیتی خودت رو بی‌اطلاع خودت علیه هدفی که هیچ برنامه‌ای
# مجازش نکرده مسلح کنه. توکن زیر رو در لحظه‌ی start فرآیند می‌سازیم،
# توی index.html embed می‌شه، و فرانت‌اند هر POST رو باهاش هدر می‌زنه.
# چون یه صفحه‌ی cross-origin نمی‌تونه این توکن رو بخونه (Same-Origin
# Policy) یا یه هدر دلخواه ست کنه بدون trigger کردن preflight‌ای که رد
# می‌شه (این سرور هیچ Access-Control-Allow-Origin ای نمی‌ده)، این کافیه.
CSRF_TOKEN = secrets.token_hex(32)
CSRF_HEADER = "X-CSRF-Token"
CSRF_EXEMPT_PATHS = set()  # فعلاً هیچ POST ای معاف نیست


@app.before_request
def _enforce_csrf():
    if request.method != "POST" or request.path in CSRF_EXEMPT_PATHS:
        return None
    sent = request.headers.get(CSRF_HEADER, "")
    if not secrets.compare_digest(sent, CSRF_TOKEN):
        return jsonify({"error": "CSRF token نامعتبر یا وجود نداره — صفحه‌ی داشبورد رو رفرش کن"}), 403
    return None


PROJECT_ROOT = Path(__file__).resolve().parent.parent
TASK_DB = str(PROJECT_ROOT / "tasks.db")
FINDINGS_DB = str(PROJECT_ROOT / "findings.db")
RUNS_DB = str(PROJECT_ROOT / "runs.db")
DIFF_DB = str(PROJECT_ROOT / "diff.db")
KNOWLEDGE_DB = str(PROJECT_ROOT / "knowledge.db")

SCOPE_FILE = PROJECT_ROOT / "config" / "scope.json"
SETTINGS_FILE = PROJECT_ROOT / "config" / "settings.json"
HUNTERS_ENABLED_FILE = PROJECT_ROOT / "config" / "hunters_enabled.json"
API_KEYS_FILE = PROJECT_ROOT / "config" / "api_keys.json"
AUTH_FILE = PROJECT_ROOT / "config" / "auth.json"
PROGRAMS_DIR = PROJECT_ROOT / "config" / "programs"

HUNTER_INFO = {
    "recon": {"label": "Recon", "desc": "subfinder → httpx → katana. پایه‌ی همه‌چیز؛ ساب‌دامین/URL پیدا می‌کنه."},
    "idor": {"label": "IDOR", "desc": "Broken Access Control و دسترسی cross-account با استفاده از session های تست."},
    "xss": {"label": "XSS", "desc": "Reflected XSS با تأیید واقعی از طریق headless browser (اگه Playwright نصب باشه)."},
    "cors_redirect": {"label": "CORS + Open Redirect", "desc": "Origin دلخواه رو تست می‌کنه (misconfiguration) و پارامترها رو برای ریدایرکت باز چک می‌کنه — دقیقاً روی همون URLهای IDOR/XSS."},
    "ssrf": {"label": "SSRF", "desc": "پارامترها رو با URL های داخلی/متادیتای ابری (169.254.169.254, localhost) عوض می‌کنه و reflect شدن محتوا رو چک می‌کنه؛ با تنظیم ssrf_oob_domain در تنظیمات، SSRF کور هم قابل تست می‌شه."},
    "nuclei": {"label": "Nuclei", "desc": "اسکن با هزاران تمپلیت عمومی برای CVE و misconfiguration شناخته‌شده."},
    "template_forge": {"label": "Template Forge", "desc": "تولید تمپلیت Nuclei سفارشی با AI بر اساس سیگنال‌های واقعی این هدف — نه تمپلیت‌های عمومی. با validation امنیتی قوی؛ اجرا پیش‌فرض غیرفعاله (فقط تولید و ذخیره)."},
    "param_miner": {"label": "Param Miner", "desc": "کشف پارامترهای مخفی (سبک arjun) که هیچ‌جا لینک نشدن ولی backend بهشون واکنش نشون می‌ده؛ وقتی پیدا کنه، فوراً همون URL رو برای IDOR/XSS/CORS/SSRF هم صف می‌کنه."},
    "takeover": {"label": "Subdomain Takeover", "desc": "دنبال CNAME های dangling می‌گرده (GitHub Pages, Heroku, S3, ...)."},
    "secrets": {"label": "Secrets", "desc": "کلید API / توکن هاردکدشده توی فایل‌های JS و منابع دیگه."},
    "diffscan": {"label": "Diff Scan (افتراقی)", "desc": "فقط asset های جدید نسبت به اسکن قبلی رو صف می‌کنه — خودش finding تولید نمی‌کنه، فقط سرعت رسیدن به asset های تازه رو بالا می‌بره."},
}

# این هانترها finding تولید می‌کنن؛ diffscan فرق داره (متریک جداگونه داره)
FINDING_PRODUCING_HUNTERS = {"recon", "idor", "xss", "cors_redirect", "ssrf", "nuclei", "template_forge", "param_miner", "takeover", "secrets"}


# ---------- کمکی‌ها ----------

def _load_json(path: Path, default):
    if not path.exists():
        return default
    return json.loads(path.read_text(encoding="utf-8"))


def _save_json(path: Path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")


def _mask(value: str | None) -> str:
    if not value:
        return ""
    if len(value) <= 8:
        return "*" * len(value)
    return f"{value[:4]}{'*' * (len(value) - 8)}{value[-4:]}"


def get_stores():
    return TaskStore(TASK_DB), FindingsStore(FINDINGS_DB)


# ---------- صفحه‌ی اصلی ----------

@app.route("/")
def index():
    return render_template("index.html", csrf_token=CSRF_TOKEN)


# ---------- خلاصه / Kanban / یافته‌ها ----------

@app.route("/api/summary")
def api_summary():
    tasks, findings = get_stores()
    return jsonify({
        "board": {k: len(v) for k, v in tasks.board().items()},
        "findings": findings.summary(),
        "earnings": findings.earnings_summary(),
        "scan_status": scan_runner.get_status(),
    })


@app.route("/api/board")
def api_board():
    tasks, _ = get_stores()
    return jsonify(tasks.board())


@app.route("/api/findings")
def api_findings():
    _, findings = get_stores()
    all_findings = findings.all_findings()
    for f in all_findings:
        try:
            f["evidence"] = json.loads(f["evidence"])
        except (json.JSONDecodeError, TypeError):
            pass
    return jsonify(all_findings)


@app.route("/api/findings/<finding_id>/report")
def api_finding_report(finding_id):
    _, findings = get_stores()
    finding = findings.get(finding_id)
    if not finding or not finding.get("report_path"):
        return jsonify({"error": "گزارشی برای این finding پیدا نشد"}), 404
    report_path = Path(finding["report_path"])
    if not report_path.exists():
        return jsonify({"error": "فایل گزارش روی دیسک پیدا نشد"}), 404
    return jsonify({"content": report_path.read_text(encoding="utf-8")})


@app.route("/api/findings/<finding_id>/verify", methods=["POST"])
def api_verify_finding(finding_id):
    _, findings = get_stores()
    data = request.get_json(silent=True) or {}
    verified = bool(data.get("verified", True))
    finding = findings.get(finding_id)
    if not finding:
        return jsonify({"error": "finding پیدا نشد"}), 404
    findings.mark_verified(finding_id, verified=verified)
    return jsonify({"ok": True, "verified": verified})


@app.route("/api/findings/<finding_id>/submission", methods=["POST"])
def api_update_submission(finding_id):
    _, findings = get_stores()
    data = request.get_json(force=True) or {}
    findings.update_submission(
        finding_id,
        submission_status=data.get("submission_status"),
        bounty_amount=data.get("bounty_amount"),
        bounty_currency=data.get("bounty_currency"),
        submitted_at=data.get("submitted_at"),
        platform=data.get("platform"),
    )
    return jsonify({"ok": True})


# ---------- هانترها ----------

@app.route("/api/hunters")
def api_hunters():
    enabled = _load_json(HUNTERS_ENABLED_FILE, {})
    _, findings = get_stores()
    all_findings = findings.all_findings()
    counts: dict[str, int] = {}
    for f in all_findings:
        counts[f["hunter"]] = counts.get(f["hunter"], 0) + 1

    scope = _load_json(SCOPE_FILE, {"program_name": ""})
    diff_store = DiffStore(DIFF_DB)
    diff_tracked = diff_store.stats(scope.get("program_name", "")).get("total_tracked", 0)

    result = []
    for name, info in HUNTER_INFO.items():
        if name in FINDING_PRODUCING_HUNTERS:
            metric_label, metric_value = "یافته‌ها", counts.get(name, 0)
        else:
            metric_label, metric_value = "Asset ردیابی‌شده", diff_tracked
        result.append({
            "name": name,
            "label": info["label"],
            "description": info["desc"],
            "enabled": enabled.get(name, True),
            "metric_label": metric_label,
            "metric_value": metric_value,
        })
    return jsonify(result)


@app.route("/api/hunters/toggle", methods=["POST"])
def api_toggle_hunter():
    data = request.get_json(force=True) or {}
    hunter = data.get("hunter")
    enabled = bool(data.get("enabled", True))
    if hunter not in HUNTER_INFO:
        return jsonify({"error": "هانتر ناشناخته"}), 400
    current = _load_json(HUNTERS_ENABLED_FILE, {})
    current[hunter] = enabled
    _save_json(HUNTERS_ENABLED_FILE, current)
    return jsonify({"ok": True})


@app.route("/api/diffscan/reset", methods=["POST"])
def api_reset_diffscan():
    """تاریخچه‌ی asset های دیده‌شده رو برای برنامه‌ی فعال پاک می‌کنه —
    دور بعدی اسکن، همه‌چیز دوباره 'جدید' حساب می‌شه (اسکن کامل)."""
    scope = _load_json(SCOPE_FILE, {"program_name": ""})
    program_name = scope.get("program_name", "")
    diff_store = DiffStore(DIFF_DB)
    diff_store.reset(program_name)
    return jsonify({"ok": True})


# ---------- آموزش هانترها (Knowledge Base) ----------

@app.route("/api/knowledge")
def api_list_knowledge():
    ks = KnowledgeStore(KNOWLEDGE_DB)
    return jsonify(ks.all_notes())


@app.route("/api/knowledge", methods=["POST"])
def api_add_knowledge():
    data = request.get_json(force=True) or {}
    hunter = (data.get("hunter") or "general").strip()
    title = (data.get("title") or "").strip()
    content = (data.get("content") or "").strip()
    source_url = (data.get("source_url") or "").strip()

    if not title or not content:
        return jsonify({"error": "عنوان و متن یادداشت نمی‌تونن خالی باشن"}), 400
    if hunter not in {**HUNTER_INFO, "general": {}}:
        return jsonify({"error": "هانتر ناشناخته"}), 400

    ks = KnowledgeStore(KNOWLEDGE_DB)
    note_id = ks.add(hunter=hunter, title=title, content=content, source_url=source_url)
    return jsonify({"ok": True, "id": note_id})


@app.route("/api/knowledge/<note_id>/delete", methods=["POST"])
def api_delete_knowledge(note_id):
    ks = KnowledgeStore(KNOWLEDGE_DB)
    ks.delete(note_id)
    return jsonify({"ok": True})


@app.route("/api/knowledge/<note_id>/suggest", methods=["POST"])
def api_suggest_patterns(note_id):
    """از روی یه یادداشت، پیشنهاد الگوی جدید می‌سازه -- فقط پیشنهاد،
    هیچ فایلی خودکار تغییر نمی‌کنه."""
    ks = KnowledgeStore(KNOWLEDGE_DB)
    note = ks.get(note_id)
    if not note:
        return jsonify({"error": "یادداشت پیدا نشد"}), 404

    _apply_api_key_for_advisor()

    try:
        from core.pattern_advisor import suggest_patterns
        suggestions = suggest_patterns(hunter=note["hunter"], note_content=note["content"])
        return jsonify({"suggestions": suggestions})
    except Exception as e:
        return jsonify({"error": f"خطا در گرفتن پیشنهاد: {e}"}), 500


def _apply_api_key_for_advisor():
    """قبل از صدا زدن pattern_advisor، اگه کلید از داشبورد ذخیره شده،
    اونو به‌عنوان متغیر محیطی ست می‌کنه (همون منطقی که scan_runner هم
    برای Overseer استفاده می‌کنه)."""
    keys = _load_json(API_KEYS_FILE, {})
    if keys.get("gemini_api_key"):
        os.environ["GEMINI_API_KEY"] = keys["gemini_api_key"]


# ---------- API Keys ----------

@app.route("/api/keys")
def api_get_keys():
    keys = _load_json(API_KEYS_FILE, {})
    auth = _load_json(AUTH_FILE, {})
    return jsonify({
        "gemini_api_key_masked": _mask(keys.get("gemini_api_key")),
        "gemini_api_key_set": bool(keys.get("gemini_api_key")),
        "session_a_cookie_masked": _mask((auth.get("session_a") or {}).get("cookie")),
        "session_a_set": bool((auth.get("session_a") or {}).get("cookie")),
        "session_b_cookie_masked": _mask((auth.get("session_b") or {}).get("cookie")),
        "session_b_set": bool((auth.get("session_b") or {}).get("cookie")),
    })


@app.route("/api/keys/gemini", methods=["POST"])
def api_set_gemini_key():
    data = request.get_json(force=True) or {}
    value = (data.get("api_key") or "").strip()
    if not value:
        return jsonify({"error": "کلید نمی‌تونه خالی باشه"}), 400
    current = _load_json(API_KEYS_FILE, {})
    current["gemini_api_key"] = value
    _save_json(API_KEYS_FILE, current)
    return jsonify({"ok": True, "masked": _mask(value)})


@app.route("/api/keys/session", methods=["POST"])
def api_set_session():
    data = request.get_json(force=True) or {}
    slot = data.get("slot")  # "session_a" یا "session_b"
    if slot not in ("session_a", "session_b"):
        return jsonify({"error": "slot باید session_a یا session_b باشه"}), 400
    current = _load_json(AUTH_FILE, {})
    current[slot] = {
        "cookie": data.get("cookie", ""),
        "headers": {"Authorization": data.get("authorization", "")},
    }
    _save_json(AUTH_FILE, current)
    return jsonify({"ok": True})


# ---------- Scope / دامنه‌های مجاز ----------

@app.route("/api/scope")
def api_get_scope():
    scope = _load_json(SCOPE_FILE, {"program_name": "", "in_scope": [], "out_of_scope": []})
    return jsonify(scope)


@app.route("/api/scope/program_name", methods=["POST"])
def api_set_program_name():
    data = request.get_json(force=True) or {}
    scope = _load_json(SCOPE_FILE, {"program_name": "", "in_scope": [], "out_of_scope": []})
    scope["program_name"] = data.get("name", "").strip()
    _save_json(SCOPE_FILE, scope)
    return jsonify({"ok": True})


@app.route("/api/scope/domain/add", methods=["POST"])
def api_add_domain():
    data = request.get_json(force=True) or {}
    list_name = data.get("list")  # "in_scope" یا "out_of_scope"
    domain = normalize_scope_pattern(str(data.get("domain") or ""))
    if list_name not in ("in_scope", "out_of_scope") or not domain:
        return jsonify({"error": "دامنه/URL نامعتبر است"}), 400
    scope = _load_json(SCOPE_FILE, {"program_name": "", "in_scope": [], "out_of_scope": []})
    if domain not in scope.get(list_name, []):
        scope.setdefault(list_name, []).append(domain)
    _save_json(SCOPE_FILE, scope)
    return jsonify({"ok": True, "scope": scope})


@app.route("/api/scope/domain/remove", methods=["POST"])
def api_remove_domain():
    data = request.get_json(force=True) or {}
    list_name = data.get("list")
    domain = (data.get("domain") or "").strip().lower()
    scope = _load_json(SCOPE_FILE, {"program_name": "", "in_scope": [], "out_of_scope": []})
    if list_name in scope and domain in scope[list_name]:
        scope[list_name].remove(domain)
    _save_json(SCOPE_FILE, scope)
    return jsonify({"ok": True, "scope": scope})


# ---------- چند-برنامه‌ای (Programs) ----------

@app.route("/api/programs")
def api_list_programs():
    PROGRAMS_DIR.mkdir(parents=True, exist_ok=True)
    names = [p.stem for p in PROGRAMS_DIR.glob("*.json")]
    return jsonify(sorted(names))


@app.route("/api/programs/save", methods=["POST"])
def api_save_program():
    data = request.get_json(force=True) or {}
    name = (data.get("name") or "").strip()
    if not name:
        return jsonify({"error": "اسم برنامه نمی‌تونه خالی باشه"}), 400
    if not SCOPE_FILE.exists():
        return jsonify({"error": "هنوز scope.json فعالی وجود نداره"}), 400
    PROGRAMS_DIR.mkdir(parents=True, exist_ok=True)
    safe_name = "".join(c for c in name if c.isalnum() or c in "-_")
    if not safe_name:
        return jsonify({"error": "اسم برنامه نامعتبره"}), 400
    shutil.copy(SCOPE_FILE, PROGRAMS_DIR / f"{safe_name}.json")
    return jsonify({"ok": True})


@app.route("/api/programs/load", methods=["POST"])
def api_load_program():
    data = request.get_json(force=True) or {}
    name = (data.get("name") or "").strip()
    # همون sanitize ای که save می‌کنه -- وگرنه یه name مثل "../../../x"
    # می‌تونه هر فایل JSON دلخواهی رو (نه فقط چیزی که خودمون توی
    # PROGRAMS_DIR ساختیم) بخونه و روی scope.json کپی کنه.
    safe_name = "".join(c for c in name if c.isalnum() or c in "-_")
    if not safe_name:
        return jsonify({"error": "اسم برنامه نامعتبره"}), 400
    src = PROGRAMS_DIR / f"{safe_name}.json"
    if not src.exists():
        return jsonify({"error": "این برنامه پیدا نشد"}), 404
    shutil.copy(src, SCOPE_FILE)
    return jsonify({"ok": True, "scope": _load_json(SCOPE_FILE, {})})


# ---------- کنترل اسکن ----------

@app.route("/api/scan/start", methods=["POST"])
def api_start_scan():
    scope = _load_json(SCOPE_FILE, {})
    if not scope.get("in_scope"):
        return jsonify({"error": "اول باید حداقل یه دامنه‌ی in_scope تنظیم کنی (بخش دامنه‌ها)"}), 400
    started = scan_runner.run_scan_in_background()
    if not started:
        return jsonify({"error": "یه اسکن از قبل در حال اجراست"}), 409
    return jsonify({"ok": True})


@app.route("/api/scan/stop", methods=["POST"])
def api_stop_scan():
    scan_runner.request_stop()
    return jsonify({"ok": True})


@app.route("/api/scan/status")
def api_scan_status():
    return jsonify(scan_runner.get_status())


@app.route("/api/logs")
def api_logs():
    n = request.args.get("n", 200, type=int)
    return jsonify(tail_log(n))


# ---------- تاریخچه ----------

@app.route("/api/runs")
def api_runs():
    runs = RunsStore(RUNS_DB)
    return jsonify(runs.all_runs())


# ---------- تنظیمات ----------

@app.route("/api/settings")
def api_get_settings():
    return jsonify(_load_json(SETTINGS_FILE, {
        "requests_per_second": 5, "http_timeout_seconds": 10,
        "ssrf_oob_domain": "", "template_forge_auto_execute": False,
    }))


@app.route("/api/settings", methods=["POST"])
def api_save_settings():
    data = request.get_json(force=True) or {}
    settings = _load_json(SETTINGS_FILE, {})
    if "requests_per_second" in data:
        value = float(data["requests_per_second"])
        if not 0.1 <= value <= 50:
            return jsonify({"error": "requests_per_second باید بین 0.1 و 50 باشد"}), 400
        settings["requests_per_second"] = value
    if "http_timeout_seconds" in data:
        value = int(data["http_timeout_seconds"])
        if not 1 <= value <= 120:
            return jsonify({"error": "http_timeout_seconds باید بین 1 و 120 باشد"}), 400
        settings["http_timeout_seconds"] = value
    if "ssrf_oob_domain" in data:
        settings["ssrf_oob_domain"] = (data["ssrf_oob_domain"] or "").strip()
    if "template_forge_auto_execute" in data:
        settings["template_forge_auto_execute"] = bool(data["template_forge_auto_execute"])
    _save_json(SETTINGS_FILE, settings)
    return jsonify({"ok": True})


if __name__ == "__main__":
    print("داشبورد در حال اجرا روی http://127.0.0.1:5000")
    print("⚠️  این پورت رو هیچ‌وقت به اینترنت expose نکن (فقط 127.0.0.1).")
    app.run(host="127.0.0.1", port=5000, debug=False)
