"""
core/scan_runner.py

منطق کامل اجرای یک دور اسکن (recon → seed هانترها → اجرای هانترها →
تولید گزارش). این ماژول هم از خط‌فرمان (main.py) و هم از داشبورد وب
صدا زده می‌شه — یه نسخه‌ی واحد از منطق، دو تا نقطه‌ی ورود.

از داشبورد، run_scan_in_background() یه thread جدا باز می‌کنه تا Flask
همچنان بتونه به درخواست‌های دیگه (وضعیت، لاگ زنده و غیره) جواب بده.
وضعیت اسکن (idle/running/completed/error/stopped) توی یه متغیر global
با lock نگه‌داری می‌شه.

توقف اسکن (stop) "نرم" هست: بین هر تسک چک می‌شه، نه وسط یه درخواست HTTP
در حال اجرا؛ یعنی ممکنه چند ثانیه طول بکشه تا واقعاً متوقف بشه.
"""

from __future__ import annotations
import os
import json
import threading
import uuid
from pathlib import Path
from datetime import datetime, timezone

from core.overseer import Overseer
from core.findings_store import FindingsStore
from core.rate_limiter import RateLimiter
from core.report_generator import generate_all_reports
from core.runs_store import RunsStore
from core.logger import log, clear_log
from hunters.recon_hunter import ReconHunter
from hunters.idor_hunter import IDORHunter
from hunters.xss_hunter import XSSHunter
from hunters.cors_redirect_hunter import CorsRedirectHunter
from hunters.ssrf_hunter import SSRFHunter
from hunters.nuclei_hunter import NucleiHunter
from hunters.template_forge_hunter import TemplateForgeHunter
from hunters.param_miner_hunter import ParamMinerHunter
from hunters.takeover_hunter import TakeoverHunter
from hunters.secrets_hunter import SecretsHunter

# قبلاً این مسیرها رشته‌ی relative بودن ("config/scope.json" و غیره).
# این فایل هم از main.py (CWD = ریشه‌ی پروژه) و هم از داشبورد (که طبق
# راهنما با «cd dashboard && python app.py» اجرا می‌شه، یعنی CWD =
# dashboard/) صدا زده می‌شه. با مسیر relative، وقتی از داشبورد اجرا
# می‌شد دنبال dashboard/config/scope.json می‌گشت که وجود نداره -- یعنی
# دکمه‌ی «شروع اسکن» همیشه فوری با خطای «scope file پیدا نشد» شکست
# می‌خورد (این با تست مستقیم پیدا شد: دقیقاً همون سناریوی مستندشده‌ی
# راهنما رو اجرا کردم و خطا رو گرفتم). حالا مثل dashboard/app.py از
# PROJECT_ROOT مطلق استفاده می‌کنیم تا هر دو نقطه‌ی ورود دقیقاً همون
# فایل‌ها (config، tasks.db، findings.db، runs.db، reports/) رو بخونن
# و بنویسن -- نه یه کپی جدا زیر دایرکتوری دیگه.
PROJECT_ROOT = Path(__file__).resolve().parent.parent
SCOPE_FILE = str(PROJECT_ROOT / "config" / "scope.json")
SETTINGS_FILE = str(PROJECT_ROOT / "config" / "settings.json")
HUNTERS_ENABLED_FILE = str(PROJECT_ROOT / "config" / "hunters_enabled.json")
API_KEYS_FILE = str(PROJECT_ROOT / "config" / "api_keys.json")
TASK_DB = str(PROJECT_ROOT / "tasks.db")
FINDINGS_DB = str(PROJECT_ROOT / "findings.db")
RUNS_DB = str(PROJECT_ROOT / "runs.db")
REPORTS_DIR = str(PROJECT_ROOT / "reports")

_status_lock = threading.Lock()
_status = {"state": "idle", "message": "", "started_at": None, "finished_at": None}
_stop_event = threading.Event()


def get_status() -> dict:
    with _status_lock:
        return dict(_status)


def _set_status(**kwargs):
    with _status_lock:
        _status.update(kwargs)


def request_stop():
    _stop_event.set()


def _load_json(path: str, default):
    p = Path(path)
    if not p.exists():
        return default
    return json.loads(p.read_text(encoding="utf-8"))


def _apply_api_key_from_file():
    """اگه از داشبورد یه API key ذخیره شده، اونو به‌عنوان متغیر محیطی
    ست می‌کنه تا Overseer بتونه ازش استفاده کنه. اگه فایل نبود یا خالی
    بود، از GEMINI_API_KEY محیطی موجود استفاده می‌شه (بدون تغییر)."""
    keys = _load_json(API_KEYS_FILE, {})
    if keys.get("gemini_api_key"):
        os.environ["GEMINI_API_KEY"] = keys["gemini_api_key"]


def run_scan():
    """اجرای همزمان (blocking) یک دور کامل اسکن. هم از CLI هم از
    background thread داشبورد صدا زده می‌شه."""
    run_id = None
    runs = RunsStore(RUNS_DB)
    try:
        _set_status(
            state="running", message="در حال شروع...",
            started_at=datetime.now(timezone.utc).isoformat(), finished_at=None,
        )
        clear_log()  # لاگ اسکن قبلی رو پاک کن تا لاگ تازه و مرتبط باشه
        _apply_api_key_from_file()

        settings = _load_json(SETTINGS_FILE, {"requests_per_second": 5})
        enabled = _load_json(HUNTERS_ENABLED_FILE, {
            "recon": True, "idor": True, "xss": True, "cors_redirect": True, "ssrf": True,
            "nuclei": True, "template_forge": True, "param_miner": True,
            "takeover": True, "secrets": True, "diffscan": True,
        })
        use_diff = enabled.get("diffscan", True)

        rate_limiter = RateLimiter(requests_per_second=settings.get("requests_per_second", 5))
        # Each scan gets its own run id. Unfinished work from an older/interrupted
        # run is stale because the queue is seeded deterministically from fresh recon.
        run_id = str(uuid.uuid4())
        overseer = Overseer(scope_file=SCOPE_FILE, db_path=TASK_DB,
                             diff_db_path=str(PROJECT_ROOT / "diff.db"),
                             knowledge_db_path=str(PROJECT_ROOT / "knowledge.db"),
                             run_id=run_id)
        cleared = overseer.store.purge_pending()
        if cleared:
            log(f"[queue] {cleared} تسک معلق قدیمی پاک شد")
        findings = FindingsStore(FINDINGS_DB)
        runs.start_run(program_name=overseer.scope.program_name, run_id=run_id)

        hunters = {
            "recon": ReconHunter(scope=overseer.scope, store=overseer.store, findings=findings, rate_limiter=rate_limiter),
            "idor": IDORHunter(scope=overseer.scope, store=overseer.store, findings=findings, rate_limiter=rate_limiter, auth_file=str(PROJECT_ROOT / "config" / "auth.json")),
            "xss": XSSHunter(scope=overseer.scope, store=overseer.store, findings=findings, rate_limiter=rate_limiter),
            "cors_redirect": CorsRedirectHunter(scope=overseer.scope, store=overseer.store, findings=findings, rate_limiter=rate_limiter),
            "ssrf": SSRFHunter(scope=overseer.scope, store=overseer.store, findings=findings, rate_limiter=rate_limiter, settings_file=SETTINGS_FILE),
            "nuclei": NucleiHunter(scope=overseer.scope, store=overseer.store, findings=findings, rate_limiter=rate_limiter),
            "template_forge": TemplateForgeHunter(scope=overseer.scope, store=overseer.store, findings=findings, rate_limiter=rate_limiter),
            "param_miner": ParamMinerHunter(scope=overseer.scope, store=overseer.store, findings=findings, rate_limiter=rate_limiter),
            "takeover": TakeoverHunter(scope=overseer.scope, store=overseer.store, findings=findings, rate_limiter=rate_limiter),
            "secrets": SecretsHunter(scope=overseer.scope, store=overseer.store, findings=findings, rate_limiter=rate_limiter),
        }
        for _hunter in hunters.values():
            _hunter.run_id = run_id

        if enabled.get("recon", True):
            overseer.seed_recon()
            _set_status(message="در حال اجرای Recon...")
            log("=== مرحله‌ی Recon ===")
            while not _stop_event.is_set():
                result = hunters["recon"].run_next()
                if result is None:
                    break
                log(f"[recon] {result['target']}: {len(result.get('subdomains', []))} ساب‌دامین, "
                    f"{len(result.get('live_hosts', []))} هاست زنده, {len(result.get('urls', []))} URL")
                if result.get("warning"):
                    log(f"[recon] ⚠️ {result['warning']}")
                overseer.seed_vuln_hunters_from_recon(result, use_diff=use_diff)
                try:
                    overseer.plan_next_steps(context=result)
                except Exception as e:
                    log(f"[overseer] planning skip شد: {e}")
        else:
            log("=== Recon غیرفعاله، رد شد ===")

        for hunter_name in ("takeover", "secrets", "param_miner", "idor", "xss", "cors_redirect", "ssrf", "nuclei", "template_forge"):
            if _stop_event.is_set():
                break
            if not enabled.get(hunter_name, True):
                log(f"=== {hunter_name} غیرفعاله، رد شد ===")
                continue
            _set_status(message=f"در حال اجرای {hunter_name}...")
            log(f"=== مرحله‌ی {hunter_name} ===")
            hunter = hunters[hunter_name]
            count = 0
            while not _stop_event.is_set():
                result = hunter.run_next()
                if result is None:
                    break
                count += 1
            log(f"[{hunter_name}] {count} تسک پردازش شد")

        all_findings = findings.all_findings()
        if all_findings:
            report_paths = generate_all_reports(all_findings, output_dir=REPORTS_DIR)
            for fid, path in report_paths:
                findings.set_report_path(fid, path)
            log(f"{len(report_paths)} گزارش draft ساخته شد در پوشه‌ی reports/")

        summary = findings.summary()
        final_status = "stopped" if _stop_event.is_set() else "completed"
        runs.finish_run(run_id, findings_count=summary["total"], status=final_status)

        _set_status(
            state=final_status,
            message=f"تمام شد. {summary['total']} یافته پیدا شد.",
            finished_at=datetime.now(timezone.utc).isoformat(),
        )
        log(f"=== پایان اسکن ({final_status}): {summary['total']} یافته ===")

    except Exception as e:
        log(f"❌ خطا در اجرای اسکن: {e}")
        if run_id:
            runs.finish_run(run_id, findings_count=0, status="error")
        _set_status(state="error", message=str(e), finished_at=datetime.now(timezone.utc).isoformat())


def run_scan_in_background() -> bool:
    """اسکن رو توی یه thread جدا شروع می‌کنه (برای داشبورد وب، تا Flask
    قفل نشه). اگه از قبل یه اسکن در حال اجراست، False برمی‌گردونه.
    
    چک وضعیت و شروع thread اتمیک انجام می‌شه (زیر _status_lock) تا دو
    درخواست همزمان نتونن هم‌زمان اسکن شروع کنن (TOCTOU race condition)."""
    with _status_lock:
        if _status["state"] == "running":
            return False
        _status["state"] = "running"
    _stop_event.clear()
    thread = threading.Thread(target=run_scan, daemon=True)
    thread.start()
    return True
