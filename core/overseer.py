"""
core/overseer.py

Overseer چند کار می‌کنه:
1) seed_recon: تسک اولیه‌ی recon رو برای هر دامنه‌ی scope می‌سازه.
2) seed_vuln_hunters_from_recon: بعد از هر recon، به‌صورت قطعی (نه با
   حدس LLM) URLهایی که پارامتر دارن رو به idor/xss می‌فرسته و
   هاست‌های زنده رو به nuclei.
3) plan_next_steps (اختیاری/تکمیلی): از Gemini API می‌پرسه با توجه به
   نتایج، تسک اضافه‌ی دیگه‌ای هم لازمه یا نه.

نکته‌ی حیاتی طراحی: LLM هیچ‌وقت مستقیم subprocess صدا نمی‌زنه و هیچ‌وقت
مستقیم به scope.json دسترسی نداره که تغییرش بده. خروجی Gemini فقط یه
لیست از "target + hunter name" پیشنهادیه؛ قبل از این‌که واقعاً صف بشه،
از همون ScopeGuard رد می‌شه. یعنی حتی اگه Gemini به‌خاطر prompt
injection توی محتوای یه صفحه‌ی وب هالوسینیت کنه و بگه "برو google.com
رو اسکن کن"، ScopeGuard جلوش رو می‌گیره.

seed_vuln_hunters_from_recon عمداً deterministic نوشته شده (نه وابسته
به تصمیم LLM) چون قابل‌اعتمادتره: هر URL با پارامتر باید حتماً تست بشه،
نه فقط وقتی Gemini تصادفاً پیشنهادش داد.
"""

from __future__ import annotations
import json
import time
from pathlib import Path
from urllib.parse import urlparse

from core.logger import log
from core.scope import ScopeGuard, ScopeViolationError, normalize_hostname
from core.task_store import TaskStore, canonical_target
from core.diff_store import DiffStore
from core.knowledge_store import KnowledgeStore
from core.llm_client import GeminiTextClient, DEFAULT_MODEL, strip_json_fences

ALLOWED_PLANNING_HUNTERS = {"recon", "idor", "xss", "nuclei", "cors_redirect", "ssrf", "param_miner", "secrets", "takeover", "template_forge"}

# دیفالت‌های db_path/diff_db_path/knowledge_db_path پایین قبلاً رشته‌ی
# relative بودن ("tasks.db" و غیره). چون Overseer هم از main.py (CWD =
# ریشه‌ی پروژه) و هم از داشبورد (CWD = dashboard/) صدا زده می‌شه، یه
# caller که این آرگومان‌ها رو صریح پاس نده (این دقیقاً همون چیزیه که
# قبلاً برای diff_db_path/knowledge_db_path از scan_runner.py اتفاق
# می‌افتاد) یه فایل دیتابیس جدا و اشتباه زیر dashboard/ می‌ساخت --
# جدا از فایلی که بقیه‌ی سیستم واقعاً می‌خونه. برای امنیت در برابر
# همین اشتباه (چه توی این نسخه چه در آینده)، دیفالت‌ها الان مطلق و
# ریشه‌شون در PROJECT_ROOT (نه CWD) هستن.
PROJECT_ROOT = Path(__file__).resolve().parent.parent

PLANNING_SYSTEM_PROMPT = """تو بخش planning یک سیستم bug bounty خودکار هستی.
فقط باید یک آرایه‌ی JSON از تسک‌های تکمیلی پیشنهادی برگردونی، هیچ توضیح اضافه‌ای نده.
هر آیتم باید این شکل باشه:
{"hunter": "recon" | "idor" | "xss" | "nuclei", "target": "<domain or url>", "reason": "..."}
تسک‌های اصلی idor/xss/nuclei از قبل به‌صورت خودکار (نه با کمک تو) برای
همه‌ی URLهای مرتبط ساخته می‌شن؛ فقط اگه چیز اضافه‌ای لازمه که سیستم قطعی
از قلم انداخته پیشنهاد بده. تو هیچ اختیاری برای تعیین scope نداری - فقط
target پیشنهاد بده، تصمیم نهایی رو یک سیستم جدا (خارج از کنترل تو) می‌گیره."""


class Overseer:
    def __init__(self, scope_file: str, db_path: str | None = None, model: str = DEFAULT_MODEL,
                 diff_db_path: str | None = None, knowledge_db_path: str | None = None,
                 run_id: str | None = None):
        db_path = db_path or str(PROJECT_ROOT / "tasks.db")
        diff_db_path = diff_db_path or str(PROJECT_ROOT / "diff.db")
        knowledge_db_path = knowledge_db_path or str(PROJECT_ROOT / "knowledge.db")
        self.scope = ScopeGuard(scope_file)
        self.store = TaskStore(db_path)
        self.diff_store = DiffStore(diff_db_path)
        self.knowledge = KnowledgeStore(knowledge_db_path)
        self.model = model
        self.run_id = run_id
        self.client = GeminiTextClient(model=self.model)


    def seed_recon(self):
        """Seed exactly one host-level Recon task per unique in-scope root.

        Scope entries are normalized to hostnames, so pasted URLs never seed
        /robots.txt, /sitemap.xml, or any other path as a Recon target.
        """
        roots = []
        seen = set()
        for pattern in self.scope.in_scope:
            root = normalize_hostname(pattern.lstrip("*."))
            if root and root not in seen:
                seen.add(root)
                roots.append(root)
                self.store.add_task_unique(hunter="recon", target=root, run_id=self.run_id)
        log(f"[overseer] {len(roots)} تسک recon اولیه ثبت شد")

    def seed_vuln_hunters_from_recon(self, recon_result: dict, use_diff: bool = True) -> dict:
        """Build a broader deterministic attack surface from recon.

        Design goals:
        - never depend on the LLM for mandatory coverage;
        - schedule IDOR only for ID-like path/query locations;
        - schedule XSS/CORS on dynamic in-scope URLs, not only URLs with `?`;
        - keep SSRF focused on parameterized URLs;
        - run Nuclei on every live host;
        - keep takeover checks on discovered in-scope hostnames;
        - de-duplicate work through DiffStore.
        """
        counts = {
            "idor": 0, "xss": 0, "cors_redirect": 0, "ssrf": 0,
            "nuclei": 0, "template_forge": 0, "takeover": 0,
            "secrets": 0, "param_miner": 0,
        }
        program = self.scope.program_name

        def enqueue(hunter: str, target: str, payload: dict | None, counter: str | None = None):
            _, created = self.store.add_task_unique(hunter=hunter, target=target, payload=payload, run_id=self.run_id)
            if created and counter:
                counts[counter] += 1
            return created

        def fresh(items, kind):
            items = [canonical_target(x) for x in items if isinstance(x, str)]
            items = [x for x in dict.fromkeys(items) if self.scope.check(x).allowed]
            return self.diff_store.filter_new(items, kind, program) if use_diff else items

        urls = [u for u in recon_result.get("urls", []) if isinstance(u, str)]
        in_scope_urls = fresh(urls, "crawled_url")

        # All dynamic-looking pages get reflected-input, CORS and redirect checks.
        # The hunters themselves remain conservative about what they actually probe.
        dynamic_urls = [u for u in in_scope_urls if "?" in u or "/" in urlparse(u).path]
        for url in dynamic_urls:
            enqueue("xss", url, {"url": url}, "xss")
            enqueue("cors_redirect", url, {"url": url}, "cors_redirect")

        # IDOR/SSRF need stronger signals before probing.
        param_urls = [u for u in in_scope_urls if "?" in u]
        idor_urls = []
        try:
            from hunters.idor_hunter import find_id_like_params, find_id_like_path_segments
            for url in in_scope_urls:
                if find_id_like_params(url) or find_id_like_path_segments(url):
                    idor_urls.append(url)
        except Exception:
            idor_urls = param_urls

        for url in fresh(idor_urls, "idor_url"):
            enqueue("idor", url, {"url": url}, "idor")

        for url in fresh(param_urls, "ssrf_url"):
            enqueue("ssrf", url, {"url": url}, "ssrf")

        # Secrets and parameter discovery operate on the full in-scope URL set.
        for url in in_scope_urls:
            enqueue("secrets", url, {"url": url}, "secrets")

        for url in fresh(in_scope_urls, "param_miner_url"):
            enqueue("param_miner", url, {"url": url}, "param_miner")

        live_hosts = fresh(recon_result.get("live_hosts", []), "live_host")
        for host in live_hosts:
            enqueue("nuclei", host, None, "nuclei")
            enqueue("template_forge", host, {"url": host}, "template_forge")

        subdomains = fresh(recon_result.get("subdomains", []), "subdomain")
        for host in subdomains:
            enqueue("takeover", host, None, "takeover")

        diff_note = " (حالت افتراقی فعاله؛ فقط asset های جدید)" if use_diff else " (حالت افتراقی غیرفعاله؛ اسکن کامل)"
        log(
            f"[overseer] از روی recon{diff_note}: "
            f"{counts['idor']} تسک IDOR، {counts['xss']} تسک XSS، "
            f"{counts['cors_redirect']} تسک CORS/Redirect، {counts['ssrf']} تسک SSRF، "
            f"{counts['nuclei']} تسک nuclei، {counts['template_forge']} تسک Template Forge، "
            f"{counts['param_miner']} تسک Param Miner، {counts['takeover']} تسک takeover، "
            f"{counts['secrets']} تسک secrets ثبت شد"
        )
        return counts

    def plan_next_steps(self, context: dict) -> list[dict]:
        """از Gemini می‌خواد تسک تکمیلی پیشنهاد بده (فقط چیزی که سیستم
        قطعی از قلم انداخته). خروجی قبل از صف‌شدن از ScopeGuard رد می‌شه.

        اگه یادداشت‌های آموزشی (از بخش «آموزش هانترها» توی داشبورد) وجود
        داشته باشن، به‌عنوان context اضافه به Gemini داده می‌شن تا
        پیشنهادهاش آگاهانه‌تر باشن. این کاملاً امنه چون خروجی Gemini
        همیشه، حتی وقتی از یادداشت‌های آموزشی الهام گرفته، باز از
        ScopeGuard رد می‌شه قبل از صف‌شدن -- یعنی حتی اگه یه یادداشت
        (متن ورودی از کاربر) دستکاری‌شده باشه، نمی‌تونه هدف خارج از
        scope رو صف کنه."""
        system_prompt = PLANNING_SYSTEM_PROMPT
        notes = self.knowledge.for_context(limit=10)
        if notes:
            excerpts = [
                f"### {n['title']} (مرتبط با: {n['hunter']})\n{n['content'][:800]}"
                for n in notes
            ]
            system_prompt += (
                "\n\nیادداشت‌های آموزشی که محقق قبلاً جمع کرده (می‌تونی برای "
                "پیشنهاد تسک‌های هوشمندانه‌تر ازشون الهام بگیری، ولی هیچ‌وقت "
                "این یادداشت‌ها اختیار تعیین scope رو بهت نمی‌دن):\n\n"
                + "\n\n".join(excerpts)
            )

        raw = None
        last_error = None
        for attempt in range(2):
            try:
                raw = self.client.generate_text(
                    system_prompt=system_prompt,
                    user_content=json.dumps(context, ensure_ascii=False),
                    max_output_tokens=1024,
                )
                break
            except Exception as exc:
                last_error = exc
                if attempt == 0:
                    time.sleep(0.8)
        if raw is None:
            log(f"[overseer] planning پس از retry رد شد: {last_error}")
            return []

        try:
            proposals = json.loads(strip_json_fences(raw))
        except json.JSONDecodeError:
            log("[overseer] پاسخ planning قابل‌پارس نبود، نادیده گرفته شد")
            return []

        accepted = []
        for p in proposals:
            # این حلقه باید در برابر خروجی بدشکل یا ناقص LLM هم مقاوم باشه،
            # نه فقط در برابر هدف خارج از scope. قبلاً یه proposal بدون
            # کلید "target" (یا "hunter") کل فراخوانی رو با KeyError
            # می‌ترکوند -- یعنی هر پیشنهاد معتبر دیگه‌ای که بعدش توی همون
            # لیست بود هم بی‌صدا از دست می‌رفت. این با تست مستقیم پیدا شد.
            if not isinstance(p, dict) or "target" not in p or "hunter" not in p:
                log(f"[overseer] پیشنهاد بدشکل نادیده گرفته شد (فیلد hunter/target نداشت): {p!r}")
                continue
            if p.get("hunter") not in ALLOWED_PLANNING_HUNTERS:
                log(f"[overseer] هانتر planning غیرمجاز نادیده گرفته شد: {p.get('hunter')!r}")
                continue
            try:
                requested_target = p["target"]
                if p["hunter"] == "recon":
                    requested_target = normalize_hostname(requested_target)
                    if not requested_target:
                        log(f"[overseer] پیشنهاد recon بدون hostname نادیده گرفته شد: {p!r}")
                        continue
                safe_target = self.scope.enforce(requested_target)
                self.store.add_task_unique(hunter=p["hunter"], target=safe_target, payload={"reason": p.get("reason"), "url": safe_target}, run_id=self.run_id)
                accepted.append({**p, "target": safe_target})
            except ScopeViolationError as e:
                log(f"[overseer] پیشنهاد رد شد: {e}")
        return accepted

    def report(self) -> dict:
        return self.store.board()
