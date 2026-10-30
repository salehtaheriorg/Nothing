"""
hunters/template_forge_hunter.py

برخلاف NucleiHunter (که تمپلیت‌های عمومی و از پیش نوشته‌شده‌ی community
رو اجرا می‌کنه)، این هانتر از روی سیگنال‌های واقعی این هدف خاص (هدر
Server، محتوای صفحه، URLهای کراول‌شده) با کمک Gemini یه تمپلیت Nuclei
**مخصوص همین اپ** می‌سازه -- چیزی که هیچ تمپلیت عمومی‌ای پوششش نمی‌ده
چون مختص این استک تکنولوژی/رفتار خاصه، نه یه CVE شناخته‌شده.

⚠️ ملاحظات امنیتی مهم (چون این تنها هانتریه که محتوای HTTP probe رو
خود AI تولید می‌کنه، نه یه الگوی ثابت و از پیش بررسی‌شده):

1. **Validation اجباری**: هر تمپلیت تولیدشده قبل از هر استفاده‌ای باید
   YAML معتبر باشه، ساختار nuclei رو رعایت کنه، و از HTTP methodهای
   مخرب (DELETE/PUT/PATCH) یا کلیدواژه‌های مخرب (DROP TABLE، rm -rf و
   غیره) استفاده نکنه. اگه رد نشه، اصلاً ذخیره یا اجرا نمی‌شه.

2. **اجرا پیش‌فرض غیرفعاله**: با تنظیم `template_forge_auto_execute:
   false` (پیش‌فرض)، تمپلیت فقط تولید، validate، و روی دیسک ذخیره
   می‌شه -- **اجرا نمی‌شه**. باید دستی از تنظیمات داشبورد فعالش کنی تا
   خودش با nuclei روی هدف اجرا بشه. این عمداً محافظه‌کارانه‌ست: تمپلیتی
   که AI تولید کرده، حتی با validation، به‌اندازه‌ی تمپلیت‌های
   community-vetted قابل‌اعتماد نیست.

3. **شفافیت کامل**: کل YAML تولیدشده توی evidence هر finding ذخیره
   می‌شه تا بتونی دقیقاً ببینی چی نوشته شده، قبل از اینکه تصمیم بگیری
   اجراش کنی یا نه.
"""

from __future__ import annotations
import re
import json
from pathlib import Path

import requests
import yaml

from hunters.base_hunter import BaseHunter
from core.logger import log
from core.llm_client import GeminiTextClient, DEFAULT_MODEL, strip_json_fences

FORGE_SYSTEM_PROMPT = """تو داری یه تمپلیت Nuclei (YAML) برای تست
آسیب‌پذیری روی یه هدف خاص می‌سازی، بر اساس سیگنال‌هایی که از یه
درخواست HTTP واقعی به این هدف جمع‌آوری شده (هدرها، بخشی از محتوا).

قوانین اجباری:
- فقط یک آرایه‌ی JSON برگردون، هیچ توضیح اضافه‌ای نده
- هر آیتم این ساختار رو داره:
  {"title": "...", "severity": "info"|"low"|"medium"|"high"|"critical",
   "rationale": "چرا این تست بر اساس سیگنال‌های داده‌شده منطقیه",
   "template_yaml": "..."}
- template_yaml باید یه رشته‌ی YAML معتبر و کامل نیوکلای باشه (فیلدهای
  id, info, و http را شامل بشه)
- request method فقط GET, HEAD, یا POST مجازه -- هرگز DELETE/PUT/PATCH
- هیچ تمپلیتی نساز که واقعاً داده رو تغییر بده، حذف کنه، یا سیستم رو
  آسیب برسونه -- فقط تشخیص غیرمخرب (matcher روی header/body/status/
  زمان پاسخ برای تست blind، نه exploitation واقعی)
- اگه سیگنال‌های داده‌شده هیچ ایده‌ی تست معناداری نداد، آرایه‌ی خالی
  برگردون -- تمپلیت الکی نساز
- بیشتر از ۲ تمپلیت پیشنهاد نده"""

DANGEROUS_METHOD_PATTERN = re.compile(r"method\s*:\s*(delete|put|patch)", re.IGNORECASE)
DANGEROUS_KEYWORDS = [
    "drop table", "delete from", "truncate table", "rm -rf", "format c:",
    "shutdown", "wget http", "curl http", "; rm ", "&& rm ",
]

# id تمپلیت مستقیماً توی اسم فایل روی دیسک استفاده می‌شه
# (TEMPLATES_DIR / f"{template_id}.yaml")، پس باید یه شناسه‌ی ساده و
# امن باشه -- دقیقاً مثل خود nuclei که id رو یه slug می‌خواد، نه یه
# مسیر. اگه اینجا رد نشه، یه id مثل "../../etc/x" می‌تونه فایل رو
# خارج از TEMPLATES_DIR بنویسه (این چیزیه که با تست local اثبات و فیکس شد).
SAFE_TEMPLATE_ID_PATTERN = re.compile(r"^[A-Za-z0-9_-]+$")

TEMPLATES_DIR = Path(__file__).resolve().parent.parent / "generated_templates"


def _load_setting(key: str, default, settings_file: str = "config/settings.json"):
    p = Path(settings_file)
    if not p.exists():
        return default
    data = json.loads(p.read_text(encoding="utf-8"))
    return data.get(key, default)


def validate_template(template_yaml: str) -> tuple[bool, str]:
    """چک می‌کنه یه تمپلیت پیشنهادی امن و ساختارمند هست یا نه.
    برمی‌گردونه (is_valid, reason)."""
    if not template_yaml or not template_yaml.strip():
        return False, "تمپلیت خالیه"

    lowered = template_yaml.lower()
    for kw in DANGEROUS_KEYWORDS:
        if kw in lowered:
            return False, f"کلیدواژه‌ی خطرناک پیدا شد: '{kw}'"

    if DANGEROUS_METHOD_PATTERN.search(template_yaml):
        return False, "متد HTTP مخرب (DELETE/PUT/PATCH) مجاز نیست"

    try:
        parsed = yaml.safe_load(template_yaml)
    except yaml.YAMLError as e:
        return False, f"YAML نامعتبره: {e}"

    if not isinstance(parsed, dict):
        return False, "ساختار تمپلیت باید یه دیکشنری YAML باشه"

    for required_key in ("id", "info"):
        if required_key not in parsed:
            return False, f"فیلد اجباری '{required_key}' وجود نداره"

    template_id = parsed.get("id")
    if not isinstance(template_id, str) or not SAFE_TEMPLATE_ID_PATTERN.match(template_id):
        return False, (
            "فیلد id باید فقط شامل حروف/عدد انگلیسی، - و _ باشه (این id روی دیسک "
            f"به‌عنوان اسم فایل استفاده می‌شه): {template_id!r}"
        )

    has_request_block = any(k in parsed for k in ("http", "network", "dns"))
    if not has_request_block:
        return False, "هیچ بلاک درخواست (http/network/dns) پیدا نشد"

    return True, "معتبره"


class TemplateForgeHunter(BaseHunter):
    name = "template_forge"

    def __init__(self, *args, settings_file: str = "config/settings.json", model: str = DEFAULT_MODEL, **kwargs):
        super().__init__(*args, **kwargs)
        self.settings_file = settings_file
        self.model = model
        self.client = GeminiTextClient(model=self.model)

    def execute(self, target: str, payload: dict) -> dict:
        host_url = payload.get("url") or f"http://{target}"

        self.rate_limiter.wait()
        try:
            resp = requests.get(host_url, timeout=10)
        except requests.RequestException as e:
            return {"target": host_url, "status": f"unreachable: {e}"}

        signals = {
            "url": host_url,
            "status_code": resp.status_code,
            "headers": dict(resp.headers),
            "body_snippet": resp.text[:1500],
        }

        try:
            proposals = self._generate_templates(signals)
        except Exception as e:
            log(f"[template_forge] خطا در تولید تمپلیت: {e}")
            return {"target": host_url, "status": f"generation_failed: {e}"}

        findings_reported = []
        for proposal in proposals:
            findings_reported += self._process_proposal(host_url, proposal)

        return {"target": host_url, "proposals_generated": len(proposals), "findings": findings_reported}

    def _generate_templates(self, signals: dict) -> list[dict]:
        raw = self.client.generate_text(
            system_prompt=FORGE_SYSTEM_PROMPT,
            user_content=json.dumps(signals, ensure_ascii=False),
            max_output_tokens=2048,
        )
        try:
            proposals = json.loads(strip_json_fences(raw))
        except json.JSONDecodeError:
            return []
        return proposals[:2] if isinstance(proposals, list) else []

    def _process_proposal(self, target_url: str, proposal: dict) -> list[str]:
        template_yaml = proposal.get("template_yaml", "")
        is_valid, reason = validate_template(template_yaml)
        if not is_valid:
            log(f"[template_forge] تمپلیت پیشنهادی رد شد: {reason}")
            return []

        TEMPLATES_DIR.mkdir(parents=True, exist_ok=True)
        parsed = yaml.safe_load(template_yaml)
        template_id = parsed.get("id", "unnamed")
        file_path = TEMPLATES_DIR / f"{template_id}.yaml"
        file_path.write_text(template_yaml, encoding="utf-8")

        auto_execute = _load_setting("template_forge_auto_execute", False, self.settings_file)

        # این بخش قبلاً (توی نسخه‌ای که برام فرستادی) تفاوت مهمی با نسخه‌ی
        # ممیزی‌شده‌ی قبلی داشت که به نظرم یه رگرسیون واقعی بود، نه بهبود:
        #
        # ۱) وقتی auto_execute خاموش بود (پیش‌فرض امن)، هیچ finding ای اصلاً
        #    ساخته نمی‌شد -- یعنی زیر تنظیمات پیش‌فرض، این هانتر همیشه
        #    ساکت می‌مونه، حتی وقتی AI واقعاً یه پیشنهاد معتبر ساخته.
        # ۲) وقتی nuclei match می‌داد، finding با confidence="confirmed" +
        #    manual_verification_required=False ثبت می‌شد -- ولی "تأیید"ی
        #    که اینجا اتفاق می‌افته، nuclei داره matcher ای رو چک می‌کنه که
        #    خودِ همون AI نوشته؛ این یه سیگنال مستقل نیست (برخلاف مثلاً
        #    XSSHunter که واقعاً توی یه مرورگر واقعی alert() رو می‌بینه).
        #    یه matcher شل (مثل صرفاً status=200) از validate_template()
        #    رد می‌شه چون validation فقط ساختار/خطر رو چک می‌کنه نه قدرت
        #    matcher رو -- یعنی عملاً هر match ای می‌تونست بدون هیچ نشونه‌ی
        #    واقعی از آسیب‌پذیری، "confirmed" و "نیازی به تأیید دستی نیست"
        #    علامت بخوره. این با تست مستقیم (matcher ساختگی status=200 روی
        #    یه صفحه‌ی عادی) بازتولید و تأیید شد.
        #
        # فیکس: مثل قبل از این تغییر، همیشه finding ثبت می‌شه (تا هانتر
        # زیر تنظیمات پیش‌فرض هم بی‌صدا نمونه)، template_yaml کامل توی
        # evidence می‌مونه (تا خودت بتونی matcher رو ببینی)، و هیچ‌جا ادعا
        # نمی‌شه که نیاز به بررسی دستی نیست -- فلسفه‌ی کل این پروژه همینه:
        # هر finding، حتی "confirmed"، قبل از ارسال باید دستی چک بشه.
        if not auto_execute:
            fid = self.report_finding(
                target=target_url,
                vuln_type=f"Template Forge: {proposal.get('title', template_id)}",
                severity=proposal.get("severity", "info"),
                confidence="candidate",
                evidence={
                    "rationale": proposal.get("rationale", ""),
                    "template_id": template_id,
                    "template_path": str(file_path),
                    "template_yaml": template_yaml,
                    "execution_note": "اجرا نشد -- template_forge_auto_execute غیرفعاله (پیش‌فرض امن). برای اجرای دستی: nuclei -t {} -u {}".format(file_path, target_url),
                    "note": "این تمپلیت رو AI بر اساس سیگنال‌های recon این هدف خاص تولید کرده -- هیچ‌وقت مثل تمپلیت‌های community-vetted نیوکلای بهش اعتماد نکن؛ قبل از گزارش، دستی هم تأییدش کن.",
                },
            )
            return [fid]

        confirmed, execution_note = self._run_against_target(file_path, target_url)
        fid = self.report_finding(
            target=target_url,
            vuln_type=f"Template Forge: {proposal.get('title', template_id)}",
            severity=proposal.get("severity", "info"),
            confidence="confirmed" if confirmed else "candidate",
            evidence={
                "rationale": proposal.get("rationale", ""),
                "template_id": template_id,
                "template_path": str(file_path),
                "template_yaml": template_yaml,
                "execution_note": execution_note,
                "note": "این تمپلیت رو AI بر اساس سیگنال‌های recon این هدف خاص تولید کرده -- 'تأیید' اینجا یعنی nuclei matcher خودِ همین تمپلیت رو برآورده دید، نه یه سیگنال مستقل. هیچ‌وقت مثل تمپلیت‌های community-vetted نیوکلای بهش اعتماد نکن؛ قبل از گزارش، دستی هم تأییدش کن.",
            },
        )
        return [fid]

    def _run_against_target(self, template_path: Path, target_url: str) -> tuple[bool, str]:
        import shutil
        import subprocess

        if not shutil.which("nuclei"):
            return False, "nuclei نصب نیست -- تمپلیت فقط ذخیره شد"

        self.rate_limiter.wait()
        try:
            proc = subprocess.run(
                ["nuclei", "-t", str(template_path), "-u", target_url, "-silent", "-jsonline"],
                capture_output=True, text=True, timeout=60,
            )
        except subprocess.TimeoutExpired:
            return False, "nuclei روی این تمپلیت timeout شد"

        matched = bool(proc.stdout.strip())
        note = "نیوکلای واقعاً match پیدا کرد -- confirmed" if matched else "نیوکلای اجرا شد ولی match ای پیدا نکرد"
        return matched, note
