"""
core/findings_store.py

جدول جدا برای ذخیره‌ی "یافته‌ها" (candidate vulnerabilities). این از
TaskStore جداست چون یه task می‌تونه چند finding تولید کنه، و findingها
باید بمونن حتی بعد از پاک‌شدن تسک‌ها.

نکته‌ی مهم: هر finding به‌طور پیش‌فرض `verified = False` هست. یعنی این
سیستم صرفاً "کاندید برای بررسی دستی" تولید می‌کنه، نه گزارش نهایی آماده‌ی
ارسال. قبل از ارسال گزارش به برنامه‌ی bug bounty، **حتماً خودت دستی
تأیید کن** — false positive توی اسکنرهای خودکار طبیعیه.

از این نسخه به بعد، ستون‌های مربوط به ردیابی ارسال گزارش و پاداش
(submission_status, bounty_amount, ...) هم اضافه شدن تا بشه از داشبورد
پیگیری درآمد کرد.
"""

from __future__ import annotations
import sqlite3
import json
import uuid
import hashlib
from datetime import datetime, timezone
from pathlib import Path

SCHEMA = """
CREATE TABLE IF NOT EXISTS findings (
    id TEXT PRIMARY KEY,
    hunter TEXT NOT NULL,
    target TEXT NOT NULL,
    vuln_type TEXT NOT NULL,
    severity TEXT NOT NULL,
    confidence TEXT NOT NULL,
    evidence TEXT,
    verified INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL,
    dedupe_key TEXT
);
"""

# ستون‌های اضافه‌شده در نسخه‌های بعدی - با migration خودکار اضافه می‌شن
# تا دیتابیس‌های قدیمی هم بدون خطا آپدیت بشن.
EXTRA_COLUMNS = {
    "dedupe_key": "TEXT",
    "submission_status": "TEXT NOT NULL DEFAULT 'not_submitted'",
    "bounty_amount": "REAL",
    "bounty_currency": "TEXT",
    "submitted_at": "TEXT",
    "platform": "TEXT",
    "report_path": "TEXT",
}

ALL_COLUMNS = [
    "id", "hunter", "target", "vuln_type", "severity", "confidence",
    "evidence", "verified", "created_at",
    "dedupe_key", "submission_status", "bounty_amount", "bounty_currency",
    "submitted_at", "platform", "report_path",
]


class FindingsStore:
    # این دیفالت قبلاً رشته‌ی relative بود ("findings.db"). چون
    # hunters/base_hunter.py وقتی findings صریح پاس داده نشه از همین
    # دیفالت استفاده می‌کنه (`findings or FindingsStore()`)، و چون
    # هانترها هم از CWD ریشه‌ی پروژه (main.py) هم از CWD متفاوت
    # (داشبورد) صدا زده می‌شن، یه دیفالت relative می‌تونست دقیقاً همون
    # باگ «فایل دیتابیس اشتباه زیر یه دایرکتوری دیگه ساخته می‌شه» رو
    # تکرار کنه که در core/scan_runner.py و core/overseer.py پیدا و
    # فیکس شد. الان دیفالت مطلق و ریشه‌ش PROJECT_ROOT هست، نه CWD.
    def __init__(self, db_path: str | Path = None):
        db_path = db_path or str(Path(__file__).resolve().parent.parent / "findings.db")
        self.db_path = str(db_path)
        self._conn = sqlite3.connect(self.db_path, timeout=10, check_same_thread=False)
        self._conn.execute(SCHEMA)
        self._migrate()
        self._conn.commit()

    def _migrate(self):
        existing_cols = {row[1] for row in self._conn.execute("PRAGMA table_info(findings)").fetchall()}
        for col, coltype in EXTRA_COLUMNS.items():
            if col not in existing_cols:
                self._conn.execute(f"ALTER TABLE findings ADD COLUMN {col} {coltype}")
        self._conn.commit()

    def add_finding(
        self,
        hunter: str,
        target: str,
        vuln_type: str,
        severity: str,
        evidence: dict,
        confidence: str = "candidate",
    ) -> str:
        """confidence: 'candidate' (نیاز به بررسی دستی) یا 'confirmed'
        (مثلاً وقتی XSS واقعاً توی headless browser اجرا شده)."""
        evidence = evidence or {}
        sig_material = {
            "hunter": hunter,
            "target": target,
            "vuln_type": vuln_type,
            "param": evidence.get("param"),
            "probe_url": evidence.get("probe_url"),
        }
        dedupe_key = hashlib.sha256(json.dumps(sig_material, sort_keys=True, ensure_ascii=False).encode("utf-8")).hexdigest()
        existing = self._conn.execute(
            "SELECT id FROM findings WHERE dedupe_key = ? LIMIT 1", (dedupe_key,)
        ).fetchone()
        if existing:
            return existing[0]

        finding_id = str(uuid.uuid4())
        now = datetime.now(timezone.utc).isoformat()
        self._conn.execute(
            "INSERT INTO findings (id, hunter, target, vuln_type, severity, confidence, "
            "evidence, verified, created_at, dedupe_key) VALUES (?, ?, ?, ?, ?, ?, ?, 0, ?, ?)",
            (finding_id, hunter, target, vuln_type, severity, confidence, json.dumps(evidence, ensure_ascii=False), now, dedupe_key),
        )
        self._conn.commit()
        return finding_id

    def mark_verified(self, finding_id: str, verified: bool = True):
        self._conn.execute(
            "UPDATE findings SET verified = ? WHERE id = ?", (int(verified), finding_id)
        )
        self._conn.commit()

    def set_report_path(self, finding_id: str, path: str):
        self._conn.execute(
            "UPDATE findings SET report_path = ? WHERE id = ?", (path, finding_id)
        )
        self._conn.commit()

    def update_submission(self, finding_id: str, **fields):
        """آپدیت وضعیت ارسال/پاداش. فیلدهای مجاز:
        submission_status, bounty_amount, bounty_currency, submitted_at, platform"""
        allowed = {"submission_status", "bounty_amount", "bounty_currency", "submitted_at", "platform"}
        updates = {k: v for k, v in fields.items() if k in allowed}
        if not updates:
            return
        set_clause = ", ".join(f"{k} = ?" for k in updates)
        values = list(updates.values()) + [finding_id]
        self._conn.execute(f"UPDATE findings SET {set_clause} WHERE id = ?", values)
        self._conn.commit()

    def all_findings(self) -> list[dict]:
        rows = self._conn.execute(
            f"SELECT {', '.join(ALL_COLUMNS)} FROM findings ORDER BY created_at DESC"
        ).fetchall()
        return [dict(zip(ALL_COLUMNS, r)) for r in rows]

    def get(self, finding_id: str) -> dict | None:
        row = self._conn.execute(
            f"SELECT {', '.join(ALL_COLUMNS)} FROM findings WHERE id = ?", (finding_id,)
        ).fetchone()
        return dict(zip(ALL_COLUMNS, row)) if row else None

    def summary(self) -> dict:
        findings = self.all_findings()
        by_severity: dict[str, int] = {}
        for f in findings:
            by_severity[f["severity"]] = by_severity.get(f["severity"], 0) + 1
        return {
            "total": len(findings),
            "verified": sum(1 for f in findings if f["verified"]),
            "by_severity": by_severity,
        }

    def earnings_summary(self) -> dict:
        """جمع پاداش‌های دریافت‌شده، تفکیک‌شده بر اساس واحد پول."""
        rows = self._conn.execute(
            "SELECT COALESCE(bounty_currency, 'نامشخص'), SUM(bounty_amount) "
            "FROM findings WHERE bounty_amount IS NOT NULL GROUP BY bounty_currency"
        ).fetchall()
        totals = {currency: amount for currency, amount in rows}
        by_status = {}
        for f in self.all_findings():
            status = f["submission_status"] or "not_submitted"
            by_status[status] = by_status.get(status, 0) + 1
        return {"totals_by_currency": totals, "by_status": by_status}
