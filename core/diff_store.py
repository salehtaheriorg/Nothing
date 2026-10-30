"""
core/diff_store.py

پایه‌ی قابلیت Incremental/Diff Scan. ردیابی می‌کنه کدوم asset ها
(ساب‌دامین/URL/هاست) توی اسکن‌های قبلی *برای همین برنامه* دیده شدن.
دفعه‌ی بعد که اسکن می‌کنی، فقط asset های *جدید* به هانترهای آسیب‌پذیری
(idor/xss/secrets/nuclei/takeover) فرستاده می‌شن، نه همه‌چیز از اول.

چرا مهمه برای درآمد: توی bug bounty معمولاً نفر اول که یه آسیب‌پذیری رو
گزارش می‌ده پول می‌گیره، نه نفر دقیق‌تر. اگه هر بار همه‌چیز رو دوباره از
صفر تست کنی، وقتت صرف asset هایی می‌شه که دیروز هم چک کرده بودی؛ اسکن
افتراقی باعث می‌شه سریع‌تر بری سراغ چیزهایی که همین امروز تازه ظاهر شدن.

محدودیت مهم: این فقط "URL/دامنه‌ی جدید" رو تشخیص می‌ده، نه "محتوای
تغییرکرده". اگه یه URL قبلاً چک شده ولی محتواش (مثلاً یه فایل JS) عوض
شده باشه، دوباره فرستاده نمی‌شه. برای اسکن دوره‌ای عمیق‌تر، هر چند وقت
یک‌بار می‌تونی از داشبورد تاریخچه رو reset کنی تا یه اسکن کامل انجام بشه.

ردیابی به‌ازای هر برنامه (program_name) جداست، پس چند-برنامه‌ای
(Programs) بدون تداخل با این قابلیت کار می‌کنه.
"""

from __future__ import annotations
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

SCHEMA = """
CREATE TABLE IF NOT EXISTS seen_assets (
    asset TEXT NOT NULL,
    asset_type TEXT NOT NULL,
    program_name TEXT NOT NULL,
    first_seen_at TEXT NOT NULL,
    last_seen_at TEXT NOT NULL,
    PRIMARY KEY (asset, asset_type, program_name)
);
"""


class DiffStore:
    def __init__(self, db_path: str | Path = "diff.db"):
        self.db_path = str(db_path)
        self._conn = sqlite3.connect(self.db_path, timeout=10, check_same_thread=False)
        self._conn.execute(SCHEMA)
        self._conn.commit()

    def filter_new(self, assets: list[str], asset_type: str, program_name: str) -> list[str]:
        """فقط asset هایی که قبلاً برای این برنامه دیده نشدن رو
        برمی‌گردونه. همه‌ی assetهای ورودی (چه جدید چه تکراری) به‌عنوان
        seen ثبت/آپدیت می‌شن (last_seen_at آپدیت می‌شه).
        
        کل عملیات توی یه transaction اتمیک انجام می‌شه تا crash وسط
        حلقه باعث وضعیت ناسازگار نشه."""
        if not assets:
            return []
        now = datetime.now(timezone.utc).isoformat()
        new_ones = []
        try:
            for asset in assets:
                row = self._conn.execute(
                    "SELECT 1 FROM seen_assets WHERE asset = ? AND asset_type = ? AND program_name = ?",
                    (asset, asset_type, program_name),
                ).fetchone()
                if row is None:
                    new_ones.append(asset)
                    self._conn.execute(
                        "INSERT INTO seen_assets (asset, asset_type, program_name, first_seen_at, last_seen_at) "
                        "VALUES (?, ?, ?, ?, ?)",
                        (asset, asset_type, program_name, now, now),
                    )
                else:
                    self._conn.execute(
                        "UPDATE seen_assets SET last_seen_at = ? WHERE asset = ? AND asset_type = ? AND program_name = ?",
                        (now, asset, asset_type, program_name),
                    )
            self._conn.commit()
        except Exception:
            self._conn.rollback()
            raise
        return new_ones

    def stats(self, program_name: str) -> dict:
        total = self._conn.execute(
            "SELECT COUNT(*) FROM seen_assets WHERE program_name = ?", (program_name,)
        ).fetchone()[0]
        by_type_rows = self._conn.execute(
            "SELECT asset_type, COUNT(*) FROM seen_assets WHERE program_name = ? GROUP BY asset_type",
            (program_name,),
        ).fetchall()
        return {"total_tracked": total, "by_type": dict(by_type_rows)}

    def reset(self, program_name: str | None = None):
        """پاک کردن تاریخچه. اگه program_name داده نشه، تاریخچه‌ی همه‌ی
        برنامه‌ها پاک می‌شه."""
        if program_name:
            self._conn.execute("DELETE FROM seen_assets WHERE program_name = ?", (program_name,))
        else:
            self._conn.execute("DELETE FROM seen_assets")
        self._conn.commit()
