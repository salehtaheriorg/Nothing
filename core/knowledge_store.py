"""
core/knowledge_store.py

پایگاه دانش هانترها. اینجا رایتاپ‌ها، یادداشت‌های آموزشی، یا تکنیک‌های
تازه‌ای که خوندی رو ذخیره می‌کنی، تگ‌شده به یه هانتر خاص (یا 'general'
برای چیزهای عمومی).

این یادداشت‌ها به دو شکل استفاده می‌شن:
1) خودکار: به Overseer کمک می‌کنن وقتی داره توی plan_next_steps تصمیم
   می‌گیره "قدم بعدی چیه"، از تکنیک‌هایی که بهش دادی هم خبر داشته باشه.
2) دستی (با دکمه‌ی «پیشنهاد الگو» توی داشبورد): از روی یه یادداشت،
   Gemini پیشنهاد می‌ده چه regex/payload/fingerprint جدیدی می‌تونه به
   هانتر مربوطه اضافه بشه -- ولی همیشه به‌عنوان پیشنهاد قابل‌بررسی، نه
   تغییر خودکار فایل‌های کد.

⚠️ این پایگاه دانش منطق قطعی/regex-based هانترها رو به‌صورت خودکار
تغییر نمی‌ده -- اون‌ها همیشه دقیقاً همون قوانین سخت‌کدشده‌ی موجود رو
اجرا می‌کنن.
"""

from __future__ import annotations
import sqlite3
import uuid
from datetime import datetime, timezone
from pathlib import Path

SCHEMA = """
CREATE TABLE IF NOT EXISTS knowledge (
    id TEXT PRIMARY KEY,
    hunter TEXT NOT NULL,
    title TEXT NOT NULL,
    content TEXT NOT NULL,
    source_url TEXT,
    created_at TEXT NOT NULL
);
"""


class KnowledgeStore:
    def __init__(self, db_path: str | Path = "knowledge.db"):
        self.db_path = str(db_path)
        self._conn = sqlite3.connect(self.db_path, timeout=10, check_same_thread=False)
        self._conn.execute(SCHEMA)
        self._conn.commit()

    def add(self, hunter: str, title: str, content: str, source_url: str = "") -> str:
        note_id = str(uuid.uuid4())
        now = datetime.now(timezone.utc).isoformat()
        self._conn.execute(
            "INSERT INTO knowledge (id, hunter, title, content, source_url, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (note_id, hunter, title, content, source_url, now),
        )
        self._conn.commit()
        return note_id

    def delete(self, note_id: str):
        self._conn.execute("DELETE FROM knowledge WHERE id = ?", (note_id,))
        self._conn.commit()

    def get(self, note_id: str) -> dict | None:
        row = self._conn.execute(
            "SELECT id, hunter, title, content, source_url, created_at FROM knowledge WHERE id = ?",
            (note_id,),
        ).fetchone()
        if not row:
            return None
        cols = ["id", "hunter", "title", "content", "source_url", "created_at"]
        return dict(zip(cols, row))

    def all_notes(self) -> list[dict]:
        rows = self._conn.execute(
            "SELECT id, hunter, title, content, source_url, created_at FROM knowledge ORDER BY created_at DESC"
        ).fetchall()
        cols = ["id", "hunter", "title", "content", "source_url", "created_at"]
        return [dict(zip(cols, r)) for r in rows]

    def for_context(self, limit: int = 10) -> list[dict]:
        """برای تزریق به پرامپت planning -- محدود به تعداد مشخص تا
        پرامپت خیلی بزرگ نشه."""
        rows = self._conn.execute(
            "SELECT id, hunter, title, content, source_url, created_at FROM knowledge "
            "ORDER BY created_at DESC LIMIT ?",
            (limit,),
        ).fetchall()
        cols = ["id", "hunter", "title", "content", "source_url", "created_at"]
        return [dict(zip(cols, r)) for r in rows]
