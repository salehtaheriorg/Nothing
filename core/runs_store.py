"""
core/runs_store.py

تاریخچه‌ی اجراهای اسکن. هر بار که یه اسکن شروع می‌شه، یه ردیف جدید ثبت
می‌شه؛ وقتی تموم شد، تعداد یافته‌ها و وضعیت نهایی آپدیت می‌شه. این به تو
اجازه می‌ده ببینی هر دور اسکن چقدر مؤثر بوده و روند رو در طول زمان مقایسه
کنی.
"""

from __future__ import annotations
import sqlite3
import uuid
from datetime import datetime, timezone
from pathlib import Path

SCHEMA = """
CREATE TABLE IF NOT EXISTS runs (
    id TEXT PRIMARY KEY,
    program_name TEXT,
    status TEXT NOT NULL DEFAULT 'running',
    findings_count INTEGER DEFAULT 0,
    started_at TEXT NOT NULL,
    finished_at TEXT
);
"""


class RunsStore:
    def __init__(self, db_path: str | Path = "runs.db"):
        self.db_path = str(db_path)
        self._conn = sqlite3.connect(self.db_path, timeout=10, check_same_thread=False)
        self._conn.execute(SCHEMA)
        self._conn.commit()

    def start_run(self, program_name: str, run_id: str | None = None) -> str:
        run_id = run_id or str(uuid.uuid4())
        now = datetime.now(timezone.utc).isoformat()
        self._conn.execute(
            "INSERT INTO runs (id, program_name, status, started_at) VALUES (?, ?, 'running', ?)",
            (run_id, program_name, now),
        )
        self._conn.commit()
        return run_id


    def finish_run(self, run_id: str, findings_count: int, status: str = "completed"):
        now = datetime.now(timezone.utc).isoformat()
        self._conn.execute(
            "UPDATE runs SET status = ?, findings_count = ?, finished_at = ? WHERE id = ?",
            (status, findings_count, now, run_id),
        )
        self._conn.commit()

    def all_runs(self) -> list[dict]:
        rows = self._conn.execute(
            "SELECT id, program_name, status, findings_count, started_at, finished_at "
            "FROM runs ORDER BY started_at DESC"
        ).fetchall()
        cols = ["id", "program_name", "status", "findings_count", "started_at", "finished_at"]
        return [dict(zip(cols, r)) for r in rows]
