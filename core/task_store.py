"""Task queue for the Bug Bounty Agent.

The queue is intentionally idempotent *within a scan run*: repeated recon
results cannot enqueue the same hunter/target/payload over and over while the
same run is active. A new scan gets a new run_id, so a deliberate full scan can
still re-test previously completed work.
"""
from __future__ import annotations
import hashlib
import json
import sqlite3
import uuid
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit
from datetime import datetime, timezone
from pathlib import Path

SCHEMA = """
CREATE TABLE IF NOT EXISTS tasks (
    id TEXT PRIMARY KEY,
    hunter TEXT NOT NULL,
    target TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'todo',
    payload TEXT,
    result TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    run_id TEXT,
    dedupe_key TEXT
);
CREATE INDEX IF NOT EXISTS idx_tasks_queue ON tasks(hunter, status, created_at);
CREATE INDEX IF NOT EXISTS idx_tasks_run_dedupe ON tasks(run_id, dedupe_key);
"""


def canonical_target(target: str) -> str:
    """Normalize URL targets so harmless spelling differences do not create duplicate jobs."""
    value = (target or "").strip()
    try:
        parts = urlsplit(value)
        if not parts.scheme or not parts.netloc:
            return value.rstrip("/") or value
        host = (parts.hostname or "").lower()
        netloc = host
        if parts.port:
            default = (parts.scheme.lower() == "http" and parts.port == 80) or (parts.scheme.lower() == "https" and parts.port == 443)
            if not default:
                netloc = f"{host}:{parts.port}"
        path = parts.path or "/"
        if path != "/":
            path = path.rstrip("/") or "/"
        query = urlencode(sorted(parse_qsl(parts.query, keep_blank_values=True)), doseq=True)
        return urlunsplit((parts.scheme.lower(), netloc, path, query, ""))
    except Exception:
        return value


class TaskStore:
    def __init__(self, db_path: str | Path = "tasks.db"):
        self.db_path = str(db_path)
        self._conn = sqlite3.connect(self.db_path, timeout=10, check_same_thread=False)
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.executescript(SCHEMA)
        self._migrate()
        self._conn.commit()

    def _migrate(self):
        cols = {row[1] for row in self._conn.execute("PRAGMA table_info(tasks)").fetchall()}
        for col, coltype in (("run_id", "TEXT"), ("dedupe_key", "TEXT")):
            if col not in cols:
                self._conn.execute(f"ALTER TABLE tasks ADD COLUMN {col} {coltype}")
        self._conn.execute("CREATE INDEX IF NOT EXISTS idx_tasks_queue ON tasks(hunter, status, created_at)")
        self._conn.execute("CREATE INDEX IF NOT EXISTS idx_tasks_run_dedupe ON tasks(run_id, dedupe_key)")

    @staticmethod
    def _dedupe_key(hunter: str, target: str, payload: dict | None) -> str:
        # Recon is host-level work: its identity is hunter + canonical host,
        # never the incidental reason/payload attached by an LLM proposal.
        # Otherwise /robots.txt and /sitemap.xml would collapse to the same
        # host but still receive different dedupe keys and recreate Recon jobs.
        clean_payload = {} if hunter == "recon" else dict(payload or {})
        if isinstance(clean_payload.get("url"), str):
            clean_payload["url"] = canonical_target(clean_payload["url"])
        canonical = json.dumps(clean_payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        raw = f"{hunter}\0{target}\0{canonical}".encode("utf-8")
        return hashlib.sha256(raw).hexdigest()

    def add_task_unique(
        self,
        hunter: str,
        target: str,
        payload: dict | None = None,
        *,
        run_id: str | None = None,
    ) -> tuple[str, bool]:
        """Enqueue a task and report whether a new row was created.
        
        Dedup works both with and without run_id: with run_id, duplicates
        are scoped to that run; without, duplicates are checked globally
        among pending tasks."""
        payload = payload or {}
        target = canonical_target(target)
        key = self._dedupe_key(hunter, target, payload)
        if run_id:
            row = self._conn.execute(
                "SELECT id FROM tasks WHERE run_id = ? AND dedupe_key = ? LIMIT 1",
                (run_id, key),
            ).fetchone()
        else:
            # بدون run_id هم dedup انجام بشه: اگه تسکی با همین dedupe_key
            # و وضعیت todo/in_progress وجود داره، تکراری نسازیم.
            row = self._conn.execute(
                "SELECT id FROM tasks WHERE dedupe_key = ? AND status IN ('todo', 'in_progress') LIMIT 1",
                (key,),
            ).fetchone()
        if row:
            return row[0], False
        task_id = self.add_task(hunter, target, payload, run_id=run_id, dedupe=False)
        return task_id, True

    def add_task(
        self,
        hunter: str,
        target: str,
        payload: dict | None = None,
        *,
        run_id: str | None = None,
        dedupe: bool = True,
    ) -> str:
        payload = payload or {}
        target = canonical_target(target)
        now = datetime.now(timezone.utc).isoformat()
        key = self._dedupe_key(hunter, target, payload)
        if dedupe and run_id:
            row = self._conn.execute(
                "SELECT id FROM tasks WHERE run_id = ? AND dedupe_key = ? LIMIT 1",
                (run_id, key),
            ).fetchone()
            if row:
                return row[0]

        task_id = str(uuid.uuid4())
        self._conn.execute(
            "INSERT INTO tasks (id, hunter, target, status, payload, result, created_at, updated_at, run_id, dedupe_key) "
            "VALUES (?, ?, ?, 'todo', ?, NULL, ?, ?, ?, ?)",
            (task_id, hunter, target, json.dumps(payload, ensure_ascii=False), now, now, run_id, key),
        )
        self._conn.commit()
        return task_id

    def purge_pending(self) -> int:
        """Remove unfinished tasks left by an older/interrupted scan.

        The dashboard queue represents the current scan; stale pending work is
        otherwise a common source of 100s/1000s of queued duplicate jobs.
        """
        cur = self._conn.execute(
            "DELETE FROM tasks WHERE status IN ('todo', 'in_progress')"
        )
        self._conn.commit()
        return cur.rowcount

    def counts(self) -> dict[str, int]:
        rows = self._conn.execute(
            "SELECT status, COUNT(*) FROM tasks GROUP BY status"
        ).fetchall()
        return {status: int(count) for status, count in rows}

    def next_task(self, hunter: str) -> dict | None:
        row = self._conn.execute(
            "SELECT id, target, payload FROM tasks WHERE hunter = ? AND status = 'todo' "
            "ORDER BY created_at LIMIT 1",
            (hunter,),
        ).fetchone()
        if not row:
            return None
        task_id, target, payload = row
        self._set_status(task_id, "in_progress")
        return {"id": task_id, "target": target, "payload": json.loads(payload or "{}")}

    def complete_task(self, task_id: str, result: dict):
        now = datetime.now(timezone.utc).isoformat()
        self._conn.execute(
            "UPDATE tasks SET status = 'done', result = ?, updated_at = ? WHERE id = ?",
            (json.dumps(result, ensure_ascii=False), now, task_id),
        )
        self._conn.commit()

    def fail_task(self, task_id: str, error: str):
        now = datetime.now(timezone.utc).isoformat()
        self._conn.execute(
            "UPDATE tasks SET status = 'failed', result = ?, updated_at = ? WHERE id = ?",
            (json.dumps({"error": error}, ensure_ascii=False), now, task_id),
        )
        self._conn.commit()

    def _set_status(self, task_id: str, status: str):
        now = datetime.now(timezone.utc).isoformat()
        self._conn.execute(
            "UPDATE tasks SET status = ?, updated_at = ? WHERE id = ?",
            (status, now, task_id),
        )
        self._conn.commit()

    def board(self) -> dict[str, list[dict]]:
        rows = self._conn.execute(
            "SELECT id, hunter, target, status, created_at FROM tasks ORDER BY created_at"
        ).fetchall()
        board: dict[str, list[dict]] = {"todo": [], "in_progress": [], "done": [], "failed": []}
        for task_id, hunter, target, status, created_at in rows:
            board.setdefault(status, []).append(
                {"id": task_id, "hunter": hunter, "target": target, "created_at": created_at}
            )
        return board
