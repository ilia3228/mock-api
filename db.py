"""SQLite persistence for the mock API.

Tables
------
- users(id, email, name, pw_hash, pw_salt, created_at)
- tokens(token, user_id, created_at)
- llm_key_owner(id, user_id, updated_at)
- jobs(id, user_id, filename, size, lang, status, phase, progress,
       result_json, error, created_at, updated_at)

The DB file lives at ``mock-api/data.db`` and is treated as throwaway.
Delete it to reset all state.
"""

from __future__ import annotations

import json
import sqlite3
import threading
import time
from pathlib import Path
from typing import Any

DB_PATH = Path(__file__).parent / "data.db"
_LOCK = threading.RLock()
_CONN: sqlite3.Connection | None = None


def _conn() -> sqlite3.Connection:
    global _CONN
    if _CONN is None:
        _CONN = sqlite3.connect(DB_PATH, check_same_thread=False, isolation_level=None)
        _CONN.row_factory = sqlite3.Row
        _CONN.execute("PRAGMA journal_mode=WAL")
        _CONN.execute("PRAGMA foreign_keys=ON")
    return _CONN


def init() -> None:
    with _LOCK:
        c = _conn()
        c.executescript(
            """
            CREATE TABLE IF NOT EXISTS users (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                email       TEXT UNIQUE NOT NULL,
                name        TEXT NOT NULL DEFAULT '',
                pw_hash     TEXT NOT NULL,
                pw_salt     TEXT NOT NULL,
                created_at  REAL NOT NULL
            );

            CREATE TABLE IF NOT EXISTS tokens (
                token       TEXT PRIMARY KEY,
                user_id     INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                created_at  REAL NOT NULL
            );
            CREATE INDEX IF NOT EXISTS tokens_user_idx ON tokens(user_id);

            CREATE TABLE IF NOT EXISTS llm_key_owner (
                id          INTEGER PRIMARY KEY CHECK (id = 1),
                user_id     INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                updated_at  REAL NOT NULL
            );

            CREATE TABLE IF NOT EXISTS jobs (
                id           TEXT PRIMARY KEY,
                user_id      INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                filename     TEXT NOT NULL,
                size         INTEGER NOT NULL DEFAULT 0,
                lang         TEXT NOT NULL,
                status       TEXT NOT NULL,
                phase        TEXT NOT NULL DEFAULT 'detect',
                progress     REAL NOT NULL DEFAULT 0,
                result_json  TEXT,
                options_json TEXT,
                error        TEXT,
                created_at   REAL NOT NULL,
                updated_at   REAL NOT NULL
            );
            CREATE INDEX IF NOT EXISTS jobs_user_idx ON jobs(user_id, created_at DESC);
            """
        )
        # ── lightweight schema migration ────────────────────────────────────
        # ``options_json`` was added in v0.4; older databases that already
        # contain rows need the column added in-place. SQLite has no
        # ``ADD COLUMN IF NOT EXISTS``, so we sniff PRAGMA table_info first.
        existing_cols = {
            row["name"]
            for row in c.execute("PRAGMA table_info(jobs)").fetchall()
        }
        if "options_json" not in existing_cols:
            c.execute("ALTER TABLE jobs ADD COLUMN options_json TEXT")

        # Any job left in `queued` or `running` from a previous process must
        # have been orphaned by a crash/restart — the live asyncio task that
        # owned it is gone and can never resume. Mark them as errored so the
        # frontend doesn't get stuck on the analysing view forever.
        now = time.time()
        c.execute(
            "UPDATE jobs"
            " SET status = 'error', error = COALESCE(error, ?), updated_at = ?"
            " WHERE status IN ('queued', 'running')",
            ("server restarted before job completed", now),
        )


# ─── users ──────────────────────────────────────────────────────────────────

def insert_user(email: str, name: str, pw_hash: str, pw_salt: str) -> dict[str, Any]:
    with _LOCK:
        c = _conn()
        try:
            cur = c.execute(
                "INSERT INTO users(email,name,pw_hash,pw_salt,created_at) VALUES(?,?,?,?,?)",
                (email, name, pw_hash, pw_salt, time.time()),
            )
        except sqlite3.IntegrityError as exc:
            raise ValueError("email already registered") from exc
        return user_by_id(cur.lastrowid)  # type: ignore[arg-type]


def user_by_email(email: str) -> dict[str, Any] | None:
    with _LOCK:
        row = _conn().execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()
        return dict(row) if row else None


def user_by_id(user_id: int) -> dict[str, Any] | None:
    with _LOCK:
        row = _conn().execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
        return dict(row) if row else None


# ─── tokens ─────────────────────────────────────────────────────────────────

def single_user_id() -> int | None:
    """Return the only user id in the DB, or None when there are 0 or 2+."""
    with _LOCK:
        rows = _conn().execute(
            "SELECT id FROM users ORDER BY id ASC LIMIT 2"
        ).fetchall()
    return int(rows[0]["id"]) if len(rows) == 1 else None


def insert_token(token: str, user_id: int) -> None:
    with _LOCK:
        _conn().execute(
            "INSERT INTO tokens(token,user_id,created_at) VALUES(?,?,?)",
            (token, user_id, time.time()),
        )


def user_by_token(token: str) -> dict[str, Any] | None:
    with _LOCK:
        row = _conn().execute(
            "SELECT u.* FROM users u JOIN tokens t ON t.user_id = u.id WHERE t.token = ?",
            (token,),
        ).fetchone()
        return dict(row) if row else None


def delete_token(token: str) -> None:
    with _LOCK:
        _conn().execute("DELETE FROM tokens WHERE token = ?", (token,))


# ─── jobs ───────────────────────────────────────────────────────────────────

def llm_key_owner_user_id() -> int | None:
    """Return the user id that owns the shared on-disk LLM key, if any."""
    with _LOCK:
        row = _conn().execute(
            "SELECT user_id FROM llm_key_owner WHERE id = 1"
        ).fetchone()
        return int(row["user_id"]) if row else None


def set_llm_key_owner(user_id: int) -> None:
    """Mark ``user_id`` as the owner of the currently stored LLM API key."""
    with _LOCK:
        _conn().execute(
            """
            INSERT INTO llm_key_owner(id, user_id, updated_at)
            VALUES(1, ?, ?)
            ON CONFLICT(id) DO UPDATE SET
                user_id = excluded.user_id,
                updated_at = excluded.updated_at
            """,
            (user_id, time.time()),
        )


def clear_llm_key_owner(user_id: int | None = None) -> bool:
    """Clear the stored LLM key owner.

    When ``user_id`` is provided, the row is removed only if that user owns
    it. Returns True when a row was deleted.
    """
    with _LOCK:
        if user_id is None:
            cur = _conn().execute("DELETE FROM llm_key_owner WHERE id = 1")
        else:
            cur = _conn().execute(
                "DELETE FROM llm_key_owner WHERE id = 1 AND user_id = ?",
                (user_id,),
            )
        return (cur.rowcount or 0) > 0


def insert_job(
    job_id: str,
    user_id: int,
    filename: str,
    size: int,
    lang: str,
    status: str,
    options: dict[str, Any] | None = None,
) -> None:
    now = time.time()
    opts_blob = json.dumps(options, ensure_ascii=False) if options else None
    with _LOCK:
        _conn().execute(
            "INSERT INTO jobs(id,user_id,filename,size,lang,status,phase,progress,"
            "options_json,created_at,updated_at)"
            " VALUES(?,?,?,?,?,?,?,?,?,?,?)",
            (job_id, user_id, filename, size, lang, status,
             "detect", 0.0, opts_blob, now, now),
        )


def update_job(
    job_id: str,
    *,
    status: str | None = None,
    phase: str | None = None,
    progress: float | None = None,
    result: dict | None = None,
    error: str | None = None,
) -> None:
    fields: list[str] = []
    values: list[Any] = []
    if status is not None:
        fields.append("status = ?"); values.append(status)
    if phase is not None:
        fields.append("phase = ?"); values.append(phase)
    if progress is not None:
        fields.append("progress = ?"); values.append(progress)
    if result is not None:
        fields.append("result_json = ?"); values.append(json.dumps(result, ensure_ascii=False))
    if error is not None:
        fields.append("error = ?"); values.append(error)
    if not fields:
        return
    fields.append("updated_at = ?"); values.append(time.time())
    values.append(job_id)
    with _LOCK:
        _conn().execute(f"UPDATE jobs SET {', '.join(fields)} WHERE id = ?", values)


def get_job(job_id: str) -> dict[str, Any] | None:
    with _LOCK:
        row = _conn().execute("SELECT * FROM jobs WHERE id = ?", (job_id,)).fetchone()
        if not row:
            return None
        data = dict(row)
        data["result"] = json.loads(data.pop("result_json")) if data.get("result_json") else None
        data["options"] = (
            json.loads(data.pop("options_json")) if data.get("options_json") else None
        )
        return data


def delete_job(job_id: str, user_id: int) -> bool:
    """Remove a job row. Returns True if a row owned by `user_id` was deleted."""
    with _LOCK:
        cur = _conn().execute(
            "DELETE FROM jobs WHERE id = ? AND user_id = ?",
            (job_id, user_id),
        )
        return cur.rowcount > 0


def jobs_for_user(user_id: int, limit: int = 50) -> list[dict[str, Any]]:
    with _LOCK:
        rows = _conn().execute(
            "SELECT id,filename,size,lang,status,result_json,created_at"
            " FROM jobs WHERE user_id = ? ORDER BY created_at DESC LIMIT ?",
            (user_id, limit),
        ).fetchall()
    out = []
    for r in rows:
        d = dict(r)
        d["result"] = json.loads(d.pop("result_json")) if d.get("result_json") else None
        out.append(d)
    return out


def all_job_ids_for_user(user_id: int) -> list[str]:
    """Return every job id owned by ``user_id`` (used by bulk-delete + export)."""
    with _LOCK:
        rows = _conn().execute(
            "SELECT id FROM jobs WHERE user_id = ?", (user_id,)
        ).fetchall()
    return [row["id"] for row in rows]


def delete_jobs_for_user(user_id: int) -> int:
    """Bulk-remove every job row owned by ``user_id``. Returns row count.

    Caller is responsible for any on-disk cleanup (``runs/<job_id>/``).
    """
    with _LOCK:
        cur = _conn().execute("DELETE FROM jobs WHERE user_id = ?", (user_id,))
        return cur.rowcount or 0


# ─── account management ─────────────────────────────────────────────────────

def update_user_password(user_id: int, pw_hash: str, pw_salt: str) -> None:
    """Replace the password hash + salt for a user. Tokens stay valid."""
    with _LOCK:
        _conn().execute(
            "UPDATE users SET pw_hash = ?, pw_salt = ? WHERE id = ?",
            (pw_hash, pw_salt, user_id),
        )


def delete_user_tokens(user_id: int, *, except_token: str | None = None) -> int:
    """Revoke every token for ``user_id`` (sign-out from all devices).

    Pass ``except_token`` to preserve the caller's own session.
    """
    with _LOCK:
        if except_token is not None:
            cur = _conn().execute(
                "DELETE FROM tokens WHERE user_id = ? AND token <> ?",
                (user_id, except_token),
            )
        else:
            cur = _conn().execute(
                "DELETE FROM tokens WHERE user_id = ?", (user_id,)
            )
        return cur.rowcount or 0


def delete_user(user_id: int) -> None:
    """Delete the user row. ON DELETE CASCADE clears tokens and jobs."""
    with _LOCK:
        _conn().execute("DELETE FROM users WHERE id = ?", (user_id,))
