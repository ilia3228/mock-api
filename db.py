"""PostgreSQL persistence for the mock API (async, asyncpg).

Tables
------
- users(id, email, name, pw_hash, pw_salt, created_at)
- tokens(token, user_id, created_at)
- llm_key_owner(id, user_id, updated_at)
- jobs(id, user_id, filename, size, lang, status, phase, progress,
       result_json, options_json, error, created_at, updated_at)

Connection comes from ``$DATABASE_URL`` (default points at the local
docker ``postgres:16`` container started for this project). The schema is
treated as throwaway — drop/recreate the database to reset all state.

Every public function is a coroutine; a single ``asyncpg`` connection pool
is created lazily on first use (and eagerly by :func:`init` at startup).
asyncpg runs each pool-proxy call in its own implicit transaction that
auto-commits, matching the previous SQLite autocommit semantics.
"""

from __future__ import annotations

import asyncio
import json
import os
import time
from typing import Any

import asyncpg

# DSN for the project's docker postgres container (see mock-api/README.md).
# Override with DATABASE_URL to point at any other PostgreSQL instance.
DATABASE_URL = os.environ.get(
    "DATABASE_URL",
    "postgresql://sitedeobf:deobf@127.0.0.1:5432/sitedeobf",
)

_POOL: asyncpg.Pool | None = None
_POOL_LOCK = asyncio.Lock()


async def _pool() -> asyncpg.Pool:
    global _POOL
    if _POOL is None:
        async with _POOL_LOCK:
            if _POOL is None:
                _POOL = await asyncpg.create_pool(
                    DATABASE_URL, min_size=1, max_size=10
                )
    return _POOL


def _affected(status: str) -> int:
    """Parse the row count out of an asyncpg command tag.

    asyncpg's ``execute`` returns a status string such as ``"DELETE 3"``,
    ``"UPDATE 2"`` or ``"INSERT 0 1"`` — the trailing integer is the number
    of affected rows in every case.
    """
    try:
        return int(status.split()[-1])
    except (ValueError, IndexError):
        return 0


async def init() -> None:
    pool = await _pool()
    # asyncpg runs a multi-statement query in one batch when no arguments
    # are passed, so the whole schema block goes in a single execute().
    await pool.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            id          BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
            email       TEXT UNIQUE NOT NULL,
            name        TEXT NOT NULL DEFAULT '',
            pw_hash     TEXT NOT NULL,
            pw_salt     TEXT NOT NULL,
            created_at  DOUBLE PRECISION NOT NULL
        );

        CREATE TABLE IF NOT EXISTS tokens (
            token       TEXT PRIMARY KEY,
            user_id     BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            created_at  DOUBLE PRECISION NOT NULL
        );
        CREATE INDEX IF NOT EXISTS tokens_user_idx ON tokens(user_id);

        CREATE TABLE IF NOT EXISTS llm_key_owner (
            id          INTEGER PRIMARY KEY CHECK (id = 1),
            user_id     BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            updated_at  DOUBLE PRECISION NOT NULL
        );

        CREATE TABLE IF NOT EXISTS jobs (
            id           TEXT PRIMARY KEY,
            user_id      BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            filename     TEXT NOT NULL,
            size         BIGINT NOT NULL DEFAULT 0,
            lang         TEXT NOT NULL,
            status       TEXT NOT NULL,
            phase        TEXT NOT NULL DEFAULT 'detect',
            progress     DOUBLE PRECISION NOT NULL DEFAULT 0,
            result_json  TEXT,
            options_json TEXT,
            error        TEXT,
            created_at   DOUBLE PRECISION NOT NULL,
            updated_at   DOUBLE PRECISION NOT NULL
        );
        CREATE INDEX IF NOT EXISTS jobs_user_idx ON jobs(user_id, created_at DESC);
        """
    )

    # Any job left in `queued` or `running` from a previous process must
    # have been orphaned by a crash/restart — the live asyncio task that
    # owned it is gone and can never resume. Mark them as errored so the
    # frontend doesn't get stuck on the analysing view forever.
    await pool.execute(
        "UPDATE jobs"
        " SET status = 'error', error = COALESCE(error, $1), updated_at = $2"
        " WHERE status IN ('queued', 'running')",
        "server restarted before job completed",
        time.time(),
    )


async def close() -> None:
    """Close the connection pool (called on application shutdown)."""
    global _POOL
    if _POOL is not None:
        await _POOL.close()
        _POOL = None


# ─── users ──────────────────────────────────────────────────────────────────

async def insert_user(email: str, name: str, pw_hash: str, pw_salt: str) -> dict[str, Any]:
    pool = await _pool()
    try:
        user_id = await pool.fetchval(
            "INSERT INTO users(email,name,pw_hash,pw_salt,created_at)"
            " VALUES($1,$2,$3,$4,$5) RETURNING id",
            email, name, pw_hash, pw_salt, time.time(),
        )
    except asyncpg.UniqueViolationError as exc:
        raise ValueError("email already registered") from exc
    return await user_by_id(int(user_id))  # type: ignore[arg-type]


async def user_by_email(email: str) -> dict[str, Any] | None:
    pool = await _pool()
    row = await pool.fetchrow("SELECT * FROM users WHERE email = $1", email)
    return dict(row) if row else None


async def user_by_id(user_id: int) -> dict[str, Any] | None:
    pool = await _pool()
    row = await pool.fetchrow("SELECT * FROM users WHERE id = $1", user_id)
    return dict(row) if row else None


# ─── tokens ─────────────────────────────────────────────────────────────────

async def single_user_id() -> int | None:
    """Return the only user id in the DB, or None when there are 0 or 2+."""
    pool = await _pool()
    rows = await pool.fetch("SELECT id FROM users ORDER BY id ASC LIMIT 2")
    return int(rows[0]["id"]) if len(rows) == 1 else None


async def insert_token(token: str, user_id: int) -> None:
    pool = await _pool()
    await pool.execute(
        "INSERT INTO tokens(token,user_id,created_at) VALUES($1,$2,$3)",
        token, user_id, time.time(),
    )


async def user_by_token(token: str) -> dict[str, Any] | None:
    pool = await _pool()
    row = await pool.fetchrow(
        "SELECT u.* FROM users u JOIN tokens t ON t.user_id = u.id WHERE t.token = $1",
        token,
    )
    return dict(row) if row else None


async def delete_token(token: str) -> None:
    pool = await _pool()
    await pool.execute("DELETE FROM tokens WHERE token = $1", token)


# ─── llm key owner ──────────────────────────────────────────────────────────

async def llm_key_owner_user_id() -> int | None:
    """Return the user id that owns the shared on-disk LLM key, if any."""
    pool = await _pool()
    val = await pool.fetchval("SELECT user_id FROM llm_key_owner WHERE id = 1")
    return int(val) if val is not None else None


async def set_llm_key_owner(user_id: int) -> None:
    """Mark ``user_id`` as the owner of the currently stored LLM API key."""
    pool = await _pool()
    await pool.execute(
        """
        INSERT INTO llm_key_owner(id, user_id, updated_at)
        VALUES(1, $1, $2)
        ON CONFLICT(id) DO UPDATE SET
            user_id = excluded.user_id,
            updated_at = excluded.updated_at
        """,
        user_id, time.time(),
    )


async def clear_llm_key_owner(user_id: int | None = None) -> bool:
    """Clear the stored LLM key owner.

    When ``user_id`` is provided, the row is removed only if that user owns
    it. Returns True when a row was deleted.
    """
    pool = await _pool()
    if user_id is None:
        status = await pool.execute("DELETE FROM llm_key_owner WHERE id = 1")
    else:
        status = await pool.execute(
            "DELETE FROM llm_key_owner WHERE id = 1 AND user_id = $1", user_id
        )
    return _affected(status) > 0


# ─── jobs ───────────────────────────────────────────────────────────────────

async def insert_job(
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
    pool = await _pool()
    await pool.execute(
        "INSERT INTO jobs(id,user_id,filename,size,lang,status,phase,progress,"
        "options_json,created_at,updated_at)"
        " VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)",
        job_id, user_id, filename, size, lang, status,
        "detect", 0.0, opts_blob, now, now,
    )


async def update_job(
    job_id: str,
    *,
    status: str | None = None,
    phase: str | None = None,
    progress: float | None = None,
    result: dict | None = None,
    error: str | None = None,
) -> None:
    sets: list[str] = []
    values: list[Any] = []

    def _add(col: str, val: Any) -> None:
        values.append(val)
        sets.append(f"{col} = ${len(values)}")

    if status is not None:
        _add("status", status)
    if phase is not None:
        _add("phase", phase)
    if progress is not None:
        _add("progress", progress)
    if result is not None:
        _add("result_json", json.dumps(result, ensure_ascii=False))
    if error is not None:
        _add("error", error)
    if not sets:
        return
    _add("updated_at", time.time())
    values.append(job_id)
    sql = f"UPDATE jobs SET {', '.join(sets)} WHERE id = ${len(values)}"
    pool = await _pool()
    await pool.execute(sql, *values)


async def get_job(job_id: str) -> dict[str, Any] | None:
    pool = await _pool()
    row = await pool.fetchrow("SELECT * FROM jobs WHERE id = $1", job_id)
    if not row:
        return None
    data = dict(row)
    data["result"] = json.loads(data.pop("result_json")) if data.get("result_json") else None
    data["options"] = (
        json.loads(data.pop("options_json")) if data.get("options_json") else None
    )
    return data


async def delete_job(job_id: str, user_id: int) -> bool:
    """Remove a job row. Returns True if a row owned by `user_id` was deleted."""
    pool = await _pool()
    status = await pool.execute(
        "DELETE FROM jobs WHERE id = $1 AND user_id = $2", job_id, user_id
    )
    return _affected(status) > 0


async def jobs_for_user(user_id: int, limit: int = 50) -> list[dict[str, Any]]:
    pool = await _pool()
    rows = await pool.fetch(
        "SELECT id,filename,size,lang,status,result_json,created_at"
        " FROM jobs WHERE user_id = $1 ORDER BY created_at DESC LIMIT $2",
        user_id, limit,
    )
    out = []
    for r in rows:
        d = dict(r)
        d["result"] = json.loads(d.pop("result_json")) if d.get("result_json") else None
        out.append(d)
    return out


async def all_job_ids_for_user(user_id: int) -> list[str]:
    """Return every job id owned by ``user_id`` (used by bulk-delete + export)."""
    pool = await _pool()
    rows = await pool.fetch("SELECT id FROM jobs WHERE user_id = $1", user_id)
    return [row["id"] for row in rows]


async def delete_jobs_for_user(user_id: int) -> int:
    """Bulk-remove every job row owned by ``user_id``. Returns row count.

    Caller is responsible for any on-disk cleanup (``runs/<job_id>/``).
    """
    pool = await _pool()
    status = await pool.execute("DELETE FROM jobs WHERE user_id = $1", user_id)
    return _affected(status)


# ─── account management ─────────────────────────────────────────────────────

async def update_user_password(user_id: int, pw_hash: str, pw_salt: str) -> None:
    """Replace the password hash + salt for a user. Tokens stay valid."""
    pool = await _pool()
    await pool.execute(
        "UPDATE users SET pw_hash = $1, pw_salt = $2 WHERE id = $3",
        pw_hash, pw_salt, user_id,
    )


async def delete_user_tokens(user_id: int, *, except_token: str | None = None) -> int:
    """Revoke every token for ``user_id`` (sign-out from all devices).

    Pass ``except_token`` to preserve the caller's own session.
    """
    pool = await _pool()
    if except_token is not None:
        status = await pool.execute(
            "DELETE FROM tokens WHERE user_id = $1 AND token <> $2",
            user_id, except_token,
        )
    else:
        status = await pool.execute(
            "DELETE FROM tokens WHERE user_id = $1", user_id
        )
    return _affected(status)


async def delete_user(user_id: int) -> None:
    """Delete the user row. ON DELETE CASCADE clears tokens and jobs."""
    pool = await _pool()
    await pool.execute("DELETE FROM users WHERE id = $1", user_id)
