"""HTTP API for deobfuscator-app.

Dispatches uploaded files to the real JS or Python deobfuscator (see
``runner.py``) based on filename detection, streams the subprocess log
output back to the frontend over SSE, and assembles a result bundle
(sha256 + unified diff + coarse MITRE) on the API side.

Persistence
-----------
- Users / tokens / job metadata live in ``data.db`` (SQLite, see ``db.py``).
- Uploaded files and deobfuscator outputs live under ``runs/<job_id>/``.
- Live SSE state (async events, in-flight log buffer) is held in memory.
  Restarting the process drops live state; finished jobs survive in SQLite
  and are restored on demand.
"""

from __future__ import annotations

import asyncio
import ctypes
import difflib
import hashlib
import json
import logging
import os
import re
import shutil
import sys
import threading
import time
import uuid

# ─── Windows: force Proactor event loop ─────────────────────────────────────
# `asyncio.create_subprocess_exec` (used by runner.py to spawn the JS and
# Python backends) is only implemented on the Proactor loop. On Windows,
# Python 3.8+ already defaults to ``WindowsProactorEventLoopPolicy`` — but
# uvicorn 0.32, when running with ``--reload`` (or multi-worker), explicitly
# switches the policy to ``WindowsSelectorEventLoopPolicy`` inside
# ``uvicorn.loops.asyncio.asyncio_setup`` *before* the app is even imported.
# That call happens in ``Server.run`` → ``Config.setup_event_loop`` and runs
# strictly before ``main.py`` is loaded, so no amount of monkey-patching here
# can intervene in time. The launch script therefore passes ``--loop none``
# to uvicorn, which skips uvicorn's loop setup entirely and lets the Python
# default (Proactor) survive. The policy pin below is a belt-and-suspenders
# safeguard for ad-hoc scripts and tests that import ``main`` directly.
if sys.platform == "win32":
    asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())

    # ── IOCP double-registration guard (idem: same logic as run.py) ───
    # uvicorn ``--reload`` spawns worker processes with ``multiprocessing
    # .spawn()``. Each worker imports ``main.py`` in a brand-new interpreter
    # where the monkey-patch from ``run.py`` does NOT exist, so without this
    # safeguard the worker's IocpProactor hits WinError 87 again and silently
    # kills the listener.
    from asyncio.windows_events import IocpProactor  # noqa: E402
    if getattr(IocpProactor._register_with_iocp, "_patched_for_winerror87", False) is False:
        _orig_register_with_iocp_worker = IocpProactor._register_with_iocp
        def _register_with_iocp_safe(self, obj):  # noqa: ANN001, ANN201
            try:
                _orig_register_with_iocp_worker(self, obj)
            except OSError as exc:
                if exc.winerror != 87:
                    raise
                try:
                    self._registered.add(obj)
                except Exception:  # noqa: BLE001
                    pass
        _register_with_iocp_safe._patched_for_winerror87 = True  # type: ignore[attr-defined]
        IocpProactor._register_with_iocp = _register_with_iocp_safe


def _start_windows_supervisor_watchdog() -> None:
    if sys.platform != "win32":
        return

    try:
        supervisor_pid = int(os.environ.get("MOCK_API_SUPERVISOR_PID", "0"))
    except ValueError:
        return

    if supervisor_pid <= 0 or supervisor_pid == os.getpid():
        return

    from ctypes import wintypes

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    kernel32.OpenProcess.restype = wintypes.HANDLE
    kernel32.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
    kernel32.WaitForSingleObject.restype = wintypes.DWORD
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel32.CloseHandle.restype = wintypes.BOOL

    handle = kernel32.OpenProcess(0x00100000, False, supervisor_pid)  # SYNCHRONIZE
    if not handle:
        os._exit(3)

    def _watch_supervisor() -> None:
        try:
            kernel32.WaitForSingleObject(handle, 0xFFFFFFFF)
        finally:
            kernel32.CloseHandle(handle)
        os._exit(3)

    threading.Thread(target=_watch_supervisor, name="uvicorn-supervisor-watchdog", daemon=True).start()


_start_windows_supervisor_watchdog()

from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, AsyncIterator

from fastapi import Depends, FastAPI, File, Form, Header, HTTPException, Query, Request, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import PlainTextResponse, StreamingResponse
from pydantic import BaseModel, Field

import auth
import db
import runner
import sample_data as sd
from logging_config import configure_logging, get_logger, kv

RUNS_DIR = Path(__file__).resolve().parent / "runs"

configure_logging()
log = get_logger("app")
request_log = get_logger("request")
job_log = get_logger("job")

# ─── domain types ────────────────────────────────────────────────────────────

JobStatus = str  # 'queued' | 'running' | 'done' | 'error' | 'cancelled'


@dataclass
class LogLine:
    t: str
    level: str
    indent: int
    text: str

    def as_dict(self) -> dict:
        return {"t": self.t, "level": self.level, "indent": self.indent, "text": self.text}


@dataclass
class Job:
    id: str
    user_id: int
    filename: str
    size: int
    lang: str
    use_llm: bool
    dynamic_eval: bool
    auto_ioc: bool
    speed: str
    status: JobStatus = "queued"
    phase: str = "detect"
    progress: float = 0.0
    logs: list[LogLine] = field(default_factory=list)
    result: dict | None = None
    error: str | None = None
    created_at: float = field(default_factory=time.time)
    input_path: str | None = None
    _event: asyncio.Event | None = None
    _cancel: asyncio.Event | None = None


JOBS: dict[str, Job] = {}


# ─── helpers ─────────────────────────────────────────────────────────────────

# Strong content signatures for sniff-based detection. Each marker is
# specific enough that two hits + zero hits on the other side is a solid
# override of an ambiguous (or wrong) file extension.
_PY_MARKERS = (
    "__import__", "import zlib", "import base64", "import marshal",
    "from typing", "def __", "lambda ", "print(", "exec(b",
    "pyarmor", "py_compile",
)
_JS_MARKERS = (
    "function ", "=>", "console.", "var ", "let ", "const ",
    "require(", "module.exports", "window.", "document.",
    "navigator.", "globalThis",
)


def _sniff_lang(content: bytes | None) -> str | None:
    if not content:
        return None
    head = content[:8192].decode("utf-8", errors="ignore")
    py = sum(1 for m in _PY_MARKERS if m in head)
    js = sum(1 for m in _JS_MARKERS if m in head)
    if py >= 2 and js == 0:
        return "py"
    if js >= 2 and py == 0:
        return "js"
    return None


def detect_lang(filename: str, hint: str | None, content: bytes | None = None) -> str:
    if hint in ("js", "py"):
        return hint
    lower = (filename or "").lower()
    # Unambiguous extensions short-circuit the sniffer.
    if lower.endswith((".py", ".pyc", ".pyo")):
        return "py"
    if lower.endswith((".mjs", ".cjs", ".ts")):
        return "js"
    # `.js` and "no useful extension" both fall through to content
    # sniffing so a Python sample saved as `pasted.js` still ends up
    # in pydeobf instead of being mis-routed to the JS pipeline.
    sniffed = _sniff_lang(content)
    if sniffed is not None:
        return sniffed
    return "js"


def wall_clock() -> str:
    now = datetime.now(timezone.utc).astimezone()
    return now.strftime("%H:%M:%S") + f".{now.microsecond // 1000:03d}"


def _make_unified_diff(original: str, clean: str, filename: str) -> str:
    if not original and not clean:
        return ""
    diff = difflib.unified_diff(
        original.splitlines(keepends=True),
        clean.splitlines(keepends=True),
        fromfile=f"{filename} (original)",
        tofile=f"{filename} (clean)",
        n=3,
    )
    return "".join(diff)


def _backend_log_level(level: str) -> int:
    normalized = (level or "").upper()
    if normalized in {"ERROR", "ERR", "FATAL"}:
        return logging.ERROR
    if normalized in {"WARN", "WARNING"}:
        return logging.WARNING
    return logging.DEBUG


async def run_job(job: Job) -> None:
    assert job._event is not None and job._cancel is not None
    assert job.input_path is not None, "job.input_path must be set before run_job"
    job.status = "running"
    db.update_job(job.id, status="running")

    input_path = Path(job.input_path)
    out_dir = input_path.parent / "out"
    out_dir.mkdir(parents=True, exist_ok=True)
    job_log.info(
        "job_started %s",
        kv(
            job_id=job.id,
            user_id=job.user_id,
            lang=job.lang,
            filename=job.filename,
            size=job.size,
            use_llm=job.use_llm,
            dynamic_eval=job.dynamic_eval,
            auto_ioc=job.auto_ioc,
            run_dir=str(out_dir),
        ),
    )

    def on_log(t: str, level: str, indent: int, text: str) -> None:
        job.logs.append(LogLine(t=t or wall_clock(), level=level, indent=indent, text=text))
        job_log.log(
            _backend_log_level(level),
            "backend_log %s",
            kv(job_id=job.id, level=level, indent=indent, text=text[:1000]),
        )
        # wake any SSE consumer parked on the current event, then rotate.
        ev = job._event
        job._event = asyncio.Event()
        if ev is not None:
            ev.set()

    def on_phase(ph: str) -> None:
        if ph == job.phase:
            return
        job.phase = ph
        job.progress = max(job.progress, runner.PHASE_PROGRESS.get(ph, job.progress))
        db.update_job(job.id, phase=ph, progress=job.progress)
        job_log.info(
            "job_phase %s",
            kv(job_id=job.id, phase=job.phase, progress=round(job.progress, 3)),
        )

    try:
        if job.lang == "js":
            rr = await runner.run_js(
                input_path=input_path, run_dir=out_dir, use_llm=job.use_llm,
                dynamic_eval=job.dynamic_eval, auto_ioc=job.auto_ioc,
                on_log=on_log, on_phase=on_phase, cancel_event=job._cancel,
            )
        else:
            rr = await runner.run_py(
                input_path=input_path, run_dir=out_dir, use_llm=job.use_llm,
                dynamic_eval=job.dynamic_eval, auto_ioc=job.auto_ioc,
                on_log=on_log, on_phase=on_phase, cancel_event=job._cancel,
            )
        iocs = rr.iocs if job.auto_ioc else []

        if job._cancel.is_set():
            job.status = "cancelled"
            db.update_job(job.id, status="cancelled", phase=job.phase, progress=job.progress)
            job_log.warning(
                "job_cancelled %s",
                kv(job_id=job.id, phase=job.phase, progress=round(job.progress, 3)),
            )
            return

        try:
            input_bytes = input_path.read_bytes()
        except OSError:
            input_bytes = b""
        original_code = input_bytes.decode("utf-8", errors="replace") if input_bytes else ""
        sha256 = hashlib.sha256(input_bytes).hexdigest() if input_bytes else ""
        diff_code = _make_unified_diff(original_code, rr.clean_code, job.filename)
        mitre = runner.derive_mitre(job.lang, iocs)
        duration_ms = int((time.time() - job.created_at) * 1000)

        job.result = {
            "engine":   "jsdeobf" if job.lang == "js" else "pydeobf",
            "lang":     job.lang,
            "filename": job.filename,
            "sha256":   sha256,
            "stats": {
                "input_bytes":  len(input_bytes),
                "output_bytes": len(rr.clean_code.encode("utf-8")),
                "duration_ms":  duration_ms,
                "layers":       len(rr.layer_cards),
                "llm_used":     job.use_llm,
                "dynamic_eval": job.dynamic_eval,
                "auto_ioc":     job.auto_ioc,
            },
            "layer_cards":   rr.layer_cards,
            "iocs":          iocs,
            "mitre":         mitre,
            "original_code": original_code,
            "clean_code":    rr.clean_code,
            "diff_code":     diff_code,
        }
        job.status = "done"
        job.phase = "ioc"
        job.progress = 1.0
        db.update_job(job.id, status="done", phase="ioc", progress=1.0, result=job.result)
        job_log.info(
            "job_done %s",
            kv(
                job_id=job.id,
                lang=job.lang,
                duration_ms=duration_ms,
                layers=len(rr.layer_cards),
                iocs=len(iocs),
                input_bytes=len(input_bytes),
                output_bytes=len(rr.clean_code.encode("utf-8")),
            ),
        )
    except Exception as exc:
        job.status = "error"
        job.error = repr(exc)
        db.update_job(job.id, status="error", error=job.error)
        job_log.exception(
            "job_error %s",
            kv(job_id=job.id, lang=job.lang, filename=job.filename, error=repr(exc)),
        )
    finally:
        if job._event is not None:
            job._event.set()


def _session_view(row: dict[str, Any]) -> dict[str, Any]:
    """Shape a DB job row into the sidebar Session item."""
    r = row.get("result") or {}
    iocs = r.get("iocs") or []
    high = sum(1 for x in iocs if x.get("sev") == "high")
    med = sum(1 for x in iocs if x.get("sev") == "med")
    sev = "high" if high >= 1 else ("med" if med >= 1 else "low")
    size_b = row.get("size") or (r.get("stats") or {}).get("input_bytes") or 0
    return {
        "id": row["id"],
        "name": row["filename"],
        "sev": sev,
        "time": _fmt_time(row["created_at"]),
        "size": f"{size_b / 1024:.1f} KB" if size_b else "—",
        "layers": (r.get("stats") or {}).get("layers") or len(r.get("layer_cards") or []) or 0,
        "active": False,
        "status": row["status"],
        "lang": row["lang"],
    }


def _fmt_time(ts: float) -> str:
    now = datetime.now().astimezone()
    when = datetime.fromtimestamp(ts).astimezone()
    if when.date() == now.date():
        return when.strftime("%H:%M")
    delta_days = (now.date() - when.date()).days
    if delta_days == 1:
        return "Yesterday"
    if delta_days < 7:
        return when.strftime("%a")
    return when.strftime("%b %d")


# ─── app ─────────────────────────────────────────────────────────────────────

app = FastAPI(
    title="deobfuscator-app API",
    version="0.3.0",
    # Mount the auto-generated docs under /api/* so the Vite dev-server
    # proxy (which only forwards /api/*) can reach them, and so the
    # frontend's "Docs" button (Header.jsx → /api/docs) actually lands
    # on Swagger instead of a 404.
    docs_url="/api/docs",
    redoc_url="/api/redoc",
    openapi_url="/api/openapi.json",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://127.0.0.1:5173",
    ],
    allow_methods=["*"],
    allow_headers=["*"],
)


def _request_level(status_code: int) -> int:
    if status_code >= 500:
        return logging.ERROR
    if status_code >= 400:
        return logging.WARNING
    return logging.INFO


@app.middleware("http")
async def log_requests(request: Request, call_next):  # noqa: ANN001, ANN201
    request_id = request.headers.get("x-request-id") or uuid.uuid4().hex[:12]
    started = time.perf_counter()
    client = request.client.host if request.client else "-"
    path = request.url.path
    request_log.info(
        "request_start %s",
        kv(request_id=request_id, method=request.method, path=path, client=client),
    )
    try:
        response = await call_next(request)
    except Exception as exc:
        duration_ms = int((time.perf_counter() - started) * 1000)
        request_log.exception(
            "request_error %s",
            kv(
                request_id=request_id,
                method=request.method,
                path=path,
                client=client,
                duration_ms=duration_ms,
                error=repr(exc),
            ),
        )
        raise

    duration_ms = int((time.perf_counter() - started) * 1000)
    response.headers["X-Request-ID"] = request_id
    request_log.log(
        _request_level(response.status_code),
        "request_done %s",
        kv(
            request_id=request_id,
            method=request.method,
            path=path,
            status=response.status_code,
            duration_ms=duration_ms,
            client=client,
        ),
    )
    return response


@app.on_event("startup")
def _startup() -> None:
    db.init()
    RUNS_DIR.mkdir(parents=True, exist_ok=True)
    # Diagnostic — confirm that the running event loop is the Proactor
    # variant on Windows so subprocess spawns actually work. Logged once
    # per worker startup.
    try:
        loop = asyncio.get_running_loop()
        log.info(
            "startup %s",
            kv(
                event_loop=type(loop).__name__,
                policy=type(asyncio.get_event_loop_policy()).__name__,
                runs_dir=str(RUNS_DIR),
            ),
        )
    except RuntimeError:
        log.warning("startup_no_running_loop")


# ─── auth ────────────────────────────────────────────────────────────────────

EMAIL_RE = re.compile(r"^[^\s@]+@[^\s@]+\.[^\s@]+$")


class SignupBody(BaseModel):
    email: str = Field(..., max_length=200)
    password: str = Field(..., min_length=6, max_length=200)
    name: str = Field(default="", max_length=120)


class LoginBody(BaseModel):
    email: str
    password: str


def _public_user(u: dict[str, Any]) -> dict[str, Any]:
    return {"id": u["id"], "email": u["email"], "name": u.get("name") or ""}


@app.post("/api/auth/signup")
def signup(body: SignupBody) -> dict[str, Any]:
    email = body.email.strip().lower()
    if not EMAIL_RE.match(email):
        raise HTTPException(400, "invalid email")
    if db.user_by_email(email):
        raise HTTPException(409, "email already registered")
    pw_hash, pw_salt = auth.hash_password(body.password)
    user = db.insert_user(email=email, name=body.name.strip(), pw_hash=pw_hash, pw_salt=pw_salt)
    token = auth.issue_token(user["id"])
    return {"token": token, "user": _public_user(user)}


@app.post("/api/auth/login")
def login(body: LoginBody) -> dict[str, Any]:
    email = body.email.strip().lower()
    user = db.user_by_email(email)
    if not user or not auth.verify_password(body.password, user["pw_hash"], user["pw_salt"]):
        raise HTTPException(401, "invalid email or password")
    token = auth.issue_token(user["id"])
    return {"token": token, "user": _public_user(user)}


@app.post("/api/auth/logout")
def logout(
    authorization: str | None = Header(default=None),
    token: str | None = Query(default=None),
    user: dict = Depends(auth.current_user),
) -> dict:
    if authorization and authorization.lower().startswith("bearer "):
        db.delete_token(authorization[7:].strip())
    elif token:
        db.delete_token(token.strip())
    return {"ok": True}


@app.get("/api/auth/me")
def me(user: dict = Depends(auth.current_user)) -> dict:
    return _public_user(user)


# ─── public ──────────────────────────────────────────────────────────────────

@app.get("/api/health")
def health() -> dict:
    return {
        "ok": True,
        "engines": {"jsdeobf": "online", "pydeobf": "online"},
        "llm": {"provider": "openai", "model": "gpt-4o", "online": True},
        "jobs_in_memory": len(JOBS),
    }


@app.get("/api/phases")
def phases() -> list[dict]:
    return sd.PHASES


# ─── protected: sessions + jobs ──────────────────────────────────────────────

@app.get("/api/sessions")
def sessions(user: dict = Depends(auth.current_user)) -> list[dict]:
    rows = db.jobs_for_user(user["id"])
    out = [_session_view(r) for r in rows]
    if out:
        out[0]["active"] = True
    return out


@app.post("/api/analyze")
async def analyze(
    file: UploadFile = File(...),
    use_llm: bool = Form(False),
    dynamic_eval: bool = Form(True),
    auto_ioc: bool = Form(True),
    lang_hint: str | None = Form(None),
    speed: str = Form("normal"),
    user: dict = Depends(auth.current_user),
) -> dict:
    if speed not in ("normal", "fast"):
        raise HTTPException(400, "speed must be 'normal' or 'fast'")
    blob = await file.read()
    raw_name = file.filename or "upload.bin"
    safe_name = Path(raw_name).name or "upload.bin"
    lang = detect_lang(safe_name, lang_hint, content=blob)
    sha256 = hashlib.sha256(blob).hexdigest() if blob else ""

    job_id = uuid.uuid4().hex[:12]
    work_dir = RUNS_DIR / job_id
    work_dir.mkdir(parents=True, exist_ok=True)
    input_path = work_dir / safe_name
    input_path.write_bytes(blob)

    job = Job(
        id=job_id,
        user_id=user["id"],
        filename=safe_name,
        size=len(blob),
        lang=lang,
        use_llm=use_llm,
        dynamic_eval=dynamic_eval,
        auto_ioc=auto_ioc,
        speed=speed,
        input_path=str(input_path),
    )
    job._event = asyncio.Event()
    job._cancel = asyncio.Event()
    JOBS[job.id] = job
    db.insert_job(job.id, user["id"], job.filename, job.size, job.lang, "queued")
    job_log.info(
        "job_queued %s",
        kv(
            job_id=job.id,
            user_id=user["id"],
            filename=job.filename,
            size=job.size,
            sha256=sha256[:16],
            lang=job.lang,
            lang_hint=lang_hint,
            speed=speed,
            use_llm=use_llm,
            dynamic_eval=dynamic_eval,
            auto_ioc=auto_ioc,
        ),
    )
    asyncio.create_task(run_job(job))
    return {"job_id": job.id, "lang": lang, "filename": job.filename, "size": job.size}


def _load_job_for_user(job_id: str, user_id: int) -> Job | None:
    """Resolve a Job from memory or hydrate a read-only snapshot from DB."""
    job = JOBS.get(job_id)
    if job is not None:
        if job.user_id != user_id:
            return None
        return job
    row = db.get_job(job_id)
    if not row or row["user_id"] != user_id:
        return None
    snap = Job(
        id=row["id"],
        user_id=row["user_id"],
        filename=row["filename"],
        size=row["size"],
        lang=row["lang"],
        use_llm=False,
        dynamic_eval=True,
        auto_ioc=True,
        speed="normal",
        status=row["status"],
        phase=row["phase"],
        progress=row["progress"],
        result=row["result"],
        error=row["error"],
        created_at=row["created_at"],
    )
    return snap


@app.get("/api/jobs/{job_id}")
def get_job(job_id: str, user: dict = Depends(auth.current_user)) -> dict:
    job = _load_job_for_user(job_id, user["id"])
    if job is None:
        raise HTTPException(404, f"job {job_id!r} not found")
    return {
        "id": job.id,
        "status": job.status,
        "phase": job.phase,
        "progress": job.progress,
        "lang": job.lang,
        "filename": job.filename,
        "size": job.size,
        "logs": [l.as_dict() for l in job.logs],
        "result": job.result,
        "error": job.error,
    }


@app.post("/api/jobs/{job_id}/cancel")
def cancel_job(job_id: str, user: dict = Depends(auth.current_user)) -> dict:
    job = JOBS.get(job_id)
    if job is None or job.user_id != user["id"]:
        raise HTTPException(404, f"job {job_id!r} not found")
    if job._cancel is not None and job.status == "running":
        job._cancel.set()
        job_log.info("job_cancel_requested %s", kv(job_id=job.id, user_id=user["id"], status=job.status))
    return {"id": job.id, "status": job.status}


@app.delete("/api/jobs/{job_id}")
def delete_job_endpoint(job_id: str, user: dict = Depends(auth.current_user)) -> dict:
    # If the job is still in memory we need to signal cancellation first so
    # the background coroutine winds down cleanly; otherwise it would carry
    # on writing to a DB row we're about to remove.
    job = JOBS.get(job_id)
    if job is not None and job.user_id == user["id"]:
        if job._cancel is not None and job.status in ("queued", "running"):
            job._cancel.set()
        JOBS.pop(job_id, None)
    removed = db.delete_job(job_id, user["id"])
    if not removed and job is None:
        raise HTTPException(404, f"job {job_id!r} not found")
    # Best-effort cleanup of the per-job working directory.
    work_dir = RUNS_DIR / job_id
    if work_dir.exists():
        shutil.rmtree(work_dir, ignore_errors=True)
    job_log.info(
        "job_deleted %s",
        kv(job_id=job_id, user_id=user["id"], removed=removed, had_memory_job=job is not None),
    )
    return {"id": job_id, "deleted": True}


@app.get("/api/jobs/{job_id}/clean", response_class=PlainTextResponse)
def download_clean(job_id: str, user: dict = Depends(auth.current_user)) -> PlainTextResponse:
    job = _load_job_for_user(job_id, user["id"])
    if job is None:
        raise HTTPException(404, f"job {job_id!r} not found")
    if job.result is None:
        raise HTTPException(409, "job is not finished")
    clean_code = job.result["clean_code"]
    base, _, ext = (job.filename or "sample.js").rpartition(".")
    if not base:
        base, ext = ext, "js"
    dl_name = f"{base}.cleaned.{ext}"
    return PlainTextResponse(
        clean_code,
        headers={"Content-Disposition": f'attachment; filename="{dl_name}"'},
    )


@app.get("/api/jobs/{job_id}/stream")
async def stream_job(job_id: str, user: dict = Depends(auth.current_user)) -> StreamingResponse:
    # Live stream only makes sense for in-memory jobs.
    job = JOBS.get(job_id)
    if job is None:
        # Finished job — emit a one-shot snapshot+end derived from DB.
        snap = _load_job_for_user(job_id, user["id"])
        if snap is None:
            raise HTTPException(404, f"job {job_id!r} not found")

        async def replay() -> AsyncIterator[bytes]:
            yield _sse("snapshot", {
                "status": snap.status, "phase": snap.phase, "progress": snap.progress,
                "logs": [],
            })
            yield _sse("end", {
                "status": snap.status, "phase": snap.phase, "progress": snap.progress,
                "result": snap.result, "error": snap.error,
            })

        return StreamingResponse(replay(), media_type="text/event-stream")

    if job.user_id != user["id"]:
        raise HTTPException(404, f"job {job_id!r} not found")

    async def gen() -> AsyncIterator[bytes]:
        cursor = 0
        yield _sse("snapshot", {
            "status": job.status, "phase": job.phase, "progress": job.progress,
            "logs": [l.as_dict() for l in job.logs],
        })
        while True:
            if cursor < len(job.logs):
                for line in job.logs[cursor:]:
                    yield _sse("log", line.as_dict())
                cursor = len(job.logs)
                yield _sse("phase", {"phase": job.phase, "progress": job.progress})
            if job.status in ("done", "error", "cancelled"):
                yield _sse("end", {
                    "status": job.status, "phase": job.phase, "progress": job.progress,
                    "result": job.result, "error": job.error,
                })
                return
            ev = job._event
            if ev is None:
                await asyncio.sleep(0.1)
            else:
                try:
                    await asyncio.wait_for(ev.wait(), timeout=15.0)
                except asyncio.TimeoutError:
                    yield b": keepalive\n\n"

    return StreamingResponse(gen(), media_type="text/event-stream")


def _sse(event: str, data: dict) -> bytes:
    payload = json.dumps(data, ensure_ascii=False)
    return f"event: {event}\ndata: {payload}\n\n".encode("utf-8")
