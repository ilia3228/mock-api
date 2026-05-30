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
import io
import json
import logging
import os
import re
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import uuid
import zipfile

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
import llm_config as llmcfg
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


VALID_LLM_MODES = ("off", "rename", "format", "both")


@dataclass
class Job:
    id: str
    user_id: int
    filename: str
    size: int
    lang: str
    # Per-run options. ``llm_mode`` supersedes the legacy boolean ``use_llm``.
    llm_mode: str = "off"
    dynamic_eval: bool = True
    auto_ioc: bool = True
    static_analysis: bool = True
    rename: bool = True
    max_layers: int | None = None
    timeout: int | None = None
    verbose: bool = True
    speed: str = "normal"
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

    @property
    def use_llm(self) -> bool:  # legacy alias used by older logs/snapshots
        return self.llm_mode != "off"

    def options_dict(self) -> dict[str, Any]:
        """Per-run options snapshot. Serialised into ``jobs.options_json``
        and copied into ``result.stats.options`` so the frontend can offer
        “retry with same options” after a failure.
        """
        return {
            "llm_mode":        self.llm_mode,
            "dynamic_eval":    self.dynamic_eval,
            "auto_ioc":        self.auto_ioc,
            "static_analysis": self.static_analysis,
            "rename":          self.rename,
            "max_layers":      self.max_layers,
            "timeout":         self.timeout,
            "verbose":         self.verbose,
            "speed":           self.speed,
        }


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


ZIP_DEFAULT_PASSWORD = b"infected"


def _extract_and_validate_zip(blob: bytes) -> tuple[str, bytes]:
    """Extract and validate ZIP archive with MalwareBazaar compatibility.

    If the archive is not a valid ZIP, contains other than exactly one file,
    cannot be decrypted with password 'infected' or has an unsupported extension
    (other than .js or .py), raises ValueError with a descriptive message.
    """
    if not zipfile.is_zipfile(io.BytesIO(blob)):
        raise ValueError("Not a valid ZIP archive.")

    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)
        zip_file = tmp_path / "upload.zip"
        zip_file.write_bytes(blob)

        # Output directory for 7z extraction
        out_dir = tmp_path / "out"
        out_dir.mkdir()

        # Run 7z to extract the zip file
        cmd = ["7z", "e", "-pinfected", f"-o{out_dir}", str(zip_file), "-y"]
        try:
            res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
        except Exception as e:
            raise ValueError(f"Failed to execute 7z extraction: {e}")

        if res.returncode != 0:
            raise ValueError("Could not decrypt ZIP archive. Password 'infected' is expected.")

        # List all extracted files
        extracted_files = [f for f in out_dir.iterdir() if f.is_file()]
        if len(extracted_files) != 1:
            raise ValueError(
                f"ZIP archive must contain exactly one file. Found {len(extracted_files)} files."
            )

        extracted_file = extracted_files[0]
        inner_name = extracted_file.name

        # Check extension (must be .js or .py)
        suffix = extracted_file.suffix.lower()
        if suffix not in (".js", ".py"):
            raise ValueError(
                f"Rejected: ZIP archive contains an unsupported file type '{suffix}'. "
                f"Only .js and .py files are accepted."
            )

        inner_bytes = extracted_file.read_bytes()

        # Zip-bomb protection: check size
        MAX_UNCOMPRESSED_BYTES = 50 * 1024 * 1024  # 50 MB
        if len(inner_bytes) > MAX_UNCOMPRESSED_BYTES:
            raise ValueError("Extracted file size exceeds the limit of 50 MB.")

        ratio = len(inner_bytes) / max(len(blob), 1)
        if ratio > 1000:
            raise ValueError("Potential ZIP bomb detected (compression ratio too high).")

        return inner_name, inner_bytes


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
            llm_mode=job.llm_mode,
            dynamic_eval=job.dynamic_eval,
            auto_ioc=job.auto_ioc,
            static_analysis=job.static_analysis,
            rename=job.rename,
            max_layers=job.max_layers,
            timeout=job.timeout,
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

    runner_kwargs = dict(
        input_path=input_path, run_dir=out_dir,
        llm_mode=job.llm_mode,
        dynamic_eval=job.dynamic_eval,
        auto_ioc=job.auto_ioc,
        static_analysis=job.static_analysis,
        rename=job.rename,
        max_layers=job.max_layers,
        timeout=job.timeout,
        verbose=job.verbose,
        on_log=on_log, on_phase=on_phase, cancel_event=job._cancel,
    )
    try:
        if job.lang == "js":
            rr = await runner.run_js(**runner_kwargs)
        else:
            rr = await runner.run_py(**runner_kwargs)
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
                "llm_mode":     job.llm_mode,
                "llm_used":     job.use_llm,  # legacy alias
                "dynamic_eval": job.dynamic_eval,
                "auto_ioc":     job.auto_ioc,
                "options":      job.options_dict(),
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
    allow_origins=["*"],
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


def _adopt_legacy_llm_key_owner() -> None:
    if db.llm_key_owner_user_id() is not None or not llmcfg.is_configured():
        return
    only_user_id = db.single_user_id()
    if only_user_id is None:
        llmcfg.clear_verified_fingerprint()
        log.warning("llm_key_unowned_legacy_config")
        return
    db.set_llm_key_owner(only_user_id)
    llmcfg.clear_verified_fingerprint()
    log.info("llm_key_legacy_owner_adopted %s", kv(user_id=only_user_id))


@app.on_event("startup")
def _startup() -> None:
    db.init()
    _adopt_legacy_llm_key_owner()
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


class ChangePasswordBody(BaseModel):
    current_password: str = Field(..., min_length=1, max_length=200)
    new_password:     str = Field(..., min_length=6, max_length=200)


@app.post("/api/auth/change-password")
def change_password(
    body: ChangePasswordBody,
    user: dict = Depends(auth.current_user),
) -> dict:
    """Replace the user's password. Reuses the PBKDF2 hashing in ``auth``.

    Existing tokens stay valid intentionally — the user just confirmed
    knowledge of the current password and we don't want to log them out
    of their own session as a side-effect.
    """
    if not auth.verify_password(
        body.current_password, user["pw_hash"], user["pw_salt"]
    ):
        raise HTTPException(401, "current password incorrect")
    pw_hash, pw_salt = auth.hash_password(body.new_password)
    db.update_user_password(user["id"], pw_hash, pw_salt)
    log.info(
        "auth_password_changed %s",
        kv(user_id=user["id"], email=user["email"]),
    )
    return {"ok": True}


@app.delete("/api/auth/tokens")
def auth_delete_tokens(
    authorization: str | None = Header(default=None),
    token: str | None = Query(default=None),
    user: dict = Depends(auth.current_user),
) -> dict:
    """Sign-out from every device *except* the caller's own session."""
    own_token: str | None = None
    if authorization and authorization.lower().startswith("bearer "):
        own_token = authorization[7:].strip() or None
    elif token:
        own_token = token.strip() or None
    revoked = db.delete_user_tokens(user["id"], except_token=own_token)
    log.info(
        "auth_tokens_revoked %s",
        kv(user_id=user["id"], revoked=revoked, kept_own=bool(own_token)),
    )
    return {"ok": True, "revoked": revoked}


class DeleteAccountBody(BaseModel):
    email_confirm: str = Field(..., max_length=200)


@app.delete("/api/auth/me")
def delete_me(
    body: DeleteAccountBody,
    user: dict = Depends(auth.current_user),
) -> dict:
    """Delete the user account and every owned job/token cascade.

    Requires the caller to retype their own email as a confirmation step
    (matches the deletion flow in Settings → Account).
    """
    confirm = (body.email_confirm or "").strip().lower()
    if confirm != (user["email"] or "").lower():
        raise HTTPException(400, "email confirmation does not match")

    # Cancel any in-flight jobs for this user before tearing down the row;
    # otherwise a still-running coroutine could later UPDATE a vanished
    # jobs row and resurrect it via SQLite's auto-vacuum semantics.
    in_flight = [j for j in JOBS.values() if j.user_id == user["id"]]
    for job in in_flight:
        if job._cancel is not None and job.status in ("queued", "running"):
            job._cancel.set()
        JOBS.pop(job.id, None)

    # Wipe each per-job directory before we lose the id list.
    for job_id in db.all_job_ids_for_user(user["id"]):
        work_dir = RUNS_DIR / job_id
        if work_dir.exists():
            shutil.rmtree(work_dir, ignore_errors=True)

    if _llm_key_owned_by(user):
        llmcfg.write_config({"clear_api_key": True})
        db.clear_llm_key_owner(int(user["id"]))
        llmcfg.clear_verified_fingerprint()

    db.delete_user(user["id"])  # CASCADE clears tokens + jobs
    log.warning(
        "auth_account_deleted %s",
        kv(user_id=user["id"], email=user["email"], in_flight=len(in_flight)),
    )
    return {"ok": True}


# ─── LLM configuration ──────────────────────────────────────────────────────

class LLMConfigBody(BaseModel):
    """Payload for ``PUT /api/llm/config``.

    Every field is optional — only the keys that are present get written
    through to the underlying ``llm_config.toml`` files. ``api_key`` has
    three-state semantics:
        - missing / null → keep the existing value
        - non-empty str  → overwrite both files
        - empty str ""   → must come with ``clear_api_key=true``
    """
    provider:        str | None   = Field(default=None, max_length=64)
    model:           str | None   = Field(default=None, max_length=200)
    base_url:        str | None   = Field(default=None, max_length=500)
    api_key:         str | None   = Field(default=None, max_length=2048)
    clear_api_key:   bool         = Field(default=False)
    temperature:     float | None = Field(default=None, ge=0, le=2)
    max_tokens:      int | None   = Field(default=None, ge=1, le=200_000)
    max_code_size:   int | None   = Field(default=None, ge=1024)
    timeout_seconds: int | None   = Field(default=None, ge=1, le=3600)
    api_key_env:     str | None   = Field(default=None, max_length=128)


def _llm_key_owner_id() -> int | None:
    return db.llm_key_owner_user_id()


def _llm_key_owned_by(user: dict[str, Any]) -> bool:
    return _llm_key_owner_id() == int(user["id"])


def _llm_configured_for_user(user: dict[str, Any]) -> bool:
    return _llm_key_owned_by(user) and llmcfg.is_configured()


def _llm_public_view_for_user(cfg: dict[str, Any], user: dict[str, Any]) -> dict:
    owns_key = _llm_key_owned_by(user)
    effective_cfg = cfg if owns_key else {**cfg, "api_key": ""}
    view = llmcfg.public_view(effective_cfg)
    view["api_key_owned"] = owns_key and bool(view["api_key_present"])
    view["verified"] = (
        llmcfg.is_verified(cfg, user_id=int(user["id"]))
        if owns_key else False
    )
    return view


@app.get("/api/llm/config")
def llm_get_config(
    reveal: bool = Query(False),
    user: dict = Depends(auth.current_user),
) -> dict:
    """Return the current merged LLM config.

    By default the ``api_key`` is replaced by ``api_key_present`` +
    ``api_key_last4`` so the secret never crosses the network. When the
    caller explicitly opts in via ``?reveal=1`` we additionally include
    the plaintext ``api_key`` — used by the Settings "show" button so
    operators can copy/edit a previously-saved key without re-typing it.

    Reveal requires the bearer token for the same user that saved the key;
    other users see the shared test config as if no key were present.
    """
    cfg = llmcfg.read_config()
    view = _llm_public_view_for_user(cfg, user)
    if reveal:
        if not _llm_key_owned_by(user) or not str(cfg.get("api_key") or "").strip():
            raise HTTPException(403, "llm api key is not owned by this user")
        view["api_key"] = str(cfg.get("api_key") or "")
        log.info(
            "llm_config_reveal %s",
            kv(user_id=user["id"], api_key_present=view["api_key_present"]),
        )
    return view


@app.put("/api/llm/config")
def llm_put_config(
    body: LLMConfigBody,
    user: dict = Depends(auth.current_user),
) -> dict:
    """Write to both ``js_deobf/llm_config.toml`` and
    ``py_deobf/llm_config.toml`` simultaneously.

    Comments and unknown keys (multi-line prompts, ``rename_prompt``,
    ``format_prompt``) are preserved by ``llm_config.write_config``.
    """
    payload: dict[str, Any] = body.model_dump(exclude_unset=True)
    # When ``clear_api_key`` is set, drop any inadvertent api_key value
    # so the writer takes the clear path.
    if payload.get("clear_api_key"):
        payload.pop("api_key", None)
    elif "api_key" in payload and not (payload["api_key"] or "").strip():
        # Empty string without explicit clear flag → treat as "no change".
        payload.pop("api_key")
    if "api_key" in payload:
        payload["api_key"] = str(payload["api_key"]).strip()

    owner_id = _llm_key_owner_id()
    owns_key = owner_id == int(user["id"])
    key_being_set = "api_key" in payload
    key_being_cleared = bool(payload.get("clear_api_key"))

    if key_being_cleared and not owns_key:
        raise HTTPException(403, "llm api key is not owned by this user")
    if not key_being_set and not key_being_cleared and llmcfg.is_configured() and not owns_key:
        raise HTTPException(
            403,
            "llm api key is not owned by this user; paste a new key to replace it",
        )

    llmcfg.write_config(payload)
    if key_being_set:
        db.set_llm_key_owner(int(user["id"]))
        llmcfg.clear_verified_fingerprint()
    elif key_being_cleared:
        db.clear_llm_key_owner(int(user["id"]))
        llmcfg.clear_verified_fingerprint()
    elif not llmcfg.is_configured():
        db.clear_llm_key_owner(int(user["id"]))
    log.info(
        "llm_config_updated %s",
        kv(
            user_id=user["id"],
            keys_set=sorted(k for k in payload.keys() if k != "api_key"),
            api_key_changed=key_being_set or key_being_cleared,
            api_key_cleared=key_being_cleared,
            previous_owner_id=owner_id,
            owner_id=_llm_key_owner_id(),
        ),
    )
    return _llm_public_view_for_user(llmcfg.read_config(), user)


@app.post("/api/llm/check")
async def llm_check(
    engine: str = Query("both", regex="^(js|py|both)$"),
    user: dict = Depends(auth.current_user),
) -> dict:
    """Probe the configured LLM by spawning the backends' built-in
    health-check commands and timing the round-trip.

    - JS: ``node dist/main.js --llm-check``
    - PY: ``python tests/test_llm.py --max-tokens 8``

    Returns ``{ok, engine, results: [{engine, ok, latency_ms, ...}]}``
    so the frontend can render either one or two rows.
    """
    if not _llm_configured_for_user(user):
        raise HTTPException(400, "llm not configured")

    cfg = llmcfg.read_config()
    targets: list[str] = []
    if engine in ("js", "both"):
        targets.append("js")
    if engine in ("py", "both"):
        targets.append("py")

    results = []
    for tgt in targets:
        results.append(await _run_llm_check(tgt, cfg))
    overall_ok = all(r.get("ok") for r in results) if results else False
    # Persist the "verified" stamp server-side so it survives page
    # refreshes and server restarts. Stamp on full success only — a
    # mixed result (one engine ok, one failing) means LLM mode is not
    # safely usable from the upload screen yet.
    if overall_ok:
        llmcfg.write_verified_fingerprint(llmcfg.fingerprint_for(cfg), user_id=int(user["id"]))
    else:
        llmcfg.clear_verified_fingerprint()
    log.info(
        "llm_check %s",
        kv(
            user_id=user["id"],
            engine=engine,
            ok=overall_ok,
            results=[{"engine": r["engine"], "ok": r["ok"]} for r in results],
        ),
    )
    return {"ok": overall_ok, "engine": engine, "results": results}


async def _run_llm_check(target: str, cfg: dict[str, Any]) -> dict[str, Any]:
    """Spawn one backend's --llm-check and parse exit code + stderr/out."""
    started = time.perf_counter()
    if target == "js":
        repo = runner._js_repo_dir()
        main_js = repo / "dist" / "main.js"
        if not main_js.exists():
            return {
                "engine": "js", "ok": False,
                "error": "JS backend is not built",
                "latency_ms": 0,
                "model": cfg.get("model") or "",
            }
        args = ["node", str(main_js), "--llm-check"]
        cwd = str(repo)
    else:
        repo = runner._py_repo_dir()
        test_py = repo / "tests" / "test_llm.py"
        if not test_py.exists():
            return {
                "engine": "py", "ok": False,
                "error": "Python LLM check is unavailable",
                "latency_ms": 0,
                "model": cfg.get("model") or "",
            }
        args = [sys.executable, str(test_py), "--max-tokens", "8"]
        cwd = str(repo)

    # Force UTF-8 stdout in the subprocess so the Python smoke test's
    # box-drawing chars (───) don't crash with UnicodeEncodeError when the
    # mock-api itself happens to be running under a non-UTF-8 locale
    # (e.g. cp1251 on Russian Windows). PYTHONIOENCODING covers <3.13 and
    # PYTHONUTF8 covers the modern "UTF-8 mode" toggle. Harmless for Node.
    env = {
        **os.environ,
        "NO_COLOR": "1",
        "FORCE_COLOR": "0",
        "PYTHONIOENCODING": "utf-8",
        "PYTHONUTF8": "1",
    }
    try:
        proc = await asyncio.create_subprocess_exec(
            *args,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
            cwd=cwd,
            env=env,
        )
        try:
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=30.0)
        except asyncio.TimeoutError:
            try:
                proc.kill()
            except ProcessLookupError:
                pass
            await proc.wait()
            return {
                "engine": target, "ok": False,
                "error": "timeout (30s)",
                "latency_ms": int((time.perf_counter() - started) * 1000),
                "model": cfg.get("model") or "",
            }
        rc = proc.returncode or 0
        latency_ms = int((time.perf_counter() - started) * 1000)
        text = (stdout or b"").decode("utf-8", errors="replace")
        result: dict[str, Any] = {
            "engine":     target,
            "ok":         rc == 0,
            "latency_ms": latency_ms,
            "model":      cfg.get("model") or "",
            "provider":   cfg.get("provider") or "",
        }
        if rc != 0:
            result["error"] = _safe_llm_check_error(text, rc)
            result["exit_code"] = rc
        return result
    except FileNotFoundError as exc:
        process_log.warning(
            "llm_check_executable_missing %s",
            kv(engine=target, error=repr(exc)),
        )
        return {
            "engine": target, "ok": False,
            "error": "required executable is unavailable",
            "latency_ms": int((time.perf_counter() - started) * 1000),
            "model": cfg.get("model") or "",
        }


def _safe_llm_check_error(text: str, exit_code: int) -> str:
    """Convert noisy backend output into a UI-safe one-line reason.

    LLM probes can print local paths, stack traces, provider URLs, or parts
    of a configured API key. The Settings screen only needs the category.
    """
    raw = text or ""
    lowered = raw.lower()
    if "invalid_api_key" in lowered or "incorrect api key" in lowered or "authenticationerror" in lowered:
        return "authentication failed (invalid API key)"
    if "401" in lowered and "api key" in lowered:
        return "authentication failed (invalid API key)"
    if "unicodeencodeerror" in lowered or "charmap" in lowered:
        return "LLM check failed while writing console output"
    if "timeout" in lowered:
        return "LLM check timed out"
    if "rate_limit" in lowered or "rate limit" in lowered or "429" in lowered:
        return "provider rate limit reached"
    if "connection" in lowered or "econnrefused" in lowered or "connecterror" in lowered:
        return "provider endpoint is unreachable"
    return f"LLM check failed (exit {exit_code})"


# ─── public ──────────────────────────────────────────────────────────────────

@app.get("/api/health")
def health() -> dict:
    """Cheap status pill source for the frontend Header.

    “online” here means “the backend is reachable and looks runnable” —
    we don’t spin up a full subprocess on every poll. The JS engine
    requires its ``dist/main.js`` to exist; the Python engine just needs
    its ``src/main.py``. ``llm.online`` mirrors whether an API key is
    actually configured (use ``POST /api/llm/check`` for a deeper probe).
    """
    js_repo = runner._js_repo_dir()
    py_repo = runner._py_repo_dir()
    js_ok = (js_repo / "dist" / "main.js").exists()
    py_ok = (py_repo / "src" / "main.py").exists()

    cfg = llmcfg.read_config()
    llm_online = bool(str(cfg.get("api_key") or "").strip())

    return {
        "ok": js_ok or py_ok,
        "engines": {
            "jsdeobf": "online" if js_ok else "offline",
            "pydeobf": "online" if py_ok else "offline",
        },
        "llm": {
            "provider": cfg.get("provider") or "",
            "model":    cfg.get("model") or "",
            "online":   llm_online,
        },
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
    # Per-run options ──────────────────────────────────────────────────────
    # New (preferred): granular four-way LLM mode.
    llm_mode: str | None = Form(None),
    # Legacy fallback — maps ``true`` → “both” when ``llm_mode`` is omitted.
    use_llm: bool = Form(False),
    dynamic_eval: bool = Form(True),
    auto_ioc: bool = Form(True),
    static_analysis: bool = Form(True),
    rename: bool = Form(True),
    max_layers: int | None = Form(None),
    timeout: int | None = Form(None),
    verbose: bool = Form(True),
    lang_hint: str | None = Form(None),
    speed: str = Form("normal"),
    user: dict = Depends(auth.current_user),
) -> dict:
    if speed not in ("normal", "fast"):
        raise HTTPException(400, "speed must be 'normal' or 'fast'")
    # Resolve llm_mode — explicit value wins, otherwise legacy use_llm decides.
    if llm_mode is None:
        llm_mode = "both" if use_llm else "off"
    if llm_mode not in VALID_LLM_MODES:
        raise HTTPException(
            400, f"llm_mode must be one of {VALID_LLM_MODES!r}"
        )
    if llm_mode != "off" and not _llm_configured_for_user(user):
        # Frontend treats this as “redirect to Settings → LLM”.
        raise HTTPException(400, "llm not configured")
    if max_layers is not None and max_layers <= 0:
        max_layers = None
    if timeout is not None and timeout <= 0:
        timeout = None

    blob = await file.read()
    raw_name = file.filename or "upload.bin"
    safe_name = Path(raw_name).name or "upload.bin"

    # ── ZIP handling (MalwareBazaar compatibility) ────────────────────────
    if zipfile.is_zipfile(io.BytesIO(blob)):
        try:
            inner_name, inner_bytes = _extract_and_validate_zip(blob)
            job_log.info(
                "zip_extracted %s",
                kv(
                    outer=safe_name,
                    inner=inner_name,
                    outer_bytes=len(blob),
                    inner_bytes=len(inner_bytes),
                ),
            )
            safe_name = inner_name
            blob = inner_bytes
        except ValueError as exc:
            raise HTTPException(400, detail=str(exc))

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
        llm_mode=llm_mode,
        dynamic_eval=dynamic_eval,
        auto_ioc=auto_ioc,
        static_analysis=static_analysis,
        rename=rename,
        max_layers=max_layers,
        timeout=timeout,
        verbose=verbose,
        speed=speed,
        input_path=str(input_path),
    )
    job._event = asyncio.Event()
    job._cancel = asyncio.Event()
    JOBS[job.id] = job
    db.insert_job(
        job.id, user["id"], job.filename, job.size, job.lang,
        "queued", options=job.options_dict(),
    )
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
            **job.options_dict(),
        ),
    )
    asyncio.create_task(run_job(job))
    try:
        uploaded_code = blob.decode("utf-8", errors="replace")
    except Exception:
        uploaded_code = ""
    return {
        "job_id": job.id,
        "lang": lang,
        "filename": job.filename,
        "size": job.size,
        "uploaded_code": uploaded_code,
    }


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
    saved_opts = row.get("options") or {}
    snap = Job(
        id=row["id"],
        user_id=row["user_id"],
        filename=row["filename"],
        size=row["size"],
        lang=row["lang"],
        llm_mode=saved_opts.get("llm_mode", "off"),
        dynamic_eval=saved_opts.get("dynamic_eval", True),
        auto_ioc=saved_opts.get("auto_ioc", True),
        static_analysis=saved_opts.get("static_analysis", True),
        rename=saved_opts.get("rename", True),
        max_layers=saved_opts.get("max_layers"),
        timeout=saved_opts.get("timeout"),
        verbose=saved_opts.get("verbose", True),
        speed=saved_opts.get("speed", "normal"),
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
        "options": job.options_dict(),
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
