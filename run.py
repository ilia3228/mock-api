"""Launcher: ``python run.py`` instead of plain ``uvicorn main:app …``.

Why this exists
---------------
``runner.py`` spawns the JS / Python deobfuscator backends with
``asyncio.create_subprocess_exec``. That call is only implemented on the
Proactor event loop. On Windows + ``--reload``, uvicorn 0.32 forcibly
switches the policy to ``WindowsSelectorEventLoopPolicy`` inside its own
``Config.setup_event_loop`` step, **before** the app module is imported,
so we can't intercept it from inside ``main.py``.

The internal escape hatch is ``loop="none"`` — it tells uvicorn to skip
its loop setup entirely so the Python default (Proactor on 3.8+) wins.
But uvicorn's *CLI* deliberately omits ``"none"`` from the allowed
``--loop`` choices, so we have to invoke uvicorn programmatically.

Use:
    python run.py            # one-shot run, no auto-reload
    python run.py --reload   # opt-in: watch *.py and restart the worker

Reload defaults to OFF. uvicorn's supervisor/worker split breaks a few
things that bite hard in practice — IOCP double-registration on Windows,
mid-request rebuilds of in-memory SSE buffers, and the occasional zombie
listener that hogs port 8090. The cleanup_stale logic below handles the
zombie listener case when reload IS enabled, but the safest default for
day-to-day work is a single process that you restart manually.
"""

from __future__ import annotations

import asyncio
import ctypes
import csv
import os
import socket
import subprocess
import sys
import time
from io import StringIO
from pathlib import Path

from logging_config import configure_logging, get_logger, kv

configure_logging()
launcher_log = get_logger("launcher")

# Pin the policy here too as a safeguard for any ad-hoc import of ``main``.
if sys.platform == "win32":
    asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())

    # ── IOCP double-registration guard ──────────────────────────────────
    # uvicorn ``--reload`` runs a supervisor process that binds the
    # listening socket and registers it with *its* IOCP, then hands the
    # fd to the worker subprocess via inheritance. The worker spins up a
    # fresh ``IocpProactor`` whose internal ``_registered`` set is empty,
    # so ``_register_with_iocp`` cheerfully calls
    # ``CreateIoCompletionPort`` on the inherited fd — and Windows fires
    # ``ERROR_INVALID_PARAMETER (87)`` because that fd is already wired
    # to the supervisor's IOCP.
    #
    # The default accept-loop (``proactor_events.py:loop``) treats that
    # OSError as fatal and ``sock.close()``s the listener, silently
    # killing the server: the process keeps running but every new
    # connection gets refused. We swallow exactly winerror 87 here — the
    # fd is already attached to a completion port, so the re-registration
    # is a benign no-op. Same workaround Sanic / aiohttp ship.
    from asyncio.windows_events import IocpProactor  # noqa: E402
    if getattr(IocpProactor._register_with_iocp, "_patched_for_winerror87", False) is False:
        _orig_register_with_iocp = IocpProactor._register_with_iocp
        def _register_with_iocp_safe(self, obj):  # noqa: ANN001, ANN201
            try:
                _orig_register_with_iocp(self, obj)
            except OSError as exc:
                if exc.winerror != 87:
                    raise
                # Already attached to an IOCP — record the object in the
                # loop's registered set (CPython 3.12 keys on ``obj`` itself,
                # not ``obj.fileno()``) so subsequent accept calls take the
                # short-circuit path instead of re-issuing a doomed
                # ``CreateIoCompletionPort`` syscall every time.
                try:
                    self._registered.add(obj)
                except Exception:  # noqa: BLE001
                    pass
        _register_with_iocp_safe._patched_for_winerror87 = True  # type: ignore[attr-defined]
        IocpProactor._register_with_iocp = _register_with_iocp_safe

import uvicorn

HOST = "127.0.0.1"
PORT = 8090
BASE_DIR = Path(__file__).resolve().parent
RUNS_DIR = BASE_DIR / "runs"
_JOB_HANDLE: int | None = None


def _install_windows_job_cleanup() -> None:
    """Put the launcher in a Windows Job Object that kills children on exit."""
    if sys.platform != "win32":
        return

    class JOBOBJECT_BASIC_LIMIT_INFORMATION(ctypes.Structure):
        _fields_ = [
            ("PerProcessUserTimeLimit", ctypes.c_int64),
            ("PerJobUserTimeLimit", ctypes.c_int64),
            ("LimitFlags", ctypes.c_uint32),
            ("MinimumWorkingSetSize", ctypes.c_size_t),
            ("MaximumWorkingSetSize", ctypes.c_size_t),
            ("ActiveProcessLimit", ctypes.c_uint32),
            ("Affinity", ctypes.c_size_t),
            ("PriorityClass", ctypes.c_uint32),
            ("SchedulingClass", ctypes.c_uint32),
        ]

    class IO_COUNTERS(ctypes.Structure):
        _fields_ = [
            ("ReadOperationCount", ctypes.c_uint64),
            ("WriteOperationCount", ctypes.c_uint64),
            ("OtherOperationCount", ctypes.c_uint64),
            ("ReadTransferCount", ctypes.c_uint64),
            ("WriteTransferCount", ctypes.c_uint64),
            ("OtherTransferCount", ctypes.c_uint64),
        ]

    class JOBOBJECT_EXTENDED_LIMIT_INFORMATION(ctypes.Structure):
        _fields_ = [
            ("BasicLimitInformation", JOBOBJECT_BASIC_LIMIT_INFORMATION),
            ("IoInfo", IO_COUNTERS),
            ("ProcessMemoryLimit", ctypes.c_size_t),
            ("JobMemoryLimit", ctypes.c_size_t),
            ("PeakProcessMemoryUsed", ctypes.c_size_t),
            ("PeakJobMemoryUsed", ctypes.c_size_t),
        ]

    from ctypes import wintypes

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.CreateJobObjectW.argtypes = [ctypes.c_void_p, ctypes.c_wchar_p]
    kernel32.CreateJobObjectW.restype = wintypes.HANDLE
    kernel32.SetInformationJobObject.argtypes = [
        wintypes.HANDLE,
        ctypes.c_int,
        ctypes.c_void_p,
        wintypes.DWORD,
    ]
    kernel32.SetInformationJobObject.restype = wintypes.BOOL
    kernel32.AssignProcessToJobObject.argtypes = [wintypes.HANDLE, wintypes.HANDLE]
    kernel32.AssignProcessToJobObject.restype = wintypes.BOOL
    kernel32.GetCurrentProcess.restype = wintypes.HANDLE
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel32.CloseHandle.restype = wintypes.BOOL

    job = kernel32.CreateJobObjectW(None, None)
    if not job:
        launcher_log.warning("windows_job_cleanup_disabled %s", kv(reason="CreateJobObjectW failed"))
        return

    info = JOBOBJECT_EXTENDED_LIMIT_INFORMATION()
    info.BasicLimitInformation.LimitFlags = 0x00002000  # JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE

    if not kernel32.SetInformationJobObject(
        job,
        9,  # JobObjectExtendedLimitInformation
        ctypes.byref(info),
        ctypes.sizeof(info),
    ):
        err = ctypes.get_last_error()
        kernel32.CloseHandle(job)
        launcher_log.warning("windows_job_cleanup_disabled %s", kv(reason="SetInformationJobObject failed", error=err))
        return

    if not kernel32.AssignProcessToJobObject(job, kernel32.GetCurrentProcess()):
        err = ctypes.get_last_error()
        kernel32.CloseHandle(job)
        launcher_log.warning("windows_job_cleanup_disabled %s", kv(reason="AssignProcessToJobObject failed", error=err))
        return

    global _JOB_HANDLE
    _JOB_HANDLE = job


def _can_bind_port() -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        try:
            probe.bind((HOST, PORT))
        except OSError:
            return False
    return True


def _listening_pids_on_port() -> set[int]:
    if sys.platform != "win32":
        return set()

    try:
        output = subprocess.check_output(
            ["netstat", "-ano", "-p", "tcp"],
            text=True,
            encoding="utf-8",
            errors="ignore",
        )
    except Exception as exc:  # noqa: BLE001
        launcher_log.warning("tcp_owner_inspection_failed %s", kv(error=repr(exc)))
        return set()

    pids: set[int] = set()
    expected_local = f"{HOST}:{PORT}"
    wildcard_local = f"0.0.0.0:{PORT}"
    for raw_line in output.splitlines():
        parts = raw_line.split()
        if len(parts) < 5 or parts[0].upper() != "TCP":
            continue

        local_addr = parts[1]
        state = parts[-2].upper()
        pid_text = parts[-1]
        if state != "LISTENING" or local_addr not in {expected_local, wildcard_local}:
            continue

        try:
            pids.add(int(pid_text))
        except ValueError:
            continue
    return pids


def _process_image_name(pid: int) -> str | None:
    try:
        output = subprocess.check_output(
            ["tasklist", "/FI", f"PID eq {pid}", "/FO", "CSV", "/NH"],
            text=True,
            encoding="utf-8",
            errors="ignore",
        ).strip()
    except Exception:  # noqa: BLE001
        return None

    if not output or output.upper().startswith("INFO:"):
        return None

    try:
        row = next(csv.reader(StringIO(output)))
    except Exception:  # noqa: BLE001
        return None
    return row[0] if row else None


def _kill_process_tree(pid: int) -> bool:
    try:
        subprocess.run(
            ["taskkill", "/PID", str(pid), "/T", "/F"],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        return True
    except Exception as exc:  # noqa: BLE001
        launcher_log.warning("stale_listener_stop_failed %s", kv(pid=pid, error=repr(exc)))
        return False


def _cleanup_stale_windows_port_owner() -> None:
    """Replace stale Python listeners left behind by uvicorn reload crashes."""
    if sys.platform != "win32" or _can_bind_port():
        return

    stale_pids = _listening_pids_on_port()
    if not stale_pids:
        return

    stopped_any = False
    current_pid = os.getpid()
    for pid in stale_pids:
        if pid == current_pid:
            continue

        image_name = (_process_image_name(pid) or "").lower()
        if not image_name.startswith(("python", "py.exe")):
            launcher_log.warning(
                "port_busy_non_python %s",
                kv(host=HOST, port=PORT, pid=pid, image=image_name or "unknown"),
            )
            continue

        launcher_log.warning("stopping_stale_python_listener %s", kv(host=HOST, port=PORT, pid=pid))
        stopped_any = _kill_process_tree(pid) or stopped_any

    if stopped_any:
        for _ in range(20):
            if _can_bind_port():
                return
            time.sleep(0.1)


def main() -> None:
    # Auto-reload is opt-in: pass --reload to enable it. The default is
    # a single, non-restarting worker — uvicorn's reload supervisor
    # caused too many subtle breakages (stale listeners, half-loaded
    # modules during edits, dropped SSE streams mid-analysis).
    reload = "--reload" in sys.argv
    os.chdir(BASE_DIR)
    if sys.platform == "win32":
        os.environ["MOCK_API_SUPERVISOR_PID"] = str(os.getpid())
        _install_windows_job_cleanup()
        _cleanup_stale_windows_port_owner()

    reload_kwargs = {}
    if reload:
        RUNS_DIR.mkdir(exist_ok=True)
        reload_kwargs = {
            "reload_dirs": [str(BASE_DIR)],
            "reload_excludes": [str(RUNS_DIR)],
        }

    launcher_log.info(
        "launcher_start %s",
        kv(host=HOST, port=PORT, reload=reload, base_dir=str(BASE_DIR)),
    )
    uvicorn.run(
        "main:app",
        host=HOST,
        port=PORT,
        reload=reload,
        loop="none",  # critical: see module docstring
        access_log=False,  # request middleware logs paths without leaking ?token=
        **reload_kwargs,
    )


if __name__ == "__main__":
    main()
