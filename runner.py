"""Real deobfuscator runners.

Spawns the JS or Python deobfuscator CLI as a subprocess, streams its
stdout line by line through callbacks, and collects the resulting
artefacts (cleaned source + layer cards + optional IOC list) from the
run directory once the process exits.

The two backend CLIs live in sibling repositories:

    JS_DEOBF_DIR  -> ../js_deobf                 (node dist/main.js)
    PY_DEOBF_DIR  -> ../py_deobf                 (python src/main.py)

Both can be overridden with environment variables of the same name.

This module is intentionally framework-agnostic: it knows nothing about
FastAPI, jobs, SSE or the database. It just runs a process, parses its
text output, and returns plain data structures.
"""

from __future__ import annotations

import asyncio
import json
import os
import re
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Awaitable, Callable

from logging_config import get_logger, kv

process_log = get_logger("process")

# ─── log parsing ─────────────────────────────────────────────────────────────

_ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")
_LEVEL_RE = re.compile(
    r"^\s*(?P<t>\d{1,2}:\d{2}:\d{2}\.\d{3})?\s*\[(?P<lvl>[A-Z]+)\]\s*(?P<txt>.*)$"
)
_LAYER_RE_JS = re.compile(r"layer\s+(\d+)\s*/\s*(\d+)", re.IGNORECASE)
_LAYER_RE_PY = re.compile(r"layer\s+(\d+)", re.IGNORECASE)

# Phase keyword table. Earlier matches win, so order from most-specific
# (later in the pipeline) to least-specific (detection at the start).
_PHASE_KEYWORDS: list[tuple[str, tuple[str, ...]]] = [
    ("ioc",    ("extracting ioc", "ioc_report", "iocextractor", "ioc:")),
    ("rename", ("llm rename", "llm format", "renamer", "formatter",
                "formatted", "rename pass")),
    ("ast",    ("ast pass", "ast simplification", "ast pipeline",
                "decompil", "beautif", "constant fold")),
    ("unpack", ("dynamic analysis", "sandbox", "string array",
                "marshal", "anti-analysis", "unpack", "unwrap")),
    ("detect", ("pattern detect", "detected:", "source entropy",
                "pattern scan")),
]

# Coarse progress per phase (we don't know how many layers there will be).
PHASE_PROGRESS = {
    "detect": 0.10,
    "unpack": 0.30,
    "ast":    0.60,
    "rename": 0.85,
    "ioc":    0.95,
}

PHASE_ORDER = {
    "detect": 0,
    "unpack": 1,
    "ast":    2,
    "rename": 3,
    "ioc":    4,
}


def _float_env(name: str, default: float) -> float:
    try:
        return float(os.environ.get(name, str(default)))
    except ValueError:
        return default


BACKEND_IDLE_TIMEOUT_SECONDS = _float_env("MOCK_API_BACKEND_IDLE_TIMEOUT_SECONDS", 180.0)
BACKEND_MAX_RUNTIME_SECONDS = _float_env("MOCK_API_BACKEND_MAX_RUNTIME_SECONDS", 3600.0)
BACKEND_STOP_GRACE_SECONDS = _float_env("MOCK_API_BACKEND_STOP_GRACE_SECONDS", 5.0)

# Python deobfuscator sandbox backend. py-deobf's CLI defaults to ``subprocess``,
# which cannot decrypt AES-protected pyobfuscate.com / Hyperion / Fernet stealers
# because the host venv is unlikely to have pycryptodome/cryptography installed
# in the exact form those decryptor stubs expect. The Docker backend uses the
# ``python-deobf-sandbox:latest`` image (see ``py_deobf/src/sandbox/docker/
# Dockerfile.sandbox``) which has pycryptodome + cryptography + requests
# pre-installed, so AES/CBC/GCM decryptor stubs run to completion and the real
# stealer source is captured. Override with ``MOCK_API_PY_SANDBOX=subprocess``
# for hosts without Docker.
PY_SANDBOX_BACKEND = os.environ.get("MOCK_API_PY_SANDBOX", "docker").strip().lower()
if PY_SANDBOX_BACKEND not in ("docker", "subprocess"):
    process_log.warning(
        "py_sandbox_invalid %s",
        kv(value=PY_SANDBOX_BACKEND, fallback="docker"),
    )
    PY_SANDBOX_BACKEND = "docker"

# JS deobfuscator sandbox backend. js-deobf's CLI defaults to ``vm``, which
# runs untrusted JS inside the host node process and exposes the analysis
# machine to packer payloads that escape Node's ``vm`` module. The Docker
# backend isolates execution in a ``node:18`` container with ``--network none``,
# matching the security posture of the Python backend. Override with
# ``MOCK_API_JS_SANDBOX=vm`` (or ``puppeteer``, which requires the optional
# Puppeteer peer dep) for hosts without Docker.
JS_SANDBOX_BACKEND = os.environ.get("MOCK_API_JS_SANDBOX", "docker").strip().lower()
if JS_SANDBOX_BACKEND not in ("docker", "vm", "puppeteer"):
    process_log.warning(
        "js_sandbox_invalid %s",
        kv(value=JS_SANDBOX_BACKEND, fallback="docker"),
    )
    JS_SANDBOX_BACKEND = "docker"


def _strip_ansi(s: str) -> str:
    return _ANSI_RE.sub("", s)


def parse_line(raw: str) -> tuple[str, str, int, str]:
    """Decode a raw stdout line into ``(time, level, indent, text)``.

    ``time`` is empty when the producer didn't print one — the caller
    should substitute the current wall-clock time in that case.
    Unrecognised lines fall back to ``INFO`` at indent ``0``.
    """
    line = _strip_ansi(raw).rstrip("\r\n")
    indent = 0
    rest = line
    while rest.startswith("  "):
        rest = rest[2:]
        indent += 1
    m = _LEVEL_RE.match(rest)
    if m:
        return (m.group("t") or "", m.group("lvl"), indent, m.group("txt"))
    return ("", "INFO", indent, rest)


def guess_phase(text: str, current: str) -> str:
    lowered = text.lower()
    for phase, kws in _PHASE_KEYWORDS:
        for kw in kws:
            if kw in lowered:
                return phase
    return current


def _can_advance_phase(current: str, candidate: str) -> bool:
    return PHASE_ORDER.get(candidate, -1) >= PHASE_ORDER.get(current, -1)


async def _stop_process_tree(
    proc: asyncio.subprocess.Process,
    *,
    engine: str,
    reason: str,
) -> None:
    if proc.returncode is not None:
        return

    process_log.warning("backend_stopping %s", kv(engine=engine, pid=proc.pid, reason=reason))

    if sys.platform == "win32" and proc.pid:
        try:
            killer = await asyncio.create_subprocess_exec(
                "taskkill", "/PID", str(proc.pid), "/T", "/F",
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.DEVNULL,
            )
            await asyncio.wait_for(killer.wait(), timeout=BACKEND_STOP_GRACE_SECONDS)
            await asyncio.wait_for(proc.wait(), timeout=BACKEND_STOP_GRACE_SECONDS)
            return
        except Exception as exc:  # noqa: BLE001
            process_log.warning(
                "backend_taskkill_failed %s",
                kv(engine=engine, pid=proc.pid, error=repr(exc)),
            )

    try:
        proc.terminate()
    except ProcessLookupError:
        return

    try:
        await asyncio.wait_for(proc.wait(), timeout=BACKEND_STOP_GRACE_SECONDS)
    except asyncio.TimeoutError:
        try:
            proc.kill()
        except ProcessLookupError:
            return
        await proc.wait()


# ─── runner API ──────────────────────────────────────────────────────────────

# Callback signatures:
#   on_log(t, level, indent, text)
#   on_phase(phase)
LogCb = Callable[[str, str, int, str], None]
PhaseCb = Callable[[str], None]


@dataclass
class RunResult:
    clean_code: str
    layer_cards: list[dict] = field(default_factory=list)
    iocs: list[dict] = field(default_factory=list)
    layers_seen: int = 0


async def _stream_process(
    proc: asyncio.subprocess.Process,
    *,
    engine: str,
    on_log: LogCb,
    on_phase: PhaseCb,
    layer_re: re.Pattern[str],
    cancel_event: asyncio.Event,
) -> int:
    """Pump the subprocess stdout through ``on_log`` / ``on_phase``.

    Returns the highest layer number seen in the output (best-effort).
    Terminates the process if ``cancel_event`` is set.
    """
    current_phase = "detect"
    on_phase(current_phase)
    layers = 0
    started_at = time.monotonic()
    last_output_at = started_at
    assert proc.stdout is not None
    while True:
        if cancel_event.is_set():
            await _stop_process_tree(proc, engine=engine, reason="cancel_requested")
            break

        now = time.monotonic()
        runtime = now - started_at
        idle = now - last_output_at
        if BACKEND_MAX_RUNTIME_SECONDS > 0 and runtime > BACKEND_MAX_RUNTIME_SECONDS:
            await _stop_process_tree(proc, engine=engine, reason="max_runtime_timeout")
            raise RuntimeError(
                f"{engine} exceeded max runtime "
                f"({BACKEND_MAX_RUNTIME_SECONDS:.0f}s)"
            )
        if BACKEND_IDLE_TIMEOUT_SECONDS > 0 and idle > BACKEND_IDLE_TIMEOUT_SECONDS:
            await _stop_process_tree(proc, engine=engine, reason="idle_timeout")
            raise RuntimeError(
                f"{engine} produced no output for "
                f"{BACKEND_IDLE_TIMEOUT_SECONDS:.0f}s"
            )

        try:
            line_b = await asyncio.wait_for(proc.stdout.readline(), timeout=1.0)
        except asyncio.TimeoutError:
            continue
        if not line_b:
            break
        last_output_at = time.monotonic()
        raw = line_b.decode("utf-8", errors="replace")
        t, level, indent, text = parse_line(raw)
        if not text and not t:
            continue  # skip blank lines
        new_phase = guess_phase(text, current_phase)
        if new_phase != current_phase and _can_advance_phase(current_phase, new_phase):
            current_phase = new_phase
            on_phase(current_phase)
        m = layer_re.search(text)
        if m:
            try:
                layers = max(layers, int(m.group(1)))
            except (ValueError, IndexError):
                pass
        on_log(t, level, indent, text)
    return layers


# ─── JS backend ──────────────────────────────────────────────────────────────

def _js_repo_dir() -> Path:
    env = os.environ.get("JS_DEOBF_DIR")
    if env:
        return Path(env)
    return Path(__file__).resolve().parent.parent / "js_deobf"


async def run_js(
    *,
    input_path: Path,
    run_dir: Path,
    llm_mode: str = "off",
    dynamic_eval: bool = True,
    auto_ioc: bool = True,
    static_analysis: bool = True,
    rename: bool = True,
    max_layers: int | None = None,
    timeout: int | None = None,
    verbose: bool = True,
    on_log: LogCb,
    on_phase: PhaseCb,
    cancel_event: asyncio.Event,
) -> RunResult:
    repo_dir = _js_repo_dir()
    main_js = repo_dir / "dist" / "main.js"
    if not main_js.exists():
        process_log.error(
            "backend_missing %s",
            kv(engine="jsdeobf", expected=str(main_js), repo_dir=str(repo_dir)),
        )
        raise RuntimeError(
            f"js-deobf not built: {main_js} missing — "
            f"run `npm install && npm run build` in {repo_dir}"
        )

    args: list[str] = [
        "node", str(main_js), str(input_path),
        "--output-dir", str(run_dir),
        "--no-isolate-runs",
        # Force the docker-based sandbox by default so untrusted JS runs
        # inside a ``node:18`` container with ``--network none`` instead of
        # the in-process ``vm`` module. ``MOCK_API_JS_SANDBOX`` overrides
        # this for hosts without Docker.
        "--backend", JS_SANDBOX_BACKEND,
    ]
    args.append("-v" if verbose else "-q")
    # JS backend exposes ‘use-llm’ (both), ‘use-llm-rename’, ‘use-llm-format’
    # as positive flags. ``llm_mode='off'`` means: pass none of them.
    if llm_mode == "both":
        args.append("--use-llm")
    elif llm_mode == "rename":
        args.append("--use-llm-rename")
    elif llm_mode == "format":
        args.append("--use-llm-format")
    if not dynamic_eval:
        args.append("--no-dynamic")
    if not auto_ioc:
        args.append("--no-ioc")
    if not static_analysis:
        args.append("--no-static")
    if not rename:
        args.append("--no-rename")
    if max_layers is not None and max_layers > 0:
        args += ["--max-layers", str(int(max_layers))]
    if timeout is not None and timeout > 0:
        args += ["--timeout", str(int(timeout))]

    process_log.info(
        "backend_start %s",
        kv(
            engine="jsdeobf",
            input=str(input_path),
            output_dir=str(run_dir),
            backend=JS_SANDBOX_BACKEND,
            llm_mode=llm_mode,
            dynamic_eval=dynamic_eval,
            auto_ioc=auto_ioc,
            static_analysis=static_analysis,
            rename=rename,
            max_layers=max_layers,
            timeout=timeout,
            verbose=verbose,
            cwd=str(repo_dir),
        ),
    )
    env = {**os.environ, "NO_COLOR": "1", "FORCE_COLOR": "0"}
    proc = await asyncio.create_subprocess_exec(
        *args,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.STDOUT,
        cwd=str(repo_dir),
        env=env,
    )
    process_log.info("backend_spawned %s", kv(engine="jsdeobf", pid=proc.pid))
    layers_seen = await _stream_process(
        proc, engine="jsdeobf", on_log=on_log, on_phase=on_phase,
        layer_re=_LAYER_RE_JS, cancel_event=cancel_event,
    )
    rc = await proc.wait()
    if cancel_event.is_set():
        process_log.warning("backend_cancelled %s", kv(engine="jsdeobf", pid=proc.pid, rc=rc))
        return RunResult(clean_code="", layers_seen=layers_seen)
    if rc != 0:
        process_log.error("backend_failed %s", kv(engine="jsdeobf", pid=proc.pid, rc=rc))
        raise RuntimeError(f"js-deobf exited with code {rc}")

    report_path = run_dir / "report.json"
    if not report_path.exists():
        process_log.error("backend_report_missing %s", kv(engine="jsdeobf", report=str(report_path)))
        raise RuntimeError(f"js-deobf did not produce report.json at {report_path}")
    report = json.loads(report_path.read_text(encoding="utf-8", errors="replace"))

    clean_code = ""
    out_path_str = report.get("outputPath") or ""
    if out_path_str:
        out_path = Path(out_path_str)
        if out_path.exists():
            clean_code = out_path.read_text(encoding="utf-8", errors="replace")
    # Fallback: pick the last layer file.
    if not clean_code:
        layer_files = sorted(
            run_dir.glob("layer_*.js"),
            key=lambda p: _trailing_int(p.stem),
        )
        if layer_files:
            clean_code = layer_files[-1].read_text(encoding="utf-8", errors="replace")

    result = RunResult(
        clean_code=clean_code,
        layer_cards=_js_layer_cards(report, run_dir),
        iocs=_js_iocs(run_dir) if auto_ioc else [],
        layers_seen=max(layers_seen, len(report.get("layers") or [])),
    )
    process_log.info(
        "backend_done %s",
        kv(
            engine="jsdeobf",
            pid=proc.pid,
            rc=rc,
            layers=result.layers_seen,
            output_bytes=len(result.clean_code.encode("utf-8")),
            iocs=len(result.iocs),
        ),
    )
    return result


def _js_layer_cards(report: dict, run_dir: Path) -> list[dict]:
    cards: list[dict] = []
    for entry in report.get("layers") or []:
        lid = entry.get("layerId") or (len(cards) + 1)
        layer_file = run_dir / f"layer_{lid}.js"
        cards.append({
            "id": lid,
            "label": f"L{lid}",
            "obfuscator": entry.get("detectedObfuscator") or "unknown",
            "antiAnalysis": list(entry.get("antiAnalysisFindings") or []),
            "methods": list(entry.get("methodsApplied") or []),
            "inputKB": round((entry.get("inputBytes") or 0) / 1024, 2),
            "outputKB": round((entry.get("outputBytes") or 0) / 1024, 2),
            "timeMs": None,
            "entropy": None,
            "done": True,
            "notes": list(entry.get("notes") or []),
            "preview": _read_text_capped(layer_file) if layer_file.exists() else "",
        })
    return cards


def _js_iocs(run_dir: Path) -> list[dict]:
    """Parse ``layer_0_ioc_report.js`` produced by js-deobf."""
    return _parse_ioc_file(run_dir / "layer_0_ioc_report.js")


def _py_iocs(result_dir: Path, report: dict | None = None) -> list[dict]:
    """Parse Python IOC findings, preferring report-embedded findings
    when present and otherwise reading the flat ``ioc_report.json`` file.
    """
    if isinstance(report, dict):
        report_items = _ioc_items_from_data(report.get("ioc"))
        if report_items:
            return _normalize_ioc_items(report_items)
    return _parse_ioc_file(result_dir / "ioc_report.json")


def _parse_ioc_file(p: Path) -> list[dict]:
    """Shared IOC-report reader for both backends.

    Accepts a JSON file (or JSON object embedded in a wrapper for the
    JS variant) and returns a flat ``[{type, value, sev}, ...]`` list.
    Returns ``[]`` if the file is missing or unparseable — the backend
    just didn't find anything (or hasn't dumped its report yet).
    """
    if not p.exists():
        return []
    text = p.read_text(encoding="utf-8", errors="replace").strip()
    data: object
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        # Recover a JSON object/array out of a wrapper (older js-deobf).
        m = re.search(r"(\{.*\}|\[.*\])", text, re.S)
        if not m:
            return []
        try:
            data = json.loads(m.group(0))
        except json.JSONDecodeError:
            return []

    return _normalize_ioc_items(_ioc_items_from_data(data))


def _ioc_items_from_data(data: object) -> list[dict]:
    if isinstance(data, list):
        return [x for x in data if isinstance(x, dict)]
    if isinstance(data, dict):
        for key in ("findings", "iocs", "items", "results"):
            v = data.get(key)
            if isinstance(v, list):
                return [x for x in v if isinstance(x, dict)]
    return []


def _normalize_ioc_items(items: list[dict]) -> list[dict]:
    out: list[dict] = []
    for it in items:
        sev = str(it.get("severity") or it.get("sev") or "low").lower()
        if sev == "medium":
            sev = "med"
        if sev not in ("low", "med", "high"):
            sev = "low"
        out.append({
            "type": str(it.get("type") or it.get("category") or "Misc"),
            "value": str(it.get("value") or it.get("artifact") or it.get("match") or ""),
            "sev": sev,
        })
    return out


# ─── Python backend ──────────────────────────────────────────────────────────

def _py_repo_dir() -> Path:
    env = os.environ.get("PY_DEOBF_DIR")
    if env:
        return Path(env)
    return Path(__file__).resolve().parent.parent / "py_deobf"


def _py_executable(repo_dir: Path) -> str:
    """Return the Python interpreter from py_deobf's own venv if available."""
    if sys.platform == "win32":
        venv_python = repo_dir / ".venv" / "Scripts" / "python.exe"
    else:
        venv_python = repo_dir / ".venv" / "bin" / "python"
    if venv_python.exists():
        return str(venv_python)
    return sys.executable


async def run_py(
    *,
    input_path: Path,
    run_dir: Path,
    llm_mode: str = "off",
    dynamic_eval: bool = True,
    auto_ioc: bool = True,
    static_analysis: bool = True,
    rename: bool = True,
    max_layers: int | None = None,
    timeout: int | None = None,
    verbose: bool = True,
    on_log: LogCb,
    on_phase: PhaseCb,
    cancel_event: asyncio.Event,
) -> RunResult:
    repo_dir = _py_repo_dir()
    main_py = repo_dir / "src" / "main.py"
    if not main_py.exists():
        process_log.error(
            "backend_missing %s",
            kv(engine="pydeobf", expected=str(main_py), repo_dir=str(repo_dir)),
        )
        raise RuntimeError(
            f"py-deobf not found: {main_py} missing — "
            f"check PY_DEOBF_DIR env or that {repo_dir} exists"
        )

    args: list[str] = [
        _py_executable(repo_dir), str(main_py), str(input_path),
        "--output-dir", str(run_dir),
        # Force the docker-based sandbox by default so AES-protected
        # pyobfuscate.com / Hyperion / Fernet decryptor stubs run inside
        # an image that already has pycryptodome + cryptography + requests
        # available. ``MOCK_API_PY_SANDBOX`` switches this to ``subprocess``
        # for hosts without Docker.
        "--sandbox", PY_SANDBOX_BACKEND,
    ]
    args.append("-v" if verbose else "-q")
    # PY backend uses ‘--use-llm’ (both), ‘--llm-rename’, ‘--llm-format’.
    if llm_mode == "both":
        args.append("--use-llm")
    elif llm_mode == "rename":
        args.append("--llm-rename")
    elif llm_mode == "format":
        args.append("--llm-format")
    if not dynamic_eval:
        args.append("--no-dynamic")
    if not auto_ioc:
        args.append("--no-ioc")
    if not static_analysis:
        args.append("--no-static")
    if not rename:
        args.append("--no-rename")
    if max_layers is not None and max_layers > 0:
        args += ["--max-layers", str(int(max_layers))]
    if timeout is not None and timeout > 0:
        args += ["--timeout", str(int(timeout))]

    process_log.info(
        "backend_start %s",
        kv(
            engine="pydeobf",
            input=str(input_path),
            output_dir=str(run_dir),
            sandbox=PY_SANDBOX_BACKEND,
            llm_mode=llm_mode,
            dynamic_eval=dynamic_eval,
            auto_ioc=auto_ioc,
            static_analysis=static_analysis,
            rename=rename,
            max_layers=max_layers,
            timeout=timeout,
            verbose=verbose,
            cwd=str(repo_dir),
        ),
    )
    env = {**os.environ, "NO_COLOR": "1", "FORCE_COLOR": "0", "PYTHONIOENCODING": "utf-8"}
    proc = await asyncio.create_subprocess_exec(
        *args,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.STDOUT,
        cwd=str(repo_dir),
        env=env,
    )
    process_log.info("backend_spawned %s", kv(engine="pydeobf", pid=proc.pid))
    layers_seen = await _stream_process(
        proc, engine="pydeobf", on_log=on_log, on_phase=on_phase,
        layer_re=_LAYER_RE_PY, cancel_event=cancel_event,
    )
    rc = await proc.wait()
    if cancel_event.is_set():
        process_log.warning("backend_cancelled %s", kv(engine="pydeobf", pid=proc.pid, rc=rc))
        return RunResult(clean_code="", layers_seen=layers_seen)
    if rc != 0:
        process_log.error("backend_failed %s", kv(engine="pydeobf", pid=proc.pid, rc=rc))
        raise RuntimeError(f"py-deobf exited with code {rc}")

    result_dir = _py_find_result_dir(run_dir, input_path.stem)
    report_path = (result_dir / "report.json") if result_dir else (run_dir / "report.json")
    if not report_path.exists():
        process_log.error("backend_report_missing %s", kv(engine="pydeobf", report=str(report_path)))
        raise RuntimeError(f"py-deobf did not produce report.json at {report_path}")
    report = json.loads(report_path.read_text(encoding="utf-8", errors="replace"))

    clean_code = ""
    out_path_str = report.get("outputPath") or ""
    if out_path_str:
        out_path = Path(out_path_str)
        if out_path.exists():
            clean_code = out_path.read_text(encoding="utf-8", errors="replace")
    if not clean_code and result_dir:
        clean_code = _py_find_clean(result_dir, input_path)
    if not clean_code:
        # py-deobf produced nothing (input had nothing to deobfuscate, or
        # detection said `unknown`). Mirror the input back so the frontend
        # has something to render and the diff comes out empty.
        try:
            clean_code = input_path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            clean_code = ""
    layer_cards = _py_layer_cards_from_report(report, result_dir or run_dir)
    iocs = _py_iocs(result_dir or run_dir, report) if auto_ioc else []
    result = RunResult(
        clean_code=clean_code,
        layer_cards=layer_cards,
        iocs=iocs,
        layers_seen=max(layers_seen, len(report.get("layers") or [])),
    )
    process_log.info(
        "backend_done %s",
        kv(
            engine="pydeobf",
            pid=proc.pid,
            rc=rc,
            layers=result.layers_seen,
            output_bytes=len(result.clean_code.encode("utf-8")),
            iocs=len(result.iocs),
            result_dir=str(result_dir) if result_dir else "",
        ),
    )
    return result


def _py_find_result_dir(run_dir: Path, stem: str) -> Path | None:
    """Locate the directory the py_deobf backend wrote into.

    Two known layouts depending on whether ``--output-dir`` is set:

    * Flat — files dumped directly into ``run_dir`` (current behaviour
      with our explicit ``--output-dir <out>``).
    * Subdir — files dumped into ``run_dir/<stem>/`` (default layout
      under ``decoded_layers/<stem>/``).
    """
    if (
        (run_dir / "report.json").exists()
        or (run_dir / "final_result.py").exists()
        or any(run_dir.glob("layer_*.py"))
    ):
        return run_dir
    candidate = run_dir / stem
    if candidate.exists() and candidate.is_dir():
        return candidate
    for p in run_dir.iterdir():
        if p.is_dir() and (
            (p / "report.json").exists()
            or (p / "final_result.py").exists()
            or any(p.glob("layer_*.py"))
        ):
            return p
    return None


def _py_find_clean(result_dir: Path, input_path: Path) -> str:
    """Pick the most-finished cleaned file out of a py-deobf run dir.

    Priority order (first that exists wins):
      1. ``final_result.py``                     — explicit final marker.
      2. ``<input_stem>.py`` / ``<input_name>``  — backend may name the
         final after the input itself.
      3. ``*_decompiled.py``                     — .pyc decompiler output.
      4. last ``layer_*.py``                     — final layer fallback.
    """
    candidates: list[Path] = [
        result_dir / "final_result.py",
        result_dir / f"{input_path.stem}.py",
        result_dir / input_path.name,
    ]
    candidates += sorted(result_dir.glob("*_decompiled.py"))
    layers = sorted(result_dir.glob("layer_*.py"), key=lambda p: _trailing_int(p.stem))
    if layers:
        candidates.append(layers[-1])
    for c in candidates:
        # Skip anything that is itself just a copy of the input path we passed in.
        try:
            if c.exists() and c.resolve() != input_path.resolve():
                return c.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
    # If only the input copy is present, return it — the input wasn't
    # obfuscated, so "cleaned" == input.
    for c in candidates:
        if c.exists():
            return c.read_text(encoding="utf-8", errors="replace")
    return ""


def _py_layer_cards_from_report(report: dict, result_dir: Path) -> list[dict]:
    """Build Python layer cards from the JS-compatible ``report.json``."""
    cards: list[dict] = []
    for entry in report.get("layers") or []:
        lid = entry.get("layerId") or (len(cards) + 1)
        layer_file = _py_layer_preview_path(result_dir, int(lid))
        cards.append({
            "id": lid,
            "label": f"L{lid}",
            "obfuscator": entry.get("detectedObfuscator") or "unknown",
            "antiAnalysis": list(entry.get("antiAnalysisFindings") or []),
            "methods": list(entry.get("methodsApplied") or []),
            "inputKB": round((entry.get("inputBytes") or 0) / 1024, 2),
            "outputKB": round((entry.get("outputBytes") or 0) / 1024, 2),
            "timeMs": None,
            "entropy": None,
            "done": True,
            "notes": list(entry.get("notes") or []),
            "preview": _read_text_capped(layer_file) if layer_file else "",
        })
    return cards


def _py_layer_preview_path(result_dir: Path, layer_id: int) -> Path | None:
    for suffix in (".py", ".pyc_dump", ".bin"):
        candidate = result_dir / f"layer_{layer_id}{suffix}"
        if candidate.exists():
            return candidate
    matches = sorted(result_dir.glob(f"layer_{layer_id}.*"))
    return matches[0] if matches else None


# Per-layer preview is what the frontend ResultsState renders in the
# `layer-N.<ext>` tabs. Cap the size so a single huge layer doesn't blow
# up the JSON response (clean_code/original_code are already in there).
_LAYER_PREVIEW_MAX_BYTES = 512 * 1024  # 512 KiB


def _read_text_capped(path: Path, max_bytes: int = _LAYER_PREVIEW_MAX_BYTES) -> str:
    try:
        raw = path.read_bytes()
    except OSError:
        return ""
    truncated = len(raw) > max_bytes
    head = raw[:max_bytes] if truncated else raw
    text = head.decode("utf-8", errors="replace")
    if truncated:
        text += f"\n\n# … truncated ({len(raw) - max_bytes} more bytes)\n"
    return text


# ─── shared helpers ──────────────────────────────────────────────────────────

def _trailing_int(s: str) -> int:
    m = re.search(r"(\d+)\s*$", s)
    return int(m.group(1)) if m else 0


def derive_mitre(lang: str, iocs: list[dict]) -> list[dict]:
    """Map detected language + IOCs to a coarse MITRE ATT&CK list.

    Always includes T1027 (obfuscation) and a language-specific T1059
    sub-technique. C2 indicators (URL/Domain/IP) add T1041, persistence
    paths add T1547.001, credential keys add T1552.001.
    """
    out: list[dict] = [
        {"id": "T1027", "name": "Obfuscated Files or Information", "tac": "Defense Evasion"},
    ]
    if lang == "js":
        out.append({"id": "T1059.007", "name": "Command & Scripting: JavaScript", "tac": "Execution"})
    else:
        out.append({"id": "T1059.006", "name": "Command & Scripting: Python", "tac": "Execution"})
    types = {str(i.get("type") or "").lower() for i in iocs}
    if types & {"url", "domain", "ip"}:
        out.append({"id": "T1041", "name": "Exfiltration Over C2 Channel", "tac": "Exfiltration"})
    if types & {"path"}:
        out.append({"id": "T1547.001",
                    "name": "Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder",
                    "tac": "Persistence"})
    if types & {"key", "wallet"}:
        out.append({"id": "T1552.001",
                    "name": "Unsecured Credentials: Credentials In Files",
                    "tac": "Credential Access"})
    return out
