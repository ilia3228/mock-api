# mock-api

HTTP API for `deobfuscator-app`. Dispatches uploaded files to one of two
real deobfuscators based on filename detection:

- **jsdeobf** — `.js` files → `node dist/main.js` from
  `../js-python-deobfuscator`.
- **pydeobf** — `.py` / `.pyc` files → `python src/main.py` from
  `../python-deobfuscator`.

The API persists users, tokens and job metadata in a local SQLite file
(`data.db`) and stores each job's working directory under `runs/<job_id>/`
(uploaded blob + deobfuscator output). Live SSE buffers and asyncio
primitives stay in memory; restarting the process drops in-flight jobs
(they are auto-marked `error` on startup), but completed jobs survive and
are replayed as a one-shot snapshot.

## Run

```bash
cd mock-api
python -m venv .venv
.venv\Scripts\activate          # Windows
pip install -r requirements.txt
python run.py        # Windows-safe launcher (see note below)
```

> On Windows port 8000 is often reserved by Hyper-V / WinNAT excluded
> ranges, which produces `WinError 10013`. Pick any free port (8090 here)
> and update `deobfuscator-app/vite.config.js` proxy target to match.

> **Windows + `--reload`**: use the bundled `run.py` launcher (it calls
> `uvicorn.run(..., loop="none")`). Plain `uvicorn main:app --reload …`
> won't work because uvicorn 0.32 forces `WindowsSelectorEventLoopPolicy`
> during subprocess-mode loop setup, and `asyncio.create_subprocess_exec`
> (used by `runner.py` to spawn the JS / Python backends) only works on
> `ProactorEventLoop`. The internal `loop="none"` value tells uvicorn to
> skip its loop setup so Python's default Proactor policy survives — but
> uvicorn's CLI deliberately rejects `--loop none`, hence the wrapper.
> The launcher also owns the reload worker with Windows cleanup guards, so
> stale Python workers left on port 8090 are stopped on the next start.
> Runtime job files under `runs/` are excluded from reload watching, so
> uploading `pasted.py` does not restart the API mid-analysis.

Open <http://localhost:8090/docs> for an interactive Swagger UI.

## Logs

The API writes structured key-value logs to both stdout and
`mock-api/logs/mock-api.log` with rotation (`5 MB`, 5 backups).

Useful events:

- `request_start` / `request_done` — method, path, status, latency and
  `request_id` (also returned as `X-Request-ID`).
- `job_queued`, `job_started`, `job_phase`, `job_done`, `job_error` — analysis
  lifecycle with job id, user id, selected options and output stats.
- `backend_start`, `backend_spawned`, `backend_done`, `backend_failed` — JS/Python
  deobfuscator subprocess lifecycle.

Environment variables:

- `MOCK_API_LOG_LEVEL=DEBUG|INFO|WARNING|ERROR` (default `INFO`).
- `MOCK_API_LOG_DIR=C:\path\to\logs` to override the log directory.
- `MOCK_API_BACKEND_IDLE_TIMEOUT_SECONDS=180` kills a backend that stops
  producing output.
- `MOCK_API_BACKEND_MAX_RUNTIME_SECONDS=600` kills a backend that runs too long
  even if it keeps printing.

Uvicorn access logs are disabled by `run.py`; the request middleware logs only
`request.url.path`, so bearer tokens in SSE query strings are not printed.

### One-time setup of the deobfuscator backends

The API spawns the backends as subprocesses, so they must exist on disk
before the first analyze call.

```bash
# JS — build dist/ once; subsequent runs reuse the build.
cd ../js-python-deobfuscator
npm install
npm run build

# Python — install Python dependency in the same venv as mock-api.
pip install rich
```

By default the API looks for the backends at `../js-python-deobfuscator`
and `../python-deobfuscator` (relative to `mock-api/`). Override with the
`JS_DEOBF_DIR` / `PY_DEOBF_DIR` environment variables if they live
somewhere else.

## Endpoints

| Method | Path                          | Auth | Purpose                                              |
|--------|-------------------------------|------|------------------------------------------------------|
| GET    | `/api/health`                 |  —   | Liveness probe + which engines are "online".         |
| POST   | `/api/auth/signup`            |  —   | Create account, returns `{token, user}`.             |
| POST   | `/api/auth/login`             |  —   | Exchange email+password for a bearer token.          |
| POST   | `/api/auth/logout`            |  ✓   | Invalidate the caller's token.                       |
| GET    | `/api/auth/me`                |  ✓   | Current user (token check).                          |
| GET    | `/api/sessions`               |  ✓   | Caller's analysis history (from SQLite).             |
| POST   | `/api/analyze`                |  ✓   | Upload a file, kick off a job. Returns `job_id`.     |
| GET    | `/api/jobs/{job_id}`          |  ✓   | Current job snapshot (status, phase, logs, result).  |
| GET    | `/api/jobs/{job_id}/stream`   |  ✓   | SSE stream of log lines and phases.                  |
| POST   | `/api/jobs/{job_id}/cancel`   |  ✓   | Mark a running job as cancelled.                     |
| GET    | `/api/jobs/{job_id}/clean`    |  ✓   | Download deobfuscated source as text.                |

Auth: pass the bearer token in the `Authorization: Bearer <token>` header,
or — for `EventSource` streams that can't set headers — as `?token=<token>`
query string.

### `POST /api/analyze`

Form-data:

- `file` (required) — uploaded sample.
- `use_llm` (`true` / `false`, default `false`) — forwards `--use-llm` to
  the backend (LLM rename + format).
- `dynamic_eval` (`true` / `false`, default `true`) — forwards
  `--no-dynamic` when disabled.
- `auto_ioc` (`true` / `false`, default `true`) — forwards `--no-ioc` when
  disabled and returns an empty IOC list.
- `lang_hint` (`js` / `py`, optional) — overrides detection by extension.
- `speed` — accepted for compatibility but ignored; analysis takes as
  long as the backend takes.

Returns:

```json
{ "job_id": "8f3a…", "lang": "js", "filename": "loader.js", "size": 51234 }
```

### Result shape (`GET /api/jobs/{id}` when `status == "done"`)

```json
{
  "status": "done",
  "phase": "ioc",
  "progress": 1.0,
  "logs": [ { "t": "11:54:59.657", "level": "INFO", "indent": 0, "text": "…" } ],
  "result": {
    "lang": "js",
    "filename": "malware_loader.js",
    "sha256": "a3f2…c8d1",
    "stats": { "input_bytes": 51234, "output_bytes": 12700, "duration_ms": 16100, "layers": 3 },
    "layer_cards": [ … ],
    "iocs":        [ … ],
    "mitre":       [ … ],
    "original_code": "…",
    "clean_code":    "…",
    "diff_code":     "…"
  }
}
```

## Result assembly

The API spawns the backend, streams stdout into `job.logs` (level/indent
parsed from `[LEVEL]` prefixes), and on exit assembles the bundle on the
API side:

| Field           | Source                                                          |
|-----------------|-----------------------------------------------------------------|
| `engine`        | `"jsdeobf"` / `"pydeobf"` based on detected language.           |
| `sha256`        | `hashlib.sha256` of the uploaded blob.                          |
| `original_code` | raw uploaded blob, UTF-8 decoded (replace on error).            |
| `clean_code`    | JS: `report.outputPath`. PY: `final_result.py` / last layer.    |
| `diff_code`     | `difflib.unified_diff(original_code, clean_code)`.              |
| `layer_cards`   | JS: mapped from `report.json#/layers[]`. PY: synthesised from `layer_*.py` file sizes. |
| `iocs`          | JS: parsed from `layer_0_ioc_report.js`. PY: parsed from `ioc_report.json` written by the orchestrator's `_dump_ioc_report`. Same `{type, value, sev}` shape both ways. |
| `mitre`         | Heuristic on the API side (`runner.derive_mitre`) — always `T1027` + language `T1059.*`, plus `T1041` / `T1547.001` / `T1552.001` from IOC types. |

## Notes

- CORS is wide-open for `http://localhost:5173` and `http://127.0.0.1:5173`.
- `sample_data.py` is kept only for `PHASES` (served at `/api/phases`).
  Everything else in that file (including the legacy `PY_IOCS` stub) is
  unused by the running API — Python IOCs now come from the orchestrator's
  `ioc_report.json`.
- `runs/<job_id>/` contains the uploaded blob plus the backend's output
  (`out/`). `DELETE /api/jobs/{job_id}` removes both the DB row and the
  on-disk run directory.
