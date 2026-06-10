# mock-api

HTTP API for `deobfuscator-app`. Dispatches uploaded files to one of two
real deobfuscators based on filename detection:

- **jsdeobf** — `.js` files → `node dist/main.js` from
  `../js_deobf`.
- **pydeobf** — `.py` / `.pyc` files → `python src/main.py` from
  `../py_deobf`.

The API persists users, tokens and job metadata in **PostgreSQL** through
the async `asyncpg` driver (see `db.py`); the connection string comes from
`$DATABASE_URL`. Each job's working directory lives under `runs/<job_id>/`
(uploaded blob + deobfuscator output). Live SSE buffers and asyncio
primitives stay in memory; restarting the process drops in-flight jobs
(they are auto-marked `error` on startup), but completed jobs survive in
PostgreSQL and are replayed as a one-shot snapshot.

## Database (PostgreSQL)

User accounts, bearer tokens and job metadata live in PostgreSQL, reached
through the async `asyncpg` driver (`db.py`). Bring up a local server in
Docker (matches the project's existing Docker usage):

```bash
docker run -d --name sitedeobf-pg \
  -e POSTGRES_USER=sitedeobf -e POSTGRES_PASSWORD=deobf -e POSTGRES_DB=sitedeobf \
  -p 127.0.0.1:5432:5432 \
  -v sitedeobf-pgdata:/var/lib/postgresql/data \
  postgres:16
```

The API reads its DSN from `DATABASE_URL`, defaulting to the container
above:

```
DATABASE_URL=postgresql://sitedeobf:deobf@127.0.0.1:5432/sitedeobf
```

Export `DATABASE_URL` before launching to point at any other instance.
Tables are created automatically on startup (`db.init()`) — there is no
separate migration step. To reset all state, drop and recreate the
database, or run:

```sql
TRUNCATE jobs, tokens, llm_key_owner, users RESTART IDENTITY CASCADE;
```

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
- `MOCK_API_BACKEND_MAX_RUNTIME_SECONDS=3600` kills a backend that runs too long
  even if it keeps printing (default `3600`; a high backstop so it never
  pre-empts the user-chosen per-sandbox `--timeout`).
- `MOCK_API_PY_SANDBOX=docker|subprocess` (default `docker`). The Python
  deobfuscator's sandbox backend. Docker is required to recover AES-protected
  pyobfuscate.com / Hyperion / Fernet stealers — the
  `python-deobf-sandbox:latest` image ships pycryptodome + cryptography +
  requests so decryptor stubs run to completion. Set to `subprocess` only on
  hosts without Docker (output quality will degrade for AES-encrypted samples).
- `MOCK_API_JS_SANDBOX=docker|vm|puppeteer` (default `docker`). The JS
  deobfuscator's sandbox backend. Docker runs untrusted JS inside a `node:18`
  container with `--network none` for isolation. Set to `vm` to fall back to
  Node's in-process `vm` module on hosts without Docker; `puppeteer` requires
  the optional `puppeteer` peer dep in `../js_deobf`.

Uvicorn access logs are disabled by `run.py`; the request middleware logs only
`request.url.path`, so bearer tokens in SSE query strings are not printed.

### One-time setup of the deobfuscator backends

The API spawns the backends as subprocesses, so they must exist on disk
before the first analyze call.

```bash
# JS — build dist/ once; subsequent runs reuse the build.
cd ../js_deobf
npm install
npm run build

# Python — install Python dependency in the same venv as mock-api.
pip install rich

# Python sandbox image — required for AES-protected stealer recovery.
# Build once; py-deobf falls back to ``python:3.12-slim`` with a warning
# if this image is missing (decryptor stubs will fail to ``import Crypto``).
docker build -t python-deobf-sandbox:latest \
    -f ../py_deobf/src/sandbox/docker/Dockerfile.sandbox ../py_deobf

# JS sandbox image — pulled lazily by docker on first run, but pre-pulling
# avoids a multi-second cold-start on the first analyze call.
docker pull node:18
```

By default the API looks for the backends at `../js_deobf`
and `../py_deobf` (relative to `mock-api/`). Override with the
`JS_DEOBF_DIR` / `PY_DEOBF_DIR` environment variables if they live
somewhere else.

Both backends are always spawned with their docker sandbox by default:

- The Python backend uses ``--sandbox docker`` so that AES-encrypted
  pyobfuscate.com / Hyperion / Fernet decryptor stubs execute inside the
  prebuilt ``python-deobf-sandbox:latest`` image (with ``pycryptodome``,
  ``cryptography`` and ``requests`` preinstalled). Set
  ``MOCK_API_PY_SANDBOX=subprocess`` to fall back to the host interpreter.
- The JS backend uses ``--backend docker`` so that untrusted JS runs inside
  a ``node:18`` container with ``--network none``. Set
  ``MOCK_API_JS_SANDBOX=vm`` to fall back to Node's in-process ``vm`` module
  (less safe but does not require Docker).

## Endpoints

| Method | Path                          | Auth | Purpose                                              |
|--------|-------------------------------|------|------------------------------------------------------|
| GET    | `/api/health`                 |  —   | Liveness probe + which engines are "online".         |
| POST   | `/api/auth/signup`            |  —   | Create account, returns `{token, user}`.             |
| POST   | `/api/auth/login`             |  —   | Exchange email+password for a bearer token.          |
| POST   | `/api/auth/logout`            |  ✓   | Invalidate the caller's token.                       |
| GET    | `/api/auth/me`                |  ✓   | Current user (token check).                          |
| GET    | `/api/sessions`               |  ✓   | Caller's analysis history (from PostgreSQL).         |
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

- `file` (required) — uploaded sample. ZIP archives containing exactly one
  file are automatically extracted (MalwareBazaar compatibility). Password-
  protected ZIPs are tried with the default password `infected`.
- `use_llm` (`true` / `false`, default `false`) — forwards `--use-llm` to
  the backend (LLM rename + format). Requires an API key saved by the same
  authenticated user; a key from another account is treated as absent.
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
| `clean_code`    | JS/PY: `report.outputPath` with backend-specific fallback.       |
| `diff_code`     | `difflib.unified_diff(original_code, clean_code)`.              |
| `layer_cards`   | JS/PY: mapped from `report.json#/layers[]`.                      |
| `iocs`          | JS: parsed from `layer_0_ioc_report.js`. PY: parsed from `ioc_report.json`; `report.json#/ioc` carries severity summary. Same `{type, value, sev}` shape both ways. |
| `mitre`         | Heuristic on the API side (`runner.derive_mitre`) — always `T1027` + language `T1059.*`, plus `T1041` / `T1547.001` / `T1552.001` from IOC types. |

## Notes

- CORS is wide-open for `http://localhost:5173` and `http://127.0.0.1:5173`.
- `sample_data.py` is kept only for `PHASES` (served at `/api/phases`).
  Everything else in that file (including the legacy `PY_IOCS` stub) is
  unused by the running API — Python metadata now comes from `report.json`,
  while IOC values come from `ioc_report.json`.
- `runs/<job_id>/` contains the uploaded blob plus the backend's output
  (`out/`). `DELETE /api/jobs/{job_id}` removes both the DB row and the
  on-disk run directory.
