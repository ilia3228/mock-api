# mock-api — что менять

Аудит `mock-api/` на 2026-05-22. Каждый пункт верифицирован чтением кода + где возможно — экспериментом. Помечено:

- **[BUG]** — баг сработает в realistic-сценарии
- **[SEC]** — security-проблема
- **[PERF]** — производительность / ресурсы
- **[DEBT]** — технический долг / некрасиво

Severity:
- **High** — даёт NameError / OOM / unauth-доступ
- **Med**  — деградация под нагрузкой или edge-case фейл
- **Low**  — стиль / мелкий долг

---

## 1. Подтверждённые баги (срабатывают)

### [BUG][High] `process_log` NameError в `_run_llm_check`

`@/home/remnux/SiteDeobf/mock-api/main.py:1020`

```python
except FileNotFoundError as exc:
    process_log.warning(
        "llm_check_executable_missing %s",
        kv(engine=target, error=repr(exc)),
    )
```

Верификация: `grep -E "^(import|from)" main.py` показывает только `from logging_config import configure_logging, get_logger, kv` (`@/home/remnux/SiteDeobf/mock-api/main.py:127`). `process_log` определён только в `@/home/remnux/SiteDeobf/mock-api/runner.py:34` и не реэкспортируется.

Триггер: `POST /api/llm/check`, когда `node` или `python` отсутствуют в `PATH` подпроцесса. Ответ: 500 + `NameError: name 'process_log' is not defined` вместо ожидаемого JSON `{ok: False, error: "required executable is unavailable", ...}`.

**Фикс:** `log.warning(...)` (использовать уже импортированный `log` из строки 132), либо `from runner import process_log`.

---

### [BUG][Med] `download_clean` падает на legacy job без `clean_code` в результате

`@/home/remnux/SiteDeobf/mock-api/main.py:1310`

```python
clean_code = job.result["clean_code"]
```

Жёсткое индексирование. Если `result` сохранён старой схемой (где ключа нет — например, ранний alpha без `clean_code`), получаем `KeyError` → 500.

В DB-снапшотах после `_load_job_for_user` нет валидации ключей. Сейчас все джобы пишутся через текущий `run_job` (всегда вкладывает `clean_code`), но при миграции схемы / ручной правке `data.db` сломается.

**Фикс:** `clean_code = job.result.get("clean_code", "")`.

---

### [BUG][Low] Комментарий про "SQLite auto-vacuum semantics" неверен

`@/home/remnux/SiteDeobf/mock-api/main.py:732-734`

```python
# Cancel any in-flight jobs for this user before tearing down the row;
# otherwise a still-running coroutine could later UPDATE a vanished
# jobs row and resurrect it via SQLite's auto-vacuum semantics.
```

`UPDATE ... WHERE id = ?` на удалённой строке возвращает 0 affected rows. SQLite **никогда** не воссоздаёт удалённые строки через UPDATE — независимо от `auto_vacuum`. Auto-vacuum переутилизирует свободные страницы при `VACUUM` / autovacuum, к восстановлению строк отношения не имеет.

Поведение кода (отмена in-flight) полезно по другой причине — экономит CPU и не пишет лишних логов. Но комментарий вводит в заблуждение.

**Фикс:** переписать комментарий: "Cancel in-flight jobs so they don't keep burning CPU and writing log noise after the account is gone."

---

### [BUG][Med] Утечка ZIP-handle в `_try_extract_zip`

`@/home/remnux/SiteDeobf/mock-api/main.py:251`

```python
zf = zipfile.ZipFile(io.BytesIO(blob))
```

`zf` не закрывается ни через `with`, ни через `zf.close()` в путях возврата. GC закроет при сборке, но в asyncio-окружении сборка задерживается. На in-memory ZIP'ах риск только в накоплении объектов, не FD.

**Фикс:** `with zipfile.ZipFile(io.BytesIO(blob)) as zf:` обёртка.

---

## 2. Безопасность

### [SEC][High] Zip-bomb через `/api/analyze`

`@/home/remnux/SiteDeobf/mock-api/main.py:258-262`

```python
for pwd in (None, ZIP_DEFAULT_PASSWORD):
    try:
        data = zf.read(member.filename, pwd=pwd)
```

`zf.read()` декомпрессирует весь файл в RAM. Нет проверок `member.file_size` или ratio compressed/uncompressed. Стандартный 42-байтный zip-bomb `42.zip` распакуется в 4.5 ПБ.

Конкретный сценарий: атакующий с валидным токеном (signup открыт всем — см. **[SEC][Med] enumeration** ниже) загружает 10 КБ ZIP → API съедает RAM → OOM-kill всего процесса.

**Фикс:**

```python
MAX_UNCOMPRESSED_BYTES = 50 * 1024 * 1024  # 50 MB
if member.file_size > MAX_UNCOMPRESSED_BYTES:
    return None
ratio = (member.file_size / max(member.compress_size, 1))
if ratio > 1000:
    return None
```

---

### [SEC][High] Отсутствует лимит на размер тела `/api/analyze`

`@/home/remnux/SiteDeobf/mock-api/main.py:1142`

```python
blob = await file.read()
```

`UploadFile.read()` без аргументов читает всё. Starlette за пределами spooled-tempfile (>1 МБ — на диск), но финальный `read()` всё равно вернёт `bytes` целиком в RAM.

uvicorn 0.32 не имеет дефолтного `--limit-max-requests-size`. Конфигурация `run.py:319-327` его не ставит.

Атака: `POST /api/analyze` с 10 ГБ телом → OOM-kill.

**Фикс:** прочитать стримом с инкрементальным контролем + 413:

```python
MAX_UPLOAD_BYTES = 50 * 1024 * 1024
chunks: list[bytes] = []
total = 0
while True:
    chunk = await file.read(1024 * 1024)
    if not chunk:
        break
    total += len(chunk)
    if total > MAX_UPLOAD_BYTES:
        raise HTTPException(413, "upload too large")
    chunks.append(chunk)
blob = b"".join(chunks)
```

---

### [SEC][Med] Токены без TTL и `last_used_at`

`@/home/remnux/SiteDeobf/mock-api/auth.py:37-40` + `@/home/remnux/SiteDeobf/mock-api/db.py:53-58`

Tokens-таблица:

```sql
CREATE TABLE IF NOT EXISTS tokens (
    token       TEXT PRIMARY KEY,
    user_id     INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at  REAL NOT NULL
);
```

`created_at` пишется, но в `db.user_by_token` (`@/home/remnux/SiteDeobf/mock-api/db.py:154-160`) не проверяется. Token валиден вечно. Нет `last_used_at` → юзер не видит, какие сессии активны.

**Фикс:** добавить `expires_at REAL` (например, +30 дней) и `last_used_at REAL`; чекать в `user_by_token`:

```python
"SELECT u.* FROM users u JOIN tokens t ON t.user_id = u.id"
" WHERE t.token = ? AND (t.expires_at IS NULL OR t.expires_at > ?)"
```

Дополнительно: эндпоинт `GET /api/auth/sessions` с listing (token-prefix, created_at, last_used_at, ip).

---

### [SEC][Med] PBKDF2-SHA256 120 000 итераций ниже OWASP-2023

`@/home/remnux/SiteDeobf/mock-api/auth.py:15`

```python
_PBKDF2_ITERS = 120_000
```

[OWASP Password Storage Cheat Sheet, ред. 2023](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html#pbkdf2): минимум **600 000** для PBKDF2-HMAC-SHA256. Рекомендация — `argon2id`, `scrypt` или `bcrypt`.

Атака: оффлайн-брутфорс украденного `data.db` идёт в 5 раз быстрее, чем должен.

**Фикс:** поднять `_PBKDF2_ITERS = 600_000` + миграция: при успешном `verify_password` если у юзера старый hash (детектится через colon-version префикс или через сравнение длины) — перехешировать и сохранить. Или сразу перейти на `argon2-cffi`.

---

### [SEC][Med] Нет rate-limit на `/api/auth/login` и `/api/auth/signup`

`@/home/remnux/SiteDeobf/mock-api/main.py:624-644`

Грепом ничего похожего на rate-limit (`slowapi`, `limiter`, `bucket`) не найдено. Брутфорс паролей и спам signup'ов ничем не ограничены.

Дополнительная грань: signup создаёт пользователей под слабые пароли (минимум 6 символов — `@/home/remnux/SiteDeobf/mock-api/main.py:611`), что в сочетании с отсутствием rate-limit даёт работающий брутфорс через signup-перебор.

**Фикс:** `slowapi` с лимитами:
- `signup`: 5/hour per IP
- `login`: 5/minute per IP + 10/hour per email

---

### [SEC][Med] Token в query-string пишется в логи прокси

`@/home/remnux/SiteDeobf/mock-api/auth.py:51-55`, `@/home/remnux/SiteDeobf/mock-api/main.py:1322`

```python
def current_user(
    authorization: str | None = Header(default=None),
    token: str | None = Query(default=None),
) -> dict[str, Any]:
```

SSE через `EventSource` не умеет ставить headers, поэтому токен идёт `?token=...`. `main.py:530` логирует только `path` (без query) — это закрывает только мок-апи. Любой обратный прокси (nginx, Cloudflare, Apache) по-дефолту пишет полный URL в access-log. Браузер шлёт URL в `Referer`.

**Фикс:** ввести однонажатиевые "stream-tickets": `POST /api/jobs/{id}/stream-ticket` отдаёт 60-секундный токен, привязанный к `(job_id, user_id)`. SSE принимает только ticket в query. Основной bearer не уходит в URL.

---

### [SEC][Med] User enumeration через `/api/auth/signup`

`@/home/remnux/SiteDeobf/mock-api/main.py:629-630`

```python
if db.user_by_email(email):
    raise HTTPException(409, "email already registered")
```

Атакующий перебирает emails, отличает зарегистрированных по 409 vs 200.

**Фикс:** всегда отдавать 200 при signup + рассылать "confirm your account" письмо. Но для dev-API задокументировать как known-trade-off.

---

### [SEC][Med] Login enumeration через timing

`@/home/remnux/SiteDeobf/mock-api/main.py:637-644`

```python
user = db.user_by_email(email)
if not user or not auth.verify_password(body.password, user["pw_hash"], user["pw_salt"]):
    raise HTTPException(401, "invalid email or password")
```

Когда юзер не существует, ответ возвращается мгновенно (без PBKDF2). Когда существует — задержка ≈ 120ms (на 120k итераций SHA256). Атакующий измеряет timing и enumerate'ит.

**Фикс:** при `user is None` вызывать `auth.verify_password("dummy", ...)` с фиктивным salt того же размера, чтобы выровнять время. Стандартный паттерн.

---

### [SEC][Med] CORS прибит к localhost

`@/home/remnux/SiteDeobf/mock-api/main.py:506-514`

```python
allow_origins=[
    "http://localhost:5173",
    "http://127.0.0.1:5173",
],
```

Прод-деплоймент не работает без правки кода. Не баг сейчас, но негибко.

**Фикс:** `os.environ.get("MOCK_API_CORS_ORIGINS", "http://localhost:5173,...").split(",")`.

---

### [SEC][Low] `os.environ` целиком пробрасывается в subprocess

`@/home/remnux/SiteDeobf/mock-api/main.py:976-982`, `@/home/remnux/SiteDeobf/mock-api/runner.py:331, 593`

```python
env = {**os.environ, "NO_COLOR": "1", ...}
```

В подпроцесс (`node dist/main.js`, `python src/main.py`) пробрасываются все парент-env, включая возможные `OPENAI_API_KEY`, `AWS_*`, прочие секреты. Для LLM-check это нужно (бэкенды читают свои `*_API_KEY`). Для запуска деобфускации — нет.

Если py-deobf вдруг логирует `os.environ` (для debug) — секрет утечёт в `runs/<id>/debug.log`.

**Фикс:** в `runner.run_js`/`run_py` передавать whitelist (`PATH`, `HOME`, `LANG`, `LC_*`, `TMPDIR`, `PYTHONPATH`, `NODE_PATH`) вместо `**os.environ`.

---

## 3. Надёжность / корректность

### [BUG][Med] Утечка `runs/<job_id>/` при сбое `db.insert_job`

`@/home/remnux/SiteDeobf/mock-api/main.py:1165-1194`

Порядок:

```python
job_id = uuid.uuid4().hex[:12]
work_dir = RUNS_DIR / job_id
work_dir.mkdir(parents=True, exist_ok=True)  # 1167
input_path.write_bytes(blob)                  # 1169
...
JOBS[job.id] = job                            # 1190
db.insert_job(...)                            # 1191
```

Если `db.insert_job` упадёт (например, IntegrityError на повторе UUID, disk full, lock contention), `work_dir` уже создан и blob записан. `JOBS[job.id]` уже выставлен. Никакой компенсаторной логики нет.

`DELETE /api/jobs/{id}` не сработает: `db.delete_job` вернёт `removed=False` (строки нет), джоб в JOBS не удаляется по этому пути (он удаляется только если `job is not None and job.user_id == user["id"]`, причём по успешной DB-delete).

**Фикс:** try/except вокруг pair (`mkdir`+`write_bytes`+`insert_job`), на failure — `shutil.rmtree(work_dir, ignore_errors=True)` и `JOBS.pop(job.id, None)`. Плюс startup-GC: при `_startup` найти orphan-dirs без соответствующей DB-row и удалить.

---

### [BUG][Med] `asyncio.create_task` без сохранения reference

`@/home/remnux/SiteDeobf/mock-api/main.py:1208`

```python
asyncio.create_task(run_job(job))
```

[Python docs warning](https://docs.python.org/3/library/asyncio-task.html#asyncio.create_task): "Save a reference to the result of this function, to avoid a task disappearing mid-execution. The event loop only keeps weak references to tasks."

На практике loop держит strong-ref через `_all_tasks` в большинстве реализаций, но это не контракт. В разных Python/uvloop версиях поведение менялось. Безопасный паттерн — pin reference:

**Фикс:** добавить `_task: asyncio.Task | None = None` в `Job` dataclass, выставлять `job._task = asyncio.create_task(run_job(job))`. Заодно решает проблему "как cancel'нуть task программно".

---

### [BUG][Med] `_session_view` тянет полный `result_json` для боковой панели

`@/home/remnux/SiteDeobf/mock-api/db.py:284-296` + `@/home/remnux/SiteDeobf/mock-api/main.py:458-476`

```sql
SELECT id,filename,size,lang,status,result_json,created_at
FROM jobs WHERE user_id = ? ORDER BY created_at DESC LIMIT 50
```

`result_json` парсится в Python (`json.loads`), но `_session_view` использует только `result.iocs[*].sev` и `result.stats.layers`/`stats.input_bytes`. Остальное (`clean_code`, `original_code`, `diff_code` — десятки КБ каждый) выбрасывается.

При 50 джобах × 80 КБ полезной нагрузки в `result_json` = 4 МБ JSON-парсинга на каждый `GET /api/sessions`.

**Фикс A (минимальный):** добавить `iocs_summary_json`, `layers` отдельными колонками; в `_session_view` НЕ читать `result_json`.

**Фикс B (миграционный):** SELECT'ить только нужные поля через subquery+`json_extract`:

```sql
SELECT id, filename, size, lang, status, created_at,
       json_extract(result_json, '$.iocs')        AS iocs_blob,
       json_extract(result_json, '$.stats.layers') AS layers
FROM jobs WHERE user_id = ? ORDER BY created_at DESC LIMIT 50
```

---

### [BUG][Med] `JOBS` dict растёт без эвикции

`@/home/remnux/SiteDeobf/mock-api/main.py:205`

```python
JOBS: dict[str, Job] = {}
```

Каждый успешно завершённый джоб остаётся в `JOBS` пока юзер не удалит. На каждом — `Job.logs` (десятки/сотни строк × ~200 байт) + `Job.result` dict (`clean_code` + `original_code` + `diff_code` + layer_cards + iocs).

Для долгоживущего процесса с активным юзером это утечка. Через сутки активной работы — сотни МБ в RAM, при этом данные уже сохранены в DB.

**Фикс:** TTL-эвикция: при каждом `GET /api/jobs/{id}` обновлять `last_touch`, фоновая корутина каждые 5 минут удаляет из `JOBS` записи с `status in ("done","error","cancelled") and last_touch < now-300s`. `_load_job_for_user` поднимет их обратно из DB при следующем обращении.

---

### [BUG][Med] `Job.logs` растёт безлимитно

`@/home/remnux/SiteDeobf/mock-api/main.py:175,344-345`

```python
logs: list[LogLine] = field(default_factory=list)
...
def on_log(t, level, indent, text):
    job.logs.append(LogLine(t=..., level=level, indent=indent, text=text))
```

`text` хранится в полной длине (в `job_log.log` есть `text[:1000]` cap для файла, но НЕ для in-memory списка). На verbose-run сложного сэмпла — 10к+ строк × средние 200 байт = 2 МБ на джоб. Плюс при `GET /api/jobs/{id}` сериализуется весь список (`logs: [l.as_dict() for l in job.logs]`).

**Фикс:** rolling-window:

```python
MAX_LOGS_IN_MEMORY = 5000
job.logs.append(...)
if len(job.logs) > MAX_LOGS_IN_MEMORY:
    job.logs = job.logs[-MAX_LOGS_IN_MEMORY:]  # keep tail
```

Плюс writes-through в `runs/<job_id>/backend.log` для долгоживущих логов.

---

### [DEBT][Med] `BACKEND_MAX_RUNTIME_SECONDS` не учитывает user-supplied `timeout`

`@/home/remnux/SiteDeobf/mock-api/runner.py:84-86, 212-217`

```python
BACKEND_MAX_RUNTIME_SECONDS = _float_env("MOCK_API_BACKEND_MAX_RUNTIME_SECONDS", 600.0)
...
if BACKEND_MAX_RUNTIME_SECONDS > 0 and runtime > BACKEND_MAX_RUNTIME_SECONDS:
    await _stop_process_tree(proc, ...)
```

Юзер передаёт `timeout=1200` через `/api/analyze` (заявка: "хочу до 20 мин на сэмпл"). Это пробрасывается в `--timeout 1200` для py-deobf, что означает per-sandbox-eval timeout. НО внешний watchdog убивает процесс на 600s — раньше, чем юзер ожидает.

Поведение: backend завершается с `RuntimeError(f"{engine} exceeded max runtime (600s)")` → джоб в `error`, юзер видит "сервис ограничил время" вместо своего лимита.

**Фикс:** `effective_max_runtime = max(BACKEND_MAX_RUNTIME_SECONDS, (timeout or 0) * 1.5)`.

---

### [DEBT][Med] Docker-контейнер не очищается при kill py-deobf

`@/home/remnux/SiteDeobf/mock-api/runner.py:125-164`

`_stop_process_tree` шлёт SIGTERM/SIGKILL на процесс py-deobf'а (или js-deobf'а). Но **дочерние** процессы (`docker run --rm ...`) не получают сигнал — у них свой process group.

Сценарий: SSE-кэнсел → mock-api убивает py-deobf → py-deobf не успел отправить SIGTERM в docker-cli → `docker run` продолжает работать → контейнер живёт до своего внутреннего timeout (`docker run --rm` пометит контейнер для удаления только после exit).

**Фикс:** `subprocess.run` с `start_new_session=True` (Linux) или `creationflags=CREATE_NEW_PROCESS_GROUP` (Windows), затем `os.killpg(pid, SIGTERM)`. Альтернативно — py-deobf должен сам передавать сигналы в docker-cli (это уже задача py-deobf, не mock-api).

---

### [BUG][Low] `detect_lang` дефолтит в `js` для неоднозначных файлов

`@/home/remnux/SiteDeobf/mock-api/main.py:271-286`

```python
sniffed = _sniff_lang(content)
if sniffed is not None:
    return sniffed
return "js"
```

Сниффер требует ≥2 маркеров одной стороны и 0 другой. Короткий питоновский обфусцированный one-liner вида `exec(__import__("zlib").decompress(...))` имеет `__import__` (py) + `exec(` (общий) — попадает в `py` маркеры. Но если сэмпл сделан без `__import__` (через `getattr(__builtins__, ...)`), маркеров не будет → дефолт в `js`.

Реальный риск: pyobfuscate.com 2024 кэпшен (770 байт AES-decryptor):

```python
exec(__import__('zlib').decompress(...))
```

— `__import__` есть, `import zlib` тоже (если distinct). 2 маркера → правильно `py`.

Но сэмплы вроде `getattr(__builtins__, 'exec')(...)` — 0 py-маркеров, 0 js-маркеров → дефолт `js`.

**Фикс:** при ambiguity (sniffed is None) и расширении `.txt`/`.bin`/нет — вернуть 400 с просьбой указать `lang_hint=js|py`.

---

### [DEBT][Low] `delete_me` не ждёт реальной отмены in-flight задач

`@/home/remnux/SiteDeobf/mock-api/main.py:735-756`

```python
for job in in_flight:
    if job._cancel is not None and job.status in ("queued", "running"):
        job._cancel.set()
    JOBS.pop(job.id, None)
...
db.delete_user(user["id"])  # CASCADE clears tokens + jobs
```

`_cancel.set()` ставит флаг, но `delete_me` сразу удаляет user из DB и возвращает 200. Фоновая `run_job` корутина может продолжать работать ещё до 1s (это период readline-таймаута в `_stream_process`), пытаясь UPDATE'нуть удалённую строку (no-op, не fatal). Хвост логов от уже мёртвого джоба уходит в `mock-api.log`.

Не опасно, но шум в логах и трата ресурсов.

**Фикс:** после `_cancel.set()` сохранить `task` ссылки и `await asyncio.gather(*tasks, return_exceptions=True)` с таймаутом 3-5 секунд, потом уже `db.delete_user`.

---

### [BUG][Low] Мёртвый код: `current_user_optional`, `delete_jobs_for_user`

`@/home/remnux/SiteDeobf/mock-api/auth.py:64-71` + `@/home/remnux/SiteDeobf/mock-api/db.py:308-315`

Грепом `current_user_optional` / `delete_jobs_for_user` — 0 вызовов вне определений. Тащим неиспользуемый интерфейс.

**Фикс:** удалить.

---

## 4. Производительность

### [PERF][Med] `/api/jobs/{id}` всегда возвращает полный `result`

`@/home/remnux/SiteDeobf/mock-api/main.py:1248-1265`

Если фронт делает polling (например, если SSE по какой-то причине отключился), каждый GET тащит десятки КБ `clean_code` + `original_code` + `diff_code`, хотя нужен только `status` + `progress`.

**Фикс:** опциональный `?fields=status|logs|result` параметр, default — без `result` и без `logs`.

---

### [PERF][Med] SSE keepalive не флашится через nginx

`@/home/remnux/SiteDeobf/mock-api/main.py:1369-1371`

```python
yield b": keepalive\n\n"
```

При nginx с дефолтным `proxy_buffering on` keepalive накапливается в буфере и не доходит до клиента → клиент таймаутится на простоях.

**Фикс:** добавить header в `StreamingResponse`:

```python
return StreamingResponse(
    gen(),
    media_type="text/event-stream",
    headers={"X-Accel-Buffering": "no", "Cache-Control": "no-cache"},
)
```

---

### [PERF][Med] `current_user` — sync dep в async route

`@/home/remnux/SiteDeobf/mock-api/auth.py:51-61`

FastAPI запускает sync deps в threadpool (default size 40). Каждый authenticated request занимает 1 thread на время `db.user_by_token`. Под нагрузкой 50+ одновременных запросов вычерпываются thread'ы → новые HTTP requests блокируются.

**Фикс:** `async def current_user` + `aiosqlite`. Либо in-memory token-cache с TTL 60s, чтобы повторные хиты не лезли в DB.

---

### [PERF][Med] SHA256 + read_bytes в `run_job` дублируют работу `/api/analyze`

`@/home/remnux/SiteDeobf/mock-api/main.py:1163` (analyze) и `@/home/remnux/SiteDeobf/mock-api/main.py:397-401` (run_job)

В `/api/analyze`:

```python
blob = await file.read()
sha256 = hashlib.sha256(blob).hexdigest()  # ← вычислен
```

`blob` затем записан в `input_path`. В `run_job` (тот же `Job` объект):

```python
input_bytes = input_path.read_bytes()        # ← повторное чтение диска
sha256 = hashlib.sha256(input_bytes).hexdigest()  # ← повторный hash
original_code = input_bytes.decode(...)
```

Для сэмплов ≥10 МБ — заметные секунды на пересчёт.

**Фикс:** сохранять `sha256` и `original_code` в `Job` сразу при `/api/analyze`, в `run_job` только читать поля.

---

### [PERF][Low] `_make_unified_diff` без guard на размер

`@/home/remnux/SiteDeobf/mock-api/main.py:294-304`

`difflib.unified_diff` использует `SequenceMatcher`, который O(N²) worst-case. Для типичного pyobfuscate-стилера (30 КБ × ~500 строк) — мгновенно. Для редкого 5+ МБ сэмпла — минуты.

**Фикс:**

```python
def _make_unified_diff(original, clean, filename):
    if len(original) > 1_000_000 or len(clean) > 1_000_000:
        return f"# diff omitted: input ({len(original)}b) or output ({len(clean)}b) too large\n"
    ...
```

---

### [PERF][Low] `verbose=True` дефолт удваивает объём логов

`@/home/remnux/SiteDeobf/mock-api/main.py:1120,170,1236`

Frontend всегда отправляет `verbose=True` (или не указывает — дефолт True). Бэкенды отвечают `-v` режимом → больше DEBUG-строк. Большинство юзеров не читают эти логи.

**Фикс:** дефолт `verbose=False`, ручка "Show debug logs" в UI поднимает `verbose=True` при необходимости.

---

## 5. Качество кода

### [DEBT][Low] `sample_data.py` мёртв на 95%

17 КБ файла. README говорит "Everything else in that file (including the legacy PY_IOCS stub) is unused". Используется только `PHASES` (10 строк) — отдаётся `/api/phases`.

**Фикс:** инлайнить `PHASES = [...]` в `main.py`, удалить `sample_data.py` и `__pycache__/sample_data.cpython-*.pyc`.

---

### [DEBT][Med] Windows-specific логика в `main.py` (60+ строк)

`@/home/remnux/SiteDeobf/mock-api/main.py:48-110`

IOCP-guard + supervisor-watchdog. Дублирует `run.py:48-86`. На Linux — no-op, но читателю усложняет восприятие. Логически принадлежит windows-launcher'у.

**Фикс:** вынести в `_windows_compat.py`, одной строкой `import _windows_compat  # noqa: F401` в `main.py`.

---

### [DEBT][Low] DB-миграция без version-таблицы

`@/home/remnux/SiteDeobf/mock-api/db.py:88-93`

```python
existing_cols = {row["name"] for row in c.execute("PRAGMA table_info(jobs)").fetchall()}
if "options_json" not in existing_cols:
    c.execute("ALTER TABLE jobs ADD COLUMN options_json TEXT")
```

Хардкод-проверка одной колонки. При следующей миграции нужна копипаста.

**Фикс:**

```sql
CREATE TABLE schema_version (version INT PRIMARY KEY);
INSERT OR IGNORE INTO schema_version VALUES (0);
```

И в коде:

```python
MIGRATIONS = [
    lambda c: c.execute("ALTER TABLE jobs ADD COLUMN options_json TEXT"),
    # future migrations append here
]
current = c.execute("SELECT version FROM schema_version").fetchone()[0]
for i in range(current, len(MIGRATIONS)):
    MIGRATIONS[i](c)
    c.execute("UPDATE schema_version SET version = ?", (i + 1,))
```

---

### [DEBT][Low] `requirements.txt` без dev-deps и lockfile

`@/home/remnux/SiteDeobf/mock-api/requirements.txt` — 3 строки (`fastapi`, `uvicorn[standard]`, `python-multipart`). Транзитивные зависимости не зафиксированы. На разных машинах подтягиваются разные версии `starlette`, `pydantic`.

**Фикс:** `pip-compile requirements.in → requirements.txt` с `--generate-hashes`. Отдельный `requirements-dev.txt` для `pytest`, `httpx`.

---

### [DEBT][Med] Тестов нет

Грепом `pytest|test_` в `mock-api/` — 0 файлов вне `.venv/`. Все эндпоинты живут на ручном smoke.

Минимальное покрытие, которое стоит написать:

```python
# tests/test_api.py
async def test_signup_login_flow(api):
    r = await api.post("/api/auth/signup", json={"email": "a@b.c", "password": "Test1234"})
    token = r.json()["token"]
    r = await api.get("/api/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert r.json()["email"] == "a@b.c"

async def test_analyze_mock(api, monkeypatch):
    monkeypatch.setattr(runner, "run_py", AsyncMock(return_value=RunResult(clean_code="ok")))
    # ... POST /api/analyze, poll /api/jobs/{id}, assert result
```

С `pytest-asyncio` + `httpx.AsyncClient` это ~150 строк, ловит регрессии типа NameError (1.1) и schema-breaks.

---

### [DEBT][Low] `LogLine.t` — строка `HH:MM:SS.mmm` без даты

`@/home/remnux/SiteDeobf/mock-api/main.py:142-149`

Cross-midnight джоб (начало 23:59, конец 00:01) показывает строки в порядке "23:59 → 00:01", но при сортировке как строк дата теряется. Не критично, но для post-mortem'а неудобно.

**Фикс:** хранить `t: float` (POSIX timestamp), форматировать в UI / при `as_dict()`.

---

### [DEBT][Low] Маркеры в `_PY_MARKERS` неточные

`@/home/remnux/SiteDeobf/mock-api/main.py:213-217`

```python
_PY_MARKERS = (
    "__import__", "import zlib", "import base64", "import marshal",
    "from typing", "def __", "lambda ", "print(", "exec(b",
    "pyarmor", "py_compile",
)
```

`print(` — слабый маркер: TS-проекты используют `print(...)` в дебаге. `lambda ` — есть в TS arrow-functions с лексическим `lambda` (редко, но не уникально).

**Фикс:** убрать `print(` и `lambda ` (слабые), оставить только однозначные.

---

## 6. Наблюдаемость / эксплуатация

### [DEBT][Low] Нет `/api/metrics`

`@/home/remnux/SiteDeobf/mock-api/main.py:1057-1087`

`/api/health` хороший liveness-probe для UI, но нет queue-depth, latency-p95, error-rate.

**Фикс:** `prometheus-client` + counters/histograms для JOBS-операций.

---

### [DEBT][Low] Логи — key=value, не JSON

`@/home/remnux/SiteDeobf/mock-api/logging_config.py:74-93`

`kv(job_id=..., user_id=...)` → `job_id=abc user_id=5` строка. Grep'абельно глазом, но Loki/ELK ждут JSON.

**Фикс:** добавить `JsonFormatter` опцией через `MOCK_API_LOG_FORMAT=json|text` env-var.

---

### [DEBT][Low] Cancel не подтверждает реальную остановку

`@/home/remnux/SiteDeobf/mock-api/main.py:1268-1276`

```python
@app.post("/api/jobs/{job_id}/cancel")
def cancel_job(job_id, user):
    ...
    if job._cancel is not None and job.status == "running":
        job._cancel.set()
    return {"id": job.id, "status": job.status}
```

Возвращает текущий статус (`running`), не дождавшись фактического перехода в `cancelled`. UI показывает stale state до следующего polling-tick'а.

**Фикс:** короткий `await asyncio.wait_for(...)` (1-2с) на переход в `cancelled` перед ответом. Или: SSE-event `cancelled` гарантированно эмиттится из стрима — UI слушает.

---

## 7. Приоритизация

| # | Тема | Severity | Усилие |
|---|---|---|---|
| 1.1 | `process_log` NameError | High | 1 строка |
| 2.1 | Zip-bomb | High | 5 строк |
| 2.2 | Upload size | High | 10 строк |
| 1.2 | `KeyError` в download_clean | Med | 1 строка |
| 2.3 | Token TTL | Med | 50 строк + миграция |
| 2.4 | PBKDF2 итерации | Med | 1 строка + миграция-перехеш |
| 3.5 | `JOBS` без эвикции | Med | 30 строк |
| 3.6 | `Job.logs` без cap | Med | 5 строк |
| 3.1 | Orphan `runs/<id>/` при сбое insert | Med | 15 строк |
| 3.3 | `_session_view` тянет полный result | Med | 20 строк |
| 4.4 | Двойной SHA256 | Low | 5 строк |
| 5.5 | Тестов нет | Med | 200+ строк |

---

## 8. Quick wins (10 строк или меньше — можно сделать за час)

| # | Файл / строка | Изменение |
|---|---|---|
| 1.1 | `@/home/remnux/SiteDeobf/mock-api/main.py:1020` | `process_log` → `log` |
| 1.2 | `@/home/remnux/SiteDeobf/mock-api/main.py:1310` | `job.result.get("clean_code", "")` |
| 1.3 | `@/home/remnux/SiteDeobf/mock-api/main.py:732-734` | переписать комментарий — убрать ложь про "auto-vacuum" |
| 1.4 | `@/home/remnux/SiteDeobf/mock-api/main.py:251` | обернуть `zipfile.ZipFile` в `with` |
| 4.2 | `@/home/remnux/SiteDeobf/mock-api/main.py:1373` | `X-Accel-Buffering: no` в SSE headers |
| 5.1 | `@/home/remnux/SiteDeobf/mock-api/sample_data.py` | инлайнить `PHASES`, удалить файл |
| 3.10 | `@/home/remnux/SiteDeobf/mock-api/auth.py:64-71` + `@/home/remnux/SiteDeobf/mock-api/db.py:308-315` | удалить мёртвые функции |
| 5.7 | `@/home/remnux/SiteDeobf/mock-api/main.py:213-217` | убрать `print(`, `lambda ` из py-маркеров |

---

## 9. Отозванные / непод­тверждённые гипотезы

Эти проверял отдельно — не баги, оставляю чтобы не возвращаться:

- **`db.init()` race при `uvicorn --workers N`** — `run.py:319-327` не передаёт `workers=N`, а `--reload` запускает один worker. Race возможен только если кто-то вручную запустит `uvicorn main:app --workers 4` в обход `run.py`. Не баг текущего кода.

- **`_event` rotation race в SSE** — анализ кода: consumer держит локальный `ev` ref до `await ev.wait()`. `on_log` атомарно (single-threaded asyncio) подменяет `job._event` и сетит старый event. Consumer всегда видит `set` на своём ref'е. Логи не теряются благодаря append-only `job.logs[cursor:]`. Работает корректно.

- **Path traversal через `safe_name = Path(raw_name).name`** — `Path("../../etc/passwd").name == "passwd"`. `Path("..").name == ".."` приводит к `runs/<job_id>/..` → попытка `write_bytes` фейлится с IsADirectoryError, не пишет ничего опасного. Можно усилить (`re.sub(r'[^\w.-]', '_', safe_name)`), но не критично.

- **Content-Disposition injection через `job.filename`** — `safe_name` фильтруется через `Path().name`, но `Path("foo\r\n").name` возвращает `"foo\r\n"` на Linux. Header injection в принципе возможен. Стоит ужесточить (`re.sub` whitelist), но эксплуатация требует валидный токен + конкретный браузер.
