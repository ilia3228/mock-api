"""LLM configuration round-trip between the mock API and the two backends.

The JS and Python deobfuscators each have their own ``llm_config.toml``
sitting next to their entry point. The web UI exposes a single LLM
configuration panel that has to update *both* files at once so that an
analysis using either backend talks to the same provider/model/key.

This module keeps the two files in sync without ever leaking the
plaintext API key to the frontend (``public_view`` masks it) and
preserves the per-file extra keys each backend understands
(``max_code_size`` for JS, ``api_key_env`` / ``timeout_seconds`` for
Python) — they are read back as part of the merged shape and written
through unchanged on update.

Read shape (``read_config``):

    {provider, model, api_key, base_url, temperature, max_tokens,
     max_code_size, api_key_env, timeout_seconds}

Public shape (``public_view``) — what the API returns over the wire:

    same keys, but ``api_key`` is replaced by
    ``{api_key_present: bool, api_key_last4: str}``.

Write contract (``write_config``):
- A non-empty ``api_key`` string overwrites both files.
- ``clear_api_key=True`` (or ``api_key=""`` with ``clear_api_key``)
  resets the key in both files to ``""``.
- An absent ``api_key`` field leaves the existing key untouched.
"""

from __future__ import annotations

import json
import re
import tomllib
from pathlib import Path
from typing import Any

_ROOT = Path(__file__).resolve().parent.parent

JS_REPO = _ROOT / "js-deobfuscator"
PY_REPO = _ROOT / "python-deobfuscator"

JS_CONFIG = JS_REPO / "llm_config.toml"
JS_EXAMPLE = JS_REPO / "llm_config.example.toml"
PY_CONFIG = PY_REPO / "llm_config.toml"
PY_EXAMPLE = PY_REPO / "llm_config.example.toml"

# Sidecar file that stores the "Test connection" verification stamp so the
# verified state survives both page refreshes and server restarts. Kept
# next to ``data.db`` (same gitignore-pattern: never committed).
VERIFIED_STATE = Path(__file__).resolve().parent / "llm_verified.json"


# ─── read ────────────────────────────────────────────────────────────────────

def _read_toml(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    try:
        return tomllib.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}


def _ensure_exists(target: Path, example: Path) -> None:
    """Bootstrap ``target`` from ``example`` if it doesn't exist yet.

    Falls back to an empty file when the example is also missing so that
    a fresh checkout can still receive an LLM config through the API.
    """
    if target.exists():
        return
    target.parent.mkdir(parents=True, exist_ok=True)
    if example.exists():
        target.write_bytes(example.read_bytes())
    else:
        target.write_text("", encoding="utf-8")


def read_config() -> dict[str, Any]:
    """Merge js + py llm_config.toml into a single canonical shape.

    JS takes precedence on shared keys (it's the more frequently used
    backend). Per-file extras stay attached so PUT can round-trip them.
    """
    js = _read_toml(JS_CONFIG)
    py = _read_toml(PY_CONFIG)
    merged: dict[str, Any] = {}
    for key in ("provider", "model", "api_key", "base_url"):
        merged[key] = js.get(key) or py.get(key) or ""
    merged["temperature"] = (
        js.get("temperature") if js.get("temperature") is not None
        else (py.get("temperature") if py.get("temperature") is not None else 0)
    )
    merged["max_tokens"] = int(
        js.get("max_tokens") or py.get("max_tokens") or 0
    )
    merged["max_code_size"] = int(js.get("max_code_size") or 0) or 65536
    merged["api_key_env"] = py.get("api_key_env") or ""
    merged["timeout_seconds"] = int(py.get("timeout_seconds") or 0) or 120
    return merged


def public_view(cfg: dict[str, Any]) -> dict[str, Any]:
    """Strip the secret api_key, replace it with a presence flag + last4."""
    api_key = str(cfg.get("api_key") or "").strip()
    return {
        "provider":         cfg.get("provider") or "",
        "model":            cfg.get("model") or "",
        "base_url":         cfg.get("base_url") or "",
        "temperature":      cfg.get("temperature") if cfg.get("temperature") is not None else 0,
        "max_tokens":       int(cfg.get("max_tokens") or 0),
        "max_code_size":    int(cfg.get("max_code_size") or 0),
        "api_key_env":      cfg.get("api_key_env") or "",
        "timeout_seconds":  int(cfg.get("timeout_seconds") or 0),
        "api_key_present":  bool(api_key),
        "api_key_last4":    api_key[-4:] if len(api_key) >= 4 else "",
        # Length of the stored key (0 when absent). Used by the Settings
        # input placeholder so the "••••" stand-in matches the real key's
        # width — real provider tokens are 40–100+ chars, so the previous
        # fixed 8-dot placeholder looked misleadingly short.
        "api_key_length":   len(api_key),
        "verified":         is_verified(cfg),
    }


def is_configured() -> bool:
    """True iff both files exist (or can be created) AND have an api_key."""
    cfg = read_config()
    return bool(str(cfg.get("api_key") or "").strip())


# ─── verified-connection fingerprint ────────────────────────────────────────
# Persisted server-side so the "Test connection" stamp survives page
# refreshes and server restarts, regardless of which browser the user was
# on when they ran the check. The fingerprint is a hash of the four
# connection-affecting fields (provider, model, base_url, api_key_last4)
# so any change to the saved config automatically invalidates the stamp.

def fingerprint_for(cfg: dict[str, Any]) -> str:
    """Join the connection-defining fields into the canonical stamp string.

    Must stay byte-identical to the frontend's previous
    ``llmConfigFingerprint`` helper so any in-flight ``llm_verified.json``
    files from prior client-side stamps still resolve correctly.
    """
    api_key = str(cfg.get("api_key") or "").strip()
    last4 = api_key[-4:] if len(api_key) >= 4 else ""
    return "|".join([
        str(cfg.get("provider") or ""),
        str(cfg.get("model") or ""),
        str(cfg.get("base_url") or ""),
        last4,
    ])


def read_verified_state() -> dict[str, Any]:
    """Return the stored verification state, or an empty dict."""
    if not VERIFIED_STATE.exists():
        return {}
    try:
        data = json.loads(VERIFIED_STATE.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def read_verified_fingerprint() -> str:
    """Return the stored fingerprint, or '' if no successful test on record."""
    return str(read_verified_state().get("fingerprint") or "")


def write_verified_fingerprint(fp: str, user_id: int | None = None) -> None:
    """Persist ``fp`` as the latest 'Test connection succeeded' stamp.

    Writes atomically through a tempfile so a crash mid-write never leaves
    a half-truncated JSON behind.
    """
    try:
        tmp = VERIFIED_STATE.with_suffix(VERIFIED_STATE.suffix + ".tmp")
        data: dict[str, Any] = {"fingerprint": fp}
        if user_id is not None:
            data["user_id"] = int(user_id)
        tmp.write_text(
            json.dumps(data, ensure_ascii=False),
            encoding="utf-8",
        )
        tmp.replace(VERIFIED_STATE)
    except Exception:
        # Persistence is best-effort: a missing/unwritable state file
        # only costs the user one extra Test-connection click.
        pass


def clear_verified_fingerprint() -> None:
    """Remove the stored fingerprint (next Test connection re-stamps it)."""
    try:
        VERIFIED_STATE.unlink(missing_ok=True)
    except Exception:
        pass


def is_verified(cfg: dict[str, Any], user_id: int | None = None) -> bool:
    """True iff there's a stored fingerprint matching ``cfg``'s connection."""
    if not str(cfg.get("api_key") or "").strip():
        return False
    state = read_verified_state()
    stored = str(state.get("fingerprint") or "")
    if not stored or stored != fingerprint_for(cfg):
        return False
    if user_id is None:
        return True
    return state.get("user_id") == int(user_id)


# ─── write ───────────────────────────────────────────────────────────────────

# Payload accepted by ``write_config``::
#
#   {provider?, model?, base_url?, temperature?, max_tokens?,
#    max_code_size?, timeout_seconds?, api_key_env?,
#    api_key?,        # non-empty string → overwrite both files
#    clear_api_key?,  # truthy → reset both keys to ""
#   }
#
# Any key absent from the payload is left untouched in the underlying TOML.

def _js_updates(p: dict[str, Any]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for k in ("provider", "model", "base_url"):
        if k in p:
            out[k] = str(p[k] if p[k] is not None else "")
    if "temperature" in p and p["temperature"] is not None:
        out["temperature"] = float(p["temperature"])
    if "max_tokens" in p and p["max_tokens"] is not None:
        out["max_tokens"] = int(p["max_tokens"])
    if "max_code_size" in p and p["max_code_size"] is not None:
        out["max_code_size"] = int(p["max_code_size"])
    if p.get("clear_api_key"):
        out["api_key"] = ""
    elif p.get("api_key"):
        out["api_key"] = str(p["api_key"])
    return out


def _py_updates(p: dict[str, Any]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for k in ("provider", "model", "base_url"):
        if k in p:
            out[k] = str(p[k] if p[k] is not None else "")
    if "temperature" in p and p["temperature"] is not None:
        out["temperature"] = float(p["temperature"])
    if "max_tokens" in p and p["max_tokens"] is not None:
        out["max_tokens"] = int(p["max_tokens"])
    if "timeout_seconds" in p and p["timeout_seconds"] is not None:
        out["timeout_seconds"] = int(p["timeout_seconds"])
    if "api_key_env" in p:
        out["api_key_env"] = str(p["api_key_env"] or "")
    if p.get("clear_api_key"):
        out["api_key"] = ""
    elif p.get("api_key"):
        out["api_key"] = str(p["api_key"])
    return out


def write_config(payload: dict[str, Any]) -> None:
    """Apply ``payload`` to both llm_config.toml files atomically-per-file.

    Comments, blank lines, multi-line strings (``rename_prompt`` etc.) and
    unknown keys are preserved. Missing files are bootstrapped from the
    matching ``llm_config.example.toml``.

    Side effect: when any of the connection-defining fields (provider,
    model, base_url, api_key) actually change as a result of this write,
    the persisted "Test connection" stamp is cleared. Tweaks to neutral
    fields (temperature, max_tokens, …) leave it intact so the user
    doesn't get bounced back to the verify step for unrelated edits.
    """
    _ensure_exists(JS_CONFIG, JS_EXAMPLE)
    _ensure_exists(PY_CONFIG, PY_EXAMPLE)
    before_fp = fingerprint_for(read_config())
    _update_toml_file(JS_CONFIG, _js_updates(payload))
    _update_toml_file(PY_CONFIG, _py_updates(payload))
    after_fp = fingerprint_for(read_config())
    if before_fp != after_fp:
        clear_verified_fingerprint()


# Matches a top-level ``key = …`` assignment line. Skips lines inside
# multi-line strings because our regex requires the key to start the
# (whitespace-stripped) line, but the leading whitespace allowed by the
# pattern means we only target keys with at most insignificant indentation
# — which is true for every key our two example files declare. We also
# avoid triple-quoted strings via the multi-line state machine in
# ``_update_toml_file``.
_KEY_RE = re.compile(r'^(\s*)([A-Za-z_][\w]*)\s*=')


def _toml_value(v: Any) -> str:
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, int):
        return str(v)
    if isinstance(v, float):
        # Keep a stable, dot-decimal form even for whole numbers.
        return repr(v) if "e" in repr(v).lower() else f"{v}"
    s = str(v)
    s = s.replace("\\", "\\\\").replace('"', '\\"')
    return f'"{s}"'


def _update_toml_file(path: Path, updates: dict[str, Any]) -> None:
    """In-place line-level update of a flat TOML file.

    For each line that looks like ``key = …`` we substitute the value if
    ``key`` appears in ``updates`` and the line is *not* inside a
    triple-quoted multi-line string. Keys not found in the file are
    appended at the end of the top-level table (before the first
    ``[section]`` header if one exists).
    """
    if not updates:
        return
    text = path.read_text(encoding="utf-8") if path.exists() else ""
    lines = text.splitlines()
    out: list[str] = []
    remaining = dict(updates)

    in_triple = False  # inside a `"""..."""` (or `'''...'''`) block
    triple_delim = ""
    insert_before_idx: int | None = None

    for idx, line in enumerate(lines):
        # Multi-line string detection — toggle on every `"""`/`'''` we see.
        # This is intentionally simple: TOML examples in this project never
        # mix the two delimiters or place keys *inside* prompt blocks.
        for delim in ('"""', "'''"):
            count = line.count(delim)
            if count:
                if not in_triple:
                    in_triple = True
                    triple_delim = delim
                    # Closes immediately on the same line if even count.
                    if count % 2 == 0:
                        in_triple = False
                        triple_delim = ""
                elif triple_delim == delim:
                    if count % 2:
                        in_triple = False
                        triple_delim = ""
                break

        stripped = line.lstrip()
        if (
            insert_before_idx is None
            and not in_triple
            and stripped.startswith("[")
            and stripped.rstrip().endswith("]")
            and not stripped.startswith("[[")
        ):
            insert_before_idx = len(out)

        if in_triple:
            out.append(line)
            continue

        m = _KEY_RE.match(line)
        if m and m.group(2) in remaining:
            key = m.group(2)
            indent = m.group(1)
            new_val = _toml_value(remaining.pop(key))
            # Preserve any trailing comment from the original line so that
            # author commentary (e.g. "# leave empty here ...") survives.
            comment = ""
            hash_idx = _find_unquoted_hash(line)
            if hash_idx is not None:
                comment = " " + line[hash_idx:].rstrip()
            out.append(f"{indent}{key} = {new_val}{comment}")
        else:
            out.append(line)

    if remaining:
        new_lines = [f"{k} = {_toml_value(v)}" for k, v in remaining.items()]
        if insert_before_idx is None:
            if out and out[-1].strip():
                out.append("")
            out.extend(new_lines)
        else:
            head = out[:insert_before_idx]
            tail = out[insert_before_idx:]
            if head and head[-1].strip():
                head.append("")
            out = head + new_lines + [""] + tail

    new_text = "\n".join(out)
    if not new_text.endswith("\n"):
        new_text += "\n"
    path.write_text(new_text, encoding="utf-8")


def _find_unquoted_hash(line: str) -> int | None:
    """Return the index of a ``#`` that begins a trailing comment.

    Skips ``#`` characters that appear inside a quoted string. Returns
    ``None`` when there is no trailing comment.
    """
    in_str = False
    quote = ""
    i = 0
    n = len(line)
    while i < n:
        ch = line[i]
        if in_str:
            if ch == "\\":
                i += 2
                continue
            if ch == quote:
                in_str = False
        else:
            if ch in ('"', "'"):
                in_str = True
                quote = ch
            elif ch == "#":
                return i
        i += 1
    return None
