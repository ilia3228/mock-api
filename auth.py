"""Password hashing + bearer-token auth dependency for the mock API."""

from __future__ import annotations

import hashlib
import hmac
import os
import secrets
from typing import Any

from fastapi import Header, HTTPException, Query

import db

_PBKDF2_ITERS = 120_000
_PBKDF2_ALGO = "sha256"


# ─── password hashing ────────────────────────────────────────────────────────

def hash_password(password: str, salt: bytes | None = None) -> tuple[str, str]:
    """Return (hex_hash, hex_salt)."""
    if salt is None:
        salt = os.urandom(16)
    digest = hashlib.pbkdf2_hmac(_PBKDF2_ALGO, password.encode("utf-8"), salt, _PBKDF2_ITERS)
    return digest.hex(), salt.hex()


def verify_password(password: str, pw_hash_hex: str, pw_salt_hex: str) -> bool:
    salt = bytes.fromhex(pw_salt_hex)
    candidate, _ = hash_password(password, salt)
    return hmac.compare_digest(candidate, pw_hash_hex)


# ─── tokens ──────────────────────────────────────────────────────────────────

async def issue_token(user_id: int) -> str:
    token = secrets.token_urlsafe(32)
    await db.insert_token(token, user_id)
    return token


# ─── FastAPI dependency ──────────────────────────────────────────────────────

def _extract_token(authorization: str | None, token_q: str | None) -> str | None:
    if authorization and authorization.lower().startswith("bearer "):
        return authorization[7:].strip() or None
    return (token_q or "").strip() or None


async def current_user(
    authorization: str | None = Header(default=None),
    token: str | None = Query(default=None),
) -> dict[str, Any]:
    tok = _extract_token(authorization, token)
    if not tok:
        raise HTTPException(401, "missing authorization token")
    user = await db.user_by_token(tok)
    if not user:
        raise HTTPException(401, "invalid or expired token")
    return user


async def current_user_optional(
    authorization: str | None = Header(default=None),
    token: str | None = Query(default=None),
) -> dict[str, Any] | None:
    tok = _extract_token(authorization, token)
    if not tok:
        return None
    return await db.user_by_token(tok)
