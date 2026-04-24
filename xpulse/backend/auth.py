from __future__ import annotations

import hashlib
import hmac
import os
import secrets
from time import time
from typing import Any

from fastapi import HTTPException, Request

SECRET = os.getenv("XPULSE_SECRET", "dev-secret-change-me")
SESSIONS: dict[str, dict[str, Any]] = {}


def hash_password(password: str) -> str:
    salt = secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 120_000).hex()
    return f"{salt}:{digest}"


def verify_password(password: str, stored: str) -> bool:
    salt, digest = stored.split(":", 1)
    check = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 120_000).hex()
    return hmac.compare_digest(check, digest)


def create_session(user: dict[str, Any]) -> str:
    token = secrets.token_urlsafe(32)
    SESSIONS[token] = {"user_id": user["id"], "username": user["username"], "created_at": time()}
    return token


def current_user(request: Request) -> dict[str, Any]:
    header = request.headers.get("authorization", "")
    token = header.removeprefix("Bearer ").strip()
    session = SESSIONS.get(token)
    if not session:
        raise HTTPException(status_code=401, detail="Authentication required")
    return session

