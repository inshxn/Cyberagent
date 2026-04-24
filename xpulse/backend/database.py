from __future__ import annotations

import os
import sqlite3
from pathlib import Path
from threading import Lock
from time import time
from typing import Any


class XPulseDB:
    def __init__(self, db_path: str | None = None) -> None:
        self.db_path = Path(db_path or os.getenv("XPULSE_DB_PATH", "data/xpulse.db"))
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.lock = Lock()
        self.init()

    def connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        return conn

    def init(self) -> None:
        with self.connect() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE NOT NULL,
                    password_hash TEXT NOT NULL,
                    created_at REAL NOT NULL
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS posts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER NOT NULL,
                    content TEXT NOT NULL,
                    created_at REAL NOT NULL,
                    FOREIGN KEY(user_id) REFERENCES users(id)
                )
                """
            )
            conn.commit()

    def create_user(self, username: str, password_hash: str) -> dict[str, Any]:
        with self.lock, self.connect() as conn:
            cursor = conn.execute(
                "INSERT INTO users (username, password_hash, created_at) VALUES (?, ?, ?)",
                (username, password_hash, time()),
            )
            conn.commit()
            return {"id": cursor.lastrowid, "username": username}

    def get_user_by_username(self, username: str) -> dict[str, Any] | None:
        with self.lock, self.connect() as conn:
            row = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
        return dict(row) if row else None

    def get_user_by_id(self, user_id: int) -> dict[str, Any] | None:
        with self.lock, self.connect() as conn:
            row = conn.execute("SELECT id, username, created_at FROM users WHERE id = ?", (user_id,)).fetchone()
        return dict(row) if row else None

    def create_post(self, user_id: int, content: str) -> dict[str, Any]:
        now = time()
        with self.lock, self.connect() as conn:
            cursor = conn.execute(
                "INSERT INTO posts (user_id, content, created_at) VALUES (?, ?, ?)",
                (user_id, content, now),
            )
            conn.commit()
            post_id = cursor.lastrowid
        return {"id": post_id, "user_id": user_id, "content": content, "created_at": now}

    def feed(self, limit: int = 50) -> list[dict[str, Any]]:
        with self.lock, self.connect() as conn:
            rows = conn.execute(
                """
                SELECT posts.id, posts.content, posts.created_at, users.username
                FROM posts
                JOIN users ON users.id = posts.user_id
                ORDER BY posts.created_at DESC
                LIMIT ?
                """,
                (limit,),
            ).fetchall()
        return [dict(row) for row in rows]

