from __future__ import annotations

import sqlite3
from datetime import datetime, timezone
from pathlib import Path

import bcrypt


DATABASE = Path("data/secureops.sqlite3")


class AuthManager:

    def __init__(self, db_path: Path = DATABASE):
        self.db_path = db_path
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.initialize()

    def _connect(self):
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def initialize(self):
        with self._connect() as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE NOT NULL,
                    password_hash TEXT NOT NULL,
                    created_at TEXT NOT NULL
                )
            """)
            conn.commit()
    def hash_password(self, password: str) -> str:
        return bcrypt.hashpw(
            password.encode(),
            bcrypt.gensalt()
        ).decode()

    def verify_password(
        self,
        password: str,
        password_hash: str,
    ) -> bool:
        return bcrypt.checkpw(
            password.encode(),
            password_hash.encode(),
        )
    def admin_exists(self) -> bool:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT COUNT(*) FROM users"
            ).fetchone()

            return row[0] > 0
    def create_admin(
        self,
        username: str,
        password: str,
    ) -> bool:

        if self.admin_exists():
            return False

        password_hash = self.hash_password(password)

        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO users
                (username, password_hash, created_at)
                VALUES (?, ?, ?)
                """,
                (
                    username,
                    password_hash,
                    datetime.now(timezone.utc).isoformat(),
                ),
            )
            conn.commit()

        return True                    
    def authenticate(
        self,
        username: str,
        password: str,
    ) -> bool:

        with self._connect() as conn:

            row = conn.execute(
                """
                SELECT password_hash
                FROM users
                WHERE username = ?
                """,
                (username,),
            ).fetchone()

            if row is None:
                return False

            return self.verify_password(
                password,
                row["password_hash"],
            )
    def get_admin_username(self) -> str | None:
        with self._connect() as conn:
            row = conn.execute(
                """
                SELECT username
                FROM users
                LIMIT 1
                """
            ).fetchone()

            if row:
                return row["username"]

            return None
    def change_password(
        self,
        username: str,
        new_password: str,
    ) -> bool:

        password_hash = self.hash_password(new_password)

        with self._connect() as conn:
            cursor = conn.execute(
                """
                UPDATE users
                SET password_hash = ?
                WHERE username = ?
                """,
                (
                    password_hash,
                    username,
                ),
            )

            conn.commit()

            return cursor.rowcount > 0            
