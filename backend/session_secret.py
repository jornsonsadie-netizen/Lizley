"""Sync helper to get or create a persistent session secret from the database.

Used at app startup so sign-in persists without requiring SESSION_SECRET in .env.
Works with SQLite (built-in) and PostgreSQL (psycopg2 if installed).
"""

import os
import secrets
import sqlite3
from typing import Optional


def get_or_create_session_secret(
    database_url: Optional[str] = None,
    database_path: str = "./proxy.db",
) -> str:
    """Get or create a persistent session secret from the database.

    No .env required. Uses the same DB as the app (SQLite or PostgreSQL).
    Call at module load before SessionMiddleware is created.

    Args:
        database_url: PostgreSQL URL (e.g. from DATABASE_URL). If set, use PostgreSQL.
        database_path: Path to SQLite file (used when database_url is None).

    Returns:
        A 32-byte hex string suitable for SessionMiddleware secret_key.
    """
    url = (database_url or "").strip()
    if url.startswith("postgresql") or url.startswith("postgres"):
        return _get_or_create_postgres(url)
    return _get_or_create_sqlite(database_path)


def _get_or_create_sqlite(path: str) -> str:
    """SQLite: create app_settings table, get or create session_secret."""
    try:
        conn = sqlite3.connect(path, timeout=5)
        try:
            conn.execute(
                "CREATE TABLE IF NOT EXISTS app_settings (key TEXT PRIMARY KEY, value TEXT)"
            )
            row = conn.execute(
                "SELECT value FROM app_settings WHERE key = ?", ("session_secret",)
            ).fetchone()
            if row and row[0]:
                return row[0].strip()
            secret = secrets.token_hex(32)
            conn.execute(
                "INSERT OR REPLACE INTO app_settings (key, value) VALUES (?, ?)",
                ("session_secret", secret),
            )
            conn.commit()
            return secret
        finally:
            conn.close()
    except Exception as e:
        print(f"[Warning] SQLite session secret error at {path}: {e}")
        return secrets.token_hex(32)


def _get_or_create_postgres(url: str) -> str:
    """PostgreSQL: create app_settings table, get or create session_secret."""
    try:
        try:
            import psycopg2
        except ImportError:
            # Fallback: no psycopg2, use random
            return secrets.token_hex(32)
            
        conn = psycopg2.connect(url, connect_timeout=5)
        try:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    CREATE TABLE IF NOT EXISTS app_settings (
                        key TEXT PRIMARY KEY,
                        value TEXT
                    )
                    """
                )
                cur.execute(
                    "SELECT value FROM app_settings WHERE key = %s", ("session_secret",)
                )
                row = cur.fetchone()
                if row and row[0]:
                    return row[0].strip()
                secret = secrets.token_hex(32)
                cur.execute(
                    "INSERT INTO app_settings (key, value) VALUES (%s, %s) ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value",
                    ("session_secret", secret),
                )
            conn.commit()
            return secret
        finally:
            conn.close()
    except Exception as e:
        print(f"[Warning] PostgreSQL session secret error: {e}")
        return secrets.token_hex(32)
