"""Database module for the AI Proxy.

Supports both SQLite (local development) and PostgreSQL (production).
Auto-detects which to use based on DATABASE_URL environment variable.
"""

import os
from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional, List, Union

# SQLite support
import aiosqlite

# PostgreSQL support (optional)
try:
    import asyncpg
    HAS_ASYNCPG = True
except ImportError:
    HAS_ASYNCPG = False


@dataclass
class ApiKeyRecord:
    """Represents an API key record from the database."""
    id: int
    key_hash: str
    key_prefix: str
    full_key: Optional[str]
    discord_id: Optional[str]  # Discord user ID (unique identifier)
    discord_email: Optional[str]  # Discord email/username for display
    ip_address: str  # Keep for logging purposes
    browser_fingerprint: Optional[str]

    current_rpm: int
    current_rpd: int
    last_rpm_reset: datetime
    last_rpd_reset: datetime
    enabled: bool
    bypass_ip_ban: bool  # If True, key is not blocked by IP ban list (admin-set)
    created_at: datetime
    last_used_at: Optional[datetime]


@dataclass
class UsageStats:
    """Usage statistics for an API key."""
    total_requests: int
    successful_requests: int
    total_tokens: int
    requests_today: int
    tokens_today: int


@dataclass
class RequestLogRecord:
    """Represents a request log record from the database."""
    id: int
    api_key_id: int
    key_prefix: str
    ip_address: str
    model: str
    input_tokens: int
    output_tokens: int
    total_tokens: int
    success: bool
    error_message: Optional[str]
    request_time: datetime


@dataclass
class KeyAnalytics:
    """Analytics for a specific API key."""
    key_id: int
    key_prefix: str
    ip_address: str
    discord_email: Optional[str]
    total_input_tokens: int
    total_output_tokens: int
    total_tokens: int
    total_requests: int
    successful_requests: int
    most_used_model: Optional[str]
    model_usage_count: int
    recent_requests: List["RequestLogRecord"]


@dataclass
class BannedIpRecord:
    """Represents a banned IP record from the database."""
    id: int
    ip_address: str
    reason: Optional[str]
    banned_at: datetime


@dataclass
class ContentFlagRecord:
    """Represents a content moderation flag from the database."""
    id: int
    api_key_id: int
    key_prefix: str
    discord_id: Optional[str]
    discord_email: Optional[str]
    ip_address: str
    flag_type: str  # 'csam', 'violence', 'hate', etc.
    severity: str  # 'low', 'medium', 'high', 'critical'
    message_preview: str  # First 500 chars of flagged content
    full_message_hash: str  # SHA256 hash of full message for deduplication
    model: str
    reviewed: bool
    action_taken: Optional[str]  # 'banned', 'warned', 'dismissed', etc.
    flagged_at: datetime
    reviewed_at: Optional[datetime]


@dataclass
class ProxyConfig:
    """Proxy configuration stored in the database."""
    target_api_url: str
    target_api_key: str
    max_context: int
    max_output_tokens: int
    fallback_api_keys: str = ""
    current_key_index: int = 0





@dataclass
class BannedUserRecord:
    id: int
    discord_id: str
    reason: Optional[str]
    banned_at: datetime

def create_database(database_url: Optional[str] = None, database_path: str = "./proxy.db") -> "Database":
    """Factory function to create the appropriate database instance."""
    if database_url:
        if not HAS_ASYNCPG:
            raise ImportError("asyncpg is required for PostgreSQL support. Install with: pip install asyncpg")
        return PostgreSQLDatabase(database_url)
    return SQLiteDatabase(database_path)


class Database(ABC):
    """Abstract base class for database operations."""
    
    @abstractmethod
    async def initialize(self) -> None:
        pass
    
    @abstractmethod
    async def close(self) -> None:
        pass
    
    # API Key operations
    @abstractmethod
    async def create_api_key(self, discord_id: str, discord_email: Optional[str], key_hash: str, key_prefix: str, full_key: str, ip_address: str = "unknown", enabled: bool = True, browser_fingerprint: Optional[str] = None) -> int:
        pass
    
    @abstractmethod
    async def get_key_by_discord_id(self, discord_id: str) -> Optional[ApiKeyRecord]:
        pass
    
    @abstractmethod
    async def get_key_by_ip(self, ip_address: str) -> Optional[ApiKeyRecord]:
        pass
    
    @abstractmethod
    async def get_key_by_fingerprint(self, fingerprint: str) -> Optional[ApiKeyRecord]:
        pass
    
    @abstractmethod
    async def get_key_by_hash(self, key_hash: str) -> Optional[ApiKeyRecord]:
        pass
    
    @abstractmethod
    async def get_all_keys(self) -> List[ApiKeyRecord]:
        pass
    
    @abstractmethod
    async def count_keys_by_ip(self, ip_address: str) -> int:
        """Return the number of API keys currently associated with this IP."""
        pass
    
    @abstractmethod
    async def count_discord_keys_by_ip(self, ip_address: str) -> int:
        """Return the number of Discord-authenticated API keys for this IP (excludes legacy ip_ keys)."""
        pass
    
    @abstractmethod
    async def delete_disabled_keys_by_ip(self, ip_address: str) -> int:
        """Delete all disabled API keys for a given IP. Returns count deleted."""
        pass

    @abstractmethod
    async def delete_keys_by_prefix_for_fingerprint(self, prefix: str, fingerprint: str) -> int:
        """Delete API keys with a specific prefix for a given browser fingerprint. Returns count deleted."""
        pass

    @abstractmethod
    async def delete_keys_by_prefix_for_ip(self, prefix: str, ip_address: str) -> int:
        """Delete API keys with a specific prefix for a given IP address. Returns count deleted."""
        pass
    
    @abstractmethod
    async def get_keys_by_ip(self, ip_address: str) -> List[ApiKeyRecord]:
        """Return all API keys associated with a given IP."""
        pass

    @abstractmethod
    async def delete_disabled_keys_by_fingerprint(self, fingerprint: str) -> int:
        """Delete all disabled API keys for a given fingerprint. Returns count deleted."""
        pass
    
    @abstractmethod
    async def delete_all_keys(self) -> int:
        """Delete ALL API keys and their usage logs. Returns count deleted."""
        pass
    
    @abstractmethod
    async def delete_key(self, key_id: int) -> bool:
        pass
    
    @abstractmethod
    async def toggle_key(self, key_id: int) -> bool:
        pass
    
    @abstractmethod
    async def set_key_enabled(self, key_id: int, enabled: bool) -> bool:
        """Set key enabled state explicitly. Returns True if key existed."""
        pass
    
    @abstractmethod
    async def update_key_ip(self, key_id: int, new_ip: str) -> None:
        pass
    
    @abstractmethod
    async def update_key_fingerprint(self, key_id: int, fingerprint: str) -> None:
        pass
    
    @abstractmethod
    async def set_key_bypass_ip_ban(self, key_id: int, bypass: bool) -> bool:
        """Set whether this key bypasses IP ban checks. Returns True if key existed."""
        pass
    
    # Rate limit operations
    @abstractmethod
    async def update_usage(self, key_id: int, rpm: int, rpd: int) -> None:
        pass
    
    @abstractmethod
    async def increment_usage(self, key_id: int) -> tuple[int, int]:
        pass
    
    @abstractmethod
    async def increment_rpm_only(self, key_id: int) -> int:
        """Increment only the RPM counter. Returns the new RPM."""
        pass
    
    @abstractmethod
    async def increment_rpd_only(self, key_id: int) -> int:
        """Increment only the daily request counter (RPD). Returns the new RPD."""
        pass
    
    @abstractmethod
    async def reset_rpm(self, key_id: int) -> None:
        pass
    
    @abstractmethod
    async def reset_rpd(self, key_id: int) -> None:
        pass
    
    @abstractmethod
    async def reset_all_rpd(self) -> int:
        pass
    
    @abstractmethod
    async def reset_all_rpm(self) -> int:
        pass
    
    # Usage logging
    @abstractmethod
    async def log_usage(self, key_id: int, model: str, tokens: int, success: bool,
                       ip_address: Optional[str] = None, input_tokens: int = 0,
                       output_tokens: int = 0, error_message: Optional[str] = None) -> None:
        pass
    
    @abstractmethod
    async def get_daily_tokens_used(self, key_id: int, since_utc: str, until_utc: str) -> int:
        """Return sum of tokens_used for this key between since_utc and until_utc (ISO format)."""
        pass

    @abstractmethod
    async def get_daily_tokens_used_all(self, since_utc: str, until_utc: str) -> dict[int, int]:
        """Return {key_id: tokens_sum} for ALL keys between since_utc and until_utc. Single query."""
        pass

    @abstractmethod
    async def get_usage_stats(self, key_id: int) -> UsageStats:
        pass
    
    @abstractmethod
    async def get_recent_requests(self, limit: int = 10) -> List[RequestLogRecord]:
        pass
    
    @abstractmethod
    async def get_top_token_requests(self, limit: int = 3) -> List[RequestLogRecord]:
        pass
    
    @abstractmethod
    async def get_key_analytics(self, key_id: int) -> Optional[KeyAnalytics]:
        pass
    
    # IP ban operations
    @abstractmethod
    async def ban_ip(self, ip_address: str, reason: Optional[str] = None) -> None:
        pass
    
    @abstractmethod
    async def unban_ip(self, ip_address: str) -> bool:
        pass
    
    @abstractmethod
    async def is_ip_banned(self, ip_address: str) -> bool:
        pass
    
    @abstractmethod
    async def get_all_banned_ips(self) -> List[BannedIpRecord]:
        pass

    # User-level ban operations
    @abstractmethod
    async def ban_user(self, discord_id: str, reason: Optional[str] = None) -> None:
        """Permanently ban a user (Discord ID)."""
        pass
    
    @abstractmethod
    async def unban_user(self, discord_id: str) -> bool:
        """Unban a user. Returns True if found."""
        pass

    @abstractmethod
    async def is_user_banned(self, discord_id: str) -> bool:
        """Check if a specific Discord ID is in the user blacklist."""
        pass

    @abstractmethod
    async def get_all_banned_users(self) -> List[BannedUserRecord]:
        """Return all banned user IDs with reasons and timestamps."""
        pass
    
    @abstractmethod
    async def disable_all_keys_for_user(self, discord_id: str) -> int:
        """Disable all API keys for a specific user ID. Returns count disabled."""
        pass
    
    @abstractmethod
    async def update_config(self, target_url: str, target_key: str, max_context: int, max_output_tokens: int = 4096, fallback_api_keys: str = "") -> None:
        pass
    
    @abstractmethod
    async def rotate_target_key(self) -> bool:
        """Rotate to the next API key in the fallback list. Returns True if rotated, False if no more keys."""
        pass
    
    # Model management operations
    @abstractmethod
    async def get_excluded_models(self) -> List[str]:
        """Return list of model IDs that are disabled."""
        pass
    
    @abstractmethod
    async def exclude_model(self, model_id: str) -> None:
        """Add a model to the exclusion list."""
        pass
    
    @abstractmethod
    async def include_model(self, model_id: str) -> bool:
        """Remove a model from the exclusion list. Returns True if was excluded."""
        pass
    
    @abstractmethod
    async def clear_excluded_models(self) -> None:
        """Enable all models by clearing the exclusion list."""
        pass
    
    @abstractmethod
    async def get_model_aliases(self) -> dict:
        """Return a mapping of model ID to its alias."""
        pass

    @abstractmethod
    async def set_model_alias(self, model_id: str, alias: str) -> None:
        """Set or update an alias for a model."""
        pass

    @abstractmethod
    async def delete_model_alias(self, model_id: str) -> bool:
        """Delete an alias for a model. Returns True if was aliased."""
        pass
    
    # Content flag operations
    @abstractmethod
    async def create_content_flag(
        self,
        api_key_id: int,
        flag_type: str,
        severity: str,
        message_preview: str,
        full_message_hash: str,
        model: str,
        ip_address: str,
    ) -> int:
        """Create a content moderation flag. Returns the flag ID."""
        pass
    
    @abstractmethod
    async def get_all_flags(self, include_reviewed: bool = False) -> List[ContentFlagRecord]:
        """Get all content flags, optionally including reviewed ones."""
        pass
    
    @abstractmethod
    async def get_flag_by_id(self, flag_id: int) -> Optional[ContentFlagRecord]:
        """Get a specific flag by ID."""
        pass
    
    @abstractmethod
    async def mark_flag_reviewed(self, flag_id: int, action_taken: str) -> bool:
        """Mark a flag as reviewed with the action taken. Returns True if found."""
        pass
    
    @abstractmethod
    async def get_flags_by_key(self, api_key_id: int) -> List[ContentFlagRecord]:
        """Get all flags for a specific API key."""
        pass
    
    @abstractmethod
    async def count_unreviewed_flags(self) -> int:
        """Count unreviewed flags."""
        pass
        




class SQLiteDatabase(Database):
    """SQLite database implementation for local development."""

    def __init__(self, database_path: str):
        self.database_path = database_path
        self._connection: Optional[aiosqlite.Connection] = None

    async def _get_connection(self) -> aiosqlite.Connection:
        if self._connection is None:
            self._connection = await aiosqlite.connect(self.database_path)
            self._connection.row_factory = aiosqlite.Row
        return self._connection

    async def close(self) -> None:
        if self._connection is not None:
            await self._connection.close()
            self._connection = None

    async def initialize(self) -> None:
        conn = await self._get_connection()
        
        await conn.execute("""
            CREATE TABLE IF NOT EXISTS api_keys (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                key_hash TEXT UNIQUE NOT NULL,
                key_prefix TEXT NOT NULL,
                full_key TEXT,
                discord_id TEXT UNIQUE,
                discord_email TEXT,
                ip_address TEXT NOT NULL DEFAULT 'unknown',
                browser_fingerprint TEXT,
                current_rpm INTEGER DEFAULT 0,
                current_rpd INTEGER DEFAULT 0,
                last_rpm_reset TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_rpd_reset TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                enabled BOOLEAN DEFAULT TRUE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_used_at TIMESTAMP
            )
        """)
        
        # Migrations
        for col, sql in [
            ("discord_id", "ALTER TABLE api_keys ADD COLUMN discord_id TEXT UNIQUE"),
            ("discord_email", "ALTER TABLE api_keys ADD COLUMN discord_email TEXT"),
            ("browser_fingerprint", "ALTER TABLE api_keys ADD COLUMN browser_fingerprint TEXT"),
            ("full_key", "ALTER TABLE api_keys ADD COLUMN full_key TEXT"),
            ("bypass_ip_ban", "ALTER TABLE api_keys ADD COLUMN bypass_ip_ban BOOLEAN DEFAULT 0"),

        ]:
            try:
                await conn.execute(f"SELECT {col} FROM api_keys LIMIT 1")
            except Exception:
                await conn.execute(sql)
        
        await conn.execute("CREATE INDEX IF NOT EXISTS idx_api_keys_ip ON api_keys(ip_address)")
        await conn.execute("CREATE INDEX IF NOT EXISTS idx_api_keys_fingerprint ON api_keys(browser_fingerprint)")
        await conn.execute("CREATE INDEX IF NOT EXISTS idx_api_keys_discord_id ON api_keys(discord_id)")
        
        await conn.execute("""
            CREATE TABLE IF NOT EXISTS usage_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                api_key_id INTEGER NOT NULL,
                ip_address TEXT,
                model TEXT,
                input_tokens INTEGER DEFAULT 0,
                output_tokens INTEGER DEFAULT 0,
                tokens_used INTEGER DEFAULT 0,
                success BOOLEAN DEFAULT TRUE,
                error_message TEXT,
                request_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (api_key_id) REFERENCES api_keys(id) ON DELETE CASCADE
            )
        """)
        
        await conn.execute("""
            CREATE TABLE IF NOT EXISTS banned_ips (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip_address TEXT UNIQUE NOT NULL,
                reason TEXT,
                banned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        await conn.execute("""
            CREATE TABLE IF NOT EXISTS proxy_config (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                target_api_url TEXT NOT NULL,
                target_api_key TEXT NOT NULL,
                max_context INTEGER DEFAULT 128000,
                max_output_tokens INTEGER DEFAULT 4096,
                fallback_api_keys TEXT DEFAULT '',
                current_key_index INTEGER DEFAULT 0,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        # Migrations for proxy_config
        for col, sql in [
            ("max_output_tokens", "ALTER TABLE proxy_config ADD COLUMN max_output_tokens INTEGER DEFAULT 4096"),
            ("fallback_api_keys", "ALTER TABLE proxy_config ADD COLUMN fallback_api_keys TEXT DEFAULT ''"),
            ("current_key_index", "ALTER TABLE proxy_config ADD COLUMN current_key_index INTEGER DEFAULT 0"),
        ]:
            try:
                await conn.execute(f"SELECT {col} FROM proxy_config LIMIT 1")
            except Exception:
                await conn.execute(sql)
        
        await conn.execute(
            "CREATE TABLE IF NOT EXISTS app_settings (key TEXT PRIMARY KEY, value TEXT)"
        )

        await conn.execute("""
            CREATE TABLE IF NOT EXISTS banned_users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                discord_id TEXT UNIQUE NOT NULL,
                reason TEXT,
                banned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        await conn.execute("CREATE INDEX IF NOT EXISTS idx_banned_users_discord ON banned_users(discord_id)")
        
        # Content moderation flags table
        await conn.execute("""
            CREATE TABLE IF NOT EXISTS content_flags (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                api_key_id INTEGER NOT NULL,
                flag_type TEXT NOT NULL,
                severity TEXT NOT NULL,
                message_preview TEXT NOT NULL,
                full_message_hash TEXT NOT NULL,
                model TEXT,
                ip_address TEXT,
                reviewed BOOLEAN DEFAULT FALSE,
                action_taken TEXT,
                flagged_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                reviewed_at TIMESTAMP,
                FOREIGN KEY (api_key_id) REFERENCES api_keys(id) ON DELETE CASCADE
            )
        """)
        await conn.execute("CREATE INDEX IF NOT EXISTS idx_content_flags_key ON content_flags(api_key_id)")
        await conn.execute("CREATE INDEX IF NOT EXISTS idx_content_flags_reviewed ON content_flags(reviewed)")
        await conn.execute("CREATE INDEX IF NOT EXISTS idx_content_flags_hash ON content_flags(full_message_hash)")
        
        # Model management table
        await conn.execute("""
            CREATE TABLE IF NOT EXISTS models_exclusion (
                model_id TEXT PRIMARY KEY
            )
        """)
        
        await conn.execute("""
            CREATE TABLE IF NOT EXISTS model_aliases (
                model_id TEXT PRIMARY KEY,
                alias TEXT NOT NULL
            )
        """)
        




    async def create_api_key(self, discord_id: str, discord_email: Optional[str], key_hash: str, key_prefix: str, full_key: str, ip_address: str = "unknown", enabled: bool = True, browser_fingerprint: Optional[str] = None) -> int:
        conn = await self._get_connection()
        cursor = await conn.execute(
            "INSERT INTO api_keys (discord_id, discord_email, ip_address, key_hash, key_prefix, full_key, enabled, browser_fingerprint) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (discord_id, discord_email, ip_address, key_hash, key_prefix, full_key, 1 if enabled else 0, browser_fingerprint)
        )
        await conn.commit()
        return cursor.lastrowid

    async def get_key_by_discord_id(self, discord_id: str) -> Optional[ApiKeyRecord]:
        conn = await self._get_connection()
        cursor = await conn.execute("SELECT * FROM api_keys WHERE discord_id = ? ORDER BY enabled DESC, created_at DESC", (discord_id,))
        row = await cursor.fetchone()
        return self._row_to_api_key(row) if row else None

    async def get_key_by_ip(self, ip_address: str) -> Optional[ApiKeyRecord]:
        conn = await self._get_connection()
        # Prioritize enabled keys, then keys without fingerprints (easier to claim/fallback),
        # then most recently used/created.
        query = """
            SELECT * FROM api_keys 
            WHERE ip_address = ? 
            ORDER BY enabled DESC, (browser_fingerprint IS NULL) DESC, last_used_at DESC, created_at DESC 
            LIMIT 1
        """
        cursor = await conn.execute(query, (ip_address,))
        row = await cursor.fetchone()
        return self._row_to_api_key(row) if row else None

    async def get_key_by_fingerprint(self, fingerprint: str) -> Optional[ApiKeyRecord]:
        conn = await self._get_connection()
        cursor = await conn.execute("SELECT * FROM api_keys WHERE browser_fingerprint = ? ORDER BY enabled DESC, created_at DESC", (fingerprint,))
        row = await cursor.fetchone()
        return self._row_to_api_key(row) if row else None

    async def get_key_by_hash(self, key_hash: str) -> Optional[ApiKeyRecord]:
        conn = await self._get_connection()
        cursor = await conn.execute("SELECT * FROM api_keys WHERE key_hash = ?", (key_hash,))
        row = await cursor.fetchone()
        return self._row_to_api_key(row) if row else None

    async def get_all_keys(self) -> List[ApiKeyRecord]:
        conn = await self._get_connection()
        cursor = await conn.execute("SELECT * FROM api_keys ORDER BY created_at DESC")
        rows = await cursor.fetchall()
        return [self._row_to_api_key(row) for row in rows]

    async def count_keys_by_ip(self, ip_address: str) -> int:
        conn = await self._get_connection()
        cursor = await conn.execute("SELECT COUNT(*) FROM api_keys WHERE ip_address = ? AND enabled = 1", (ip_address,))
        row = await cursor.fetchone()
        return row[0] if row else 0

    async def count_discord_keys_by_ip(self, ip_address: str) -> int:
        conn = await self._get_connection()
        cursor = await conn.execute(
            "SELECT COUNT(*) FROM api_keys WHERE ip_address = ? AND discord_id IS NOT NULL AND discord_id NOT LIKE 'ip_%' AND enabled = 1",
            (ip_address,)
        )
        row = await cursor.fetchone()
        return row[0] if row else 0

    async def delete_disabled_keys_by_ip(self, ip_address: str) -> int:
        conn = await self._get_connection()
        cursor = await conn.execute("DELETE FROM api_keys WHERE ip_address = ? AND enabled = 0", (ip_address,))
        count = cursor.rowcount
        await conn.commit()
        return count

    async def delete_keys_by_prefix_for_fingerprint(self, prefix: str, fingerprint: str) -> int:
        conn = await self._get_connection()
        cursor = await conn.execute("DELETE FROM api_keys WHERE browser_fingerprint = ? AND key_prefix = ?", (fingerprint, prefix))
        count = cursor.rowcount
        await conn.commit()
        return count

    async def delete_keys_by_prefix_for_ip(self, prefix: str, ip_address: str) -> int:
        conn = await self._get_connection()
        cursor = await conn.execute("DELETE FROM api_keys WHERE ip_address = ? AND key_prefix = ?", (ip_address, prefix))
        count = cursor.rowcount
        await conn.commit()
        return count

    async def get_keys_by_ip(self, ip_address: str) -> List[ApiKeyRecord]:
        conn = await self._get_connection()
        cursor = await conn.execute("SELECT * FROM api_keys WHERE ip_address = ?", (ip_address,))
        rows = await cursor.fetchall()
        return [self._row_to_api_key(row) for row in rows]

    async def delete_disabled_keys_by_fingerprint(self, fingerprint: str) -> int:
        conn = await self._get_connection()
        cursor = await conn.execute("DELETE FROM api_keys WHERE browser_fingerprint = ? AND enabled = 0", (fingerprint,))
        await conn.commit()
        return cursor.rowcount

    async def delete_all_keys(self) -> int:
        conn = await self._get_connection()
        # Delete usage logs first (foreign key), then keys
        await conn.execute("DELETE FROM usage_logs")
        cursor = await conn.execute("DELETE FROM api_keys")
        await conn.commit()
        return cursor.rowcount

    async def delete_key(self, key_id: int) -> bool:
        conn = await self._get_connection()
        cursor = await conn.execute("DELETE FROM api_keys WHERE id = ?", (key_id,))
        await conn.commit()
        return cursor.rowcount > 0

    async def toggle_key(self, key_id: int) -> bool:
        conn = await self._get_connection()
        cursor = await conn.execute("UPDATE api_keys SET enabled = NOT enabled WHERE id = ?", (key_id,))
        await conn.commit()
        return cursor.rowcount > 0

    async def set_key_enabled(self, key_id: int, enabled: bool) -> bool:
        conn = await self._get_connection()
        cursor = await conn.execute("UPDATE api_keys SET enabled = ? WHERE id = ?", (1 if enabled else 0, key_id))
        await conn.commit()
        return cursor.rowcount > 0

    async def update_key_ip(self, key_id: int, new_ip: str) -> None:
        conn = await self._get_connection()
        await conn.execute("UPDATE api_keys SET ip_address = ? WHERE id = ?", (new_ip, key_id))
        await conn.commit()

    async def update_key_fingerprint(self, key_id: int, fingerprint: str) -> None:
        conn = await self._get_connection()
        await conn.execute("UPDATE api_keys SET browser_fingerprint = ? WHERE id = ?", (fingerprint, key_id))
        await conn.commit()

    async def set_key_bypass_ip_ban(self, key_id: int, bypass: bool) -> bool:
        conn = await self._get_connection()
        cursor = await conn.execute("UPDATE api_keys SET bypass_ip_ban = ? WHERE id = ?", (1 if bypass else 0, key_id))
        await conn.commit()
        return cursor.rowcount > 0

    async def update_usage(self, key_id: int, rpm: int, rpd: int) -> None:
        conn = await self._get_connection()
        await conn.execute(
            "UPDATE api_keys SET current_rpm = ?, current_rpd = ?, last_used_at = CURRENT_TIMESTAMP WHERE id = ?",
            (rpm, rpd, key_id)
        )
        await conn.commit()

    async def increment_usage(self, key_id: int) -> tuple[int, int]:
        conn = await self._get_connection()
        await conn.execute(
            "UPDATE api_keys SET current_rpm = current_rpm + 1, current_rpd = current_rpd + 1, last_used_at = CURRENT_TIMESTAMP WHERE id = ?",
            (key_id,)
        )
        await conn.commit()
        cursor = await conn.execute("SELECT current_rpm, current_rpd FROM api_keys WHERE id = ?", (key_id,))
        row = await cursor.fetchone()
        return (row["current_rpm"], row["current_rpd"]) if row else (0, 0)

    async def increment_rpm_only(self, key_id: int) -> int:
        conn = await self._get_connection()
        await conn.execute(
            "UPDATE api_keys SET current_rpm = current_rpm + 1, last_used_at = CURRENT_TIMESTAMP WHERE id = ?",
            (key_id,)
        )
        await conn.commit()
        cursor = await conn.execute("SELECT current_rpm FROM api_keys WHERE id = ?", (key_id,))
        row = await cursor.fetchone()
        return row["current_rpm"] if row else 0

    async def increment_rpd_only(self, key_id: int) -> int:
        conn = await self._get_connection()
        await conn.execute(
            "UPDATE api_keys SET current_rpd = current_rpd + 1, last_used_at = CURRENT_TIMESTAMP WHERE id = ?",
            (key_id,)
        )
        await conn.commit()
        cursor = await conn.execute("SELECT current_rpd FROM api_keys WHERE id = ?", (key_id,))
        row = await cursor.fetchone()
        return row["current_rpd"] if row else 0

    async def reset_rpm(self, key_id: int) -> None:
        conn = await self._get_connection()
        await conn.execute("UPDATE api_keys SET current_rpm = 0, last_rpm_reset = CURRENT_TIMESTAMP WHERE id = ?", (key_id,))
        await conn.commit()

    async def reset_rpd(self, key_id: int) -> None:
        conn = await self._get_connection()
        await conn.execute("UPDATE api_keys SET current_rpd = 0, last_rpd_reset = CURRENT_TIMESTAMP WHERE id = ?", (key_id,))
        await conn.commit()

    async def reset_all_rpd(self) -> int:
        conn = await self._get_connection()
        cursor = await conn.execute("UPDATE api_keys SET current_rpd = 0, last_rpd_reset = CURRENT_TIMESTAMP")
        await conn.commit()
        return cursor.rowcount

    async def reset_all_rpm(self) -> int:
        conn = await self._get_connection()
        cursor = await conn.execute("UPDATE api_keys SET current_rpm = 0, last_rpm_reset = CURRENT_TIMESTAMP")
        await conn.commit()
        return cursor.rowcount

    async def log_usage(self, key_id: int, model: str, tokens: int, success: bool,
                       ip_address: Optional[str] = None, input_tokens: int = 0,
                       output_tokens: int = 0, error_message: Optional[str] = None) -> None:
        # Skip logging for synthetic/whitelisted keys (-1) to avoid foreign key violations
        if key_id < 0:
            return
            
        conn = await self._get_connection()
        await conn.execute(
            "INSERT INTO usage_logs (api_key_id, ip_address, model, input_tokens, output_tokens, tokens_used, success, error_message) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (key_id, ip_address, model, input_tokens, output_tokens, tokens, success, error_message)
        )
        await conn.commit()

    async def get_daily_tokens_used(self, key_id: int, since_utc: str, until_utc: str) -> int:
        conn = await self._get_connection()
        # SQLite request_time is "YYYY-MM-DD HH:MM:SS" (UTC)
        # since_utc/until_utc is usually "YYYY-MM-DDTHH:MM:SS"
        # Convert to space format for robust SQLite string comparison
        since_str = since_utc.replace("T", " ") if "T" in since_utc else since_utc
        until_str = until_utc.replace("T", " ") if "T" in until_utc else until_utc
        
        cursor = await conn.execute("""
            SELECT COALESCE(SUM(tokens_used), 0) FROM usage_logs
            WHERE api_key_id = ? AND request_time >= ? AND request_time < ?
        """, (key_id, since_str, until_str))
        row = await cursor.fetchone()
        return int(row[0]) if row and row[0] is not None else 0

    async def get_daily_tokens_used_all(self, since_utc: str, until_utc: str) -> dict[int, int]:
        conn = await self._get_connection()
        since_str = since_utc.replace("T", " ") if "T" in since_utc else since_utc
        until_str = until_utc.replace("T", " ") if "T" in until_utc else until_utc
        
        cursor = await conn.execute("""
            SELECT api_key_id, COALESCE(SUM(tokens_used), 0) as tokens_sum FROM usage_logs
            WHERE request_time >= ? AND request_time < ?
            GROUP BY api_key_id
        """, (since_str, until_str))
        rows = await cursor.fetchall()
        return {row[0]: int(row[1]) for row in rows}

    async def get_usage_stats(self, key_id: int) -> UsageStats:
        conn = await self._get_connection()
        cursor = await conn.execute("""
            SELECT COUNT(*) as total_requests, SUM(CASE WHEN success = 1 THEN 1 ELSE 0 END) as successful_requests,
                   COALESCE(SUM(tokens_used), 0) as total_tokens
            FROM usage_logs WHERE api_key_id = ? AND model != 'models'
        """, (key_id,))
        total_row = await cursor.fetchone()
        
        cursor = await conn.execute("""
            SELECT COUNT(*) as requests_today, COALESCE(SUM(tokens_used), 0) as tokens_today
            FROM usage_logs WHERE api_key_id = ? AND DATE(request_time) = DATE('now') AND model != 'models'
        """, (key_id,))
        today_row = await cursor.fetchone()
        
        return UsageStats(
            total_requests=total_row["total_requests"] or 0,
            successful_requests=total_row["successful_requests"] or 0,
            total_tokens=total_row["total_tokens"] or 0,
            requests_today=today_row["requests_today"] or 0,
            tokens_today=today_row["tokens_today"] or 0,
        )

    async def get_recent_requests(self, limit: int = 10) -> List[RequestLogRecord]:
        conn = await self._get_connection()
        cursor = await conn.execute("""
            SELECT ul.id, ul.api_key_id, ak.key_prefix, ul.ip_address, ul.model,
                   ul.input_tokens, ul.output_tokens, ul.tokens_used, ul.success,
                   ul.error_message, ul.request_time
            FROM usage_logs ul LEFT JOIN api_keys ak ON ul.api_key_id = ak.id
            ORDER BY ul.request_time DESC LIMIT ?
        """, (limit,))
        rows = await cursor.fetchall()
        return [self._row_to_request_log(row) for row in rows]

    async def get_top_token_requests(self, limit: int = 3) -> List[RequestLogRecord]:
        conn = await self._get_connection()
        cursor = await conn.execute("""
            SELECT ul.id, ul.api_key_id, ak.key_prefix, ul.ip_address, ul.model,
                   ul.input_tokens, ul.output_tokens, ul.tokens_used, ul.success,
                   ul.error_message, ul.request_time
            FROM usage_logs ul LEFT JOIN api_keys ak ON ul.api_key_id = ak.id
            WHERE ul.success = 1 ORDER BY ul.tokens_used DESC LIMIT ?
        """, (limit,))
        rows = await cursor.fetchall()
        return [self._row_to_request_log(row) for row in rows]

    async def get_key_analytics(self, key_id: int) -> Optional[KeyAnalytics]:
        conn = await self._get_connection()
        cursor = await conn.execute("SELECT key_prefix, ip_address, discord_email FROM api_keys WHERE id = ?", (key_id,))
        key_row = await cursor.fetchone()
        if not key_row:
            return None
        
        cursor = await conn.execute("""
            SELECT COALESCE(SUM(input_tokens), 0) as total_input, COALESCE(SUM(output_tokens), 0) as total_output,
                   COALESCE(SUM(tokens_used), 0) as total_tokens, COUNT(*) as total_requests,
                   SUM(CASE WHEN success = 1 THEN 1 ELSE 0 END) as successful_requests
            FROM usage_logs WHERE api_key_id = ?
        """, (key_id,))
        stats_row = await cursor.fetchone()
        
        cursor = await conn.execute("""
            SELECT model, COUNT(*) as usage_count FROM usage_logs
            WHERE api_key_id = ? AND model IS NOT NULL AND model != 'models'
            GROUP BY model ORDER BY usage_count DESC LIMIT 1
        """, (key_id,))
        model_row = await cursor.fetchone()
        
        cursor = await conn.execute("""
            SELECT ul.id, ul.api_key_id, ak.key_prefix, ul.ip_address, ul.model,
                   ul.input_tokens, ul.output_tokens, ul.tokens_used, ul.success,
                   ul.error_message, ul.request_time
            FROM usage_logs ul LEFT JOIN api_keys ak ON ul.api_key_id = ak.id
            WHERE ul.api_key_id = ? ORDER BY ul.request_time DESC LIMIT 5
        """, (key_id,))
        recent_rows = await cursor.fetchall()
        
        return KeyAnalytics(
            key_id=key_id, key_prefix=key_row["key_prefix"], ip_address=key_row["ip_address"],
            discord_email=key_row["discord_email"] if "discord_email" in key_row.keys() else None,
            total_input_tokens=stats_row["total_input"] or 0, total_output_tokens=stats_row["total_output"] or 0,
            total_tokens=stats_row["total_tokens"] or 0, total_requests=stats_row["total_requests"] or 0,
            successful_requests=stats_row["successful_requests"] or 0,
            most_used_model=model_row["model"] if model_row else None,
            model_usage_count=model_row["usage_count"] if model_row else 0,
            recent_requests=[self._row_to_request_log(row) for row in recent_rows],
        )

    async def ban_ip(self, ip_address: str, reason: Optional[str] = None) -> None:
        conn = await self._get_connection()
        await conn.execute("INSERT OR REPLACE INTO banned_ips (ip_address, reason, banned_at) VALUES (?, ?, CURRENT_TIMESTAMP)", (ip_address, reason))
        await conn.commit()

    async def unban_ip(self, ip_address: str) -> bool:
        conn = await self._get_connection()
        cursor = await conn.execute("DELETE FROM banned_ips WHERE ip_address = ?", (ip_address,))
        await conn.commit()
        return cursor.rowcount > 0

    async def is_ip_banned(self, ip_address: str) -> bool:
        conn = await self._get_connection()
        cursor = await conn.execute("SELECT 1 FROM banned_ips WHERE ip_address = ?", (ip_address,))
        return await cursor.fetchone() is not None

    async def get_all_banned_ips(self) -> List[BannedIpRecord]:
        conn = await self._get_connection()
        cursor = await conn.execute("SELECT * FROM banned_ips ORDER BY banned_at DESC")
        rows = await cursor.fetchall()
        return [BannedIpRecord(id=r["id"], ip_address=r["ip_address"], reason=r["reason"], banned_at=self._parse_ts(r["banned_at"])) for r in rows]

    async def get_all_banned_users(self) -> List[BannedUserRecord]:
        conn = await self._get_connection()
        cursor = await conn.execute("SELECT * FROM banned_users ORDER BY banned_at DESC")
        rows = await cursor.fetchall()
        return [BannedUserRecord(id=r["id"], discord_id=r["discord_id"], reason=r["reason"], banned_at=self._parse_ts(r["banned_at"])) for r in rows]

    async def ban_user(self, discord_id: str, reason: Optional[str] = None) -> None:
        if not discord_id or discord_id.startswith("manual_") or discord_id == "unknown":
             return # Don't ban anonymous or placeholder IDs this way
        conn = await self._get_connection()
        await conn.execute("INSERT OR REPLACE INTO banned_users (discord_id, reason, banned_at) VALUES (?, ?, CURRENT_TIMESTAMP)", (discord_id, reason))
        await conn.commit()

    async def unban_user(self, discord_id: str) -> bool:
        conn = await self._get_connection()
        cursor = await conn.execute("DELETE FROM banned_users WHERE discord_id = ?", (discord_id,))
        await conn.commit()
        return cursor.rowcount > 0

    async def is_user_banned(self, discord_id: str) -> bool:
        if not discord_id:
            return False
        conn = await self._get_connection()
        cursor = await conn.execute("SELECT 1 FROM banned_users WHERE discord_id = ?", (discord_id,))
        return await cursor.fetchone() is not None

    async def disable_all_keys_for_user(self, discord_id: str) -> int:
        if not discord_id:
            return 0
        conn = await self._get_connection()
        cursor = await conn.execute("UPDATE api_keys SET enabled = 0 WHERE discord_id = ?", (discord_id,))
        await conn.commit()
        return cursor.rowcount

    async def get_keys_by_ip(self, ip_address: str) -> List[ApiKeyRecord]:
        conn = await self._get_connection()
        cursor = await conn.execute("SELECT * FROM api_keys WHERE ip_address = ?", (ip_address,))
        rows = await cursor.fetchall()
        return [self._row_to_api_key(row) for row in rows]

    async def get_config(self) -> Optional[ProxyConfig]:
        conn = await self._get_connection()
        cursor = await conn.execute("SELECT * FROM proxy_config WHERE id = 1")
        row = await cursor.fetchone()
        if not row:
            return None
        max_out = row["max_output_tokens"] if "max_output_tokens" in row.keys() else 4096
        fallback = row["fallback_api_keys"] if "fallback_api_keys" in row.keys() else ""
        index = row["current_key_index"] if "current_key_index" in row.keys() else 0
        return ProxyConfig(
            target_api_url=row["target_api_url"], 
            target_api_key=row["target_api_key"], 
            max_context=row["max_context"], 
            max_output_tokens=max_out,
            fallback_api_keys=fallback,
            current_key_index=index
        )

    async def update_config(self, target_url: str, target_key: str, max_context: int, max_output_tokens: int = 4096, fallback_api_keys: str = "") -> None:
        conn = await self._get_connection()
        await conn.execute("""
            INSERT OR REPLACE INTO proxy_config (id, target_api_url, target_api_key, max_context, max_output_tokens, fallback_api_keys, current_key_index, updated_at) 
            VALUES (1, ?, ?, ?, ?, ?, 0, CURRENT_TIMESTAMP)
        """, (target_url, target_key, max_context, max_output_tokens, fallback_api_keys))
        await conn.commit()

    async def rotate_target_key(self) -> bool:
        """Rotate to the next API key in the fallback list."""
        conn = await self._get_connection()
        config = await self.get_config()
        if not config:
            return False
            
        fallback_keys = [k.strip() for k in config.fallback_api_keys.split('\n') if k.strip()]
        # The split could be by newline or comma. Let's support both.
        if not fallback_keys and ',' in config.fallback_api_keys:
             fallback_keys = [k.strip() for k in config.fallback_api_keys.split(',') if k.strip()]
             
        total_keys = 1 + len(fallback_keys)
        
        if config.current_key_index + 1 >= total_keys:
            # We already used all keys
            return False
            
        await conn.execute(
            "UPDATE proxy_config SET current_key_index = current_key_index + 1, updated_at = CURRENT_TIMESTAMP WHERE id = 1"
        )
        await conn.commit()
        return True

    async def get_excluded_models(self) -> List[str]:
        conn = await self._get_connection()
        cursor = await conn.execute("SELECT model_id FROM models_exclusion")
        rows = await cursor.fetchall()
        return [row["model_id"] for row in rows]

    async def exclude_model(self, model_id: str) -> None:
        conn = await self._get_connection()
        await conn.execute("INSERT OR IGNORE INTO models_exclusion (model_id) VALUES (?)", (model_id,))
        await conn.commit()

    async def include_model(self, model_id: str) -> bool:
        conn = await self._get_connection()
        cursor = await conn.execute("DELETE FROM models_exclusion WHERE model_id = ?", (model_id,))
        await conn.commit()
        return cursor.rowcount > 0

    async def clear_excluded_models(self) -> None:
        conn = await self._get_connection()
        await conn.execute("DELETE FROM models_exclusion")
        await conn.commit()

    async def get_model_aliases(self) -> dict:
        conn = await self._get_connection()
        cursor = await conn.execute("SELECT model_id, alias FROM model_aliases")
        rows = await cursor.fetchall()
        return {row[0]: row[1] for row in rows}

    async def set_model_alias(self, model_id: str, alias: str) -> None:
        conn = await self._get_connection()
        if not alias:
            await self.delete_model_alias(model_id)
        else:
            await conn.execute("""
                INSERT INTO model_aliases (model_id, alias) VALUES (?, ?)
                ON CONFLICT (model_id) DO UPDATE SET alias = excluded.alias
            """, (model_id, alias))
        await conn.commit()

    async def delete_model_alias(self, model_id: str) -> bool:
        conn = await self._get_connection()
        cursor = await conn.execute("DELETE FROM model_aliases WHERE model_id = ?", (model_id,))
        await conn.commit()
        return cursor.rowcount > 0

    def _row_to_api_key(self, row) -> ApiKeyRecord:
        return ApiKeyRecord(
            id=row["id"], key_hash=row["key_hash"], key_prefix=row["key_prefix"],
            full_key=row["full_key"] if "full_key" in row.keys() else None,
            discord_id=row["discord_id"] if "discord_id" in row.keys() else None,
            discord_email=row["discord_email"] if "discord_email" in row.keys() else None,
            ip_address=row["ip_address"],
            browser_fingerprint=row["browser_fingerprint"] if "browser_fingerprint" in row.keys() else None,

            current_rpm=row["current_rpm"], current_rpd=row["current_rpd"],
            last_rpm_reset=self._parse_ts(row["last_rpm_reset"]), last_rpd_reset=self._parse_ts(row["last_rpd_reset"]),
            enabled=bool(row["enabled"]),
            bypass_ip_ban=bool(row["bypass_ip_ban"]) if "bypass_ip_ban" in row.keys() else False,
            created_at=self._parse_ts(row["created_at"]),
            last_used_at=self._parse_ts(row["last_used_at"]) if row["last_used_at"] else None,
        )

    def _row_to_request_log(self, row) -> RequestLogRecord:
        return RequestLogRecord(
            id=row["id"], api_key_id=row["api_key_id"], key_prefix=row["key_prefix"] or "unknown",
            ip_address=row["ip_address"] or "unknown", model=row["model"] or "unknown",
            input_tokens=row["input_tokens"] or 0, output_tokens=row["output_tokens"] or 0,
            total_tokens=row["tokens_used"] or 0, success=bool(row["success"]),
            error_message=row["error_message"], request_time=self._parse_ts(row["request_time"]),
        )

    @staticmethod
    def _parse_ts(value) -> datetime:
        if isinstance(value, datetime):
            return value
        try:
            return datetime.fromisoformat(value)
        except (ValueError, TypeError):
            return datetime.strptime(value, "%Y-%m-%d %H:%M:%S")

    # Content flag operations
    async def create_content_flag(
        self,
        api_key_id: int,
        flag_type: str,
        severity: str,
        message_preview: str,
        full_message_hash: str,
        model: str,
        ip_address: str,
    ) -> int:
        conn = await self._get_connection()
        cursor = await conn.execute(
            """INSERT INTO content_flags
               (api_key_id, flag_type, severity, message_preview, full_message_hash, model, ip_address)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (api_key_id, flag_type, severity, message_preview, full_message_hash, model, ip_address)
        )
        await conn.commit()
        return cursor.lastrowid

    async def get_all_flags(self, include_reviewed: bool = False) -> List[ContentFlagRecord]:
        conn = await self._get_connection()
        if include_reviewed:
            query = """
                SELECT cf.*, ak.key_prefix, ak.discord_id, ak.discord_email
                FROM content_flags cf
                LEFT JOIN api_keys ak ON cf.api_key_id = ak.id
                ORDER BY cf.flagged_at DESC
            """
        else:
            query = """
                SELECT cf.*, ak.key_prefix, ak.discord_id, ak.discord_email
                FROM content_flags cf
                LEFT JOIN api_keys ak ON cf.api_key_id = ak.id
                WHERE cf.reviewed = 0
                ORDER BY cf.flagged_at DESC
            """
        cursor = await conn.execute(query)
        rows = await cursor.fetchall()
        return [self._row_to_content_flag(row) for row in rows]






    async def get_flag_by_id(self, flag_id: int) -> Optional[ContentFlagRecord]:
        conn = await self._get_connection()
        cursor = await conn.execute("""
            SELECT cf.*, ak.key_prefix, ak.discord_id, ak.discord_email
            FROM content_flags cf
            LEFT JOIN api_keys ak ON cf.api_key_id = ak.id
            WHERE cf.id = ?
        """, (flag_id,))
        row = await cursor.fetchone()
        return self._row_to_content_flag(row) if row else None

    async def mark_flag_reviewed(self, flag_id: int, action_taken: str) -> bool:
        conn = await self._get_connection()
        cursor = await conn.execute(
            "UPDATE content_flags SET reviewed = 1, action_taken = ?, reviewed_at = CURRENT_TIMESTAMP WHERE id = ?",
            (action_taken, flag_id)
        )
        await conn.commit()
        return cursor.rowcount > 0

    async def get_flags_by_key(self, api_key_id: int) -> List[ContentFlagRecord]:
        conn = await self._get_connection()
        cursor = await conn.execute("""
            SELECT cf.*, ak.key_prefix, ak.discord_id, ak.discord_email
            FROM content_flags cf
            LEFT JOIN api_keys ak ON cf.api_key_id = ak.id
            WHERE cf.api_key_id = ?
            ORDER BY cf.flagged_at DESC
        """, (api_key_id,))
        rows = await cursor.fetchall()
        return [self._row_to_content_flag(row) for row in rows]

    async def count_unreviewed_flags(self) -> int:
        conn = await self._get_connection()
        cursor = await conn.execute("SELECT COUNT(*) FROM content_flags WHERE reviewed = 0")
        row = await cursor.fetchone()
        return row[0] if row else 0

    def _row_to_content_flag(self, row) -> ContentFlagRecord:
        return ContentFlagRecord(
            id=row["id"],
            api_key_id=row["api_key_id"],
            key_prefix=row["key_prefix"] or "unknown",
            discord_id=row["discord_id"] if "discord_id" in row.keys() else None,
            discord_email=row["discord_email"] if "discord_email" in row.keys() else None,
            ip_address=row["ip_address"] or "unknown",
            flag_type=row["flag_type"],
            severity=row["severity"],
            message_preview=row["message_preview"],
            full_message_hash=row["full_message_hash"],
            model=row["model"] or "unknown",
            reviewed=bool(row["reviewed"]),
            action_taken=row["action_taken"],
            flagged_at=self._parse_ts(row["flagged_at"]),
            reviewed_at=self._parse_ts(row["reviewed_at"]) if row["reviewed_at"] else None,
        )


class PostgreSQLDatabase(Database):
    """PostgreSQL database implementation for production."""

    def __init__(self, database_url: str):
        self.database_url = database_url
        self._pool = None

    async def _get_pool(self):
        if self._pool is None:
            self._pool = await asyncpg.create_pool(self.database_url, min_size=10, max_size=50)
        return self._pool

    async def close(self) -> None:
        if self._pool is not None:
            await self._pool.close()
            self._pool = None

    async def initialize(self) -> None:
        pool = await self._get_pool()
        async with pool.acquire() as conn:
            await conn.execute("""
                CREATE TABLE IF NOT EXISTS api_keys (
                    id SERIAL PRIMARY KEY,
                    key_hash TEXT UNIQUE NOT NULL,
                    key_prefix TEXT NOT NULL,
                    full_key TEXT,
                    discord_id TEXT UNIQUE,
                    discord_email TEXT,
                    ip_address TEXT NOT NULL DEFAULT 'unknown',
                    browser_fingerprint TEXT,
                    current_rpm INTEGER DEFAULT 0,
                    current_rpd INTEGER DEFAULT 0,
                    last_rpm_reset TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    last_rpd_reset TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    enabled BOOLEAN DEFAULT TRUE,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    last_used_at TIMESTAMP
                )
            """)
            # Migrations - add new columns if they don't exist
            # Check which columns exist
            existing_cols = await conn.fetch("""
                SELECT column_name FROM information_schema.columns 
                WHERE table_name = 'api_keys'
            """)
            existing_col_names = {row['column_name'] for row in existing_cols}
            
            # Add missing columns
            if 'full_key' not in existing_col_names:
                await conn.execute("ALTER TABLE api_keys ADD COLUMN full_key TEXT")
            if 'discord_id' not in existing_col_names:
                await conn.execute("ALTER TABLE api_keys ADD COLUMN discord_id TEXT")
            if 'discord_email' not in existing_col_names:
                await conn.execute("ALTER TABLE api_keys ADD COLUMN discord_email TEXT")
            if 'bypass_ip_ban' not in existing_col_names:
                await conn.execute("ALTER TABLE api_keys ADD COLUMN bypass_ip_ban BOOLEAN DEFAULT FALSE")

            
            # Create indexes (safe to run multiple times)
            await conn.execute("CREATE INDEX IF NOT EXISTS idx_api_keys_ip ON api_keys(ip_address)")
            await conn.execute("CREATE INDEX IF NOT EXISTS idx_api_keys_fingerprint ON api_keys(browser_fingerprint)")
            
            # Create discord_id index only if column exists now
            try:
                await conn.execute("CREATE INDEX IF NOT EXISTS idx_api_keys_discord_id ON api_keys(discord_id)")
            except Exception:
                pass  # Index might already exist or column issue
            
            await conn.execute("""
                CREATE TABLE IF NOT EXISTS usage_logs (
                    id SERIAL PRIMARY KEY,
                    api_key_id INTEGER NOT NULL REFERENCES api_keys(id) ON DELETE CASCADE,
                    ip_address TEXT,
                    model TEXT,
                    input_tokens INTEGER DEFAULT 0,
                    output_tokens INTEGER DEFAULT 0,
                    tokens_used INTEGER DEFAULT 0,
                    success BOOLEAN DEFAULT TRUE,
                    error_message TEXT,
                    request_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            await conn.execute("""
                CREATE TABLE IF NOT EXISTS banned_ips (
                    id SERIAL PRIMARY KEY,
                    ip_address TEXT UNIQUE NOT NULL,
                    reason TEXT,
                    banned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)

            await conn.execute("""
                CREATE TABLE IF NOT EXISTS banned_users (
                    id SERIAL PRIMARY KEY,
                    discord_id TEXT UNIQUE NOT NULL,
                    reason TEXT,
                    banned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            await conn.execute("CREATE INDEX IF NOT EXISTS idx_banned_users_discord ON banned_users(discord_id)")
            
            await conn.execute("""
                CREATE TABLE IF NOT EXISTS proxy_config (
                    id INTEGER PRIMARY KEY CHECK (id = 1),
                    target_api_url TEXT NOT NULL,
                    target_api_key TEXT NOT NULL,
                    max_context INTEGER DEFAULT 128000,
                    max_output_tokens INTEGER DEFAULT 4096,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            # Migration: add max_output_tokens if missing
            config_cols = await conn.fetch("""
                SELECT column_name FROM information_schema.columns WHERE table_name = 'proxy_config'
            """)
            config_col_names = {r["column_name"] for r in config_cols}
            if "max_output_tokens" not in config_col_names:
                await conn.execute("ALTER TABLE proxy_config ADD COLUMN max_output_tokens INTEGER DEFAULT 4096")
            if "max_context" not in config_col_names:
                await conn.execute("ALTER TABLE proxy_config ADD COLUMN max_context INTEGER DEFAULT 128000")
            if "fallback_api_keys" not in config_col_names:
                await conn.execute("ALTER TABLE proxy_config ADD COLUMN fallback_api_keys TEXT DEFAULT ''")
            if "current_key_index" not in config_col_names:
                await conn.execute("ALTER TABLE proxy_config ADD COLUMN current_key_index INTEGER DEFAULT 0")
            
            await conn.execute(
                "CREATE TABLE IF NOT EXISTS app_settings (key TEXT PRIMARY KEY, value TEXT)"
            )
            
            # Content moderation flags table
            await conn.execute("""
                CREATE TABLE IF NOT EXISTS content_flags (
                    id SERIAL PRIMARY KEY,
                    api_key_id INTEGER NOT NULL REFERENCES api_keys(id) ON DELETE CASCADE,
                    flag_type TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    message_preview TEXT NOT NULL,
                    full_message_hash TEXT NOT NULL,
                    model TEXT,
                    ip_address TEXT,
                    reviewed BOOLEAN DEFAULT FALSE,
                    action_taken TEXT,
                    flagged_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    reviewed_at TIMESTAMP
                )
            """)
            
            # Model management tables
            await conn.execute("""
                CREATE TABLE IF NOT EXISTS models_exclusion (
                    model_id TEXT PRIMARY KEY
                )
            """)
            
            await conn.execute("""
                CREATE TABLE IF NOT EXISTS model_aliases (
                    model_id TEXT PRIMARY KEY,
                    alias TEXT NOT NULL
                )
            """)

            await conn.execute("CREATE INDEX IF NOT EXISTS idx_content_flags_key ON content_flags(api_key_id)")
            await conn.execute("CREATE INDEX IF NOT EXISTS idx_content_flags_reviewed ON content_flags(reviewed)")
            await conn.execute("CREATE INDEX IF NOT EXISTS idx_content_flags_hash ON content_flags(full_message_hash)")
            
            # Model management table
            await conn.execute("""
                CREATE TABLE IF NOT EXISTS models_exclusion (
                    model_id TEXT PRIMARY KEY
                )
            """)
            




    async def create_api_key(self, discord_id: str, discord_email: Optional[str], key_hash: str, key_prefix: str, full_key: str, ip_address: str = "unknown", enabled: bool = True, browser_fingerprint: Optional[str] = None) -> int:
        pool = await self._get_pool()
        async with pool.acquire() as conn:
            row = await conn.fetchrow(
                "INSERT INTO api_keys (discord_id, discord_email, ip_address, key_hash, key_prefix, full_key, enabled, browser_fingerprint) VALUES ($1, $2, $3, $4, $5, $6, $7, $8) RETURNING id",
                discord_id, discord_email, ip_address, key_hash, key_prefix, full_key, enabled, browser_fingerprint
            )
            return row["id"]

    async def get_key_by_discord_id(self, discord_id: str) -> Optional[ApiKeyRecord]:
        pool = await self._get_pool()
        async with pool.acquire() as conn:
            row = await conn.fetchrow("SELECT * FROM api_keys WHERE discord_id = $1 ORDER BY enabled DESC, created_at DESC LIMIT 1", discord_id)
            return self._row_to_api_key(row) if row else None

    async def get_key_by_ip(self, ip_address: str) -> Optional[ApiKeyRecord]:
        pool = await self._get_pool()
        async with pool.acquire() as conn:
            # Prioritize enabled keys, then keys without fingerprints (easier to claim/fallback),
            # then most recently used/created.
            query = """
                SELECT * FROM api_keys 
                WHERE ip_address = $1 
                ORDER BY enabled DESC, (browser_fingerprint IS NULL) DESC, last_used_at DESC, created_at DESC 
                LIMIT 1
            """
            row = await conn.fetchrow(query, ip_address)
            return self._row_to_api_key(row) if row else None

    async def get_key_by_fingerprint(self, fingerprint: str) -> Optional[ApiKeyRecord]:
        pool = await self._get_pool()
        async with pool.acquire() as conn:
            row = await conn.fetchrow("SELECT * FROM api_keys WHERE browser_fingerprint = $1 ORDER BY enabled DESC, created_at DESC LIMIT 1", fingerprint)
            return self._row_to_api_key(row) if row else None

    async def get_key_by_hash(self, key_hash: str) -> Optional[ApiKeyRecord]:
        pool = await self._get_pool()
        async with pool.acquire() as conn:
            row = await conn.fetchrow("SELECT * FROM api_keys WHERE key_hash = $1", key_hash)
            return self._row_to_api_key(row) if row else None

    async def get_all_keys(self) -> List[ApiKeyRecord]:
        pool = await self._get_pool()
        async with pool.acquire() as conn:
            rows = await conn.fetch("SELECT * FROM api_keys ORDER BY created_at DESC")
            return [self._row_to_api_key(row) for row in rows]

    async def count_keys_by_ip(self, ip_address: str) -> int:
        pool = await self._get_pool()
        async with pool.acquire() as conn:
            row = await conn.fetchrow("SELECT COUNT(*) FROM api_keys WHERE ip_address = $1 AND enabled = TRUE", ip_address)
            return row[0] if row else 0

    async def count_discord_keys_by_ip(self, ip_address: str) -> int:
        pool = await self._get_pool()
        async with pool.acquire() as conn:
            row = await conn.fetchrow(
                "SELECT COUNT(*) FROM api_keys WHERE ip_address = $1 AND discord_id IS NOT NULL AND discord_id NOT LIKE 'ip_%' AND enabled = TRUE",
                ip_address
            )
            return row[0] if row else 0

    async def delete_disabled_keys_by_ip(self, ip_address: str) -> int:
        pool = await self._get_pool()
        async with pool.acquire() as conn:
            result = await conn.execute("DELETE FROM api_keys WHERE ip_address = $1 AND enabled = FALSE", ip_address)
            # result is like 'DELETE 1'
            try:
                return int(result.split()[-1])
            except (ValueError, IndexError):
                return 0

    async def delete_keys_by_prefix_for_fingerprint(self, prefix: str, fingerprint: str) -> int:
        pool = await self._get_pool()
        async with pool.acquire() as conn:
            result = await conn.execute("DELETE FROM api_keys WHERE browser_fingerprint = $1 AND key_prefix = $2", fingerprint, prefix)
            try:
                return int(result.split()[-1])
            except (ValueError, IndexError):
                return 0

    async def get_keys_by_ip(self, ip_address: str) -> List[ApiKeyRecord]:
        pool = await self._get_pool()
        async with pool.acquire() as conn:
            rows = await conn.fetch("SELECT * FROM api_keys WHERE ip_address = $1", ip_address)
            return [self._row_to_api_key(row) for row in rows]

    async def delete_disabled_keys_by_fingerprint(self, fingerprint: str) -> int:
        pool = await self._get_pool()
        async with pool.acquire() as conn:
            result = await conn.execute("DELETE FROM api_keys WHERE browser_fingerprint = $1 AND enabled = FALSE", fingerprint)
            return int(result.split()[-1]) if result else 0

    async def delete_all_keys(self) -> int:
        pool = await self._get_pool()
        async with pool.acquire() as conn:
            # Delete usage logs first (foreign key), then keys
            await conn.execute("DELETE FROM usage_logs")
            result = await conn.execute("DELETE FROM api_keys")
            return int(result.split()[-1]) if result else 0

    async def delete_key(self, key_id: int) -> bool:
        pool = await self._get_pool()
        async with pool.acquire() as conn:
            result = await conn.execute("DELETE FROM api_keys WHERE id = $1", key_id)
            return result == "DELETE 1"

    async def toggle_key(self, key_id: int) -> bool:
        pool = await self._get_pool()
        async with pool.acquire() as conn:
            result = await conn.execute("UPDATE api_keys SET enabled = NOT enabled WHERE id = $1", key_id)
            return result == "UPDATE 1"

    async def set_key_enabled(self, key_id: int, enabled: bool) -> bool:
        pool = await self._get_pool()
        async with pool.acquire() as conn:
            result = await conn.execute("UPDATE api_keys SET enabled = $1 WHERE id = $2", enabled, key_id)
            return result == "UPDATE 1"

    async def update_key_ip(self, key_id: int, new_ip: str) -> None:
        pool = await self._get_pool()
        async with pool.acquire() as conn:
            await conn.execute("UPDATE api_keys SET ip_address = $1 WHERE id = $2", new_ip, key_id)

    async def update_key_fingerprint(self, key_id: int, fingerprint: str) -> None:
        pool = await self._get_pool()
        async with pool.acquire() as conn:
            await conn.execute("UPDATE api_keys SET browser_fingerprint = $1 WHERE id = $2", fingerprint, key_id)

    async def set_key_bypass_ip_ban(self, key_id: int, bypass: bool) -> bool:
        pool = await self._get_pool()
        async with pool.acquire() as conn:
            result = await conn.execute("UPDATE api_keys SET bypass_ip_ban = $1 WHERE id = $2", bypass, key_id)
            return result == "UPDATE 1"

    async def update_usage(self, key_id: int, rpm: int, rpd: int) -> None:
        pool = await self._get_pool()
        async with pool.acquire() as conn:
            await conn.execute("UPDATE api_keys SET current_rpm = $1, current_rpd = $2, last_used_at = CURRENT_TIMESTAMP WHERE id = $3", rpm, rpd, key_id)

    async def increment_usage(self, key_id: int) -> tuple[int, int]:
        pool = await self._get_pool()
        async with pool.acquire() as conn:
            row = await conn.fetchrow(
                "UPDATE api_keys SET current_rpm = current_rpm + 1, current_rpd = current_rpd + 1, last_used_at = CURRENT_TIMESTAMP WHERE id = $1 RETURNING current_rpm, current_rpd",
                key_id
            )
            return (row["current_rpm"], row["current_rpd"]) if row else (0, 0)

    async def increment_rpm_only(self, key_id: int) -> int:
        pool = await self._get_pool()
        async with pool.acquire() as conn:
            row = await conn.fetchrow(
                "UPDATE api_keys SET current_rpm = current_rpm + 1, last_used_at = CURRENT_TIMESTAMP WHERE id = $1 RETURNING current_rpm",
                key_id
            )
            return row["current_rpm"] if row else 0

    async def increment_rpd_only(self, key_id: int) -> int:
        pool = await self._get_pool()
        async with pool.acquire() as conn:
            row = await conn.fetchrow(
                "UPDATE api_keys SET current_rpd = current_rpd + 1, last_used_at = CURRENT_TIMESTAMP WHERE id = $1 RETURNING current_rpd",
                key_id
            )
            return row["current_rpd"] if row else 0

    async def reset_rpm(self, key_id: int) -> None:
        pool = await self._get_pool()
        async with pool.acquire() as conn:
            await conn.execute("UPDATE api_keys SET current_rpm = 0, last_rpm_reset = CURRENT_TIMESTAMP WHERE id = $1", key_id)

    async def reset_rpd(self, key_id: int) -> None:
        pool = await self._get_pool()
        async with pool.acquire() as conn:
            await conn.execute("UPDATE api_keys SET current_rpd = 0, last_rpd_reset = CURRENT_TIMESTAMP WHERE id = $1", key_id)

    async def reset_all_rpd(self) -> int:
        pool = await self._get_pool()
        async with pool.acquire() as conn:
            result = await conn.execute("UPDATE api_keys SET current_rpd = 0, last_rpd_reset = CURRENT_TIMESTAMP")
            return int(result.split()[-1]) if result else 0

    async def reset_all_rpm(self) -> int:
        pool = await self._get_pool()
        async with pool.acquire() as conn:
            result = await conn.execute("UPDATE api_keys SET current_rpm = 0, last_rpm_reset = CURRENT_TIMESTAMP")
            return int(result.split()[-1]) if result else 0

    async def log_usage(self, key_id: int, model: str, tokens: int, success: bool,
                       ip_address: Optional[str] = None, input_tokens: int = 0,
                       output_tokens: int = 0, error_message: Optional[str] = None) -> None:
        # Skip logging for synthetic/whitelisted keys (-1) to avoid foreign key violations
        if key_id < 0:
            return
            
        pool = await self._get_pool()
        async with pool.acquire() as conn:
            await conn.execute(
                "INSERT INTO usage_logs (api_key_id, ip_address, model, input_tokens, output_tokens, tokens_used, success, error_message) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
                key_id, ip_address, model, input_tokens, output_tokens, tokens, success, error_message
            )

    async def get_daily_tokens_used(self, key_id: int, since_utc: str, until_utc: str) -> int:
        # asyncpg expects datetime; PostgreSQL request_time is TIMESTAMP (naive), so pass naive UTC
        since_dt = since_utc if isinstance(since_utc, datetime) else datetime.fromisoformat(since_utc.replace("Z", "+00:00"))
        until_dt = until_utc if isinstance(until_utc, datetime) else datetime.fromisoformat(until_utc.replace("Z", "+00:00"))
        def _naive_utc(dt):
            if dt.tzinfo is not None:
                return dt.astimezone(timezone.utc).replace(tzinfo=None)
            return dt
        since_dt = _naive_utc(since_dt)
        until_dt = _naive_utc(until_dt)
        pool = await self._get_pool()
        async with pool.acquire() as conn:
            row = await conn.fetchrow("""
                SELECT COALESCE(SUM(tokens_used), 0) AS tokens_sum FROM usage_logs
                WHERE api_key_id = $1 AND request_time >= $2 AND request_time < $3
            """, key_id, since_dt, until_dt)
            return int(row["tokens_sum"]) if row and row["tokens_sum"] is not None else 0

    async def get_daily_tokens_used_all(self, since_utc: str, until_utc: str) -> dict[int, int]:
        since_dt = since_utc if isinstance(since_utc, datetime) else datetime.fromisoformat(since_utc.replace("Z", "+00:00"))
        until_dt = until_utc if isinstance(until_utc, datetime) else datetime.fromisoformat(until_utc.replace("Z", "+00:00"))
        def _naive_utc(dt):
            if dt.tzinfo is not None:
                return dt.astimezone(timezone.utc).replace(tzinfo=None)
            return dt
        since_dt = _naive_utc(since_dt)
        until_dt = _naive_utc(until_dt)
        pool = await self._get_pool()
        async with pool.acquire() as conn:
            rows = await conn.fetch("""
                SELECT api_key_id, COALESCE(SUM(tokens_used), 0) AS tokens_sum FROM usage_logs
                WHERE request_time >= $1 AND request_time < $2
                GROUP BY api_key_id
            """, since_dt, until_dt)
            return {row["api_key_id"]: int(row["tokens_sum"]) for row in rows}

    async def get_usage_stats(self, key_id: int) -> UsageStats:
        pool = await self._get_pool()
        async with pool.acquire() as conn:
            total_row = await conn.fetchrow("""
                SELECT COUNT(*) as total_requests, SUM(CASE WHEN success THEN 1 ELSE 0 END) as successful_requests,
                       COALESCE(SUM(tokens_used), 0) as total_tokens
                FROM usage_logs WHERE api_key_id = $1
            """, key_id)
            today_row = await conn.fetchrow("""
                SELECT COUNT(*) as requests_today, COALESCE(SUM(tokens_used), 0) as tokens_today
                FROM usage_logs WHERE api_key_id = $1 AND DATE(request_time) = CURRENT_DATE AND model != 'models'
            """, key_id)
            return UsageStats(
                total_requests=total_row["total_requests"] or 0, successful_requests=total_row["successful_requests"] or 0,
                total_tokens=total_row["total_tokens"] or 0, requests_today=today_row["requests_today"] or 0,
                tokens_today=today_row["tokens_today"] or 0,
            )

    async def get_recent_requests(self, limit: int = 10) -> List[RequestLogRecord]:
        pool = await self._get_pool()
        async with pool.acquire() as conn:
            rows = await conn.fetch("""
                SELECT ul.id, ul.api_key_id, ak.key_prefix, ul.ip_address, ul.model,
                       ul.input_tokens, ul.output_tokens, ul.tokens_used, ul.success,
                       ul.error_message, ul.request_time
                FROM usage_logs ul LEFT JOIN api_keys ak ON ul.api_key_id = ak.id
                ORDER BY ul.request_time DESC LIMIT $1
            """, limit)
            return [self._row_to_request_log(row) for row in rows]

    async def get_top_token_requests(self, limit: int = 3) -> List[RequestLogRecord]:
        pool = await self._get_pool()
        async with pool.acquire() as conn:
            rows = await conn.fetch("""
                SELECT ul.id, ul.api_key_id, ak.key_prefix, ul.ip_address, ul.model,
                       ul.input_tokens, ul.output_tokens, ul.tokens_used, ul.success,
                       ul.error_message, ul.request_time
                FROM usage_logs ul LEFT JOIN api_keys ak ON ul.api_key_id = ak.id
                WHERE ul.success = TRUE ORDER BY ul.tokens_used DESC LIMIT $1
            """, limit)
            return [self._row_to_request_log(row) for row in rows]

    async def get_key_analytics(self, key_id: int) -> Optional[KeyAnalytics]:
        pool = await self._get_pool()
        async with pool.acquire() as conn:
            key_row = await conn.fetchrow("SELECT key_prefix, ip_address, discord_email FROM api_keys WHERE id = $1", key_id)
            if not key_row:
                return None
            
            stats_row = await conn.fetchrow("""
                SELECT COALESCE(SUM(input_tokens), 0) as total_input, COALESCE(SUM(output_tokens), 0) as total_output,
                       COALESCE(SUM(tokens_used), 0) as total_tokens, COUNT(*) as total_requests,
                       SUM(CASE WHEN success THEN 1 ELSE 0 END) as successful_requests
                FROM usage_logs WHERE api_key_id = $1
            """, key_id)
            
            model_row = await conn.fetchrow("""
                SELECT model, COUNT(*) as usage_count FROM usage_logs
                WHERE api_key_id = $1 AND model IS NOT NULL AND model != 'models'
                GROUP BY model ORDER BY usage_count DESC LIMIT 1
            """, key_id)
            
            recent_rows = await conn.fetch("""
                SELECT ul.id, ul.api_key_id, ak.key_prefix, ul.ip_address, ul.model,
                       ul.input_tokens, ul.output_tokens, ul.tokens_used, ul.success,
                       ul.error_message, ul.request_time
                FROM usage_logs ul LEFT JOIN api_keys ak ON ul.api_key_id = ak.id
                WHERE ul.api_key_id = $1 ORDER BY ul.request_time DESC LIMIT 5
            """, key_id)
            
            return KeyAnalytics(
                key_id=key_id, key_prefix=key_row["key_prefix"], ip_address=key_row["ip_address"],
                discord_email=self._safe_get(key_row, "discord_email"),
                total_input_tokens=stats_row["total_input"] or 0, total_output_tokens=stats_row["total_output"] or 0,
                total_tokens=stats_row["total_tokens"] or 0, total_requests=stats_row["total_requests"] or 0,
                successful_requests=stats_row["successful_requests"] or 0,
                most_used_model=model_row["model"] if model_row else None,
                model_usage_count=model_row["usage_count"] if model_row else 0,
                recent_requests=[self._row_to_request_log(row) for row in recent_rows],
            )

    async def ban_ip(self, ip_address: str, reason: Optional[str] = None) -> None:
        pool = await self._get_pool()
        async with pool.acquire() as conn:
            await conn.execute("""
                INSERT INTO banned_ips (ip_address, reason, banned_at) VALUES ($1, $2, CURRENT_TIMESTAMP)
                ON CONFLICT (ip_address) DO UPDATE SET reason = $2, banned_at = CURRENT_TIMESTAMP
            """, ip_address, reason)

    async def include_model(self, model_id: str) -> bool:
        pool = await self._get_pool()
        async with pool.acquire() as conn:
            result = await conn.execute("DELETE FROM models_exclusion WHERE model_id = $1", model_id)
            return result == "DELETE 1"

    async def clear_excluded_models(self) -> None:
        pool = await self._get_pool()
        async with pool.acquire() as conn:
            await conn.execute("DELETE FROM models_exclusion")

    async def get_model_aliases(self) -> dict:
        pool = await self._get_pool()
        async with pool.acquire() as conn:
            rows = await conn.fetch("SELECT model_id, alias FROM model_aliases")
            return {row["model_id"]: row["alias"] for row in rows}

    async def set_model_alias(self, model_id: str, alias: str) -> None:
        pool = await self._get_pool()
        async with pool.acquire() as conn:
            if not alias:
                await self.delete_model_alias(model_id)
            else:
                await conn.execute("""
                    INSERT INTO model_aliases (model_id, alias) VALUES ($1, $2)
                    ON CONFLICT (model_id) DO UPDATE SET alias = EXCLUDED.alias
                """, model_id, alias)

    async def delete_model_alias(self, model_id: str) -> bool:
        pool = await self._get_pool()
        async with pool.acquire() as conn:
            result = await conn.execute("DELETE FROM model_aliases WHERE model_id = $1", model_id)
            return result == "DELETE 1"

    async def unban_ip(self, ip_address: str) -> bool:
        pool = await self._get_pool()
        async with pool.acquire() as conn:
            result = await conn.execute("DELETE FROM banned_ips WHERE ip_address = $1", ip_address)
            return result == "DELETE 1"

    async def is_ip_banned(self, ip_address: str) -> bool:
        pool = await self._get_pool()
        async with pool.acquire() as conn:
            row = await conn.fetchrow("SELECT 1 FROM banned_ips WHERE ip_address = $1", ip_address)
            return row is not None

    async def get_all_banned_ips(self) -> List[BannedIpRecord]:
        pool = await self._get_pool()
        async with pool.acquire() as conn:
            rows = await conn.fetch("SELECT * FROM banned_ips ORDER BY banned_at DESC")
            return [BannedIpRecord(id=r["id"], ip_address=r["ip_address"], reason=r["reason"], banned_at=r["banned_at"]) for r in rows]

    async def get_all_banned_users(self) -> List[BannedUserRecord]:
        pool = await self._get_pool()
        async with pool.acquire() as conn:
            rows = await conn.fetch("SELECT * FROM banned_users ORDER BY banned_at DESC")
            return [BannedUserRecord(id=r["id"], discord_id=r["discord_id"], reason=r["reason"], banned_at=r["banned_at"]) for r in rows]

    async def ban_user(self, discord_id: str, reason: Optional[str] = None) -> None:
        if not discord_id or discord_id.startswith("manual_") or discord_id == "unknown":
             return
        pool = await self._get_pool()
        async with pool.acquire() as conn:
            await conn.execute("""
                INSERT INTO banned_users (discord_id, reason, banned_at) VALUES ($1, $2, CURRENT_TIMESTAMP)
                ON CONFLICT (discord_id) DO UPDATE SET reason = $2, banned_at = CURRENT_TIMESTAMP
            """, discord_id, reason)

    async def unban_user(self, discord_id: str) -> bool:
        pool = await self._get_pool()
        async with pool.acquire() as conn:
            result = await conn.execute("DELETE FROM banned_users WHERE discord_id = $1", discord_id)
            return result == "DELETE 1"

    async def is_user_banned(self, discord_id: str) -> bool:
        if not discord_id:
            return False
        pool = await self._get_pool()
        async with pool.acquire() as conn:
            row = await conn.fetchrow("SELECT 1 FROM banned_users WHERE discord_id = $1", discord_id)
            return row is not None

    async def disable_all_keys_for_user(self, discord_id: str) -> int:
        if not discord_id:
            return 0
        pool = await self._get_pool()
        async with pool.acquire() as conn:
            result = await conn.execute("UPDATE api_keys SET enabled = FALSE WHERE discord_id = $1", discord_id)
            try:
                return int(result.split()[-1])
            except (ValueError, IndexError):
                return 0

    async def get_keys_by_ip(self, ip_address: str) -> List[ApiKeyRecord]:
        pool = await self._get_pool()
        async with pool.acquire() as conn:
            rows = await conn.fetch("SELECT * FROM api_keys WHERE ip_address = $1", ip_address)
            return [self._row_to_api_key(row) for row in rows]

    async def get_config(self) -> Optional[ProxyConfig]:
        pool = await self._get_pool()
        async with pool.acquire() as conn:
            row = await conn.fetchrow("SELECT * FROM proxy_config WHERE id = 1")
            if not row:
                return None
            return ProxyConfig(
                target_api_url=self._safe_get(row, "target_api_url", ""),
                target_api_key=self._safe_get(row, "target_api_key", ""),
                max_context=self._safe_get(row, "max_context", 128000),
                max_output_tokens=self._safe_get(row, "max_output_tokens", 4096),
                fallback_api_keys=self._safe_get(row, "fallback_api_keys", ""),
                current_key_index=self._safe_get(row, "current_key_index", 0),
            )

    async def update_config(self, target_url: str, target_key: str, max_context: int, max_output_tokens: int = 4096, fallback_api_keys: str = "") -> None:
        pool = await self._get_pool()
        async with pool.acquire() as conn:
            await conn.execute("""
                INSERT INTO proxy_config (id, target_api_url, target_api_key, max_context, max_output_tokens, fallback_api_keys, current_key_index, updated_at) 
                VALUES (1, $1, $2, $3, $4, $5, 0, CURRENT_TIMESTAMP)
                ON CONFLICT (id) DO UPDATE SET 
                    target_api_url = $1, 
                    target_api_key = $2, 
                    max_context = $3, 
                    max_output_tokens = $4,
                    fallback_api_keys = $5,
                    current_key_index = 0,
                    updated_at = CURRENT_TIMESTAMP
            """, target_url, target_key, max_context, max_output_tokens, fallback_api_keys)

    async def rotate_target_key(self) -> bool:
        """Rotate to the next API key in the fallback list."""
        pool = await self._get_pool()
        async with pool.acquire() as conn:
            config = await self.get_config()
            if not config:
                return False
                
            fallback_keys = [k.strip() for k in config.fallback_api_keys.split('\n') if k.strip()]
            if not fallback_keys and ',' in config.fallback_api_keys:
                 fallback_keys = [k.strip() for k in config.fallback_api_keys.split(',') if k.strip()]
                 
            total_keys = 1 + len(fallback_keys)
            
            if config.current_key_index + 1 >= total_keys:
                return False
                
            await conn.execute(
                "UPDATE proxy_config SET current_key_index = current_key_index + 1, updated_at = CURRENT_TIMESTAMP WHERE id = 1"
            )
            return True

    async def get_excluded_models(self) -> List[str]:
        pool = await self._get_pool()
        async with pool.acquire() as conn:
            rows = await conn.fetch("SELECT model_id FROM models_exclusion")
            return [row["model_id"] for row in rows]

    async def exclude_model(self, model_id: str) -> None:
        pool = await self._get_pool()
        async with pool.acquire() as conn:
            await conn.execute("INSERT INTO models_exclusion (model_id) VALUES ($1) ON CONFLICT (model_id) DO NOTHING", model_id)

    async def include_model(self, model_id: str) -> bool:
        pool = await self._get_pool()
        async with pool.acquire() as conn:
            result = await conn.execute("DELETE FROM models_exclusion WHERE model_id = $1", model_id)
            return result == "DELETE 1"

    async def clear_excluded_models(self) -> None:
        pool = await self._get_pool()
        async with pool.acquire() as conn:
            await conn.execute("DELETE FROM models_exclusion")

    @staticmethod
    def _safe_get(row, key, default=None):
        """Safely get a value from an asyncpg Record (which lacks .get())."""
        try:
            return row[key]
        except (KeyError, Exception):
            return default

    def _row_to_api_key(self, row) -> ApiKeyRecord:
        return ApiKeyRecord(
            id=row["id"], key_hash=row["key_hash"], key_prefix=row["key_prefix"],
            full_key=self._safe_get(row, "full_key"),
            discord_id=self._safe_get(row, "discord_id"),
            discord_email=self._safe_get(row, "discord_email"),
            ip_address=row["ip_address"],
            browser_fingerprint=self._safe_get(row, "browser_fingerprint"),

            current_rpm=row["current_rpm"], current_rpd=row["current_rpd"],
            last_rpm_reset=row["last_rpm_reset"], last_rpd_reset=row["last_rpd_reset"],
            enabled=row["enabled"],
            bypass_ip_ban=self._safe_get(row, "bypass_ip_ban", False),
            created_at=row["created_at"],
            last_used_at=row["last_used_at"],
        )

    def _row_to_request_log(self, row) -> RequestLogRecord:
        return RequestLogRecord(
            id=row["id"], api_key_id=row["api_key_id"], key_prefix=row["key_prefix"] or "unknown",
            ip_address=row["ip_address"] or "unknown", model=row["model"] or "unknown",
            input_tokens=row["input_tokens"] or 0, output_tokens=row["output_tokens"] or 0,
            total_tokens=row["tokens_used"] or 0, success=row["success"],
            error_message=row["error_message"], request_time=row["request_time"],
        )

    # Content flag operations
    async def create_content_flag(
        self,
        api_key_id: int,
        flag_type: str,
        severity: str,
        message_preview: str,
        full_message_hash: str,
        model: str,
        ip_address: str,
    ) -> int:
        pool = await self._get_pool()
        async with pool.acquire() as conn:
            row = await conn.fetchrow(
                """INSERT INTO content_flags
                   (api_key_id, flag_type, severity, message_preview, full_message_hash, model, ip_address)
                   VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING id""",
                api_key_id, flag_type, severity, message_preview, full_message_hash, model, ip_address
            )
            return row["id"]

    async def get_all_flags(self, include_reviewed: bool = False) -> List[ContentFlagRecord]:
        pool = await self._get_pool()
        async with pool.acquire() as conn:
            if include_reviewed:
                query = """
                    SELECT cf.*, ak.key_prefix, ak.discord_id, ak.discord_email
                    FROM content_flags cf
                    LEFT JOIN api_keys ak ON cf.api_key_id = ak.id
                    ORDER BY cf.flagged_at DESC
                """
                rows = await conn.fetch(query)
            else:
                query = """
                    SELECT cf.*, ak.key_prefix, ak.discord_id, ak.discord_email
                    FROM content_flags cf
                    LEFT JOIN api_keys ak ON cf.api_key_id = ak.id
                    WHERE cf.reviewed = FALSE
                    ORDER BY cf.flagged_at DESC
                """
                rows = await conn.fetch(query)
            return [self._row_to_content_flag(row) for row in rows]

    async def get_flag_by_id(self, flag_id: int) -> Optional[ContentFlagRecord]:
        pool = await self._get_pool()
        async with pool.acquire() as conn:
            row = await conn.fetchrow("""
                SELECT cf.*, ak.key_prefix, ak.discord_id, ak.discord_email
                FROM content_flags cf
                LEFT JOIN api_keys ak ON cf.api_key_id = ak.id
                WHERE cf.id = $1
            """, flag_id)
            return self._row_to_content_flag(row) if row else None

    async def mark_flag_reviewed(self, flag_id: int, action_taken: str) -> bool:
        pool = await self._get_pool()
        async with pool.acquire() as conn:
            result = await conn.execute(
                "UPDATE content_flags SET reviewed = TRUE, action_taken = $1, reviewed_at = CURRENT_TIMESTAMP WHERE id = $2",
                action_taken, flag_id
            )
            return result == "UPDATE 1"

    async def get_flags_by_key(self, api_key_id: int) -> List[ContentFlagRecord]:
        pool = await self._get_pool()
        async with pool.acquire() as conn:
            rows = await conn.fetch("""
                SELECT cf.*, ak.key_prefix, ak.discord_id, ak.discord_email
                FROM content_flags cf
                LEFT JOIN api_keys ak ON cf.api_key_id = ak.id
                WHERE cf.api_key_id = $1
                ORDER BY cf.flagged_at DESC
            """, api_key_id)
            return [self._row_to_content_flag(row) for row in rows]

    async def count_unreviewed_flags(self) -> int:
        pool = await self._get_pool()
        async with pool.acquire() as conn:
            row = await conn.fetchrow("SELECT COUNT(*) FROM content_flags WHERE reviewed = FALSE")
            return row[0] if row else 0

    def _row_to_content_flag(self, row) -> ContentFlagRecord:
        return ContentFlagRecord(
            id=row["id"],
            api_key_id=row["api_key_id"],
            key_prefix=self._safe_get(row, "key_prefix", "unknown"),
            discord_id=self._safe_get(row, "discord_id"),
            discord_email=self._safe_get(row, "discord_email"),
            ip_address=row["ip_address"] or "unknown",
            flag_type=row["flag_type"],
            severity=row["severity"],
            message_preview=row["message_preview"],
            full_message_hash=row["full_message_hash"],
            model=row["model"] or "unknown",
            action_taken=row["action_taken"],
            flagged_at=row["flagged_at"],
            reviewed_at=row["reviewed_at"],
        )




