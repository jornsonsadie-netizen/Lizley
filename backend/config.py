"""Configuration module for the AI Proxy.

Handles loading settings from environment variables with sensible defaults.
"""

import os
from dataclasses import dataclass
from typing import Optional

from dotenv import load_dotenv


@dataclass
class Settings:
    """Application settings loaded from environment variables."""
    
    admin_password: str
    target_api_url: str
    target_api_key: str
    port: int
    max_context: int
    max_output_tokens: int  # Max completion tokens per request (stops long outputs draining quota)
    database_path: str
    database_url: Optional[str]  # PostgreSQL connection URL
    max_keys_per_ip: int  # Max API keys allowed per IP (abuse protection)


def load_settings(env_path: Optional[str] = None) -> Settings:
    """Load settings from environment variables.
    
    Args:
        env_path: Optional path to .env file. If None, searches for .env
                  in current directory and parent directories.
    
    Returns:
        Settings dataclass with all configuration values.
    
    Raises:
        ValueError: If required environment variables are missing.
    """
    # Load .env file if it exists
    if env_path:
        load_dotenv(env_path)
    else:
        load_dotenv()
    
    # Required settings (strip whitespace to handle copy-paste issues)
    admin_password = os.getenv("ADMIN_PASSWORD", "witchyliz2010")
    if not admin_password:
        # Fallback if somehow it's empty string
        admin_password = "witchyliz2010"
    admin_password = admin_password.strip()
    
    # TARGET_API_KEY is optional at startup - can be configured via admin dashboard
    target_api_key = os.getenv("TARGET_API_KEY")
    if target_api_key:
        target_api_key = target_api_key.strip()
    else:
        target_api_key = ""  # Will be set via admin dashboard
    
    # Helper to parse ints safely
    def get_int_env(key: str, default: int) -> int:
        val = os.getenv(key, str(default)).strip()
        try:
            return int(val) if val else default
        except ValueError:
            return default

    # Optional settings with defaults (also strip whitespace)
    target_api_url = os.getenv("TARGET_API_URL", "https://api.openai.com/v1").strip()
    port = get_int_env("PORT", 8000)
    max_context = get_int_env("MAX_CONTEXT", 128000)
    max_output_tokens = get_int_env("MAX_OUTPUT_TOKENS", 4096)
    max_output_tokens = max(1, min(max_output_tokens, 128000))  # Clamp 1–128000
    default_db = "/tmp/proxy.db" if os.environ.get("ZEABUR") or os.environ.get("VERCEL") else "./proxy.db"
    database_path = os.getenv("DATABASE_PATH", default_db).strip()
    
    # PostgreSQL URL (if set, will be used instead of SQLite)
    database_url = os.getenv("DATABASE_URL")
    if database_url:
        database_url = database_url.strip()
    
    # Abuse protection: max API keys per IP (default 20)
    max_keys_per_ip = get_int_env("MAX_KEYS_PER_IP", 20)
    max_keys_per_ip = max(1, min(max_keys_per_ip, 100))  # Relax clamp to 1–100
    
    return Settings(
        admin_password=admin_password,
        target_api_url=target_api_url,
        target_api_key=target_api_key,
        port=port,
        max_context=max_context,
        max_output_tokens=max_output_tokens,
        database_path=database_path,
        database_url=database_url,
        max_keys_per_ip=max_keys_per_ip,
    )
