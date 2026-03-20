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
    admin_password = os.getenv("ADMIN_PASSWORD")
    if not admin_password:
        raise ValueError("ADMIN_PASSWORD environment variable is required")
    admin_password = admin_password.strip()
    
    # TARGET_API_KEY is optional at startup - can be configured via admin dashboard
    target_api_key = os.getenv("TARGET_API_KEY")
    if target_api_key:
        target_api_key = target_api_key.strip()
    else:
        target_api_key = ""  # Will be set via admin dashboard
    
    # Optional settings with defaults (also strip whitespace)
    target_api_url = os.getenv("TARGET_API_URL", "https://api.openai.com/v1").strip()
    port = int(os.getenv("PORT", "8000").strip())
    max_context = int(os.getenv("MAX_CONTEXT", "128000").strip())
    max_output_tokens = int(os.getenv("MAX_OUTPUT_TOKENS", "4096").strip())
    max_output_tokens = max(1, min(max_output_tokens, 128000))  # Clamp 1–128000
    default_db = "/tmp/proxy.db" if os.environ.get("ZEABUR") else "./proxy.db"
    database_path = os.getenv("DATABASE_PATH", default_db).strip()
    
    # PostgreSQL URL (if set, will be used instead of SQLite)
    database_url = os.getenv("DATABASE_URL")
    if database_url:
        database_url = database_url.strip()
    
    # Abuse protection: max API keys per IP (default 2)
    max_keys_per_ip = int(os.getenv("MAX_KEYS_PER_IP", "2").strip())
    max_keys_per_ip = max(1, min(max_keys_per_ip, 20))  # Clamp 1–20
    
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
