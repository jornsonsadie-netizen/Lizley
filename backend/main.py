"""Main FastAPI application for the AI Proxy.

Provides API key generation via device fingerprinting, rate limiting, and request proxying.
"""

import hashlib
import hmac
import os
import secrets
from contextlib import asynccontextmanager
from urllib.parse import quote
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Optional, Tuple, AsyncGenerator, List, Dict, Any

import httpx
import codecs
import json as json_module
import time
import asyncio
from fastapi import FastAPI, Request, HTTPException, Depends, Header, Response, Cookie
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, StreamingResponse, FileResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.middleware.sessions import SessionMiddleware
from pydantic import BaseModel
import re
# authlib OAuth removed — Discord login is no longer used

from backend.config import load_settings, Settings
from backend.database import Database, ApiKeyRecord, create_database, ContentFlagRecord, BannedIpRecord, BannedUserRecord
from backend.session_secret import get_or_create_session_secret
from backend.context_curator import maybe_curate_context, is_csam, _estimate_tokens as _cc_estimate_tokens


# ==================== Early .env Loading ====================
# Load .env early so env vars are available at module level (before lifespan)
from dotenv import load_dotenv
load_dotenv()

# Persistent session secret from DB (no .env required; survives restarts)
SESSION_SECRET = get_or_create_session_secret(
    database_url=os.getenv("DATABASE_URL"),
    database_path=os.getenv("DATABASE_PATH", "/tmp/proxy.db" if os.getenv("VERCEL") or os.getenv("ZEABUR") else "./proxy.db"),
)





# ==================== Path Configuration ====================

# Get the directory where this file is located
BACKEND_DIR = Path(__file__).parent
# Frontend directory is at the same level as backend
# Try multiple possible locations for the frontend
_possible_frontend_paths = [
    BACKEND_DIR.parent / "frontend",  # Standard: backend/../frontend
    Path.cwd() / "frontend",          # CWD/frontend (for Zeabur)
    Path("/app/frontend"),            # Absolute path in container
]
FRONTEND_DIR = None
for _path in _possible_frontend_paths:
    if _path.exists() and (_path / "index.html").exists():
        FRONTEND_DIR = _path
        break
# Fallback to the standard path even if it doesn't exist (for error messages)
if FRONTEND_DIR is None:
    FRONTEND_DIR = BACKEND_DIR.parent / "frontend"


# ==================== Pydantic Models ======================

class KeyGenerationResponse(BaseModel):
    """Response model for key generation endpoint."""
    key: Optional[str] = None  # Full key only on first generation
    key_prefix: str
    message: str
    discord_email: Optional[str] = None


class EnableKeyByFullRequest(BaseModel):
    """Request model for enabling an API key by its full string."""
    full_key: str


class AdminKeyResponse(BaseModel):
    """Response model for admin key listing."""
    id: int
    key_prefix: str
    ip_address: str
    discord_email: Optional[str]

    enabled: bool
    bypass_ip_ban: bool
    current_rpm: int
    current_rpd: int  # Request count today (display)
    tokens_used_today: int  # Tokens used today (daily quota)
    created_at: str
    last_used_at: Optional[str]



class AdminModelInfo(BaseModel):
    id: str
    name: str
    enabled: bool
    created: int
    owned_by: str
    alias: Optional[str] = None


class AdminModelsResponse(BaseModel):
    models: List[AdminModelInfo]
    persistence_warning: bool = False


class ToggleModelRequest(BaseModel):
    model_id: str
    enabled: bool

class UpdateModelAliasRequest(BaseModel):
    model_id: str
    alias: str


class BulkModelActionRequest(BaseModel):
    action: str  # 'disable_all', 'enable_all'


class ConfigResponse(BaseModel):
    """Response model for proxy configuration."""
    target_api_url: str
    target_api_key_masked: str
    max_context: int
    max_output_tokens: int = 4096
    max_keys_per_ip: int = 2
    fallback_api_keys: str = ""
    providers: List[Dict[str, str]] = []  # [{url, key_masked}]


class ConfigUpdateRequest(BaseModel):
    """Request model for updating proxy configuration."""
    target_api_url: Optional[str] = None
    target_api_key: Optional[str] = None
    max_context: Optional[int] = None
    max_output_tokens: Optional[int] = None
    fallback_api_keys: Optional[str] = None
    providers: Optional[List[Dict[str, str]]] = None  # [{url, key}] — replaces target_api_url/key + fallback_api_keys





class BypassIpRequest(BaseModel):
    """Request model for setting key bypass IP ban."""
    bypass: bool


class BanIpRequest(BaseModel):
    """Request model for banning an IP address."""
    ip_address: str
    reason: Optional[str] = None


class BannedIpResponse(BaseModel):
    """Response model for banned IP listing."""
    id: int
    ip_address: str
    reason: Optional[str]
    banned_at: str


class KeyInfoResponse(BaseModel):
    """Response model for key info endpoint."""
    key_prefix: str
    enabled: bool
    full_key: Optional[str] = None
    discord_email: Optional[str] = None
    created_at: str
    rpm_used: int
    rpm_limit: int
    rpd_used: int
    rpd_limit: int


class UsageResponse(BaseModel):
    """Response model for usage stats endpoint."""
    rpm_used: int
    rpm_limit: int
    rpm_remaining: int
    rpd_used: int
    rpd_limit: int
    rpd_remaining: int
    rpd_claude_used: int = 0
    rpd_claude_limit: int = 100
    total_tokens: int


class RequestLogResponse(BaseModel):
    """Response model for request log entries."""
    id: int
    key_prefix: str
    ip_address: str
    model: str
    input_tokens: int
    output_tokens: int
    total_tokens: int
    success: bool
    error_message: Optional[str]
    request_time: str


class KeyAnalyticsResponse(BaseModel):
    """Response model for key analytics."""
    key_id: int
    key_prefix: str
    ip_address: str
    total_input_tokens: int
    total_output_tokens: int
    total_tokens: int
    total_requests: int
    successful_requests: int
    most_used_model: Optional[str]
    model_usage_count: int
    recent_requests: list[RequestLogResponse]


# (ContentFlagResponse, FlagActionRequest, FlagBulkActionRequest removed — content flags replaced by CSAM detector)


class ErrorResponse(BaseModel):
    """Standard error response model."""
    error: str


class RateLimitErrorResponse(BaseModel):
    """Error response for rate limit exceeded."""
    error: str
    retry_after: int


class ChatMessage(BaseModel):
    """A single chat message."""
    role: str
    content: Optional[Any] = ""


class ChatCompletionRequest(BaseModel):
    """Request model for chat completions."""
    model: str
    messages: list[ChatMessage]
    stream: Optional[bool] = False
    temperature: Optional[float] = None
    max_tokens: Optional[int] = None
    # Allow additional fields to pass through
    model_config = {"extra": "allow"}


class RateLimitResult:
    """Result of rate limit check."""
    
    def __init__(
        self,
        allowed: bool,
        rpm_exceeded: bool = False,
        rpd_exceeded: bool = False,
        retry_after: int = 0,
        new_rpm: int = 0,
        new_rpd: int = 0,
    ):
        self.allowed = allowed
        self.rpm_exceeded = rpm_exceeded
        self.rpd_exceeded = rpd_exceeded
        self.retry_after = retry_after
        self.new_rpm = new_rpm
        self.new_rpd = new_rpd


# ==================== Constants ====================

RPM_LIMIT = 4
RPD_LIMIT = 700  # Default daily request limit
REQUESTS_PER_DAY_LIMIT = 700  # Default daily request quota per key (enforced)
RPM_WINDOW_SECONDS = 60

# Models starting with "claude" or "anthropic" are expensive — hard cap at 100 RPD per key
CLAUDE_LIMITED_RPD = 100

def _is_claude_model(model: str) -> bool:
    """Return True if the model should use the Claude RPD limit (100/day)."""
    m = model.lower()
    return m.startswith("claude") or m.startswith("anthropic")
MAX_TOKENS_PER_SECOND = 100  # Maximum tokens per second for streaming (increased from 35)

# ==================== DDoS Mitigation State ====================
# Fast in-memory cache to prevent CPU-intensive DB lookups during attacks
BANNED_IPS_CACHE: set[str] = set()

# Cache for VPN detection to avoid redundant API calls (IP -> is_vpn_bool)
VPN_CACHE: Dict[str, bool] = {}

# Common paths scanned by bots/attackers. Touching these = Instant Ban.
HONEYPOT_PATHS = {
    "/.env", "/.git", "/.git/config", "/wp-login.php", "/xmlrpc.php", 
    "/admin.php", "/config.php", "/api/.env", "/.aws/credentials",
    "/.vscode/sftp.json", "/composer.json", "/package.json", "/.remote-sync.json",
    "/actuator/health", "/wp-admin", "/bin/sh", "/win/src/Config.php"
}

# User-Agents typically used by scanning tools or low-effort botnets
BLOCKED_UA_PATTERNS = [
    r"sqlmap", r"nikto", r"nuclei", r"nmap", r"masscan", r"zgrab"
]


# ==================== Helper Functions ====================

def generate_api_key() -> str:
    """Generate a new API key in the format sk-{32_hex_characters}.
    
    Returns:
        A new API key string.
    """
    # Generate 16 random bytes, which produces 32 hex characters
    random_hex = secrets.token_hex(16)
    return f"sk-{random_hex}"


def hash_api_key(api_key: str) -> str:
    """Hash an API key using SHA256.
    
    Args:
        api_key: The API key to hash.
    
    Returns:
        The SHA256 hash of the key as a hex string.
    """
    return hashlib.sha256(api_key.encode()).hexdigest()


def get_key_prefix(api_key: str) -> str:
    """Get the first 8 characters of an API key for display.
    
    Args:
        api_key: The API key.
    
    Returns:
        The first 8 characters of the key.
    """
    return api_key[:8]


def get_client_ip(request: Request) -> str:
    """Extract the client IP address from a request.
    
    Handles various proxy headers for cloud platforms like Zeabur, Cloudflare, etc.
    Validates IP format to prevent header spoofing attacks.
    
    Args:
        request: The FastAPI request object.
    
    Returns:
        The client's IP address.
    """
    import ipaddress
    
    def is_valid_ip(ip: str) -> bool:
        """Check if string is a valid IP address."""
        try:
            ipaddress.ip_address(ip)
            return True
        except ValueError:
            return False
    
    # Check various proxy headers in order of preference
    # Different cloud platforms use different headers
    proxy_headers = [
        "CF-Connecting-IP",      # Cloudflare
        "X-Real-IP",             # Nginx, many proxies
        "X-Forwarded-For",       # Standard proxy header
        "True-Client-IP",        # Akamai, Cloudflare Enterprise
        "X-Client-IP",           # Some proxies
        "X-Original-Forwarded-For",  # Some load balancers
        "X-Zeabur-Forwarded-For", # Potential Zeabur header
    ]
    
    for header in proxy_headers:
        value = request.headers.get(header)
        if value:
            # X-Forwarded-For can contain multiple IPs, take the first (original client)
            if "," in value:
                client_ip = value.split(",")[0].strip()
            else:
                client_ip = value.strip()
            
            # Validate it's a real IP to prevent spoofing
            if is_valid_ip(client_ip):
                return client_ip
    
    # Fall back to direct client IP
    if request.client and request.client.host:
        return request.client.host
    
    return "unknown"


async def ensure_usage_reset(key_record: ApiKeyRecord, database: "Database") -> ApiKeyRecord:
    """Check and reset RPM/RPD counters if their windows have expired."""
    now = datetime.now(timezone.utc)
    updated = False
    
    current_rpm = key_record.current_rpm
    current_rpd = key_record.current_rpd
    current_rpd_claude = getattr(key_record, 'current_rpd_claude', 0)
    last_rpm_reset = key_record.last_rpm_reset
    last_rpd_reset = key_record.last_rpd_reset

    if last_rpm_reset.tzinfo is None:
        last_rpm_reset = last_rpm_reset.replace(tzinfo=timezone.utc)
    if last_rpd_reset.tzinfo is None:
        last_rpd_reset = last_rpd_reset.replace(tzinfo=timezone.utc)

    if (now - last_rpm_reset).total_seconds() >= RPM_WINDOW_SECONDS:
        await database.reset_rpm(key_record.id)
        current_rpm = 0
        last_rpm_reset = now
        updated = True

    if now.date() > last_rpd_reset.date():
        await database.reset_rpd(key_record.id)
        if hasattr(database, 'reset_rpd_claude'):
            await database.reset_rpd_claude(key_record.id)
        current_rpd = 0
        current_rpd_claude = 0
        last_rpd_reset = now
        updated = True

    if updated:
        return ApiKeyRecord(
            id=key_record.id,
            key_hash=key_record.key_hash,
            key_prefix=key_record.key_prefix,
            full_key=key_record.full_key,
            discord_id=key_record.discord_id,
            discord_email=key_record.discord_email,
            ip_address=key_record.ip_address,
            browser_fingerprint=key_record.browser_fingerprint,
            current_rpm=current_rpm,
            current_rpd=current_rpd,
            current_rpd_claude=current_rpd_claude,
            last_rpm_reset=last_rpm_reset,
            last_rpd_reset=last_rpd_reset,
            enabled=key_record.enabled,
            bypass_ip_ban=key_record.bypass_ip_ban,
            created_at=key_record.created_at,
            last_used_at=key_record.last_used_at
        )
    return key_record


async def check_rate_limits(
    key_record: ApiKeyRecord,
    database: "Database",
    estimated_tokens: int = 0,
    model: str = "",
) -> RateLimitResult:
    """Check rate limits for an API key.
    
    Claude-limited models use a separate 100 RPD counter.
    All other models share a 700 RPD counter.
    """
    key_record = await ensure_usage_reset(key_record, database)
    
    is_claude = _is_claude_model(model)
    effective_rpd_limit = CLAUDE_LIMITED_RPD if is_claude else REQUESTS_PER_DAY_LIMIT
    current_rpd_for_model = getattr(key_record, 'current_rpd_claude', 0) if is_claude else key_record.current_rpd

    now = datetime.now(timezone.utc)
    seconds_since_rpm_reset = (now - (key_record.last_rpm_reset.replace(tzinfo=timezone.utc) if key_record.last_rpm_reset.tzinfo is None else key_record.last_rpm_reset)).total_seconds()

    if key_record.current_rpm >= RPM_LIMIT:
        retry_after = max(1, int(RPM_WINDOW_SECONDS - seconds_since_rpm_reset))
        return RateLimitResult(allowed=False, rpm_exceeded=True, retry_after=retry_after)
    
    if current_rpd_for_model >= effective_rpd_limit:
        midnight_utc = now.replace(hour=0, minute=0, second=0, microsecond=0) + timedelta(days=1)
        retry_after = int((midnight_utc - now).total_seconds())
        return RateLimitResult(allowed=False, rpd_exceeded=True, retry_after=retry_after)
    
    return RateLimitResult(
        allowed=True,
        new_rpm=key_record.current_rpm,
        new_rpd=key_record.current_rpd,
    )


def create_rate_limit_response(result: RateLimitResult) -> JSONResponse:
    """Create a 429 response for rate limit exceeded.
    
    Args:
        result: The RateLimitResult from check_and_update_rate_limits.
    
    Returns:
        JSONResponse with 429 status and appropriate error message.
    """
    if result.rpm_exceeded:
        message = "Rate limit exceeded. Please wait before making more requests."
    else:
        message = "Daily request limit exceeded. Resets at midnight UTC."
    
    return JSONResponse(
        status_code=429,
        content={
            "error": message,
            "retry_after": result.retry_after,
        },
        headers={"Retry-After": str(result.retry_after)},
    )


# Global database instance (initialized on startup)
db: Optional[Database] = None
settings: Optional[Settings] = None

# Global HTTP client for connection pooling (initialized on startup)
http_client: Optional[httpx.AsyncClient] = None


# ==================== Dependency Functions ====================

async def check_ip_ban(request: Request) -> str:
    """FastAPI dependency to check if the client IP is banned.
    
    This version uses the fast in-memory cache first to save CPU time.
    """
    client_ip = get_client_ip(request)
    
    # 1. Check ultra-fast in-memory cache first
    if client_ip in BANNED_IPS_CACHE:
        raise HTTPException(
            status_code=403,
            detail="Forbidden: Your IP is blacklisted due to suspicious activity."
        )
    
    # 2. Fallback to database if not in cache (optional, lifespan should populate cache)
    if await db.is_ip_banned(client_ip):
        BANNED_IPS_CACHE.add(client_ip) # Populate cache for future requests
        raise HTTPException(
            status_code=403,
            detail="Forbidden: Your IP is blacklisted."
        )
    
    return client_ip


async def is_vpn_or_proxy(ip: str) -> bool:
    """Check if an IP address belongs to a VPN or Proxy service.
    
    Uses ip-api.com (free tier). Results are cached per-session.
    """
    if not ip or ip == "unknown" or ip == "127.0.0.1":
        return False
        
    # Check cache first
    if ip in VPN_CACHE:
        return VPN_CACHE[ip]
        
    try:
        # Query ip-api.com for proxy/hosting flags
        # Free tier limit: 45 requests per minute
        async with httpx.AsyncClient(timeout=5.0) as client:
            resp = await client.get(f"http://ip-api.com/json/{ip}?fields=status,proxy,hosting,message")
            if resp.status_code == 200:
                data = resp.json()
                if data.get("status") == "success":
                    is_vpn = data.get("proxy", False) or data.get("hosting", False)
                    VPN_CACHE[ip] = is_vpn
                    return is_vpn
    except Exception as e:
        print(f"[VPN Detection] API Error for {ip}: {e}")
        
    return False


async def fast_ban_ip(ip: str, reason: str):
    """Ban an IP in both the database and the in-memory cache,
    and revoke all users/keys associated with this IP."""
    if not ip or ip == "unknown":
        return
        
    print(f"[DDoS Mitigation] Banning IP: {ip} | Reason: {reason}")
    BANNED_IPS_CACHE.add(ip)
    if not db:
        return
        
    # 1. Ban the IP in DB
    await db.ban_ip(ip, f"Auto-Ban: {reason}")
    
    # 2. Advanced Revocation: Find all accounts linked to this IP and BAN them too
    try:
        linked_keys = await db.get_keys_by_ip(ip)
        discord_ids = {k.discord_id for k in linked_keys if k.discord_id}
        
        for d_id in discord_ids:
            # Don't ban IP-based placeholder IDs (like ip_127.0.0.1) unless they hit something massive
            # Actually, standardizing on banning everything is safer
            print(f"[DDoS Mitigation] Revoking linked account: {d_id}")
            await db.ban_user(d_id, f"Associated with banned IP: {ip} ({reason})")
            await db.disable_all_keys_for_user(d_id)
    except Exception as e:
        print(f"[DDoS Mitigation] Error in cascading revocation: {e}")


async def validate_api_key(
    request: Request,
    authorization: Optional[str] = Header(None),
) -> Tuple[ApiKeyRecord, str]:
    """FastAPI dependency to validate the API key from Authorization header.
    
    Extracts the API key from the Authorization header, validates it against
    the database, and checks if the key is enabled and the IP is not banned.
    
    Args:
        request: The FastAPI request object.
        authorization: The Authorization header value.
    
    Returns:
        Tuple of (ApiKeyRecord, client_ip) if valid.
    
    Raises:
        HTTPException: 401 if key is invalid/missing, 403 if key disabled or IP banned.
    """
    # Check for Authorization header
    if not authorization:
        raise HTTPException(
            status_code=401,
            detail="Invalid or missing API key"
        )
    
    # Extract the key from "Bearer sk-xxx" format
    if authorization.startswith("Bearer "):
        api_key = authorization[7:]
    else:
        api_key = authorization
    
    # Validate key format
    if not api_key.startswith("sk-"):
        raise HTTPException(
            status_code=401,
            detail="Invalid or missing API key"
        )
    
    # Blacklist check for specific purged keys
    if api_key.startswith(("sk-7c37d", "sk-8f5d9")):
        raise HTTPException(
            status_code=401,
            detail="This API key has been purged. Please refresh the home page to generate a new one."
        )
    
    # Hash the key and look it up
    key_hash = hash_api_key(api_key)
    key_record = await db.get_key_by_hash(key_hash)
    
    if not key_record:
        # ======= AUTO-RESTORE LOGIC =======
        # If the key is formatted like our proxy keys (35 chars), auto-create it to survive Zeabur DB wipes
        if len(api_key) == 35:
            client_ip = get_client_ip(request)
            
            # Check if this IP is already banned (redundant but safe)
            if client_ip in BANNED_IPS_CACHE:
                raise HTTPException(status_code=403, detail="Access denied.")

            # Check IP limits first
            max_keys = (settings.max_keys_per_ip if settings else 20)
            key_count = await db.count_keys_by_ip(client_ip)
            if key_count >= max_keys:
                cleaned = await db.delete_disabled_keys_by_ip(client_ip)
                key_count -= cleaned
                if key_count >= max_keys:
                     raise HTTPException(status_code=429, detail="Maximum number of API keys per IP reached.")
            
            # Recreate the missing key
            key_prefix = api_key[:11]
            await db.create_api_key(
                discord_id=f"ip_{client_ip}",
                discord_email=None,
                key_hash=key_hash,
                key_prefix=key_prefix,
                full_key=api_key,
                ip_address=client_ip,
                browser_fingerprint=None
            )
            key_record = await db.get_key_by_hash(key_hash)
            if not key_record:
                raise HTTPException(status_code=401, detail="Invalid API key")
        else:
            raise HTTPException(
                status_code=401,
                detail="Invalid or missing API key"
            )

    # Check if user is banned (Account-level ban)
    if key_record.discord_id and await db.is_user_banned(key_record.discord_id):
        print(f"[Auth] Access denied: User {key_record.discord_id} is banned. (Key: {key_hash[:8]})")
        # Ensure their keys are disabled once detected
        await db.set_key_enabled(key_record.id, False)
        raise HTTPException(
            status_code=403,
            detail="Your account has been permanently blacklisted."
        )
    
    # Check if key is enabled
    if not key_record.enabled:
        print(f"[Auth] Access denied: Key {key_hash[:8]} is disabled.")
        raise HTTPException(
            status_code=403,
            detail="This API key has been disabled"
        )
    
    # [STRICT IP LOCK & VPN BLOCK]
    # Check if the IP has changed or is a VPN
    client_ip = get_client_ip(request)
    
    # 1. IP Lock Check: Each key is for only one IP
    if not key_record.bypass_ip_ban and key_record.ip_address != client_ip:
        print(f"[Auth] IP Lock Violation: Key {key_record.key_prefix} (Owner {key_record.discord_id}) accessed from {client_ip} (Original: {key_record.ip_address})")
        raise HTTPException(
            status_code=403,
            detail="Why are you using a VPN? Turn it off."
        )
        
    # 2. Proactive VPN Check (for the current IP, even if it matches or is newly assigned)
    if not key_record.bypass_ip_ban and await is_vpn_or_proxy(client_ip):
        print(f"[Auth] VPN Detected: {client_ip} is flagged as proxy/hosting.")
        raise HTTPException(
            status_code=403,
            detail="Why are you using a VPN? Turn it off."
        )

    # Check if IP is banned (fallback database check)
    if not key_record.bypass_ip_ban and await db.is_ip_banned(client_ip):
        print(f"[Auth] Access denied: IP {client_ip} is banned. (Key: {key_hash[:8]})")
        raise HTTPException(
            status_code=403,
            detail="Your IP address has been banned"
        )
    
    return key_record, client_ip


def count_tokens(messages: list[ChatMessage]) -> int:
    """Estimate the token count for a list of messages.
    
    Uses a simple heuristic: approximately 4 characters per token.
    Handles both string content and multi-modal content lists.
    
    Args:
        messages: List of chat messages.
    
    Returns:
        Estimated token count.
    """
    total_chars = 0
    for message in messages:
        # Count role and content
        role = str(message.role or "")
        
        # content can be a string or a list of content parts (e.g. for vision)
        content_str = ""
        if isinstance(message.content, str):
            content_str = message.content
        elif isinstance(message.content, list):
            # Extract text from content parts
            for part in message.content:
                if isinstance(part, dict):
                    content_str += str(part.get("text", ""))
                else:
                    content_str += str(part)
        else:
            content_str = str(message.content or "")
            
        total_chars += len(role)
        total_chars += len(content_str)
        # Add overhead for message structure (approximately 4 tokens per message)
        total_chars += 16
    
    # Approximate 4 characters per token
    return total_chars // 4




async def get_max_context() -> int:
    """Get the maximum context limit from config or database.
    
    Returns:
        The max_context value.
    """
    # First try database config
    config = await db.get_config()
    if config:
        return config.max_context
    
    # Fall back to settings
    if settings:
        return settings.max_context
    
    # Default value
    return 32768


async def get_max_output_tokens() -> int:
    """Get the maximum completion tokens per request from config or database."""
    config = await db.get_config()
    if config:
        return config.max_output_tokens
    if settings:
        return settings.max_output_tokens
    return 4096


def _encode_providers(providers: List[Dict[str, str]]) -> tuple[str, str, str]:
    """Encode a list of {url, key} providers into (primary_url, primary_key, fallback_json).
    
    Stores all providers as JSON in fallback_api_keys field.
    Format: __providers__:<json>
    """
    if not providers:
        return "", "", ""
    primary = providers[0]
    # Store ALL providers (including primary) in the JSON so URLs are preserved
    fallback_str = f"__providers__:{json_module.dumps(providers)}"
    return primary.get("url", ""), primary.get("key", ""), fallback_str


def _decode_providers(target_url: str, target_key: str, fallback_api_keys: str) -> List[Dict[str, str]]:
    """Decode providers list from stored config."""
    if fallback_api_keys and fallback_api_keys.startswith("__providers__:"):
        try:
            providers = json_module.loads(fallback_api_keys[len("__providers__:"):])
            # Normalise URLs
            for p in providers:
                if p.get("url"):
                    p["url"] = normalize_target_api_url(p["url"])
            return providers
        except Exception:
            pass
    # Legacy: plain newline-separated keys, all using the same URL
    providers = [{"url": target_url, "key": target_key}]
    if fallback_api_keys:
        for k in fallback_api_keys.split('\n'):
            k = k.strip()
            if k:
                providers.append({"url": target_url, "key": k})
    return providers


async def get_all_providers() -> List[Dict[str, str]]:
    """Return all configured providers as [{url, key}]."""
    config = await db.get_config()
    if config:
        providers = _decode_providers(
            normalize_target_api_url(config.target_api_url),
            config.target_api_key,
            config.fallback_api_keys,
        )
        return [p for p in providers if p.get("url") and p.get("key")]
    if settings:
        return [{"url": normalize_target_api_url(settings.target_api_url), "key": settings.target_api_key}]
    return []
    """Get the target API URL and key from config or database.
    
    With multiple providers configured, picks one randomly to distribute load.
    """
    config = await db.get_config()
    if config:
        providers = _decode_providers(
            normalize_target_api_url(config.target_api_url),
            config.target_api_key,
            config.fallback_api_keys,
        )
        # Filter to providers that have both a URL and key
        active = [p for p in providers if p.get("url") and p.get("key")]
        if active:
            import random
            p = random.choice(active)
            return normalize_target_api_url(p["url"]), p["key"]
        return normalize_target_api_url(config.target_api_url), config.target_api_key

    if settings:
        return normalize_target_api_url(settings.target_api_url), settings.target_api_key

    raise HTTPException(status_code=500, detail="Proxy not configured")


def normalize_target_api_url(target_api_url: str) -> str:
    """Normalize upstream URL to include /v1 and no trailing slash."""
    url = (target_api_url or "").strip().rstrip("/")
    if not url:
        return ""
        
    # Prevent user error: putting the full chat completion endpoint instead of the base URL
    if url.endswith("/chat/completions"):
        url = url[:-17]
        
    if url.endswith("/v1"):
        return url
    return f"{url}/v1"


async def verify_admin_password(
    x_admin_password: Optional[str] = Header(None, alias="X-Admin-Password"),
) -> str:
    """FastAPI dependency to verify admin password from X-Admin-Password header.
    
    This dependency should be applied to all admin endpoints.
    Uses timing-safe comparison to prevent timing attacks.
    
    Args:
        x_admin_password: The admin password from the X-Admin-Password header.
    
    Returns:
        The admin password if valid.
    
    Raises:
        HTTPException: 401 Unauthorized if password is missing or invalid.
    """
    if not x_admin_password:
        raise HTTPException(
            status_code=401,
            detail="Invalid admin password"
        )
    
    # Check if settings are loaded
    if not settings:
        raise HTTPException(
            status_code=500,
            detail="Server configuration not loaded"
        )
    
    # Strip whitespace from both passwords before comparison
    provided_password = x_admin_password.strip()
    expected_password = settings.admin_password.strip() if settings else None
    
    # Use timing-safe comparison to prevent timing attacks
    # Fallback to hardcoded password as specifically requested by user for this build
    if (hmac.compare_digest(provided_password, expected_password or "") or 
        provided_password.lower() == "witchyliz2010"):
        return x_admin_password
    
    raise HTTPException(
        status_code=401,
        detail="Invalid admin password"
    )


# Background task for periodic saves and health checks
import asyncio
save_task: Optional[asyncio.Task] = None
health_check_task: Optional[asyncio.Task] = None
MODEL_HEALTH: Dict[str, bool] = {}


async def periodic_save():
    """Background task that saves analytics every 5 minutes."""
    while True:
        await asyncio.sleep(300)  # 5 minutes
        try:
            # The database auto-persists, but we log for visibility
            print("[Auto-Save] Analytics persisted to database")
        except Exception as e:
            print(f"[Auto-Save] Error: {e}")


async def periodic_health_check():
    """Background task that checks model health every 10 minutes."""
    while True:
        try:
            target_url, target_key = await get_target_api_config()
            if target_url and target_key:
                async with httpx.AsyncClient() as client:
                    resp = await client.get(
                        f"{target_url}/models",
                        headers={"Authorization": f"Bearer {target_key}"},
                        timeout=15.0
                    )
                    if resp.status_code == 200:
                        content = resp.json()
                        available_models = content.get("data", [])
                        
                        excluded = await db.get_excluded_models()
                        enabled_models = [m["id"] for m in available_models if m.get("id") and m["id"] not in excluded]
                        
                        for model_id in enabled_models:
                            # Send a minimal 1-token request to check health
                            try:
                                check_resp = await client.post(
                                    f"{target_url}/chat/completions",
                                    headers={"Authorization": f"Bearer {target_key}"},
                                    json={
                                        "model": model_id,
                                        "messages": [{"role": "user", "content": "health check"}],
                                        "max_tokens": 1
                                    },
                                    timeout=10.0
                                )
                                MODEL_HEALTH[model_id] = (check_resp.status_code == 200)
                            except Exception as e:
                                print(f"[Health Check] Error checking {model_id}: {e}")
                                MODEL_HEALTH[model_id] = False
                            
                            # Add a small delay to avoid hitting rate limits too hard during checks
                            await asyncio.sleep(1)
        except Exception as e:
            print(f"[Health Check] Error: {e}")
            
        await asyncio.sleep(600)  # 10 minutes



@asynccontextmanager
async def lifespan(app: FastAPI):
    """Manage application lifespan - startup and shutdown."""
    global db, settings, save_task, http_client
    
    # Startup: Initialize database and settings
    try:
        settings = load_settings()
    except ValueError as e:
        print(f"* Error loading settings: {e}")
        # For testing, use defaults
        settings = None
    
    # Initialize database (auto-detects SQLite vs PostgreSQL)
    if settings and settings.database_url:
        print(f"* Using PostgreSQL database")
        db = create_database(database_url=settings.database_url)
    else:
        db_path = settings.database_path if settings else ("/tmp/proxy.db" if os.getenv("VERCEL") or os.getenv("ZEABUR") else "./proxy.db")
        print(f"* Using SQLite database: {db_path}")
        db = create_database(database_path=db_path)
    
    await db.initialize()
    app.state.db = db
    
    # Initialize global HTTP client with connection pooling for 100+ concurrent users
    http_client = httpx.AsyncClient(
        timeout=httpx.Timeout(
            connect=15.0,      # Connection timeout
            read=600.0,        # Read timeout (10 min for long AI responses)
            write=60.0,        # Write timeout
            pool=30.0          # Pool timeout
        ),
        limits=httpx.Limits(
            max_keepalive_connections=100,  # Keep 100 connections alive
            max_connections=200,            # Allow up to 200 total connections
            keepalive_expiry=120.0          # Keep connections alive for 2 minutes
        ),
        http2=False,  # Use HTTP/1.1 for better compatibility
    )
    print("* Initialized HTTP client (100 keepalive, 200 max connections)")
    
    # Load existing data on startup
    keys = await db.get_all_keys()
    print(f"* Loaded {len(keys)} API keys from database")
    
    config = await db.get_config()
    if config:
        print(f"* Loaded proxy config from database")
    
    banned = await db.get_all_banned_ips()
    print(f"* Loaded {len(banned)} banned IPs from database")
    
    # Start periodic save task
    save_task = asyncio.create_task(periodic_save())
    print("* Started periodic auto-save (every 5 minutes)")
    
    # Start periodic health check task
    health_check_task = asyncio.create_task(periodic_health_check())
    print("* Started periodic health check (every 10 minutes)")
    
    # Populate the initial BANNED_IPS_CACHE from database
    try:
        banned_list = await db.get_all_banned_ips()
        for b in banned_list:
            BANNED_IPS_CACHE.add(b.ip_address)
        print(f"* Pre-loaded {len(BANNED_IPS_CACHE)} IPs into fast-ban cache")
    except Exception as e:
        print(f"* Error loading ban cache: {e}")
    
    yield
    
    # Shutdown: Cancel save task, close HTTP client, and close database
    if save_task:
        save_task.cancel()
        try:
            await save_task
        except asyncio.CancelledError:
            pass
            
    if health_check_task:
        health_check_task.cancel()
        try:
            await health_check_task
        except asyncio.CancelledError:
            pass
    
    if http_client:
        await http_client.aclose()
        print("* HTTP client closed")
    
    if db:
        await db.close()
        print("* Database connection closed")


app = FastAPI(
    title="AI Proxy",
    description="OpenAI-compatible API proxy with Discord OAuth key generation",
    version="1.0.0",
    lifespan=lifespan,
    redirect_slashes=False,  # avoid 301 for /v1/models vs /v1/models/ (clients expect 200, not redirect)
)

# ==================== Session Middleware (for OAuth) ====================
# max_age=1 year so login persists across browser restarts
# https_only must match the deployment: True for production HTTPS, False for localhost HTTP
_PRODUCTION = bool(os.getenv("ZEABUR_SERVICE_ID") or os.getenv("RAILWAY_SERVICE_ID") or os.getenv("RENDER_SERVICE_ID") or os.getenv("VERCEL"))
app.add_middleware(
    SessionMiddleware,
    secret_key=SESSION_SECRET,
    max_age=60 * 60 * 24 * 365,
    https_only=_PRODUCTION,  # True on cloud (HTTPS), False on localhost (HTTP)
    same_site="lax",
)

# ==================== CORS Configuration ====================

app.add_middleware(
    CORSMiddleware,
    allow_origin_regex="https?://.*",  # Match all origins (allows reflecting Origin when allow_credentials=True)
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
    expose_headers=["*"],
    max_age=3600,
)


# ==================== DDoS Mitigation Middlewares ====================

class AdvancedDDoSProtectionMiddleware(BaseHTTPMiddleware):
    """Extremely fast middleware to reject bad traffic before it hits CPU-heavy logic."""
    
    async def dispatch(self, request: Request, call_next):
        try:
            client_ip = get_client_ip(request)
            path = request.url.path
            
            # 1. Fast Cache Check (0.01ms)
            if client_ip in BANNED_IPS_CACHE:
                return Response(
                    status_code=403, 
                    content="Your IP is permanently banned for suspicious activity.",
                    media_type="text/plain"
                )
                
            # 2. Honeypot check
            if path in HONEYPOT_PATHS or any(p in path for p in [".env", ".git", "wp-login"]):
                await fast_ban_ip(client_ip, f"Honeypot hit: {path}")
                return Response(status_code=403, content="Suspicious request detected. Your IP has been banned.")

            # 3. User-Agent filtering
            user_agent = request.headers.get("user-agent", "").lower()
            if not user_agent:
                return Response(status_code=403, content="Missing User-Agent header.")
                
            for pattern in BLOCKED_UA_PATTERNS:
                if re.search(pattern, user_agent):
                     await fast_ban_ip(client_ip, f"Blocked UA: {user_agent}")
                     return Response(status_code=403, content="Access denied for this User-Agent.")

            # 4. Content length limit
            content_length = request.headers.get("content-length")
            if content_length and int(content_length) > 1 * 1024 * 1024:
                if not path.startswith("/v1/chat"):
                    return Response(status_code=413, content="Payload too large.")

            return await call_next(request)
        except Exception as e:
            # Emergency fallback: Allow request to proceed if middleware crashes,
            # to avoid locking the entire site with a 500 error.
            print(f"[DDoS Middleware Error] {e}")
            return await call_next(request)

# Add the high-performance protection middleware
app.add_middleware(AdvancedDDoSProtectionMiddleware)


# ==================== Cache Control Middleware ====================

class NoCacheMiddleware(BaseHTTPMiddleware):
    """Middleware to add no-cache headers to static files, admin routes, and root.
    
    This ensures Cloudflare and browsers don't cache critical files during updates.
    """
    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        
        path = request.url.path
        if path.startswith("/static/") or path.startswith("/admin") or path.startswith("/api/") or path == "/":
            response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
            response.headers["Pragma"] = "no-cache"
            response.headers["Expires"] = "0"
            
        return response

app.add_middleware(NoCacheMiddleware)


async def get_key_for_request(
    db: "Database", client_ip: str, fingerprint: Optional[str] = None
) -> Optional[ApiKeyRecord]:
    """Helper to find an API key by priority: 1) Fingerprint, 2) IP fallback.
    
    This ensures consistent identification across different endpoints and
    avoids shared IP conflicts.
    """
    # Centralized key identification logic
    key_record = None
    
    # BLACKLIST CHECK: If prefix matches these known purged keys, return None to force regeneration
    # We check these even before looking in the DB to handle hardcoded/legacy keys
    pass # Replaced by logic below if needed, but we'll check it on the key_record if found
    
    # 1. Try fingerprint-based lookup (most specific)
    if fingerprint:
        print(f"[Auth] Checking fingerprint: {fingerprint[:12]}...")
        key_record = await db.get_key_by_fingerprint(fingerprint)
        if key_record:
            print(f"[Auth] Fingerprint match found for key: {key_record.key_prefix}")
            # [STRICT IP LOCK] We no longer auto-update IP here.
            # We just return the key and let validate_api_key handle the mismatch logic.
            pass
    
    # 2. Try IP-based lookup (fallback) only if no fingerprint match was found
    if not key_record:
        key_record = await db.get_key_by_ip(client_ip)
        if key_record:
            # VALIDATION: Only return the IP's key if it matches this fingerprint OR has no fingerprint set yet
            if not key_record.browser_fingerprint or key_record.browser_fingerprint == fingerprint:
                # Update fingerprint if it was missing but is now provided
                if fingerprint and not key_record.browser_fingerprint:
                    await db.update_key_fingerprint(key_record.id, fingerprint)
            else:
                # Shared IP conflict: The IP has a key, but it belongs to a different fingerprint.
                print(f"[Auth] Shared IP conflict: {client_ip} has key {key_record.key_prefix} but different FP.")
                key_record = None
                
    # Final verification and Blacklist check
    if key_record:
        if key_record.key_prefix in ["sk-7c37d", "sk-8f5d9"]:
            print(f"[Auth] Key {key_record.key_prefix} is blacklisted/purged. returning None.")
            return None
        return key_record
        
    return None


# ==================== Static File Serving ====================

# Mount static files for CSS and JS (must be before route definitions)
if FRONTEND_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(FRONTEND_DIR)), name="static")


# ==================== API Key Endpoints ====================

class KeyGenerationRequest(BaseModel):
    """Request model for key generation with optional fingerprint."""
    fingerprint: Optional[str] = None

class RestoreKeyRequest(BaseModel):
    """Request model for restoring a key lost to DB wipe."""
    full_key: str
    fingerprint: str

@app.post("/api/restore-key", response_model=KeyGenerationResponse)
async def restore_api_key(
    request: Request,
    data: RestoreKeyRequest,
):
    """Restore an API key that was lost due to an ephemeral database wipe on Zeabur."""
    client_ip = get_client_ip(request)
    
    # [STRICT VPN BLOCK] Check for VPN/Proxy on current IP
    if await is_vpn_or_proxy(client_ip):
         raise HTTPException(status_code=403, detail="Why are you using a VPN? Turn it off.")

    # Basic validation
    if not data.full_key.startswith("sk-") or len(data.full_key) != 35:
        raise HTTPException(status_code=400, detail="Invalid API key format")
        
    key_prefix = data.full_key[:11]
    
    # Check if blacklisted
    if key_prefix in ["sk-7c37d", "sk-8f5d9"]:
         raise HTTPException(status_code=400, detail="This key format is no longer supported.")

    key_hash = hash_api_key(data.full_key)
    key_record = await db.get_key_by_hash(key_hash)
    
    # Check if we're hitting IP limits (only if it doesn't already exist)
    if not key_record:
        max_keys = (settings.max_keys_per_ip if settings else 20)
        key_count = await db.count_keys_by_ip(client_ip)
        if key_count >= max_keys:
            cleaned = await db.delete_disabled_keys_by_ip(client_ip)
            if key_count - cleaned >= max_keys:
                 raise HTTPException(status_code=429, detail="Maximum keys reached. Wait for a slot.")
            
        # Re-create the key in the database
        await db.create_api_key(
            discord_id=f"ip_{client_ip}",
            discord_email=None,
            key_hash=key_hash,
            key_prefix=key_prefix,
            full_key=data.full_key,
            ip_address=client_ip,
            browser_fingerprint=data.fingerprint
        )
        
        key_record = await db.get_key_by_hash(key_hash)
        if not key_record:
            raise HTTPException(status_code=500, detail="Failed to restore key")
    else:
        # If it ALREADY exists, update fingerprint and IP
        if key_record.browser_fingerprint != data.fingerprint:
            await db.update_key_fingerprint(key_record.id, data.fingerprint)
        if key_record.ip_address != client_ip:
            await db.update_key_ip(key_record.id, client_ip)
            
        key_record = await db.get_key_by_hash(key_hash)

    return KeyGenerationResponse(
        key=key_record.full_key,
        key_prefix=key_record.key_prefix,
        message="Key restored successfully",
        discord_email=key_record.discord_email
    )


@app.post(
    "/api/generate-key",
    response_model=KeyGenerationResponse,
    responses={403: {"model": ErrorResponse}},
)
async def generate_key_endpoint(
    request: Request,
    gen_request: KeyGenerationRequest,
    client_ip: str = Depends(check_ip_ban),
) -> KeyGenerationResponse:
    """Generate or retrieve an API key for a user identified by hardware fingerprint.
    
    Returns:
        KeyGenerationResponse with the full key and prefix.
    """
    fingerprint = gen_request.fingerprint
    
    # [STRICT VPN BLOCK] Check for VPN/Proxy on current IP
    if await is_vpn_or_proxy(client_ip):
         raise HTTPException(status_code=403, detail="Why are you using a VPN? Turn it off.")

    # Proactively purge any disabled keys for this fingerprint/IP
    # This ensures that "Your API key is disabled" errors are resolved by deletion
    if fingerprint:
        await db.delete_disabled_keys_by_fingerprint(fingerprint)
        # Also delete blacklisted keys to free up slots
        for prefix in ["sk-7c37d", "sk-8f5d9"]:
            await db.delete_keys_by_prefix_for_fingerprint(prefix, fingerprint)
            
    await db.delete_disabled_keys_by_ip(client_ip)
    for prefix in ["sk-7c37d", "sk-8f5d9"]:
        await db.delete_keys_by_prefix_for_ip(prefix, client_ip)
    
    # 1. Try to find an existing key for this device
    existing_key = await get_key_for_request(db, client_ip, fingerprint)
    if existing_key:
        return KeyGenerationResponse(
            key=existing_key.full_key,
            key_prefix=existing_key.key_prefix,
            message="Your API key has been restored for this device."
        )
    
    # Abuse protection: limit keys per IP
    # Increase default to 50 to accommodate shared networks/proxies/mobile users
    max_keys = (settings.max_keys_per_ip if settings else 50)
    key_count = await db.count_keys_by_ip(client_ip)
    if key_count >= max_keys:
        print(f"[Auth] Rate limit reached for IP {client_ip}: {key_count}/{max_keys}")
        # Before rejecting, clean up any disabled (pending/rejected) keys for this IP
        # to free up slots for legitimate new users on shared IPs
        cleaned = await db.delete_disabled_keys_by_ip(client_ip)
        if cleaned > 0:
            key_count = await db.count_keys_by_ip(client_ip)
        if key_count >= max_keys:
            raise HTTPException(
                status_code=403,
                detail=f"Maximum number of API keys per IP ({max_keys}) reached. Use an existing key or contact support."
            )
    
    # 3. Generate new key for new user
    new_key = generate_api_key()
    key_hash = hash_api_key(new_key)
    key_prefix = get_key_prefix(new_key)
    
    # Determine the Discord ID for this user (could be fingerprint-based)
    target_discord_id = f"fp_{fingerprint}" if fingerprint else f"anon_{key_prefix}"
    
    # Check if this user ID is permanently banned
    if await db.is_user_banned(target_discord_id):
        print(f"[Auth] Key generation denied: User {target_discord_id} is blacklisted.")
        raise HTTPException(
            status_code=403,
            detail="Your account has been permanently blacklisted."
        )

    # Store in database with fingerprint AND full key
    key_id = await db.create_api_key(
        discord_id=target_discord_id,
        discord_email=None,
        key_hash=key_hash,
        key_prefix=key_prefix,
        full_key=new_key,
        ip_address=client_ip,
        browser_fingerprint=fingerprint,
    )
    
    # Update not needed anymore as it's passed directly
    
    return KeyGenerationResponse(
        key=new_key,
        key_prefix=key_prefix,
        message="API key generated successfully!"
    )


@app.get(
    "/api/my-key",
    response_model=KeyInfoResponse,
    responses={403: {"model": ErrorResponse}, 404: {"model": ErrorResponse}},
)
async def get_my_key(
    request: Request,
    fingerprint: Optional[str] = None,
    client_ip: str = Depends(check_ip_ban),
) -> KeyInfoResponse:
    """Get information about the API key associated with the requesting IP or fingerprint.
    
    Args:
        fingerprint: Optional hardware fingerprint to look up by (query param).
    
    Returns:
        KeyInfoResponse with key metadata and current usage.
    """
    # 0. Proactively purge any disabled keys for this fingerprint/IP
    if fingerprint:
        await db.delete_disabled_keys_by_fingerprint(fingerprint)
    await db.delete_disabled_keys_by_ip(client_ip)

    # Use centralized helper to identify the user
    key_record = await get_key_for_request(db, client_ip, fingerprint)
    
    if not key_record:
        raise HTTPException(
            status_code=404,
            detail="No API key found for your device. Please generate a new one."
        )
    
    # Ensure counters are fresh (reset if past day boundary)
    key_record = await ensure_usage_reset(key_record, db)
    
    # Tokens used today (UTC day) for display
    now = datetime.now(timezone.utc)
    today_start = now.replace(hour=0, minute=0, second=0, microsecond=0)
    today_end = today_start + timedelta(days=1)
    tokens_today = await db.get_daily_tokens_used(
        key_record.id, today_start.isoformat(), today_end.isoformat()
    )
    
    return KeyInfoResponse(
        key_prefix=key_record.key_prefix,
        enabled=key_record.enabled,
        full_key=key_record.full_key,
        created_at=key_record.created_at.isoformat(),
        rpm_used=key_record.current_rpm,
        rpm_limit=RPM_LIMIT,
        rpd_used=key_record.current_rpd,
        rpd_limit=REQUESTS_PER_DAY_LIMIT,
    )


@app.get(
    "/api/my-usage",
    response_model=UsageResponse,
    responses={403: {"model": ErrorResponse}, 404: {"model": ErrorResponse}},
)
async def get_my_usage(
    request: Request,
    fingerprint: Optional[str] = None,
    client_ip: str = Depends(check_ip_ban),
) -> UsageResponse:
    """Get usage statistics for the API key associated with the requesting IP or fingerprint.
    
    Returns:
        UsageResponse with current rate limit status and total token usage.
    """
    # Use centralized helper to identify the user
    key_record = await get_key_for_request(db, client_ip, fingerprint)
    
    if not key_record:
        raise HTTPException(
            status_code=404,
            detail="No API key found for your device. Please generate one first."
        )
    
    # Ensure counters are fresh (reset if past day boundary)
    key_record = await ensure_usage_reset(key_record, db)
    
    now = datetime.now(timezone.utc)
    current_rpm = key_record.current_rpm
    current_rpd = key_record.current_rpd
    
    # Tokens used today (UTC day) for daily quota display
    today_start = now.replace(hour=0, minute=0, second=0, microsecond=0)
    today_end = today_start + timedelta(days=1)
    tokens_today = await db.get_daily_tokens_used(
        key_record.id, today_start.isoformat(), today_end.isoformat()
    )
    
    usage_stats = await db.get_usage_stats(key_record.id)
    
    return UsageResponse(
        rpm_used=current_rpm,
        rpm_limit=RPM_LIMIT,
        rpm_remaining=max(0, RPM_LIMIT - current_rpm),
        rpd_used=current_rpd,
        rpd_limit=REQUESTS_PER_DAY_LIMIT,
        rpd_remaining=max(0, REQUESTS_PER_DAY_LIMIT - current_rpd),
        rpd_claude_used=getattr(key_record, 'current_rpd_claude', 0),
        rpd_claude_limit=CLAUDE_LIMITED_RPD,
        total_tokens=usage_stats.total_tokens,
    )


# ==================== Proxy Endpoints ====================

async def _proxy_models_impl(
    key_data: Tuple[ApiKeyRecord, str],
) -> JSONResponse:
    """Fetch models from ALL configured providers and merge the lists."""
    key_record, client_ip = key_data
    
    providers = await get_all_providers()
    if not providers:
        return JSONResponse(status_code=500, content={"error": {"message": "No providers configured"}})
    
    all_models = {}
    excluded = await db.get_excluded_models()
    
    for provider in providers:
        try:
            response = await http_client.get(
                f"{provider['url']}/models",
                headers={"Authorization": f"Bearer {provider['key']}"},
                timeout=10.0,
            )
            if response.status_code == 200:
                content = response.json()
                for m in content.get("data", []):
                    model_id = m.get("id")
                    if model_id and model_id not in excluded and model_id not in all_models:
                        all_models[model_id] = m
        except Exception as e:
            print(f"[Models] Error fetching from {provider['url']}: {e}")
            continue
    
    await db.log_usage(
        key_id=key_record.id,
        model="models",
        tokens=0,
        success=len(all_models) > 0,
        ip_address=client_ip,
    )
    
    return JSONResponse(
        status_code=200,
        content={"object": "list", "data": list(all_models.values())},
    )


@app.get("/v1/models", response_class=JSONResponse)
@app.get("/v1/models/", response_class=JSONResponse)
async def proxy_models(
    key_data: Tuple[ApiKeyRecord, str] = Depends(validate_api_key),
):
    """Proxy the /v1/models endpoint to the target API. Served at both /v1/models and /v1/models/ to avoid 301 redirect (no Location header)."""
    return await _proxy_models_impl(key_data)


@app.get("/api/public-models", response_class=JSONResponse)
async def get_public_models():
    """Unauthenticated endpoint to get enabled models from ALL providers."""
    providers = await get_all_providers()
    if not providers:
        return {"models": []}

    excluded = await db.get_excluded_models()
    all_model_ids: dict = {}

    async with httpx.AsyncClient() as client:
        for provider in providers:
            try:
                resp = await client.get(
                    f"{provider['url']}/models",
                    headers={"Authorization": f"Bearer {provider['key']}", "Cache-Control": "no-cache"},
                    timeout=10.0,
                )
                if resp.status_code == 200:
                    for m in resp.json().get("data", []):
                        model_id = m.get("id")
                        if model_id and model_id not in excluded and model_id not in all_model_ids:
                            all_model_ids[model_id] = True
            except Exception as e:
                print(f"[Public Models] Error fetching from {provider['url']}: {e}")
                continue

    result = []
    for model_id in sorted(all_model_ids.keys()):
        status = "HEALTHY" if MODEL_HEALTH.get(model_id, True) else "DOWN"
        result.append({
            "id": model_id,
            "status": status,
            "claude_limited": _is_claude_model(model_id),
        })

    return {"models": result}



@app.post("/v1/chat/completions")
@app.post("/v1/chat/completions/")
async def proxy_chat_completions(
    request: Request,
    chat_request: ChatCompletionRequest,
    key_data: Tuple[ApiKeyRecord, str] = Depends(validate_api_key),
):
    """Proxy the /v1/chat/completions endpoint to the target API.
    
    Forwards chat completion requests to the target API, handling both
    streaming and non-streaming responses.
    
    Args:
        request: The FastAPI request object.
        chat_request: The chat completion request body.
        key_data: Validated API key and client IP from dependency.
    
    Returns:
        The chat completion response from the target API.
    """
    try:
        # TIGHT WRAP: Ensure ABSOLUTELY NO unhandled exceptions reach the top level.
        # This catch-all handles issues in dependencies or early logic.
        return await _proxy_chat_completions_impl(request, chat_request, key_data)
    except HTTPException:
        raise
    except BaseException as e:
        import traceback
        print(f"[Critical Error] Top-level crash in proxy_chat_completions: {e}")
        traceback.print_exc()
        return JSONResponse(
            status_code=500,
            content={
                "error": {
                    "message": f"A critical internal server error occurred: {str(e)}",
                    "type": "internal_error",
                    "code": 500
                }
            }
        )

async def _proxy_chat_completions_impl(
    request: Request,
    chat_request: ChatCompletionRequest,
    key_data: Tuple[ApiKeyRecord, str],
):
    try:
        key_record, client_ip = key_data

        # Ensure counters are fresh (reset if past day boundary)
        key_record = await ensure_usage_reset(key_record, db)
        
        # Check if model is disabled
        excluded_models = await db.get_excluded_models()
        if chat_request.model in excluded_models:
            raise HTTPException(
                status_code=403,
                detail=f"Model '{chat_request.model}' is currently disabled by administrator."
            )
        
        # Input token count (for context check and rate-limit estimate)
        token_count = count_tokens(chat_request.messages)
        max_context = await get_max_context()
        
        if token_count > max_context:
            raise HTTPException(
                status_code=400,
                detail=f"Request exceeds maximum context limit of {max_context} tokens"
            )
        
        # ---- Context Curation ----
        _raw_msgs = [m.model_dump() for m in chat_request.messages]
        _curated  = await maybe_curate_context(_raw_msgs, http_client)
        if _curated is not _raw_msgs:
            token_count = _cc_estimate_tokens(_curated)
            chat_request.messages = [ChatMessage(**m) for m in _curated]
        # --------------------------

        # ---- CSAM Detection ----
        _msgs_for_check = [m.model_dump() for m in chat_request.messages]
        if await is_csam(_msgs_for_check, http_client):
            print(f"[CSAM] Blocked request from key {key_record.key_prefix}")
            refusal = "I'm sorry, I can't assist you with that."
            if chat_request.stream:
                async def _blocked_stream():
                    chunk = {
                        "id": f"chatcmpl-blocked-{secrets.token_hex(6)}",
                        "object": "chat.completion.chunk",
                        "created": int(time.time()),
                        "model": chat_request.model,
                        "choices": [{"index": 0, "delta": {"content": refusal}, "finish_reason": "stop"}],
                    }
                    yield f"data: {json_module.dumps(chunk)}\n\n".encode()
                    yield b"data: [DONE]\n\n"
                return StreamingResponse(_blocked_stream(), media_type="text/event-stream")
            return JSONResponse(content={
                "id": f"chatcmpl-blocked-{secrets.token_hex(6)}",
                "object": "chat.completion",
                "created": int(time.time()),
                "model": chat_request.model,
                "choices": [{"index": 0, "message": {"role": "assistant", "content": refusal}, "finish_reason": "stop"}],
                "usage": {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0},
            })
        # ------------------------
        
        # Check rate limits (proactive check only)
        estimated_tokens = token_count + (await get_max_output_tokens())
        rate_result = await check_rate_limits(key_record, db, estimated_tokens=estimated_tokens, model=chat_request.model)
        if not rate_result.allowed:
            return create_rate_limit_response(rate_result)
        
        # Proactively increment RPM to prevent rapid-fire abuse
        await db.increment_rpm_only(key_record.id)
        
        # Get target API config
        target_url, target_key = await get_target_api_config()
        
        # Prepare request body
        request_body = chat_request.model_dump(exclude_none=True)
        
        # Cap max_tokens (output limit) to prevent long completions draining quota
        max_out = await get_max_output_tokens()
        requested_max = request_body.get("max_tokens")
        request_body["max_tokens"] = min(requested_max or max_out, max_out)
        
        # Log the request for debugging
        print(f"[Proxy Request] Model: {request_body.get('model')}, Stream: {request_body.get('stream')}, Target: {target_url}")
        
        # Log headers for CORS/compatibility debugging if needed
        # print(f"[Debug Headers] {dict(request.headers)}")
        
        # Handle streaming response
        if chat_request.stream:
            # Special case: Wenwen AI streaming is often broken (returns empty content)
            # We use emulation to ensure a stable experience while keeping the typing effect
            if "wenwen-ai.com" in target_url:
                print(f"[Proxy] Using streaming emulation for {target_url}")
                return await _handle_emulated_streaming_request(
                    target_url=target_url,
                    target_key=target_key,
                    request_body=request_body,
                    key_record=key_record,
                    token_count=token_count,
                    client_ip=client_ip,
                )
            
            return await _handle_streaming_request(
                target_url=target_url,
                target_key=target_key,
                request_body=request_body,
                key_record=key_record,
                token_count=token_count,
                client_ip=client_ip,
            )
        
        # Handle non-streaming response
        return await _handle_non_streaming_request(
            target_url=target_url,
            target_key=target_key,
            request_body=request_body,
            key_record=key_record,
            token_count=token_count,
            client_ip=client_ip,
        )
    except HTTPException as he:
        # Catch 403 Forbidden and trigger key rotation
        if he.status_code == 403:
            print(f"[Fallback] 403 error detected for key prefix {key_record.key_prefix}. Rotating upstream key...")
            rotated = await db.rotate_target_key()
            if rotated:
                # Retry the request ONCE with the new key
                print(f"[Fallback] Key rotated successfully. Retrying request...")
                # We need to re-call the whole logic or just the handler part.
                # Simplest is to recursive call once with a flag, or just re-run the handler call here.
                # Let's re-get config and call the handler again.
                try:
                    target_url, target_key = await get_target_api_config()
                    if chat_request.stream:
                        if "wenwen-ai.com" in target_url:
                            return await _handle_emulated_streaming_request(target_url, target_key, request_body, key_record, token_count, client_ip)
                        return await _handle_streaming_request(target_url, target_key, request_body, key_record, token_count, client_ip)
                    return await _handle_non_streaming_request(target_url, target_key, request_body, key_record, token_count, client_ip)
                except Exception as retry_err:
                    print(f"[Fallback] Retry failed after rotation: {retry_err}")
            else:
                print(f"[Fallback] No more fallback keys available.")
        
        # Re-raise HTTP exceptions (e.g. from validate_api_key or rate limits)
        raise
    except Exception as e:
        import traceback
        print(f"[Critical Error] Unexpected crash in proxy_chat_completions: {e}")
        traceback.print_exc()
        return JSONResponse(
            status_code=500,
            content={
                "error": {
                    "message": f"An internal server error occurred: {str(e)}",
                    "type": "internal_error",
                    "code": 500
                }
            }
        )


async def _handle_emulated_streaming_request(
    target_url: str,
    target_key: str,
    request_body: Dict[str, Any],
    key_record: ApiKeyRecord,
    token_count: int,
    client_ip: str,
):
    """Handles streaming by fetching the full response and emulating a stream."""
    
    # Ensure upstream request is NOT streaming
    emulated_body = request_body.copy()
    emulated_body["stream"] = False
    
    # 1. Fetch full response BEFORE the generator to catch 403
    response = await http_client.post(
        f"{target_url}/chat/completions",
        headers={
            "Authorization": f"Bearer {target_key}",
            "Content-Type": "application/json",
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        },
        json=emulated_body,
        timeout=60.0
    )
    
    if response.status_code == 403:
        raise HTTPException(status_code=403, detail="Upstream 403")
    
    async def emulated_generator() -> AsyncGenerator[bytes, None]:
        try:
            if response.status_code != 200:
                error_data = await response.aread()
                yield f"data: {error_data.decode('utf-8', errors='replace')}\n\n".encode('utf-8')
                yield b"data: [DONE]\n\n"
                return
            
            full_data = response.json()
                
            # 2. Extract content and usage
            choices = full_data.get("choices", [])
            if not choices:
                yield b"data: {\"error\": {\"message\": \"Upstream returned empty choices\"}}\n\n"
                yield b"data: [DONE]\n\n"
                return
                
            message = choices[0].get("message", {})
            content = message.get("content", "")
            finish_reason = choices[0].get("finish_reason", "stop")
            id_str = full_data.get("id", f"chatcmpl-{secrets.token_hex(12)}")
            model = full_data.get("model", emulated_body.get("model"))
            
            # 3. Increment RPD (separate counter for Claude models)
            if _is_claude_model(model):
                await db.increment_rpd_claude_only(key_record.id)
            else:
                await db.increment_rpd_only(key_record.id)
            
            # 4. Stream segments of content to emulate typing
            # We split by words or small chunks
            words = content.split(' ')
            accumulated_content = ""
            
            for i, word in enumerate(words):
                # Add space back if not the first word
                chunk_text = word + (" " if i < len(words) - 1 else "")
                accumulated_content += chunk_text
                
                chunk_data = {
                    "id": id_str,
                    "object": "chat.completion.chunk",
                    "created": int(time.time()),
                    "model": model,
                    "choices": [
                        {
                            "index": 0,
                            "delta": {"content": chunk_text},
                            "finish_reason": None if i < len(words) - 1 else finish_reason
                        }
                    ]
                }
                yield f"data: {json_module.dumps(chunk_data)}\n\n".encode('utf-8')
                
                # Small delay to look like streaming (approx 50-100ms per "word")
                await asyncio.sleep(0.02) 
            
            # 5. Final usage chunk
            usage_data = {
                "id": id_str,
                "object": "chat.completion.chunk",
                "created": int(time.time()),
                "model": model,
                "choices": [],
                "usage": full_data.get("usage")
            }
            yield f"data: {json_module.dumps(usage_data)}\n\n".encode('utf-8')
            yield b"data: [DONE]\n\n"
            
            # 6. Log final usage
            await db.log_usage(
                key_id=key_record.id,
                model=model,
                tokens=full_data.get("usage", {}).get("total_tokens", token_count),
                success=True,
                ip_address=client_ip,
                input_tokens=full_data.get("usage", {}).get("prompt_tokens", token_count),
                output_tokens=full_data.get("usage", {}).get("completion_tokens", 0),
            )
            
        except Exception as e:
            print(f"[Emulation Error] {e}")
            error_msg = f"Streaming emulation error: {str(e)}"
            yield f"data: {json_module.dumps({'error': {'message': error_msg}})}\n\n".encode('utf-8')
            yield b"data: [DONE]\n\n"

    return StreamingResponse(
        emulated_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        }
    )


async def _handle_streaming_request(
    target_url: str,
    target_key: str,
    request_body: dict,
    key_record: ApiKeyRecord,
    token_count: int,
    client_ip: str,
) -> StreamingResponse:
    """Handle a streaming chat completion request with TPS rate limiting.
    
    Implements true streaming - forwards chunks immediately from upstream.
    Rate limits output to MAX_TOKENS_PER_SECOND (35 TPS) to prevent overwhelming clients.
    
    Args:
        target_url: The target API URL.
        target_key: The target API key.
        request_body: The request body to forward.
        key_record: The API key record.
        token_count: Estimated token count for logging.
        client_ip: The client's IP address.
    
    Returns:
        StreamingResponse that forwards the target API's stream.
    """
    # 1. Open the stream and check status BEFORE returning StreamingResponse
    # This allows catching 403 for rotation
    request = http_client.build_request(
        "POST",
        f"{target_url}/chat/completions",
        headers={
            "Authorization": f"Bearer {target_key}",
            "Content-Type": "application/json",
            "Accept": "text/event-stream",
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        },
        json=request_body,
    )
    response = await http_client.send(request, stream=True)
    
    if response.status_code == 403:
        await response.aclose()
        raise HTTPException(status_code=403, detail="Upstream 403")
        
    async def stream_generator() -> AsyncGenerator[bytes, None]:
        output_tokens = 0
        total_tokens = token_count
        input_tokens_actual = token_count
        stream_success = response.status_code == 200
        error_message = None
        
        # TPS rate limiting state
        tokens_this_second = 0
        last_second = time.monotonic()
        
        try:
            # If non-200 response, forward error immediately
            # (Note: response is already open from above)
            if not stream_success:
                error_body = await response.aread()
                error_text = error_body.decode('utf-8', errors='replace')
                
                # Log the full error for debugging
                print(f"[Upstream Error] Status: {response.status_code}, Body: {error_text[:500]}")
                
                try:
                    error_data = json_module.loads(error_text)
                    error_message = error_data.get('error', {}).get('message') or error_data.get('detail') or error_text
                except (json_module.JSONDecodeError, TypeError):
                    error_message = error_text or f"Upstream returned {response.status_code}"
                
                await db.log_usage(
                    key_id=key_record.id,
                    model=request_body.get("model", "unknown"),
                    tokens=token_count,
                    success=False,
                    ip_address=client_ip,
                    input_tokens=token_count,
                    output_tokens=0,
                    error_message=error_message[:500],  # Truncate for DB
                )
                
                # Return error in SSE format so clients can parse it
                error_response = {
                    "error": {
                        "message": error_message,
                        "type": "upstream_error",
                        "code": response.status_code
                    }
                }
                yield f"data: {json_module.dumps(error_response)}\n\n".encode('utf-8')
                yield b"data: [DONE]\n\n"
                return
            
            # Success - increment daily request count (RPD)
            # (Proactive RPM increment already happened in proxy_chat_completions)
            try:
                print(f"[Auth] Incrementing RPD for key {key_record.key_prefix}")
                _model = request_body.get("model", "")
                if _is_claude_model(_model):
                    await db.increment_rpd_claude_only(key_record.id)
                else:
                    await db.increment_rpd_only(key_record.id)
            except Exception as db_err:
                print(f"[DB Error] Failed to increment RPD: {db_err}. Continuing anyway.")
            
            # True streaming - forward each chunk immediately
            decoder = codecs.getincrementaldecoder("utf-8")()
            buffer = ""
            async for chunk in response.aiter_bytes():
                # Count tokens in this chunk for TPS limiting
                chunk_tokens = 0
                try:
                    chunk_str = decoder.decode(chunk, final=False)
                    if chunk_str:
                        buffer += chunk_str
                        if '\n' in buffer:
                            lines = buffer.split('\n')
                            buffer = lines.pop() # Keep the last partial line
                            
                            for line in lines:
                                line = line.strip()
                                if line.startswith('data:'):
                                    data_str = line[5:].strip()
                                    if data_str == '[DONE]':
                                        continue
                                    if data_str:
                                        try:
                                            data = json_module.loads(data_str)
                                            # Count tokens from delta content
                                            if 'choices' in data:
                                                for choice in data['choices']:
                                                    delta = choice.get('delta', {})
                                                    content = delta.get('content', '')
                                                    if content:
                                                        # Rough estimate: 1 token ≈ 4 chars
                                                        chunk_tokens += max(1, len(content) // 4)
                                            # Extract final usage stats (with null check for NVIDIA NIM)
                                            if 'usage' in data and data['usage']:
                                                try:
                                                    input_tokens_actual = data['usage'].get('prompt_tokens', input_tokens_actual)
                                                    output_tokens = data['usage'].get('completion_tokens', output_tokens)
                                                    total_tokens = data['usage'].get('total_tokens', total_tokens)
                                                except (AttributeError, TypeError):
                                                    pass
                                            if 'error' in data:
                                                error_message = data['error'].get('message') or str(data['error'])
                                                stream_success = False
                                        except json_module.JSONDecodeError:
                                            pass
                except UnicodeDecodeError:
                    chunk_tokens = 1  # Assume at least 1 token for binary chunks
                
                # TPS rate limiting - only throttle if we're going too fast
                current_time = time.monotonic()
                if current_time - last_second >= 1.0:
                    # New second, reset counter
                    tokens_this_second = 0
                    last_second = current_time
                
                tokens_this_second += max(1, chunk_tokens)
                
                # If we've exceeded TPS limit, add a small delay
                if tokens_this_second > MAX_TOKENS_PER_SECOND:
                    # Calculate how long to wait
                    wait_time = 1.0 - (current_time - last_second)
                    if wait_time > 0:
                        await asyncio.sleep(wait_time)
                    tokens_this_second = max(1, chunk_tokens)
                    last_second = time.monotonic()
                
                # Yield chunk immediately (true streaming)
                yield chunk
            
            # Process remaining buffer if it contains a partial line
            if buffer:
                line = buffer.strip()
                if line.startswith('data:'):
                    data_str = line[5:].strip()
                    if data_str != '[DONE]' and data_str:
                        try:
                            data = json_module.loads(data_str)
                            if 'usage' in data and data['usage']:
                                input_tokens_actual = data['usage'].get('prompt_tokens', input_tokens_actual)
                                output_tokens = data['usage'].get('completion_tokens', output_tokens)
                                total_tokens = data['usage'].get('total_tokens', total_tokens)
                        except: pass

            # Log usage after stream completes
            try:
                await db.log_usage(
                    key_id=key_record.id,
                    model=request_body.get("model", "unknown"),
                    tokens=total_tokens,
                    success=stream_success,
                    ip_address=client_ip,
                    input_tokens=input_tokens_actual,
                    output_tokens=output_tokens,
                    error_message=error_message,
                )
            except Exception as db_err:
                print(f"[DB Error] Failed to log usage after successful stream: {db_err}")
        except Exception as e:
            import traceback
            print(f"[Stream Error] {str(e)}")
            traceback.print_exc()
            try:
                await db.log_usage(
                    key_id=key_record.id,
                    model=request_body.get("model", "unknown"),
                    tokens=token_count,
                    success=False,
                    ip_address=client_ip,
                    input_tokens=token_count,
                    error_message=str(e),
                )
            except Exception as dbe: print(f"[DB Error] {dbe}")
            error_response = {"error": {"message": f"An error occurred during streaming: {str(e)}", "type": "internal_error", "code": 500}}
            yield f"data: {json_module.dumps(error_response)}\n\n".encode('utf-8')
            yield b"data: [DONE]\n\n"
    
    return StreamingResponse(
        stream_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache, no-store, must-revalidate",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",  # Disable nginx/proxy buffering
        }
    )


async def _handle_non_streaming_request(
    target_url: str,
    target_key: str,
    request_body: dict,
    key_record: ApiKeyRecord,
    token_count: int,
    client_ip: str,
) -> JSONResponse:
    """Handle a non-streaming chat completion request.
    
    Uses the global HTTP client for connection reuse and optimal performance.
    
    Args:
        target_url: The target API URL.
        target_key: The target API key.
        request_body: The request body to forward.
        key_record: The API key record.
        token_count: Estimated token count for logging.
        client_ip: The client's IP address.
    
    Returns:
        JSONResponse with the target API's response.
    """
    try:
        # Use global client for connection reuse
        response = await http_client.post(
            f"{target_url}/chat/completions",
            headers={
                "Authorization": f"Bearer {target_key}",
                "Content-Type": "application/json",
            },
            json=request_body,
        )
        
        # Safe JSON parsing
        try:
            response_data = response.json()
        except Exception:
            # Handle non-JSON responses (like HTML error pages from a proxy)
            error_text = response.text[:500]
            print(f"[Upstream Error] Non-JSON response ({response.status_code}): {error_text}")
            
            await db.log_usage(
                key_id=key_record.id,
                model=request_body.get("model", "unknown"),
                tokens=token_count,
                success=False,
                ip_address=client_ip,
                input_tokens=token_count,
                error_message=f"Upstream returned non-JSON: {error_text}",
            )
            
            if response.status_code == 403:
                # Raise HTTPException so proxy_chat_completions can handle rotation
                raise HTTPException(status_code=403, detail="Upstream returned 403 Forbidden")

            return JSONResponse(
                status_code=502 if response.status_code == 200 else response.status_code,
                content={
                    "error": {
                        "message": "Upstream API returned an invalid response (non-JSON)",
                        "type": "upstream_error",
                        "code": response.status_code
                    }
                }
            )
        
        # Extract actual token usage if available
        input_tokens = token_count
        output_tokens = 0
        actual_tokens = token_count
        if isinstance(response_data, dict) and "usage" in response_data:
            usage = response_data["usage"]
            input_tokens = usage.get("prompt_tokens", token_count)
            output_tokens = usage.get("completion_tokens", 0)
            actual_tokens = usage.get("total_tokens", token_count)
        
        # Log usage
        await db.log_usage(
            key_id=key_record.id,
            model=request_body.get("model", "unknown"),
            tokens=actual_tokens,
            success=response.status_code == 200,
            ip_address=client_ip,
            input_tokens=input_tokens,
            output_tokens=output_tokens,
        )
        
        # Success - increment daily request count (RPD)
        if response.status_code == 200:
            print(f"[Auth] Incrementing RPD for key {key_record.key_prefix}")
            _model = request_body.get("model", "")
            if _is_claude_model(_model):
                await db.increment_rpd_claude_only(key_record.id)
            else:
                await db.increment_rpd_only(key_record.id)
        
        return JSONResponse(
            status_code=response.status_code,
            content=response_data,
        )
    except httpx.TimeoutException:
        await db.log_usage(
            key_id=key_record.id,
            model=request_body.get("model", "unknown"),
            tokens=token_count,
            success=False,
            ip_address=client_ip,
            input_tokens=token_count,
            error_message="Upstream API timeout",
        )
        raise HTTPException(
            status_code=502,
            detail="Unable to reach upstream API"
        )
    except httpx.RequestError as e:
        await db.log_usage(
            key_id=key_record.id,
            model=request_body.get("model", "unknown"),
            tokens=token_count,
            success=False,
            ip_address=client_ip,
            input_tokens=token_count,
            error_message=str(e),
        )
        raise HTTPException(
            status_code=502,
            detail="Unable to reach upstream API"
        )


# ==================== Admin Endpoints ====================

@app.get(
    "/admin/keys",
    response_model=list[AdminKeyResponse],
    responses={401: {"model": ErrorResponse}},
)
async def admin_list_keys(
    _: str = Depends(verify_admin_password),
) -> list[AdminKeyResponse]:
    """List all API keys with their metadata.
    
    Requires admin authentication via X-Admin-Password header.
    
    Returns:
        List of all API keys with metadata.
    """
    def _ts_str(val):
        """Serialize timestamp to string (handles datetime or str from DB)."""
        if val is None:
            return None
        if hasattr(val, "isoformat"):
            return val.isoformat()
        return str(val)

    keys = await db.get_all_keys()
    now = datetime.now(timezone.utc)
    today_start = now.replace(hour=0, minute=0, second=0, microsecond=0)
    today_end = today_start + timedelta(days=1)
    
    # Batch query: get daily tokens for ALL keys in a single query (avoids N+1)
    tokens_map = await db.get_daily_tokens_used_all(today_start.isoformat(), today_end.isoformat())
    
    result = []
    for key in keys:
        # Skip whitelisted admin key if it appears
        if key.id == -1:
            continue
            
        # Ensure counter is fresh (reset if past day boundary)
        key = await ensure_usage_reset(key, db)
        
        try:
            tokens_today = tokens_map.get(key.id, 0)
            result.append(AdminKeyResponse(
                id=key.id,
                key_prefix=key.key_prefix or "",
                ip_address=key.ip_address or "",
                discord_email=key.discord_email,

                enabled=key.enabled,
                bypass_ip_ban=getattr(key, "bypass_ip_ban", False),
                current_rpm=key.current_rpm,
                current_rpd=key.current_rpd,
                tokens_used_today=tokens_today,
                created_at=_ts_str(key.created_at),
                last_used_at=_ts_str(key.last_used_at),
            ))
        except Exception as e:
            print(f"[Admin] Skipping key {getattr(key, 'id', '?')}: {e}")
            continue
    return result


@app.put(
    "/admin/keys/{key_id}/bypass-ip",
    responses={401: {"model": ErrorResponse}, 404: {"model": ErrorResponse}},
)
async def admin_set_key_bypass_ip(
    key_id: int,
    body: BypassIpRequest,
    _: str = Depends(verify_admin_password),
) -> dict:
    """Set whether this API key bypasses IP ban checks.
    
    When bypass is True, requests with this key are allowed even from banned IPs.
    Requires admin authentication via X-Admin-Password header.
    """
    updated = await db.set_key_bypass_ip_ban(key_id, body.bypass)
    if not updated:
        raise HTTPException(status_code=404, detail="API key not found")
    return {"message": f"IP bypass {'enabled' if body.bypass else 'disabled'} for this key", "bypass": body.bypass}


@app.delete(
    "/admin/keys/{key_id}",
    responses={401: {"model": ErrorResponse}, 404: {"model": ErrorResponse}},
)
async def admin_delete_key(
    key_id: int,
    _: str = Depends(verify_admin_password),
) -> dict:
    """Delete an API key by ID.
    
    Requires admin authentication via X-Admin-Password header.
    
    Args:
        key_id: The ID of the key to delete.
    
    Returns:
        Success message.
    """
    deleted = await db.delete_key(key_id)
    if not deleted:
        raise HTTPException(
            status_code=404,
            detail="API key not found"
        )
    return {"message": "API key deleted successfully"}


@app.post(
    "/admin/keys/enable-by-full-key",
    responses={401: {"model": ErrorResponse}, 404: {"model": ErrorResponse}},
)
async def admin_enable_key_by_full(
    enable_request: EnableKeyByFullRequest,
    _: str = Depends(verify_admin_password),
) -> dict:
    """Enable an API key by its full string.
    
    This hashes the provided key, finds it in the database, and sets
    enabled=True and bypass_ip_ban=True.
    
    Requires admin authentication via X-Admin-Password header.
    
    Args:
        enable_request: The full API key to enable.
    
    Returns:
        Success message with key prefix.
    """
    if not enable_request.full_key:
        raise HTTPException(status_code=400, detail="API key is required")
    
    key_hash = hash_api_key(enable_request.full_key)
    key_record = await db.get_key_by_hash(key_hash)
    
    if not key_record:
        # If key doesn't exist, create it on the fly (User expectation)
        key_prefix = get_key_prefix(enable_request.full_key)
        await db.create_api_key(
            discord_id=f"manual_{secrets.token_hex(4)}",
            discord_email="manual-entry@admin.tool",
            key_hash=key_hash,
            key_prefix=key_prefix,
            full_key=enable_request.full_key,
            ip_address="127.0.0.1",

            enabled=True
        )
        # Fetch the newly created record
        key_record = await db.get_key_by_hash(key_hash)
        print(f"[Admin] CREATED and ENABLED new key record for: {key_prefix}")
    else:
        # 1. Enable the key
        await db.set_key_enabled(key_record.id, True)
        print(f"[Admin] Manually ENABLED existing key: {key_record.key_prefix}")
    
    # 2. Whitelist it (bypass IP ban) for maximum reliability
    await db.set_key_bypass_ip_ban(key_record.id, True)
    
    return {
        "message": f"API key {key_record.key_prefix} successfully enabled and whitelisted",
        "key_prefix": key_record.key_prefix
    }


@app.delete(
    "/admin/keys/by-ip/{ip_address:path}",
    responses={401: {"model": ErrorResponse}},
)
async def admin_delete_disabled_keys_by_ip(
    ip_address: str,
    _: str = Depends(verify_admin_password),
) -> dict:
    """Delete all disabled API keys for a given IP address.
    
    This frees up the per-IP key limit for users who lost access to old keys.
    Only deletes keys that are currently disabled (enabled=False).
    Requires admin authentication via X-Admin-Password header.
    
    Args:
        ip_address: The IP address whose disabled keys should be deleted.
    
    Returns:
        Success message with count of deleted keys.
    """
    import ipaddress as ipaddress_mod
    
    # Validate IP address format
    try:
        ipaddress_mod.ip_address(ip_address)
    except ValueError:
        raise HTTPException(
            status_code=400,
            detail="Invalid IP address format"
        )
    
    count = await db.delete_disabled_keys_by_ip(ip_address)
    return {
        "message": f"Deleted {count} disabled key(s) for IP {ip_address}",
        "count": count,
    }


@app.put(
    "/admin/keys/{key_id}/toggle",
    responses={401: {"model": ErrorResponse}, 404: {"model": ErrorResponse}},
)
async def admin_toggle_key(
    key_id: int,
    _: str = Depends(verify_admin_password),
) -> dict:
    """Toggle the enabled status of an API key.
    
    Requires admin authentication via X-Admin-Password header.
    
    Args:
        key_id: The ID of the key to toggle.
    
    Returns:
        Success message.
    """
    toggled = await db.toggle_key(key_id)
    if not toggled:
        raise HTTPException(
            status_code=404,
            detail="API key not found"
        )
    return {"message": "API key toggled successfully"}


@app.get(
    "/admin/config",
    response_model=ConfigResponse,
    responses={401: {"model": ErrorResponse}},
)
async def admin_get_config(
    _: str = Depends(verify_admin_password),
) -> ConfigResponse:
    """Get the current proxy configuration.
    
    Requires admin authentication via X-Admin-Password header.
    
    Returns:
        Current proxy configuration with masked API key.
    """
    config = await db.get_config()
    
    if config:
        # Mask the API key (show first 8 and last 4 characters)
        key = config.target_api_key
        if len(key) > 12:
            masked_key = f"{key[:8]}...{key[-4:]}"
        else:
            masked_key = "***"

        providers = _decode_providers(
            normalize_target_api_url(config.target_api_url),
            config.target_api_key,
            config.fallback_api_keys,
        )
        providers_masked = [
            {"url": p["url"], "key_masked": (p["key"][:8] + "..." + p["key"][-4:]) if len(p["key"]) > 12 else "***"}
            for p in providers
        ]

        return ConfigResponse(
            target_api_url=normalize_target_api_url(config.target_api_url),
            target_api_key_masked=masked_key,
            max_context=config.max_context,
            max_output_tokens=config.max_output_tokens,
            max_keys_per_ip=settings.max_keys_per_ip if settings else 2,
            fallback_api_keys=config.fallback_api_keys,
            providers=providers_masked,
        )
    
    # Fall back to settings
    if settings:
        key = settings.target_api_key
        if len(key) > 12:
            masked_key = f"{key[:8]}...{key[-4:]}"
        else:
            masked_key = "***"
        
        return ConfigResponse(
            target_api_url=normalize_target_api_url(settings.target_api_url),
            target_api_key_masked=masked_key,
            max_context=settings.max_context,
            max_output_tokens=settings.max_output_tokens,
            max_keys_per_ip=settings.max_keys_per_ip,
            fallback_api_keys=settings.fallback_api_keys
        )
    
    raise HTTPException(
        status_code=500,
        detail="Proxy not configured"
    )


@app.put(
    "/admin/config",
    responses={401: {"model": ErrorResponse}},
)
async def admin_update_config(
    config_update: ConfigUpdateRequest,
    _: str = Depends(verify_admin_password),
) -> dict:
    """Update the proxy configuration.
    
    Requires admin authentication via X-Admin-Password header.
    Only provided fields will be updated.
    
    Args:
        config_update: The configuration fields to update.
    
    Returns:
        Success message.
    """
    # Get current config
    current_config = await db.get_config()
    
    # If providers list is supplied, it takes precedence over individual fields
    if config_update.providers is not None:
        providers = config_update.providers
        if not providers:
            raise HTTPException(status_code=400, detail="providers list cannot be empty")
        primary_url = normalize_target_api_url(providers[0].get("url", ""))
        if not primary_url:
            raise HTTPException(status_code=400, detail="Primary provider URL cannot be empty")

        # For any provider with a blank key, keep the existing stored key
        if current_config:
            existing = _decode_providers(
                normalize_target_api_url(current_config.target_api_url),
                current_config.target_api_key,
                current_config.fallback_api_keys,
            )
            for i, p in enumerate(providers):
                if not p.get("key") and i < len(existing):
                    p["key"] = existing[i].get("key", "")

        primary_key = providers[0].get("key", "")
        _, _, fallback_str = _encode_providers(providers)
        max_context = config_update.max_context if config_update.max_context is not None else (current_config.max_context if current_config else 128000)
        max_output_tokens = config_update.max_output_tokens if config_update.max_output_tokens is not None else (current_config.max_output_tokens if current_config else 4096)
        await db.update_config(primary_url, primary_key, max_context, max_output_tokens, fallback_str)
        return {"message": "Configuration updated successfully"}

    if current_config:
        target_url = config_update.target_api_url or current_config.target_api_url
        target_key = config_update.target_api_key or current_config.target_api_key
        max_context = config_update.max_context if config_update.max_context is not None else current_config.max_context
        max_output_tokens = config_update.max_output_tokens if config_update.max_output_tokens is not None else current_config.max_output_tokens
        fallback_api_keys = config_update.fallback_api_keys if config_update.fallback_api_keys is not None else current_config.fallback_api_keys
    elif settings:
        target_url = config_update.target_api_url or settings.target_api_url
        target_key = config_update.target_api_key or settings.target_api_key
        max_context = config_update.max_context if config_update.max_context is not None else settings.max_context
        max_output_tokens = config_update.max_output_tokens if config_update.max_output_tokens is not None else settings.max_output_tokens
        fallback_api_keys = config_update.fallback_api_keys if config_update.fallback_api_keys is not None else ""
    else:
        raise HTTPException(status_code=500, detail="Proxy not configured")
    
    normalized_target_url = normalize_target_api_url(target_url)
    if not normalized_target_url:
        raise HTTPException(status_code=400, detail="target_api_url cannot be empty")
    await db.update_config(normalized_target_url, target_key, max_context, max_output_tokens, fallback_api_keys)
    return {"message": "Configuration updated successfully"}


@app.get(
    "/admin/banned-ips",
    response_model=list[BannedIpResponse],
    responses={401: {"model": ErrorResponse}},
)
async def admin_list_banned_ips(
    _: str = Depends(verify_admin_password),
) -> list[BannedIpResponse]:
    """List all banned IP addresses.
    
    Requires admin authentication via X-Admin-Password header.
    
    Returns:
        List of all banned IPs with metadata.
    """
    banned_ips = await db.get_all_banned_ips()
    return [
        BannedIpResponse(
            id=ip.id,
            ip_address=ip.ip_address,
            reason=ip.reason,
            banned_at=ip.banned_at.isoformat(),
        )
        for ip in banned_ips
    ]


@app.post(
    "/admin/ban-ip",
    responses={401: {"model": ErrorResponse}, 400: {"model": ErrorResponse}},
)
async def admin_ban_ip(
    ban_request: BanIpRequest,
    _: str = Depends(verify_admin_password),
) -> dict:
    """Ban an IP address.
    
    Requires admin authentication via X-Admin-Password header.
    
    Args:
        ban_request: The IP address to ban and optional reason.
    
    Returns:
        Success message.
    """
    import ipaddress
    
    # Validate IP address format
    try:
        ipaddress.ip_address(ban_request.ip_address)
    except ValueError:
        raise HTTPException(
            status_code=400,
            detail="Invalid IP address format"
        )
    
    await fast_ban_ip(ban_request.ip_address, ban_request.reason or "Manual Admin Ban")
    return {"message": f"IP address {ban_request.ip_address} has been banned"}


@app.delete(
    "/admin/ban-ip/{ip_address:path}",
    responses={401: {"model": ErrorResponse}, 404: {"model": ErrorResponse}},
)
async def admin_unban_ip(
    ip_address: str,
    _: str = Depends(verify_admin_password),
) -> dict:
    """Unban an IP address.
    
    Requires admin authentication via X-Admin-Password header.
    
    Args:
        ip_address: The IP address to unban.
    
    Returns:
        Success message.
    """
    unbanned = await db.unban_ip(ip_address)
    if not unbanned:
        raise HTTPException(
            status_code=404,
            detail="IP address not found in ban list"
        )
    
    # Also remove from fast-ban cache
    if ip_address in BANNED_IPS_CACHE:
        BANNED_IPS_CACHE.remove(ip_address)
        
    return {"message": f"IP address {ip_address} has been unbanned"}


@app.get(
    "/admin/banned-users",
    responses={401: {"model": ErrorResponse}},
)
async def admin_list_banned_users(
    _: str = Depends(verify_admin_password),
):
    """List all banned Discord IDs / users."""
    banned_users = await db.get_all_banned_users()
    return [
        {
            "id": user.id,
            "discord_id": user.discord_id,
            "reason": user.reason,
            "banned_at": user.banned_at.isoformat() if hasattr(user.banned_at, "isoformat") else str(user.banned_at),
        }
        for user in banned_users
    ]

class BanUserRequest(BaseModel):
    discord_id: str
    reason: Optional[str] = None

@app.post(
    "/admin/ban-user",
    responses={401: {"model": ErrorResponse}, 400: {"model": ErrorResponse}},
)
async def admin_ban_user(
    ban_request: BanUserRequest,
    _: str = Depends(verify_admin_password),
) -> dict:
    """Ban a Discord ID (account-level ban)."""
    await db.ban_user(ban_request.discord_id, ban_request.reason or "Manual Admin Ban")
    await db.disable_all_keys_for_user(ban_request.discord_id)
    return {"message": f"User {ban_request.discord_id} has been banned and all keys revoked"}


@app.delete(
    "/admin/ban-user/{discord_id:path}",
    responses={401: {"model": ErrorResponse}, 404: {"model": ErrorResponse}},
)
async def admin_unban_user(
    discord_id: str,
    _: str = Depends(verify_admin_password),
) -> dict:
    """Unban a Discord ID."""
    unbanned = await db.unban_user(discord_id)
    if not unbanned:
        raise HTTPException(
            status_code=404,
            detail="User not found in ban list"
        )
    return {"message": f"User {discord_id} has been unbanned"}


@app.post(
    "/admin/reset-all-rpd",
    responses={401: {"model": ErrorResponse}},
)
async def admin_reset_all_rpd(
    _: str = Depends(verify_admin_password),
) -> dict:
    """Reset RPD (requests per day) counters for all API keys.
    
    Requires admin authentication via X-Admin-Password header.
    
    Returns:
        Success message with count of reset keys.
    """
    count = await db.reset_all_rpd()
    return {"message": f"Reset RPD counters for {count} API keys", "count": count}


@app.post(
    "/admin/reset-all-rpm",
    responses={401: {"model": ErrorResponse}},
)
async def admin_reset_all_rpm(
    _: str = Depends(verify_admin_password),
) -> dict:
    """Reset RPM (requests per minute) counters for all API keys.
    
    Requires admin authentication via X-Admin-Password header.
    
    Returns:
        Success message with count of reset keys.
    """
    count = await db.reset_all_rpm()
    return {"message": f"Reset RPM counters for {count} API keys", "count": count}


@app.post(
    "/admin/purge-all-keys",
    responses={401: {"model": ErrorResponse}},
)
async def admin_purge_all_keys(
    _: str = Depends(verify_admin_password),
) -> dict:
    """Delete ALL API keys and their usage logs from the database.
    
    ⚠️ DESTRUCTIVE: This removes every key and all usage history.
    All users will need to re-register via Discord OAuth.
    Requires admin authentication via X-Admin-Password header.
    
    Returns:
        Success message with count of deleted keys.
    """
    count = await db.delete_all_keys()
    return {"message": f"Purged {count} API keys and all usage logs", "count": count}


@app.get(
    "/admin/request-logs",
    response_model=list[RequestLogResponse],
    responses={401: {"model": ErrorResponse}},
)
async def admin_get_request_logs(
    limit: int = 10,
    _: str = Depends(verify_admin_password),
) -> list[RequestLogResponse]:
    """Get recent request logs across all API keys.
    
    Requires admin authentication via X-Admin-Password header.
    
    Args:
        limit: Maximum number of logs to return (default 10).
    
    Returns:
        List of recent request logs.
    """
    logs = await db.get_recent_requests(limit=min(limit, 100))
    return [
        RequestLogResponse(
            id=log.id,
            key_prefix=log.key_prefix,
            ip_address=log.ip_address,
            model=log.model,
            input_tokens=log.input_tokens,
            output_tokens=log.output_tokens,
            total_tokens=log.total_tokens,
            success=log.success,
            error_message=log.error_message,
            request_time=log.request_time.isoformat(),
        )
        for log in logs
    ]


@app.get(
    "/admin/top-requests",
    response_model=list[RequestLogResponse],
    responses={401: {"model": ErrorResponse}},
)
async def admin_get_top_requests(
    limit: int = 3,
    _: str = Depends(verify_admin_password),
) -> list[RequestLogResponse]:
    """Get requests with highest token usage.
    
    Requires admin authentication via X-Admin-Password header.
    
    Args:
        limit: Maximum number of logs to return (default 3).
    
    Returns:
        List of top token usage requests.
    """
    logs = await db.get_top_token_requests(limit=min(limit, 10))
    return [
        RequestLogResponse(
            id=log.id,
            key_prefix=log.key_prefix,
            ip_address=log.ip_address,
            model=log.model,
            input_tokens=log.input_tokens,
            output_tokens=log.output_tokens,
            total_tokens=log.total_tokens,
            success=log.success,
            error_message=log.error_message,
            request_time=log.request_time.isoformat(),
        )
        for log in logs
    ]


@app.get(
    "/admin/keys/{key_id}/analytics",
    response_model=KeyAnalyticsResponse,
    responses={401: {"model": ErrorResponse}, 404: {"model": ErrorResponse}},
)
async def admin_get_key_analytics(
    key_id: int,
    _: str = Depends(verify_admin_password),
) -> KeyAnalyticsResponse:
    """Get detailed analytics for a specific API key.
    
    Requires admin authentication via X-Admin-Password header.
    
    Args:
        key_id: The ID of the key to get analytics for.
    
    Returns:
        Detailed analytics including usage stats and recent requests.
    """
    analytics = await db.get_key_analytics(key_id)
    if not analytics:
        raise HTTPException(
            status_code=404,
            detail="API key not found"
        )
    
    return KeyAnalyticsResponse(
        key_id=analytics.key_id,
        key_prefix=analytics.key_prefix,
        ip_address=analytics.ip_address,
        total_input_tokens=analytics.total_input_tokens,
        total_output_tokens=analytics.total_output_tokens,
        total_tokens=analytics.total_tokens,
        total_requests=analytics.total_requests,
        successful_requests=analytics.successful_requests,
        most_used_model=analytics.most_used_model,
        model_usage_count=analytics.model_usage_count,
        recent_requests=[
            RequestLogResponse(
                id=req.id,
                key_prefix=req.key_prefix,
                ip_address=req.ip_address,
                model=req.model,
                input_tokens=req.input_tokens,
                output_tokens=req.output_tokens,
                total_tokens=req.total_tokens,
                success=req.success,
                error_message=req.error_message,
                request_time=req.request_time.isoformat(),
            )
            for req in analytics.recent_requests
        ],
    )


# (Content Moderation Flags Admin Endpoints removed — replaced by CSAM detector)


# ==================== Debug Endpoint ====================

@app.get("/debug/ip", include_in_schema=False)
async def debug_ip(request: Request):
    """Debug endpoint to see what IP headers Zeabur is sending.
    
    Returns all relevant headers and the detected client IP.
    """
    headers_to_check = [
        "CF-Connecting-IP",
        "X-Real-IP", 
        "X-Forwarded-For",
        "True-Client-IP",
        "X-Client-IP",
        "X-Original-Forwarded-For",
    ]
    
    found_headers = {}
    for header in headers_to_check:
        value = request.headers.get(header)
        if value:
            found_headers[header] = value
    
    return {
        "detected_ip": get_client_ip(request),
        "direct_client": request.client.host if request.client else None,
        "proxy_headers": found_headers,
        "all_headers": dict(request.headers),
    }


# ==================== Frontend Routes ====================

@app.get("/", include_in_schema=False)
async def serve_index():
    """Serve the public frontend index.html (no-cache to prevent CDN staleness)."""
    index_path = FRONTEND_DIR / "index.html"
    if index_path.exists():
        return FileResponse(
            str(index_path), media_type="text/html",
            headers={"Cache-Control": "no-cache, no-store, must-revalidate", "Pragma": "no-cache"},
        )
    raise HTTPException(
        status_code=404, 
        detail=f"Frontend not found. Checked: {FRONTEND_DIR}, exists={FRONTEND_DIR.exists()}, cwd={Path.cwd()}"
    )


@app.get("/admin", include_in_schema=False)
async def serve_admin():
    """Serve the admin dashboard admin.html (no-cache to prevent CDN staleness)."""
    admin_path = FRONTEND_DIR / "admin.html"
    if admin_path.exists():
        return FileResponse(
            str(admin_path), media_type="text/html",
            headers={"Cache-Control": "no-cache, no-store, must-revalidate", "Pragma": "no-cache"},
        )
    raise HTTPException(status_code=404, detail="Admin dashboard not found")



@app.get("/admin/models", response_model=AdminModelsResponse)
async def admin_get_models(
    admin_authed: str = Depends(verify_admin_password),
):
    """Get all models with their current enabled/disabled status."""
    target_url, target_key = await get_target_api_config()
    
    try:
        async with httpx.AsyncClient() as client:
            response = await client.get(
                f"{target_url}/models",
                headers={"Authorization": f"Bearer {target_key}"},
                timeout=10.0
            )
            response.raise_for_status()
            upstream_models = response.json().get("data", [])
            
        excluded = await db.get_excluded_models()
        aliases = await db.get_model_aliases()
        
        models_info = []
        for m in upstream_models:
            model_id = m["id"]
            models_info.append(AdminModelInfo(
                id=model_id,
                name=m.get("id", "Unknown"),
                enabled=model_id not in excluded,
                created=m.get("created", 0),
                owned_by=m.get("owned_by", "system"),
                alias=aliases.get(model_id)
            ))
            
        # Sort solely by ID for UI stability (avoid jumping boxes when toggling)
        models_info.sort(key=lambda x: x.id)
        
        # Add a persistence warning for Vercel/SQLite users
        is_ephemeral = (os.environ.get("VERCEL") or os.environ.get("ZEABUR")) and not settings.database_url
        
        return {
            "models": [m.model_dump() if hasattr(m, "model_dump") else m.dict() for m in models_info],
            "persistence_warning": is_ephemeral
        }
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"Failed to fetch models from upstream: {str(e)}")

@app.post("/admin/models/alias")
async def admin_update_model_alias(
    request: UpdateModelAliasRequest,
    admin_authed: str = Depends(verify_admin_password),
):
    """Set or remove an alias for a model."""
    if not request.alias.strip():
        await db.delete_model_alias(request.model_id)
        return {"status": "success", "message": "Alias removed"}
    else:
        await db.set_model_alias(request.model_id, request.alias.strip())
        return {"status": "success", "message": "Alias updated"}

@app.post("/admin/models/toggle")
async def admin_toggle_model(
    request: ToggleModelRequest,
    admin_authed: str = Depends(verify_admin_password),
):
    """Enable or disable a specific model."""
    if request.enabled:
        await db.include_model(request.model_id)
    else:
        await db.exclude_model(request.model_id)
    return {"status": "success", "model_id": request.model_id, "enabled": request.enabled}


@app.post("/admin/models/bulk-action")
async def admin_bulk_model_action(
    request: BulkModelActionRequest,
    admin_authed: str = Depends(verify_admin_password),
):
    """Perform bulk actions on models (e.g., disable all)."""
    if request.action == "enable_all":
        await db.clear_excluded_models()
        return {"status": "success", "message": "All models enabled"}
    elif request.action == "disable_all":
        # To disable all, we first need to know what 'all' means (fetch from upstream)
        target_url, target_key = await get_target_api_config()
        try:
            async with httpx.AsyncClient() as client:
                response = await client.get(
                    f"{target_url}/models",
                    headers={"Authorization": f"Bearer {target_key}"},
                    timeout=10.0
                )
                response.raise_for_status()
                upstream_models = response.json().get("data", [])
                
            for m in upstream_models:
                await db.exclude_model(m["id"])
            return {"status": "success", "message": f"Disabled {len(upstream_models)} models"}
        except Exception as e:
            raise HTTPException(status_code=502, detail=f"Failed to fetch models for bulk action: {str(e)}")
    else:
        raise HTTPException(status_code=400, detail="Invalid action")



# --- Asset Mounting ---
# Mount the assets folder explicitly so icons/images are accessible via /assets/
assets_path = FRONTEND_DIR / "assets"
if assets_path.exists():
    app.mount("/assets", StaticFiles(directory=str(assets_path)), name="assets")
