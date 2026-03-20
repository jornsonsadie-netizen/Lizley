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
from typing import Optional, Tuple, AsyncGenerator, List, Dict

import httpx
from fastapi import FastAPI, Request, HTTPException, Depends, Header, Response, Cookie
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, StreamingResponse, FileResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.middleware.sessions import SessionMiddleware
from pydantic import BaseModel
# authlib OAuth removed — Discord login is no longer used

from backend.config import load_settings, Settings
from backend.database import Database, ApiKeyRecord, create_database, ContentFlagRecord
from backend.session_secret import get_or_create_session_secret


# ==================== Early .env Loading ====================
# Load .env early so env vars are available at module level (before lifespan)
from dotenv import load_dotenv
load_dotenv()

# Persistent session secret from DB (no .env required; survives restarts)
SESSION_SECRET = get_or_create_session_secret(
    database_url=os.getenv("DATABASE_URL"),
    database_path=os.getenv("DATABASE_PATH", "./proxy.db"),
)


# ==================== VoidAI Content Moderation Configuration ====================

VOIDAI_API_URL = os.getenv("VOIDAI_API_URL", "https://api.voidai.app/v1")
VOIDAI_API_KEY = os.getenv("VOIDAI_API_KEY", "")
MODERATION_ENABLED = os.getenv("MODERATION_ENABLED", "true").lower() == "true"


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


class AdminKeyResponse(BaseModel):
    """Response model for admin key listing."""
    id: int
    key_prefix: str
    ip_address: str
    discord_email: Optional[str]
    rp_application: Optional[str]
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


class AdminModelsResponse(BaseModel):
    models: List[AdminModelInfo]


class ToggleModelRequest(BaseModel):
    model_id: str
    enabled: bool


class BulkModelActionRequest(BaseModel):
    action: str  # 'disable_all', 'enable_all'


class ConfigResponse(BaseModel):
    """Response model for proxy configuration."""
    target_api_url: str
    target_api_key_masked: str
    max_context: int
    max_output_tokens: int = 4096  # Max completion tokens per request (stops long outputs)
    max_keys_per_ip: int = 2  # Abuse protection: max API keys per IP


class ConfigUpdateRequest(BaseModel):
    """Request model for updating proxy configuration."""
    target_api_url: Optional[str] = None
    target_api_key: Optional[str] = None
    max_context: Optional[int] = None
    max_output_tokens: Optional[int] = None


class CompleteSignupRequest(BaseModel):
    """Request model for completing signup with RP application."""
    rp_application: str


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


class ContentFlagResponse(BaseModel):
    """Response model for content moderation flags."""
    id: int
    api_key_id: int
    key_prefix: str
    discord_id: Optional[str]
    discord_email: Optional[str]
    ip_address: str
    flag_type: str
    severity: str
    message_preview: str
    model: str
    reviewed: bool
    action_taken: Optional[str]
    flagged_at: str
    reviewed_at: Optional[str]


class FlagActionRequest(BaseModel):
    """Request model for taking action on a flag."""
    action: str  # 'ban_ip', 'disable_key', 'dismiss', 'warn', 'ban_and_disable'
    reason: Optional[str] = None


class FlagBulkActionRequest(BaseModel):
    """Request model for bulk actions on multiple flags."""
    flag_ids: list[int]
    action: str  # 'ban_ip', 'disable_key', 'dismiss', 'ban_and_disable'
    reason: Optional[str] = None


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
    content: str


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

RPM_LIMIT = 10
RPD_LIMIT = 200  # Request count (display only; daily limit is request-based)
REQUESTS_PER_DAY_LIMIT = 200  # Daily request quota per key (enforced)
RPM_WINDOW_SECONDS = 60
MAX_TOKENS_PER_SECOND = 35  # Maximum tokens per second for streaming


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


async def check_and_update_rate_limits(
    key_record: ApiKeyRecord,
    database: "Database",
    estimated_tokens: int = 0,
) -> RateLimitResult:
    """Check rate limits for an API key and update counters if allowed.
    
    Enforces RPM (requests per minute) and daily token quota (REQUESTS_PER_DAY_LIMIT).
    Uses atomic increment for request count; token usage is summed from usage_logs.
    
    Args:
        key_record: The API key record to check.
        database: The database instance for updating counters.
        estimated_tokens: Estimated tokens for this request (input + max output); used for daily token check.
    
    Returns:
        RateLimitResult indicating whether the request is allowed and any
        rate limit information.
    """
    now = datetime.now(timezone.utc)
    
    # Get current counter values (may be reset below)
    current_rpm = key_record.current_rpm
    current_rpd = key_record.current_rpd
    
    # Check if RPM needs to be reset (60+ seconds since last reset)
    last_rpm_reset = key_record.last_rpm_reset
    if last_rpm_reset.tzinfo is None:
        last_rpm_reset = last_rpm_reset.replace(tzinfo=timezone.utc)
    
    seconds_since_rpm_reset = (now - last_rpm_reset).total_seconds()
    if seconds_since_rpm_reset >= RPM_WINDOW_SECONDS:
        await database.reset_rpm(key_record.id)
        current_rpm = 0
    
    # Check if RPD counter needs to be reset (new calendar day in UTC)
    last_rpd_reset = key_record.last_rpd_reset
    if last_rpd_reset.tzinfo is None:
        last_rpd_reset = last_rpd_reset.replace(tzinfo=timezone.utc)
    
    if now.date() > last_rpd_reset.date():
        await database.reset_rpd(key_record.id)
        current_rpd = 0
    
    # Check RPM limit
    if current_rpm >= RPM_LIMIT:
        retry_after = max(1, int(RPM_WINDOW_SECONDS - seconds_since_rpm_reset))
        return RateLimitResult(
            allowed=False,
            rpm_exceeded=True,
            retry_after=retry_after,
        )
    
    # Check daily token limit (tokens per day, not request count)
    # Only check against *actual* tokens used so far — don't pre-reject based on
    # estimated_tokens, because the estimate (input + max_output) is a worst-case
    # upper bound that would block users who haven't used any tokens yet if they
    # send a large context.  Actual usage is recorded after the request completes.
    if current_rpd >= REQUESTS_PER_DAY_LIMIT:
        midnight_utc = now.replace(hour=0, minute=0, second=0, microsecond=0) + timedelta(days=1)
        retry_after = int((midnight_utc - now).total_seconds())
        return RateLimitResult(
            allowed=False,
            rpd_exceeded=True,
            retry_after=retry_after,
        )
    
    # Request is allowed - atomically increment request counters
    new_rpm, new_rpd = await database.increment_usage(key_record.id)
    
    return RateLimitResult(
        allowed=True,
        new_rpm=new_rpm,
        new_rpd=new_rpd,
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
    
    This dependency should be applied to all endpoints that need IP ban checking.
    It extracts the client IP and checks if it's banned in the database.
    
    Args:
        request: The FastAPI request object.
    
    Returns:
        The client IP address if not banned.
    
    Raises:
        HTTPException: 403 Forbidden if the IP is banned.
    """
    client_ip = get_client_ip(request)
    
    if await db.is_ip_banned(client_ip):
        raise HTTPException(
            status_code=403,
            detail="Your IP address has been banned"
        )
    
    return client_ip


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
    
    # Hash the key and look it up
    key_hash = hash_api_key(api_key)
    key_record = await db.get_key_by_hash(key_hash)
    
    if not key_record:
        raise HTTPException(
            status_code=401,
            detail="Invalid or missing API key"
        )
    
    # Check if key is enabled
    if not key_record.enabled:
        print(f"[Auth] Access denied: Key {key_hash[:8]} is disabled.")
        raise HTTPException(
            status_code=403,
            detail="This API key has been disabled"
        )
    
    # Check if IP is banned (skip for keys with bypass_ip_ban set by admin)
    client_ip = get_client_ip(request)
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
    This is a rough estimate and may not match the exact tokenization
    used by the target API.
    
    Args:
        messages: List of chat messages.
    
    Returns:
        Estimated token count.
    """
    total_chars = 0
    for message in messages:
        # Count role and content
        total_chars += len(message.role)
        total_chars += len(message.content)
        # Add overhead for message structure (approximately 4 tokens per message)
        total_chars += 16
    
    # Approximate 4 characters per token
    return total_chars // 4


# ==================== Content Moderation ====================

async def check_content_moderation(
    messages: list[ChatMessage],
    key_record: "ApiKeyRecord",
    client_ip: str,
    model: str,
) -> Optional[dict]:
    """Check messages for CSAM content only using VoidAI Omni AI.
    
    This function sends the message content to VoidAI's moderation API before
    the request is forwarded to the target API. ONLY the sexual/minors (CSAM)
    category is checked — all other categories (sexual, violence, hate,
    harassment, self-harm) are intentionally ignored to avoid false positives.
    
    Each request is checked independently (no caching or deduplication).
    
    Args:
        messages: List of chat messages to check.
        key_record: The API key record for the user.
        client_ip: The client's IP address.
        model: The model being requested.
    
    Returns:
        None if content is safe, or a dict with flag details if flagged.
    """
    if not MODERATION_ENABLED or not VOIDAI_API_KEY:
        return None
    
    # All content for the actual moderation API call
    combined_content = "\n".join([f"{msg.role}: {msg.content}" for msg in messages])

    # Admin preview should show ONLY prompt content (user messages), not unrelated
    # assistant/system history. We still moderate the full request above for accuracy,
    # but the stored preview is focused on what the user actually prompted.
    user_messages = [msg for msg in messages if (msg.role or '').lower() == 'user']
    preview_messages = user_messages[-3:] if user_messages else messages[-1:]
    message_preview = "\n---\n".join([
        f"PROMPT {i + 1}: {msg.content}"
        for i, msg in enumerate(preview_messages)
        if (msg.content or '').strip()
    ])
    
    # Fallback if preview is somehow empty
    if not message_preview.strip():
        message_preview = f"(Flagged empty prompt or malformed messages: {len(messages)} msgs)"
    
    # Truncate preview to keep admin cards readable while still useful
    if len(message_preview) > 6000:
        message_preview = message_preview[:6000] + "\n\n...(Prompt preview truncated)..."
    
    try:
        # Call VoidAI Omni AI moderation endpoint (fresh call every time, no caching)
        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.post(
                f"{VOIDAI_API_URL}/moderations",
                headers={
                    "Authorization": f"Bearer {VOIDAI_API_KEY}",
                    "Content-Type": "application/json",
                },
                json={
                    "input": combined_content,
                    "model": "omni-moderation-latest",
                }
            )
            
            if response.status_code != 200:
                # Log error but don't block the request
                print(f"[Moderation] VoidAI API error: {response.status_code} - {response.text[:200]}")
                return None
            
            result = response.json()
            
            # Check if content was flagged
            if not result.get("results"):
                return None
            
            moderation_result = result["results"][0]
            
            # We ONLY care about sexual/minors (CSAM). Ignore everything else.
            categories = moderation_result.get("categories", {})
            category_scores = moderation_result.get("category_scores", {})
            
            # Check if sexual/minors category is flagged
            if not categories.get("sexual/minors"):
                return None
            
            csam_score = category_scores.get("sexual/minors", 0)
            
            # Require a high confidence score to avoid false positives.
            # The boolean flag from the moderation API fires at low confidence,
            # e.g. when ages 18+ are merely mentioned near sexual content.
            CSAM_MIN_SCORE = 0.65
            if csam_score < CSAM_MIN_SCORE:
                return None
            
            # Determine severity based on score
            flag_type = "csam"
            if csam_score >= 0.8:
                severity = "critical"
            elif csam_score >= 0.65:
                severity = "high"  # Flagged for admin review, NOT auto-blocked
            else:
                severity = "low"
            
            # Add the score to the beginning of the preview for easier admin review
            message_preview_with_score = f"[Refinement Score: {csam_score:.3f}]\n{message_preview}"
            
            # Create flag in database
            flag_id = await db.create_content_flag(
                api_key_id=key_record.id,
                flag_type=flag_type,
                severity=severity,
                message_preview=message_preview_with_score,
                full_message_hash="",  # No deduplication hash
                model=model,
                ip_address=client_ip,
            )
            
            print(f"[Moderation] CSAM content flagged: severity={severity}, score={csam_score:.3f}, key={key_record.key_prefix}, flag_id={flag_id}")
            
            return {
                "flagged": True,
                "flag_id": flag_id,
                "flag_type": flag_type,
                "severity": severity,
                "csam_score": csam_score,
            }
            
    except httpx.TimeoutException:
        print("[Moderation] VoidAI API timeout - allowing request")
        return None
    except Exception as e:
        print(f"[Moderation] Error: {e} - allowing request")
        return None


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
    return 128000


async def get_max_output_tokens() -> int:
    """Get the maximum completion tokens per request from config or database."""
    config = await db.get_config()
    if config:
        return config.max_output_tokens
    if settings:
        return settings.max_output_tokens
    return 4096


async def get_target_api_config() -> Tuple[str, str]:
    """Get the target API URL and key from config or database.
    
    Returns:
        Tuple of (target_api_url, target_api_key).
    """
    # First try database config
    config = await db.get_config()
    if config:
        return config.target_api_url, config.target_api_key
    
    # Fall back to settings
    if settings:
        return settings.target_api_url, settings.target_api_key
    
    raise HTTPException(
        status_code=500,
        detail="Proxy not configured"
    )


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
    expected_password = settings.admin_password.strip()
    
    # Use timing-safe comparison to prevent timing attacks
    if hmac.compare_digest(provided_password, expected_password):
        return x_admin_password
    
    raise HTTPException(
        status_code=401,
        detail="Invalid admin password"
    )


# Background task for periodic saves
import asyncio
save_task: Optional[asyncio.Task] = None


async def periodic_save():
    """Background task that saves analytics every 5 minutes."""
    while True:
        await asyncio.sleep(300)  # 5 minutes
        try:
            # The database auto-persists, but we log for visibility
            print("[Auto-Save] Analytics persisted to database")
        except Exception as e:
            print(f"[Auto-Save] Error: {e}")


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Manage application lifespan - startup and shutdown."""
    global db, settings, save_task, http_client
    
    # Startup: Initialize database and settings
    try:
        settings = load_settings()
    except ValueError:
        # For testing, use defaults
        settings = None
    
    # Initialize database (auto-detects SQLite vs PostgreSQL)
    if settings and settings.database_url:
        print(f"* Using PostgreSQL database")
        db = create_database(database_url=settings.database_url)
    else:
        db_path = settings.database_path if settings else "./proxy.db"
        print(f"* Using SQLite database: {db_path}")
        db = create_database(database_path=db_path)
    
    await db.initialize()
    
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
    
    yield
    
    # Shutdown: Cancel save task, close HTTP client, and close database
    if save_task:
        save_task.cancel()
        try:
            await save_task
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
_PRODUCTION = bool(os.getenv("ZEABUR_SERVICE_ID") or os.getenv("RAILWAY_SERVICE_ID") or os.getenv("RENDER_SERVICE_ID"))
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
    allow_origins=["*"],  # Allow all origins
    allow_credentials=True,
    allow_methods=["*"],  # Allow all methods
    allow_headers=["*"],  # Allow all headers
)


# ==================== Cache Control Middleware ====================

class NoCacheMiddleware(BaseHTTPMiddleware):
    """Middleware to add no-cache headers to static files, admin routes, and root.
    
    This ensures Cloudflare and browsers don't cache critical files during updates.
    """
    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        
        path = request.url.path
        if path.startswith("/static/") or path.startswith("/admin") or path == "/":
            response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
            response.headers["Pragma"] = "no-cache"
            response.headers["Expires"] = "0"
            
        return response

app.add_middleware(NoCacheMiddleware)
# ==================== Static File Serving ====================

# Mount static files for CSS and JS (must be before route definitions)
if FRONTEND_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(FRONTEND_DIR)), name="static")


# ==================== API Key Endpoints ====================

class KeyGenerationRequest(BaseModel):
    """Request model for key generation with optional fingerprint."""
    fingerprint: Optional[str] = None


@app.post(
    "/api/generate-key",
    response_model=KeyGenerationResponse,
    responses={403: {"model": ErrorResponse}},
)
async def generate_key_endpoint(
    request: Request,
    body: Optional[KeyGenerationRequest] = None,
    client_ip: str = Depends(check_ip_ban),
) -> KeyGenerationResponse:
    """Generate a new API key for the requesting IP address.
    
    Key lookup priority:
    1. Same IP → return existing key
    2. Same fingerprint, different IP → update IP and return existing key
    3. New IP + new fingerprint → generate new key
    
    Returns:
        KeyGenerationResponse with the full key and prefix.
    """
    fingerprint = body.fingerprint if body else None
    
    # 1. Check if IP already has a key
    existing_key = await db.get_key_by_ip(client_ip)
    if existing_key:
        # Update fingerprint if provided and not set
        if fingerprint and not existing_key.browser_fingerprint:
            await db.update_key_fingerprint(existing_key.id, fingerprint)
        return KeyGenerationResponse(
            key=existing_key.full_key,  # Return full key from database
            key_prefix=existing_key.key_prefix,
            message="Your API key is shown below."
        )
    
    # 2. Check if fingerprint matches an existing key (IP changed)
    if fingerprint:
        fingerprint_key = await db.get_key_by_fingerprint(fingerprint)
        if fingerprint_key:
            # Update the IP address to the new one
            await db.update_key_ip(fingerprint_key.id, client_ip)
            return KeyGenerationResponse(
                key=fingerprint_key.full_key,  # Return full key from database
                key_prefix=fingerprint_key.key_prefix,
                message="Welcome back! Your IP changed but we recognized your browser."
            )
    
    # Abuse protection: limit keys per IP
    max_keys = (settings.max_keys_per_ip if settings else 2)
    key_count = await db.count_keys_by_ip(client_ip)
    if key_count >= max_keys:
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
    
    # Store in database with fingerprint AND full key
    # For IP-based key generation (legacy), use IP as a pseudo discord_id
    key_id = await db.create_api_key(
        discord_id=f"fp_{fingerprint}" if fingerprint else f"anon_{key_prefix}",
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
    # Try IP first, then fingerprint
    key_record = await db.get_key_by_ip(client_ip)
    if not key_record and fingerprint:
        key_record = await db.get_key_by_fingerprint(fingerprint)
        if key_record:
            # Update IP so future lookups work
            await db.update_key_ip(key_record.id, client_ip)
    if not key_record:
        raise HTTPException(
            status_code=404,
            detail="No API key found for your IP address"
        )
    
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
    client_ip: str = Depends(check_ip_ban),
) -> UsageResponse:
    """Get usage statistics for the API key associated with the requesting IP.
    
    Returns:
        UsageResponse with current rate limit status and total token usage.
    """
    # Get key for this IP
    key_record = await db.get_key_by_ip(client_ip)
    if not key_record:
        raise HTTPException(
            status_code=404,
            detail="No API key found for your IP address"
        )
    
    # Check if rate limits need to be reset (without incrementing)
    now = datetime.now(timezone.utc)
    current_rpm = key_record.current_rpm
    current_rpd = key_record.current_rpd
    
    # Check if RPM needs to be reset
    last_rpm_reset = key_record.last_rpm_reset
    if last_rpm_reset.tzinfo is None:
        last_rpm_reset = last_rpm_reset.replace(tzinfo=timezone.utc)
    
    if (now - last_rpm_reset).total_seconds() >= RPM_WINDOW_SECONDS:
        await db.reset_rpm(key_record.id)
        current_rpm = 0
    
    # Check if RPD needs to be reset
    last_rpd_reset = key_record.last_rpd_reset
    if last_rpd_reset.tzinfo is None:
        last_rpd_reset = last_rpd_reset.replace(tzinfo=timezone.utc)
    
    if now.date() > last_rpd_reset.date():
        await db.reset_rpd(key_record.id)
        current_rpd = 0
    
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
        total_tokens=usage_stats.total_tokens,
    )


# ==================== Proxy Endpoints ====================

async def _proxy_models_impl(
    key_data: Tuple[ApiKeyRecord, str],
) -> JSONResponse:
    """Shared implementation for GET /v1/models and /v1/models/ (avoids 301 redirect)."""
    key_record, client_ip = key_data
    
    # NOTE: /v1/models does NOT count against rate limits
    # It's just listing available models, not making actual API calls
    
    # Get target API config
    target_url, target_key = await get_target_api_config()
    
    # Forward request to target API using global client
    try:
        response = await http_client.get(
            f"{target_url}/models",
            headers={"Authorization": f"Bearer {target_key}"},
        )
        
        # Log usage (0 tokens for models endpoint, doesn't affect rate limits)
        await db.log_usage(
            key_id=key_record.id,
            model="models",
            tokens=0,
            success=response.status_code == 200,
            ip_address=client_ip,
        )
        
        try:
            content = response.json()
            
            # Filter models based on exclusion list
            if response.status_code == 200 and "data" in content:
                excluded = await db.get_excluded_models()
                if excluded:
                    content["data"] = [
                        m for m in content["data"] 
                        if m.get("id") not in excluded
                    ]
        except Exception:
            content = {"error": {"message": "Upstream returned invalid JSON"}}
        return JSONResponse(
            status_code=response.status_code,
            content=content,
        )
    except httpx.TimeoutException:
        await db.log_usage(
            key_id=key_record.id,
            model="models",
            tokens=0,
            success=False,
            ip_address=client_ip,
            error_message="Upstream API timeout",
        )
        raise HTTPException(
            status_code=502,
            detail="Unable to reach upstream API"
        )
    except httpx.RequestError as e:
        await db.log_usage(
            key_id=key_record.id,
            model="models",
            tokens=0,
            success=False,
            ip_address=client_ip,
            error_message=str(e),
        )
        raise HTTPException(
            status_code=502,
            detail="Unable to reach upstream API"
        )


@app.get("/v1/models", response_class=JSONResponse)
@app.get("/v1/models/", response_class=JSONResponse)
async def proxy_models(
    key_data: Tuple[ApiKeyRecord, str] = Depends(validate_api_key),
):
    """Proxy the /v1/models endpoint to the target API. Served at both /v1/models and /v1/models/ to avoid 301 redirect (no Location header)."""
    return await _proxy_models_impl(key_data)


@app.post("/v1/chat/completions")
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
    key_record, client_ip = key_data
    
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
    
    # Check rate limits (pass estimated tokens for daily token quota: input + max output)
    estimated_tokens = token_count + (await get_max_output_tokens())
    rate_result = await check_and_update_rate_limits(key_record, db, estimated_tokens=estimated_tokens)
    if not rate_result.allowed:
        return create_rate_limit_response(rate_result)
    
    # CSAM-only moderation check BEFORE forwarding to provider
    moderation_result = await check_content_moderation(
        messages=chat_request.messages,
        key_record=key_record,
        client_ip=client_ip,
        model=chat_request.model,
    )
    
    if moderation_result and moderation_result.get("flagged"):
        # Content may be flagged for admin review, but requests are always allowed through.
        # The flag is already created in the database by check_content_moderation().
        pass
    
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
    
    # Handle streaming response
    if chat_request.stream:
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
    import json as json_module
    import time
    
    async def stream_generator() -> AsyncGenerator[bytes, None]:
        output_tokens = 0
        total_tokens = token_count
        input_tokens_actual = token_count
        stream_success = False
        error_message = None
        
        # TPS rate limiting state
        tokens_this_second = 0
        last_second = time.monotonic()
        
        try:
            # Use global client for connection reuse
            async with http_client.stream(
                "POST",
                f"{target_url}/chat/completions",
                headers={
                    "Authorization": f"Bearer {target_key}",
                    "Content-Type": "application/json",
                    "Accept": "text/event-stream",
                },
                json=request_body,
            ) as response:
                stream_success = response.status_code == 200
                
                # If non-200 response, forward error immediately
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
                
                # True streaming - forward each chunk immediately
                async for chunk in response.aiter_bytes():
                    # Count tokens in this chunk for TPS limiting
                    chunk_tokens = 0
                    try:
                        chunk_str = chunk.decode('utf-8')
                        for line in chunk_str.split('\n'):
                            if line.startswith('data: ') and line != 'data: [DONE]':
                                data_str = line[6:]
                                if data_str.strip():
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
                                        # Extract final usage stats
                                        if 'usage' in data:
                                            input_tokens_actual = data['usage'].get('prompt_tokens', token_count)
                                            output_tokens = data['usage'].get('completion_tokens', 0)
                                            total_tokens = data['usage'].get('total_tokens', token_count)
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
                
                # Log usage after stream completes
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
        except httpx.TimeoutException as e:
            print(f"[Upstream Timeout] {str(e)}")
            await db.log_usage(
                key_id=key_record.id,
                model=request_body.get("model", "unknown"),
                tokens=token_count,
                success=False,
                ip_address=client_ip,
                input_tokens=token_count,
                error_message="Upstream API timeout",
            )
            error_response = {"error": {"message": "Upstream API timeout", "type": "timeout", "code": 504}}
            yield f"data: {json_module.dumps(error_response)}\n\n".encode('utf-8')
            yield b"data: [DONE]\n\n"
        except httpx.RequestError as e:
            print(f"[Upstream Request Error] {str(e)}")
            await db.log_usage(
                key_id=key_record.id,
                model=request_body.get("model", "unknown"),
                tokens=token_count,
                success=False,
                ip_address=client_ip,
                input_tokens=token_count,
                error_message=str(e),
            )
            error_response = {"error": {"message": f"Unable to reach upstream API: {str(e)}", "type": "connection_error", "code": 502}}
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
        
        response_data = response.json()
        
        # Extract actual token usage if available
        input_tokens = token_count
        output_tokens = 0
        actual_tokens = token_count
        if "usage" in response_data:
            input_tokens = response_data["usage"].get("prompt_tokens", token_count)
            output_tokens = response_data["usage"].get("completion_tokens", 0)
            actual_tokens = response_data["usage"].get("total_tokens", token_count)
        
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
        try:
            tokens_today = tokens_map.get(key.id, 0)
            result.append(AdminKeyResponse(
                id=key.id,
                key_prefix=key.key_prefix or "",
                ip_address=key.ip_address or "",
                discord_email=key.discord_email,
                rp_application=getattr(key, "rp_application", None),
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
        
        return ConfigResponse(
            target_api_url=config.target_api_url,
            target_api_key_masked=masked_key,
            max_context=config.max_context,
            max_output_tokens=config.max_output_tokens,
            max_keys_per_ip=settings.max_keys_per_ip if settings else 2,
        )
    
    # Fall back to settings
    if settings:
        key = settings.target_api_key
        if len(key) > 12:
            masked_key = f"{key[:8]}...{key[-4:]}"
        else:
            masked_key = "***"
        
        return ConfigResponse(
            target_api_url=settings.target_api_url,
            target_api_key_masked=masked_key,
            max_context=settings.max_context,
            max_output_tokens=settings.max_output_tokens,
            max_keys_per_ip=settings.max_keys_per_ip,
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
    
    if current_config:
        target_url = config_update.target_api_url or current_config.target_api_url
        target_key = config_update.target_api_key or current_config.target_api_key
        max_context = config_update.max_context if config_update.max_context is not None else current_config.max_context
        max_output_tokens = config_update.max_output_tokens if config_update.max_output_tokens is not None else current_config.max_output_tokens
    elif settings:
        target_url = config_update.target_api_url or settings.target_api_url
        target_key = config_update.target_api_key or settings.target_api_key
        max_context = config_update.max_context if config_update.max_context is not None else settings.max_context
        max_output_tokens = config_update.max_output_tokens if config_update.max_output_tokens is not None else settings.max_output_tokens
    else:
        raise HTTPException(
            status_code=500,
            detail="Proxy not configured"
        )
    
    await db.update_config(target_url, target_key, max_context, max_output_tokens)
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
    
    await db.ban_ip(ban_request.ip_address, ban_request.reason)
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
    return {"message": f"IP address {ip_address} has been unbanned"}


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


# ==================== Content Moderation Flags Admin Endpoints ====================

@app.get(
    "/admin/flags",
    response_model=list[ContentFlagResponse],
    responses={401: {"model": ErrorResponse}},
)
async def admin_list_flags(
    include_reviewed: bool = False,
    _: str = Depends(verify_admin_password),
) -> list[ContentFlagResponse]:
    """List all content moderation flags.
    
    Requires admin authentication via X-Admin-Password header.
    
    Args:
        include_reviewed: If True, include already-reviewed flags.
    
    Returns:
        List of content flags with user details.
    """
    flags = await db.get_all_flags(include_reviewed=include_reviewed)
    return [
        ContentFlagResponse(
            id=flag.id,
            api_key_id=flag.api_key_id,
            key_prefix=flag.key_prefix,
            discord_id=flag.discord_id,
            discord_email=flag.discord_email,
            ip_address=flag.ip_address,
            flag_type=flag.flag_type,
            severity=flag.severity,
            message_preview=flag.message_preview,
            model=flag.model,
            reviewed=flag.reviewed,
            action_taken=flag.action_taken,
            flagged_at=flag.flagged_at.isoformat() if flag.flagged_at else None,
            reviewed_at=flag.reviewed_at.isoformat() if flag.reviewed_at else None,
        )
        for flag in flags
    ]


@app.get(
    "/admin/flags/count",
    responses={401: {"model": ErrorResponse}},
)
async def admin_count_unreviewed_flags(
    _: str = Depends(verify_admin_password),
) -> dict:
    """Get count of unreviewed flags.
    
    Requires admin authentication via X-Admin-Password header.
    
    Returns:
        Count of unreviewed flags.
    """
    count = await db.count_unreviewed_flags()
    return {"count": count}


@app.get(
    "/admin/flags/{flag_id}",
    response_model=ContentFlagResponse,
    responses={401: {"model": ErrorResponse}, 404: {"model": ErrorResponse}},
)
async def admin_get_flag(
    flag_id: int,
    _: str = Depends(verify_admin_password),
) -> ContentFlagResponse:
    """Get a specific content flag by ID.
    
    Requires admin authentication via X-Admin-Password header.
    
    Args:
        flag_id: The ID of the flag to retrieve.
    
    Returns:
        The content flag details.
    """
    flag = await db.get_flag_by_id(flag_id)
    if not flag:
        raise HTTPException(status_code=404, detail="Flag not found")
    
    return ContentFlagResponse(
        id=flag.id,
        api_key_id=flag.api_key_id,
        key_prefix=flag.key_prefix,
        discord_id=flag.discord_id,
        discord_email=flag.discord_email,
        ip_address=flag.ip_address,
        flag_type=flag.flag_type,
        severity=flag.severity,
        message_preview=flag.message_preview,
        model=flag.model,
        reviewed=flag.reviewed,
        action_taken=flag.action_taken,
        flagged_at=flag.flagged_at.isoformat() if flag.flagged_at else None,
        reviewed_at=flag.reviewed_at.isoformat() if flag.reviewed_at else None,
    )


@app.post(
    "/admin/flags/{flag_id}/action",
    responses={401: {"model": ErrorResponse}, 404: {"model": ErrorResponse}},
)
async def admin_flag_action(
    flag_id: int,
    action_request: FlagActionRequest,
    _: str = Depends(verify_admin_password),
) -> dict:
    """Take action on a content flag.
    
    Requires admin authentication via X-Admin-Password header.
    
    Actions:
        - ban_ip: Ban the IP address associated with the flag
        - disable_key: Disable the API key associated with the flag
        - dismiss: Mark as reviewed without action
        - warn: Mark as reviewed with warning (no automatic action)
    
    Args:
        flag_id: The ID of the flag to act on.
        action_request: The action to take and optional reason.
    
    Returns:
        Success message.
    """
    flag = await db.get_flag_by_id(flag_id)
    if not flag:
        raise HTTPException(status_code=404, detail="Flag not found")
    
    action = action_request.action
    reason = action_request.reason or f"Content flag #{flag_id}: {flag.flag_type}"
    
    if action == "ban_ip":
        # Ban the IP address
        await db.ban_ip(flag.ip_address, reason)
        await db.mark_flag_reviewed(flag_id, f"banned_ip: {flag.ip_address}")
        return {"message": f"IP {flag.ip_address} has been banned", "action": "ban_ip"}
    
    elif action == "disable_key":
        # Disable the API key
        await db.set_key_enabled(flag.api_key_id, enabled=False)
        await db.mark_flag_reviewed(flag_id, f"disabled_key: {flag.key_prefix}")
        return {"message": f"API key {flag.key_prefix} has been disabled", "action": "disable_key"}
    
    elif action == "ban_and_disable":
        # Both ban IP and disable key
        await db.ban_ip(flag.ip_address, reason)
        await db.set_key_enabled(flag.api_key_id, enabled=False)
        await db.mark_flag_reviewed(flag_id, f"banned_ip_and_disabled_key: {flag.ip_address}, {flag.key_prefix}")
        return {"message": f"IP {flag.ip_address} banned and key {flag.key_prefix} disabled", "action": "ban_and_disable"}
    
    elif action == "dismiss":
        # Just mark as reviewed
        await db.mark_flag_reviewed(flag_id, "dismissed")
        return {"message": "Flag dismissed", "action": "dismiss"}
    
    elif action == "warn":
        # Mark as reviewed with warning
        await db.mark_flag_reviewed(flag_id, f"warned: {reason}")
        return {"message": "Flag marked as warned", "action": "warn"}
    
    else:
        raise HTTPException(status_code=400, detail=f"Unknown action: {action}")


@app.post(
    "/admin/flags/bulk-action",
    responses={401: {"model": ErrorResponse}},
)
async def admin_bulk_flag_action(
    action_request: FlagBulkActionRequest,
    _: str = Depends(verify_admin_password),
) -> dict:
    """Take action on multiple content flags at once.
    
    Requires admin authentication via X-Admin-Password header.
    
    Args:
        action_request: The IDs to act on and the action to take.
    
    Returns:
        Success summary.
    """
    flag_ids = action_request.flag_ids
    action = action_request.action
    base_reason = action_request.reason or f"Bulk action: {action}"
    
    success_count = 0
    errors = []
    
    for flag_id in flag_ids:
        try:
            flag = await db.get_flag_by_id(flag_id)
            if not flag:
                errors.append(f"Flag #{flag_id} not found")
                continue
            
            reason = f"{base_reason} (Flag #{flag_id}: {flag.flag_type})"
            
            if action == "ban_ip":
                await db.ban_ip(flag.ip_address, reason)
                await db.mark_flag_reviewed(flag_id, f"bulk_banned_ip: {flag.ip_address}")
            elif action == "disable_key":
                await db.set_key_enabled(flag.api_key_id, enabled=False)
                await db.mark_flag_reviewed(flag_id, f"bulk_disabled_key: {flag.key_prefix}")
            elif action == "ban_and_disable":
                await db.ban_ip(flag.ip_address, reason)
                await db.set_key_enabled(flag.api_key_id, enabled=False)
                await db.mark_flag_reviewed(flag_id, f"bulk_banned_ip_and_disabled_key: {flag.ip_address}, {flag.key_prefix}")
            elif action == "dismiss":
                await db.mark_flag_reviewed(flag_id, "bulk_dismissed")
            else:
                raise ValueError(f"Unknown action: {action}")
            
            success_count += 1
        except Exception as e:
            errors.append(f"Error on flag #{flag_id}: {str(e)}")
            
    return {
        "message": f"Bulk action '{action}' completed: {success_count} success, {len(errors)} errors",
        "success_count": success_count,
        "error_count": len(errors),
        "errors": errors[:10] # Return first 10 errors
    }


@app.get(
    "/admin/keys/{key_id}/flags",
    response_model=list[ContentFlagResponse],
    responses={401: {"model": ErrorResponse}},
)
async def admin_get_key_flags(
    key_id: int,
    _: str = Depends(verify_admin_password),
) -> list[ContentFlagResponse]:
    """Get all flags for a specific API key.
    
    Requires admin authentication via X-Admin-Password header.
    
    Args:
        key_id: The ID of the API key.
    
    Returns:
        List of flags for this key.
    """
    flags = await db.get_flags_by_key(key_id)
    return [
        ContentFlagResponse(
            id=flag.id,
            api_key_id=flag.api_key_id,
            key_prefix=flag.key_prefix,
            discord_id=flag.discord_id,
            discord_email=flag.discord_email,
            ip_address=flag.ip_address,
            flag_type=flag.flag_type,
            severity=flag.severity,
            message_preview=flag.message_preview,
            model=flag.model,
            reviewed=flag.reviewed,
            action_taken=flag.action_taken,
            flagged_at=flag.flagged_at.isoformat() if flag.flagged_at else None,
            reviewed_at=flag.reviewed_at.isoformat() if flag.reviewed_at else None,
        )
        for flag in flags
    ]


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
        
        models_info = []
        for m in upstream_models:
            models_info.append(AdminModelInfo(
                id=m["id"],
                name=m.get("id", "Unknown"),
                enabled=m["id"] not in excluded,
                created=m.get("created", 0),
                owned_by=m.get("owned_by", "system")
            ))
            
        # Sort: enabled first, then by id
        models_info.sort(key=lambda x: (not x.enabled, x.id))
        
        return AdminModelsResponse(models=models_info)
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"Failed to fetch models from upstream: {str(e)}")


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
