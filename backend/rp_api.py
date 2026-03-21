import os
import uuid
import hashlib
import json
from datetime import datetime
import dataclasses
from threading import Lock
from typing import List, Optional, Dict, Any

from fastapi import APIRouter, Depends, HTTPException, status, Request, Header
from pydantic import BaseModel, Field
from itsdangerous import URLSafeTimedSerializer, SignatureExpired, BadSignature

from backend.database import Database, RpUser, RpBot, RpOc, RpChat

rp_router = APIRouter(prefix="/api/rp", tags=["lizrp"])

# --- Helpers ---
def bot_to_dict(bot: RpBot) -> Dict[str, Any]:
    d = dataclasses.asdict(bot)
    if isinstance(d.get("created_at"), datetime):
        d["created_at"] = d["created_at"].isoformat()
    return d

def oc_to_dict(oc: RpOc) -> Dict[str, Any]:
    d = dataclasses.asdict(oc)
    if isinstance(d.get("created_at"), datetime):
        d["created_at"] = d["created_at"].isoformat()
    return d

def chat_to_dict(chat: RpChat) -> Dict[str, Any]:
    d = dataclasses.asdict(chat)
    if isinstance(d.get("updated_at"), datetime):
        d["updated_at"] = d["updated_at"].isoformat()
    # Messages are already a string in the dataclass from DB
    if isinstance(d.get("messages"), str):
        try:
            d["messages_parsed"] = json.loads(d["messages"])
        except:
            d["messages_parsed"] = []
    return d

# --- Security & Auth ---

# We'll use the SESSION_SECRET from the app config for JWTs/Tokens
def get_secret_key() -> str:
    return os.environ.get("SESSION_SECRET", "rpc_default_insecure_secret!")

def get_serializer() -> URLSafeTimedSerializer:
    return URLSafeTimedSerializer(get_secret_key())

def hash_password(password: str) -> str:
    salt = os.urandom(16)
    key = hashlib.scrypt(password.encode(), salt=salt, n=16384, r=8, p=1, dklen=32)
    return f"{salt.hex()}${key.hex()}"

def verify_password(password: str, hashed: str) -> bool:
    try:
        salt_hex, key_hex = hashed.split("$")
        salt = bytes.fromhex(salt_hex)
        key = hashlib.scrypt(password.encode(), salt=salt, n=16384, r=8, p=1, dklen=32)
        return key.hex() == key_hex
    except Exception:
        return False

# Dependency to get current user from Authorization Header (Bearer TOKEN)
async def get_current_user(request: Request, authorization: Optional[str] = Header(None)) -> RpUser:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing or invalid Authorization header")
    
    token = authorization.split("Bearer ")[1]
    serializer = get_serializer()
    try:
        # Token valid for 30 days
        user_id = serializer.loads(token, max_age=86400 * 30)
    except SignatureExpired:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token expired")
    except BadSignature:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")
        
    db: Database = request.app.state.db
    user = await db.get_rp_user_by_id(user_id)
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found")
        
    return user


# --- Pydantic Models ---

class RegisterRequest(BaseModel):
    username: str
    password: str
    avatar: Optional[str] = None

class LoginRequest(BaseModel):
    username: str
    password: str

class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"

class ProfileUpdate(BaseModel):
    username: str
    avatar: Optional[str] = None

class BotCreate(BaseModel):
    name: str = Field(..., max_length=100)
    avatar: Optional[str] = None
    description: Optional[str] = None
    lore: Optional[str] = None
    personality: Optional[str] = None
    tags: Optional[str] = None

class OcCreate(BaseModel):
    name: str = Field(..., max_length=100)
    avatar: Optional[str] = None
    description: Optional[str] = None
    lore: Optional[str] = None
    personality: Optional[str] = None

class ChatCreate(BaseModel):
    bot_id: str
    oc_id: Optional[str] = None
    model_id: Optional[str] = None

class ChatUpdate(BaseModel):
    messages: str  # JSON String
    wallpaper: Optional[str] = None
    model_id: Optional[str] = None
    oc_id: Optional[str] = None


# --- Authentication Endpoints ---

@rp_router.post("/register", response_model=TokenResponse)
async def register(req: RegisterRequest, request: Request):
    db: Database = request.app.state.db
    
    existing = await db.get_rp_user_by_username(req.username)
    if existing:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Username already exists")
        
    user_id = str(uuid.uuid4())
    pw_hash = hash_password(req.password)
    
    success = await db.create_rp_user(user_id, req.username, pw_hash, req.avatar)
    if not success:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to create user")
        
    token = get_serializer().dumps(user_id)
    return TokenResponse(access_token=token)

@rp_router.post("/login", response_model=TokenResponse)
async def login(req: LoginRequest, request: Request):
    db: Database = request.app.state.db
    
    user = await db.get_rp_user_by_username(req.username)
    if not user or not verify_password(req.password, user.password_hash):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid username or password")
        
    token = get_serializer().dumps(user.id)
    return TokenResponse(access_token=token)

@rp_router.get("/profile")
async def get_profile(current_user: RpUser = Depends(get_current_user)):
    return {
        "id": current_user.id,
        "username": current_user.username,
        "avatar": current_user.avatar,
        "created_at": current_user.created_at
    }

@rp_router.put("/profile")
async def update_profile(req: ProfileUpdate, request: Request, current_user: RpUser = Depends(get_current_user)):
    db: Database = request.app.state.db
    
    # Check if username exists and isn't ours
    if req.username != current_user.username:
        existing = await db.get_rp_user_by_username(req.username)
        if existing:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Username already exists")
            
    success = await db.update_rp_user_profile(current_user.id, req.username, req.avatar)
    if not success:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to update profile")
        
    return {"status": "success"}


# --- Bot Management ---

@rp_router.post("/bots")
async def create_bot(req: BotCreate, request: Request, current_user: RpUser = Depends(get_current_user)):
    db: Database = request.app.state.db
    bot_id = str(uuid.uuid4())
    
    success = await db.create_rp_bot(bot_id, req.name, req.avatar, req.description, req.lore, req.personality, req.tags, current_user.id)
    if not success:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to create bot")
        
    bot = await db.get_rp_bot_by_id(bot_id)
    return bot_to_dict(bot) if bot else None

@rp_router.get("/bots")
async def list_bots(request: Request, search: Optional[str] = None, page: int = 1, limit: int = 50):
    db: Database = request.app.state.db
    offset = (page - 1) * limit
    try:
        bots = await db.get_rp_bots(limit=limit, offset=offset, search_query=search)
        return {"bots": [bot_to_dict(b) for b in bots], "page": page, "limit": limit}
    except Exception as e:
        import traceback
        print(f"ERROR list_bots: {str(e)}")
        print(traceback.format_exc())
        raise HTTPException(status_code=500, detail=f"Database error: {str(e)}")
    
@rp_router.get("/bots/{bot_id}")
async def get_bot(bot_id: str, request: Request):
    db: Database = request.app.state.db
    bot = await db.get_rp_bot_by_id(bot_id)
    if not bot:
        raise HTTPException(status_code=404, detail="Bot not found")
    return bot_to_dict(bot)

@rp_router.put("/bots/{bot_id}")
async def update_bot(bot_id: str, req: BotCreate, request: Request, current_user: RpUser = Depends(get_current_user)):
    db: Database = request.app.state.db
    bot = await db.get_rp_bot_by_id(bot_id)
    if not bot:
        raise HTTPException(status_code=404, detail="Bot not found")
        
    if bot.creator_id != current_user.id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="You do not own this bot")
        
    success = await db.update_rp_bot(bot_id, req.name, req.avatar, req.description, req.lore, req.personality, req.tags)
    if not success:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to update bot")
        
    return await db.get_rp_bot_by_id(bot_id)


# --- OC Management ---

@rp_router.post("/ocs")
async def create_oc(req: OcCreate, request: Request, current_user: RpUser = Depends(get_current_user)):
    db: Database = request.app.state.db
    oc_id = str(uuid.uuid4())
    
    success = await db.create_rp_oc(oc_id, req.name, req.avatar, req.description, req.lore, req.personality, current_user.id)
    if not success:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to create OC")
        
        
    return oc_to_dict(await db.get_rp_oc_by_id(oc_id))

@rp_router.get("/ocs")
async def list_user_ocs(request: Request, current_user: RpUser = Depends(get_current_user)):
    db: Database = request.app.state.db
    ocs = await db.get_rp_ocs_by_owner(current_user.id)
    return {"ocs": [oc_to_dict(o) for o in ocs]}
    
@rp_router.get("/ocs/{oc_id}")
async def get_oc(oc_id: str, request: Request, current_user: RpUser = Depends(get_current_user)):
    db: Database = request.app.state.db
    oc = await db.get_rp_oc_by_id(oc_id)
    if not oc:
        raise HTTPException(status_code=404, detail="OC not found")
    if oc.owner_id != current_user.id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Access denied")
    return oc_to_dict(oc)

@rp_router.put("/ocs/{oc_id}")
async def update_oc(oc_id: str, req: OcCreate, request: Request, current_user: RpUser = Depends(get_current_user)):
    db: Database = request.app.state.db
    oc = await db.get_rp_oc_by_id(oc_id)
    if not oc:
        raise HTTPException(status_code=404, detail="OC not found")
        
    if oc.owner_id != current_user.id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Access denied")
        
    success = await db.update_rp_oc(oc_id, req.name, req.avatar, req.description, req.lore, req.personality)
    if not success:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to update OC")
        
    oc = await db.get_rp_oc_by_id(oc_id)
    return oc_to_dict(oc)


# --- Chat Management ---

@rp_router.post("/chats")
async def create_chat(req: ChatCreate, request: Request, current_user: RpUser = Depends(get_current_user)):
    db: Database = request.app.state.db
    chat_id = str(uuid.uuid4())
    
    # Verify bot
    bot = await db.get_rp_bot_by_id(req.bot_id)
    if not bot:
        raise HTTPException(status_code=404, detail="Bot not found")
        
    # Standardize initial messages strictly so frontend knows where to start
    initial_messages = "[]"
    
    success = await db.create_rp_chat(chat_id, req.bot_id, req.oc_id, req.model_id, initial_messages, current_user.id)
    if not success:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to create chat")
        
    chat = await db.get_rp_chat_by_id(chat_id)
    return chat_to_dict(chat) if chat else None

@rp_router.get("/chats")
async def list_chats(request: Request, current_user: RpUser = Depends(get_current_user)):
    db: Database = request.app.state.db
    chats = await db.get_rp_chats_by_owner(current_user.id)
    
    # We should embed basic info about the bot for the frontend UI list
    chat_list = []
    for chat in chats:
        bot = await db.get_rp_bot_by_id(chat.bot_id)
        chat_dict = {
            "id": chat.id,
            "bot_id": chat.bot_id,
            "bot_name": bot.name if bot else "Unknown Bot",
            "bot_avatar": bot.avatar if bot else None,
            "model_id": chat.model_id,
            "updated_at": chat.updated_at.isoformat() if isinstance(chat.updated_at, datetime) else chat.updated_at
        }
        chat_list.append(chat_dict)
        
    return {"chats": chat_list}

@rp_router.get("/chats/{chat_id}")
async def get_chat(chat_id: str, request: Request, current_user: RpUser = Depends(get_current_user)):
    db: Database = request.app.state.db
    chat = await db.get_rp_chat_by_id(chat_id)
    if not chat:
        raise HTTPException(status_code=404, detail="Chat not found")
    if chat.owner_id != current_user.id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Access denied")
        
    bot = await db.get_rp_bot_by_id(chat.bot_id)
    
    return {
        "id": chat.id,
        "bot_id": chat.bot_id,
        "bot_name": bot.name if bot else "Unknown Bot",
        "bot_avatar": bot.avatar if bot else None,
        "bot_creator_name": bot.creator_name if bot else "System",
        "oc_id": chat.oc_id,
        "wallpaper": chat.wallpaper,
        "model_id": chat.model_id,
        "messages": json.loads(chat.messages) if isinstance(chat.messages, str) and chat.messages else (chat.messages if isinstance(chat.messages, list) else []),
        "updated_at": chat.updated_at.isoformat() if isinstance(chat.updated_at, datetime) else chat.updated_at
    }

@rp_router.put("/chats/{chat_id}")
async def update_chat(chat_id: str, req: ChatUpdate, request: Request, current_user: RpUser = Depends(get_current_user)):
    db: Database = request.app.state.db
    chat = await db.get_rp_chat_by_id(chat_id)
    if not chat:
        raise HTTPException(status_code=404, detail="Chat not found")
    if chat.owner_id != current_user.id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Access denied")
        
    success = await db.update_rp_chat(chat_id, req.messages, req.wallpaper, req.model_id, req.oc_id)
    if not success:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to update chat")
        
    return {"status": "success"}

@rp_router.delete("/chats/{chat_id}")
async def delete_chat(chat_id: str, request: Request, current_user: RpUser = Depends(get_current_user)):
    db: Database = request.app.state.db
    chat = await db.get_rp_chat_by_id(chat_id)
    if not chat:
        raise HTTPException(status_code=404, detail="Chat not found")
    if chat.owner_id != current_user.id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Access denied")
        
    success = await db.delete_rp_chat(chat_id)
    return {"status": "success" if success else "failed"}

# --- Generative Inference ---

import httpx
from fastapi.responses import StreamingResponse

class ChatCompletionsRequest(BaseModel):
    chat_id: str
    message: str
    
@rp_router.post("/chat/completions")
async def chat_completions(req: ChatCompletionsRequest, request: Request, current_user: RpUser = Depends(get_current_user)):
    db: Database = request.app.state.db
    
    # 1. Fetch Config
    config = await db.get_config()
    if not config or not config.target_api_url or not config.target_api_key:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Proxy target API is not configured by admin.")
        
    # 2. Fetch Chat Context
    chat = await db.get_rp_chat_by_id(req.chat_id)
    if not chat or chat.owner_id != current_user.id:
        raise HTTPException(status_code=404, detail="Chat not found or access denied")
        
    bot = await db.get_rp_bot_by_id(chat.bot_id)
    oc = await db.get_rp_oc_by_id(chat.oc_id) if chat.oc_id else None
    
    # 3. Compile System Prompt
    system_parts = []
    if bot:
        system_parts.append(f"You will play the role of: {bot.name}")
        if bot.description: system_parts.append(f"Description: {bot.description}")
        if bot.personality: system_parts.append(f"Personality: {bot.personality}")
        if bot.lore: system_parts.append(f"Lore/Scenario: {bot.lore}")
        
    if oc:
        system_parts.append(f"\\n\\nThe user is playing as: {oc.name}")
        if oc.description: system_parts.append(f"User Description: {oc.description}")
        if oc.personality: system_parts.append(f"User Personality: {oc.personality}")
        
    system_prompt = "\\n".join(system_parts)
    
    # 4. Compile Messages
    messages = []
    messages.append({"role": "system", "content": system_prompt})
    
    history = []
    if chat.messages:
        try:
            history = json.loads(chat.messages)
        except Exception:
            history = []
            
    # Add history
    messages.extend(history)
    
    # Add new user message
    messages.append({"role": "user", "content": req.message})
    
    # Update history in DB (Append user msg, we'll append assistant on frontend for simplicity, 
    # but strictly speaking the frontend handles the update_chat after receiving stream, or we append here)
    # Actually, it's safer if the frontend manages the history via PUT /chats/{chat_id}
    # For now, let's just stream the response.

    target_url = config.target_api_url.rstrip("/") + "/chat/completions"
    headers = {
        "Authorization": f"Bearer {config.target_api_key}",
        "Content-Type": "application/json"
    }
    
    payload = {
        "model": chat.model_id or "default-model",
        "messages": messages,
        "max_tokens": config.max_output_tokens,
        "stream": True
    }

    async def generate_stream():
        async with httpx.AsyncClient() as client:
            async with client.stream("POST", target_url, headers=headers, json=payload, timeout=60.0) as response:
                if response.status_code != 200:
                    yield f"data: {json.dumps({'error': 'Target API Error: ' + str(response.status_code)})}\\n\\n"
                    # Try to yield the text if possible
                    err_txt = await response.aread()
                    yield f"data: {json.dumps({'error_detail': err_txt.decode()})}\\n\\n"
                    return
                    
                async for chunk in response.aiter_lines():
                    if chunk:
                        yield f"{chunk}\\n\\n"
                        
    return StreamingResponse(generate_stream(), media_type="text/event-stream")
