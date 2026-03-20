import codecs
import re

with codecs.open('backend/main.py', 'r', 'utf-8') as f:
    text = f.read()

# 1. Update TOKENS_PER_DAY_LIMIT references to REQUESTS_PER_DAY_LIMIT
text = text.replace('TOKENS_PER_DAY_LIMIT', 'REQUESTS_PER_DAY_LIMIT')
text = text.replace('Daily token limit exceeded', 'Daily request limit exceeded')

# 2. Fix the check_and_update_rate_limits token block
token_block = re.search(r'today_start \= now\.replace\(hour=0, minute=0, second=0, microsecond=0\)\s*today_end \= today_start \+ timedelta\(days=1\)\s*daily_tokens_used \= await database\.get_daily_tokens_used\(\s*key_record\.id, today_start\.isoformat\(\), today_end\.isoformat\(\)\s*\)\s*if daily_tokens_used >= REQUESTS_PER_DAY_LIMIT:\s*midnight_utc = today_end\s*retry_after = int\(\(midnight_utc - now\)\.total_seconds\(\)\)\s*return RateLimitResult\(\s*allowed=False,\s*rpd_exceeded=True,\s*retry_after=retry_after,\s*\)', text)

if token_block:
    new_block = '''    if current_rpd >= REQUESTS_PER_DAY_LIMIT:
        midnight_utc = now.replace(hour=0, minute=0, second=0, microsecond=0) + timedelta(days=1)
        retry_after = int((midnight_utc - now).total_seconds())
        return RateLimitResult(
            allowed=False,
            rpd_exceeded=True,
            retry_after=retry_after,
        )'''
    text = text.replace(token_block.group(0), new_block)

# 3. Remove discord endpoints explicitly
discord_block = re.search(r'# ==================== Discord OAuth Endpoints ====================.*?# ==================== API Key Endpoints ====================', text, re.DOTALL)
if discord_block:
    text = text.replace(discord_block.group(0), '# ==================== API Key Endpoints ====================')

# 4. Modify /api/generate-key endpoint to strictly enforce hardware fingerprint
gen_key_old = re.search(r'class KeyGenerationRequest.*?def generate_key_endpoint.*?return KeyGenerationResponse[^\}]*?message="API key generated successfully!"\n    \)', text, re.DOTALL)
if gen_key_old:
    new_gen_key = '''class KeyGenerationRequest(BaseModel):
    fingerprint: str  # Hardware fingerprint is strictly required now

@app.post(
    "/api/generate-key",
    response_model=KeyGenerationResponse,
    responses={403: {"model": ErrorResponse}},
)
async def generate_key_endpoint(
    request: Request,
    body: KeyGenerationRequest,
    client_ip: str = Depends(check_ip_ban),
) -> KeyGenerationResponse:
    """Generate a new API key tied to a hardware fingerprint."""
    fingerprint = body.fingerprint
    if not fingerprint:
        raise HTTPException(status_code=400, detail="Hardware fingerprint is required")
        
    # Check if fingerprint already has a key
    existing_key = await db.get_key_by_fingerprint(fingerprint)
    if existing_key:
        # Update IP if changed
        if existing_key.ip_address != client_ip:
            await db.update_key_ip(existing_key.id, client_ip)
        return KeyGenerationResponse(
            key=existing_key.full_key,
            key_prefix=existing_key.key_prefix,
            message="Welcome back! Your existing API key has been retrieved."
        )
        
    # Abuse protection: limit keys per IP
    max_keys = (settings.max_keys_per_ip if settings else 2)
    key_count = await db.count_keys_by_ip(client_ip)
    if key_count >= max_keys:
        cleaned = await db.delete_disabled_keys_by_ip(client_ip)
        if cleaned > 0:
            key_count = await db.count_keys_by_ip(client_ip)
        if key_count >= max_keys:
            raise HTTPException(
                status_code=403,
                detail=f"Maximum number of API keys per IP ({max_keys}) reached. Use an existing key or contact support."
            )
            
    # Generate new key for new user
    new_key = generate_api_key()
    key_hash = hash_api_key(new_key)
    key_prefix = get_key_prefix(new_key)
    
    key_id = await db.create_api_key(
        discord_id=None,
        discord_email=None,
        key_hash=key_hash,
        key_prefix=key_prefix,
        full_key=new_key,
        ip_address=client_ip,
    )
    
    # Set fingerprint
    await db.update_key_fingerprint(key_id, fingerprint)
        
    return KeyGenerationResponse(
        key=new_key,
        key_prefix=key_prefix,
        message="API key generated successfully!"
    )'''
    text = text.replace(gen_key_old.group(0), new_gen_key)

# 5. Fix my-key and my-usage daily token metrics to use exact RPD
text = re.sub(r'tokens_today = await db\.get_daily_tokens_used\([\s\S]*?isoformat\(\)\n    \)', 'tokens_today = key_record.current_rpd  # Now purely checks RPD', text)

with codecs.open('backend/main.py', 'w', 'utf-8') as f:
    f.write(text)
print("done backend main patch")
