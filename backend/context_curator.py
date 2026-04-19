"""Context Curator — trims conversation history when it exceeds 16k tokens.

Uses a cheap NVIDIA-hosted model (deepseek-ai/deepseek-v3.1) with fallback
chain to summarise old messages down to ~8k tokens.

Rules:
- Only fires when estimated token count > 16 000
- Never summarises the last 3 user/assistant exchanges (6 messages)
- Never summarises the system prompt (first message if role == "system")
- Truncation of messages is NOT allowed — we summarise instead
"""

from __future__ import annotations

import json
import logging
from typing import Any, Optional

import httpx

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# NVIDIA gateway config
# ---------------------------------------------------------------------------

NVIDIA_API_BASE = "https://integrate.api.nvidia.com/v1"
NVIDIA_API_KEY  = "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"

# Primary + ordered fallback models
CHEAP_MODELS: list[str] = [
    "deepseek-ai/deepseek-v3.1",
    "moonshotai/kimi-k2.5",
    "openai/gpt-oss-120b",
    "moonshotai/kimi-k2-instruct-0905",
    "moonshotai/kimi-k2-instruct",
]

# Token thresholds (rough 4-chars-per-token heuristic)
TRIGGER_TOKENS   = 10_000   # summarise when input exceeds this
TARGET_TOKENS    = 6_000    # aim for this after summarisation
PROTECTED_TURNS  = 1        # never summarise the last N user/assistant turns (1 turn = last 2 messages)

# System prompt injected into every summarisation call
SUMMARISER_SYSTEM_PROMPT = (
    "You are a text compressor. Your only job is to summarize conversation history "
    "into 8k tokens maximum.\n\n"
    "Rules:\n"
    "- Keep only the most important facts, questions, and answers\n"
    "- Remove repetition, greetings, filler words\n"
    "- Preserve names, dates, key decisions, unresolved questions, roles\n"
    "- If the original text is already under 16k tokens, return it almost unchanged\n"
    "- Be aggressive but don't invent information\n"
    "- Output ONLY the summary, no extra text"
)


# ---------------------------------------------------------------------------
# Token estimation (mirrors main.py heuristic)
# ---------------------------------------------------------------------------

def _estimate_tokens(messages: list[dict[str, Any]]) -> int:
    total = 0
    for m in messages:
        role    = str(m.get("role", ""))
        content = m.get("content", "")
        if isinstance(content, list):
            content = " ".join(
                p.get("text", "") if isinstance(p, dict) else str(p)
                for p in content
            )
        total += len(role) + len(str(content)) + 16
    return total // 4


# ---------------------------------------------------------------------------
# NVIDIA gateway with fallback
# ---------------------------------------------------------------------------

async def _call_nvidia(
    messages: list[dict[str, Any]],
    client: httpx.AsyncClient,
) -> tuple[str, str]:
    """Try each model in CHEAP_MODELS in order.

    Returns (response_text, model_used).
    Raises RuntimeError if all models fail.
    """
    last_error: Optional[Exception] = None

    for model in CHEAP_MODELS:
        try:
            logger.info("[ContextCurator] Trying model: %s", model)
            resp = await client.post(
                f"{NVIDIA_API_BASE}/chat/completions",
                headers={
                    "Authorization": f"Bearer {NVIDIA_API_KEY}",
                    "Content-Type": "application/json",
                },
                json={
                    "model": model,
                    "messages": messages,
                    "max_tokens": 4096,
                    "temperature": 0.3,
                    "stream": False,
                },
                timeout=60.0,
            )

            if resp.status_code in (429, 500, 502, 503, 504):
                logger.warning(
                    "[ContextCurator] Model %s returned %s — trying next",
                    model, resp.status_code,
                )
                last_error = RuntimeError(f"HTTP {resp.status_code} from {model}")
                continue

            resp.raise_for_status()
            data = resp.json()
            text = data["choices"][0]["message"]["content"]
            logger.info("[ContextCurator] Used model: %s", model)
            return text, model

        except (httpx.TimeoutException, httpx.ConnectError, httpx.RemoteProtocolError) as exc:
            logger.warning("[ContextCurator] Model %s network error: %s — trying next", model, exc)
            last_error = exc
            continue
        except Exception as exc:
            logger.warning("[ContextCurator] Model %s unexpected error: %s — trying next", model, exc)
            last_error = exc
            continue

    raise RuntimeError(
        f"All NVIDIA models failed. Last error: {last_error}"
    )


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

async def maybe_curate_context(
    messages: list[dict[str, Any]],
    client: Optional[httpx.AsyncClient] = None,
) -> list[dict[str, Any]]:
    """Return (possibly summarised) messages.

    If the estimated token count is <= TRIGGER_TOKENS, returns messages unchanged.
    Otherwise, summarises the compressible portion and splices the result back in.

    Args:
        messages: The full conversation history (including system prompt).
        client:   Optional shared httpx.AsyncClient. A temporary one is created
                  if not provided.

    Returns:
        The (possibly shorter) message list.
    """
    token_count = _estimate_tokens(messages)
    if token_count <= TRIGGER_TOKENS:
        return messages

    logger.info(
        "[ContextCurator] Token count %d > %d — curating context",
        token_count, TRIGGER_TOKENS,
    )

    # Split messages into protected and compressible sections
    system_msgs:      list[dict] = []
    non_system_msgs:  list[dict] = []

    for m in messages:
        if m.get("role") == "system":
            system_msgs.append(m)
        else:
            non_system_msgs.append(m)

    # Protect the last PROTECTED_TURNS * 2 messages (each turn = user + assistant)
    protected_count = PROTECTED_TURNS * 2
    if len(non_system_msgs) <= protected_count:
        # Nothing left to compress — return as-is to avoid mangling short histories
        logger.info("[ContextCurator] Not enough messages to compress safely — skipping")
        return messages

    compressible = non_system_msgs[:-protected_count]
    protected    = non_system_msgs[-protected_count:]

    # Serialise compressible history for the summariser
    history_text = "\n".join(
        f"{m['role'].upper()}: {m.get('content', '')}"
        for m in compressible
    )

    summariser_messages = [
        {"role": "system", "content": SUMMARISER_SYSTEM_PROMPT},
        {"role": "user",   "content": f"Summarize the following conversation history:\n\n{history_text}"},
    ]

    own_client = client is None
    if own_client:
        client = httpx.AsyncClient(timeout=httpx.Timeout(connect=10.0, read=60.0, write=30.0, pool=10.0))

    try:
        summary_text, model_used = await _call_nvidia(summariser_messages, client)
        logger.info("[ContextCurator] Summary produced by %s (%d chars)", model_used, len(summary_text))
    except RuntimeError as exc:
        logger.error("[ContextCurator] Summarisation failed: %s — returning original messages", exc)
        return messages
    finally:
        if own_client:
            await client.aclose()

    # Rebuild message list: system + summary placeholder + protected tail
    summary_message: dict[str, Any] = {
        "role": "system",
        "content": (
            f"[CONVERSATION SUMMARY — earlier context compressed by context curator "
            f"using {model_used}]\n\n{summary_text}"
        ),
    }

    curated = system_msgs + [summary_message] + protected

    new_count = _estimate_tokens(curated)
    logger.info(
        "[ContextCurator] Context reduced: %d → %d tokens (model: %s)",
        token_count, new_count, model_used,
    )
    return curated
