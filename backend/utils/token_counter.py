"""AISS - LLM Token Counter (tiktoken)
Counts tokens before sending to an LLM to avoid hitting context limits
and to estimate API cost.

Usage:
    from utils.token_counter import count_tokens, truncate_to_tokens, estimate_cost
    n = count_tokens("Hello world", model="gpt-4o-mini")
    text = truncate_to_tokens(long_text, max_tokens=3000, model="gpt-4o-mini")
    cost = estimate_cost(1000, 500, model="gpt-4o-mini")
"""
import os
from typing import Optional
from utils.logger import setup_logger

logger = setup_logger("token_counter")

# Cost per 1K tokens (USD) — approximate, update as prices change
_COST_TABLE: dict[str, dict] = {
    "gpt-4o":           {"input": 0.005,  "output": 0.015},
    "gpt-4o-mini":      {"input": 0.00015,"output": 0.0006},
    "gpt-4-turbo":      {"input": 0.01,   "output": 0.03},
    "gpt-3.5-turbo":    {"input": 0.0005, "output": 0.0015},
    "claude-3-5-sonnet":{"input": 0.003,  "output": 0.015},
    "claude-3-haiku":   {"input": 0.00025,"output": 0.00125},
}

_enc_cache: dict[str, object] = {}


def _get_encoding(model: str):
    """Lazy-load tiktoken encoding for a model."""
    if model in _enc_cache:
        return _enc_cache[model]
    try:
        import tiktoken
        try:
            enc = tiktoken.encoding_for_model(model)
        except KeyError:
            enc = tiktoken.get_encoding("cl100k_base")
        _enc_cache[model] = enc
        return enc
    except ImportError:
        logger.debug("tiktoken not installed — token counting unavailable")
        return None
    except Exception as e:
        logger.debug(f"tiktoken encoding error: {e}")
        return None


def count_tokens(text: str, model: str = "gpt-4o-mini") -> int:
    """
    Count tokens in text for the given model.
    Returns character-based estimate if tiktoken is unavailable.
    """
    enc = _get_encoding(model)
    if enc:
        try:
            return len(enc.encode(text))
        except Exception:
            pass
    # Fallback: ~4 chars per token
    return len(text) // 4


def truncate_to_tokens(text: str, max_tokens: int, model: str = "gpt-4o-mini") -> str:
    """
    Truncate text to stay within max_tokens.
    Returns truncated string.
    """
    enc = _get_encoding(model)
    if enc:
        try:
            tokens = enc.encode(text)
            if len(tokens) <= max_tokens:
                return text
            return enc.decode(tokens[:max_tokens])
        except Exception:
            pass
    # Fallback: character-based
    char_limit = max_tokens * 4
    return text[:char_limit]


def estimate_cost(
    input_tokens: int,
    output_tokens: int,
    model: str = "gpt-4o-mini",
) -> dict:
    """
    Estimate API cost for a request.
    Returns dict with input_cost, output_cost, total_cost (USD).
    """
    costs = _COST_TABLE.get(model)
    # Try prefix match for model families
    if not costs:
        for prefix, c in _COST_TABLE.items():
            if model.startswith(prefix):
                costs = c
                break
    if not costs:
        costs = {"input": 0.001, "output": 0.002}  # conservative default

    input_cost  = (input_tokens  / 1000) * costs["input"]
    output_cost = (output_tokens / 1000) * costs["output"]
    return {
        "model":        model,
        "input_tokens": input_tokens,
        "output_tokens":output_tokens,
        "input_cost":   round(input_cost,  6),
        "output_cost":  round(output_cost, 6),
        "total_cost":   round(input_cost + output_cost, 6),
        "currency":     "USD",
    }


def is_available() -> bool:
    """Return True if tiktoken is installed."""
    return _get_encoding("gpt-4o-mini") is not None
