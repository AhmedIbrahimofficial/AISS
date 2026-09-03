"""AISS — LLM Router (OpenRouter-first)

All LLM calls route through OpenRouter using OPENROUTER_API_KEY.
Fallback chain: tries 8 models in order on failure.

This replaces the old multi-provider LiteLLM approach.
Set OPENROUTER_API_KEY in .env — that is the only key required.
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
import re
from typing import Any

import httpx

from utils.logger import setup_logger

logger = setup_logger("llm_router")

_OPENROUTER_URL = "https://openrouter.ai/api/v1/chat/completions"

# Models tried in order — first one that responds wins
_FALLBACK_CHAIN = [
    "anthropic/claude-3.5-sonnet",
    "anthropic/claude-3-haiku",
    "openai/gpt-4o",
    "openai/gpt-4o-mini",
    "google/gemini-pro-1.5",
    "meta-llama/llama-3.1-70b-instruct",
    "mistralai/mistral-large",
    "deepseek/deepseek-chat",
]


class LLMRouter:
    """
    Single OpenRouter client with automatic model fallback.
    One singleton shared across the whole application.

    API key is read lazily on first use so that it picks up the value
    set in .env even if the module is imported before python-dotenv runs.
    """

    def __init__(self) -> None:
        self._api_key: str = ""
        self._models: list[str] = []
        self._initialised = False

    def _lazy_init(self) -> None:
        """Initialise once — reads env vars at call time, not import time."""
        if self._initialised:
            return
        self._initialised = True
        self._api_key = os.environ.get("OPENROUTER_API_KEY", "")
        raw_model = os.environ.get("OPENROUTER_MODEL", _FALLBACK_CHAIN[0])
        self._models = [raw_model] + [m for m in _FALLBACK_CHAIN if m != raw_model]

    def is_available(self) -> bool:
        self._lazy_init()
        return bool(self._api_key)

    def available_providers(self) -> list[str]:
        self._lazy_init()
        return self._models[:4] if self.is_available() else []

    def get_stats(self) -> dict:
        self._lazy_init()
        return {
            "provider":       "openrouter",
            "available":      self.is_available(),
            "primary_model":  self._models[0] if self._models else "none",
            "fallback_count": len(self._models),
        }

    # ------------------------------------------------------------------ #
    #  Public API                                                          #
    # ------------------------------------------------------------------ #

    async def complete(
        self,
        prompt: str,
        system: str = "You are a cybersecurity AI assistant.",
        max_tokens: int = 1200,
        temperature: float = 0.1,
    ) -> str:
        """Return plain-text completion."""
        self._lazy_init()
        if not self._api_key:
            return (
                "[LLM unavailable] OPENROUTER_API_KEY is not set in .env. "
                "Add your key to enable AI features: https://openrouter.ai/keys"
            )
        messages = [
            {"role": "system", "content": system},
            {"role": "user",   "content": prompt},
        ]
        return await self._call(messages, max_tokens=max_tokens, temperature=temperature)

    async def complete_messages(
        self,
        messages: list[dict],
        max_tokens: int = 1200,
        temperature: float = 0.1,
    ) -> str:
        """Return plain-text completion from a full messages list (system+history+user)."""
        return await self._call(messages, max_tokens=max_tokens, temperature=temperature)

    async def complete_json(
        self,
        prompt: str,
        system: str = "Respond ONLY with valid JSON. No markdown fences.",
        max_tokens: int = 1000,
    ) -> dict:
        """Return parsed JSON dict from LLM response."""
        self._lazy_init()
        text = await self.complete(prompt, system=system, max_tokens=max_tokens)
        # Strip markdown code fences
        text = re.sub(r"```(?:json)?", "", text).strip().strip("`").strip()
        try:
            return json.loads(text)
        except Exception:
            m = re.search(r"\{.*\}", text, re.DOTALL)
            if m:
                try:
                    return json.loads(m.group())
                except Exception:
                    pass
        return {"raw": text}

    # ------------------------------------------------------------------ #
    #  Internal                                                            #
    # ------------------------------------------------------------------ #

    async def _call(
        self,
        messages: list[dict],
        max_tokens: int = 1200,
        temperature: float = 0.1,
    ) -> str:
        """POST to OpenRouter, try each model in fallback chain."""
        self._lazy_init()
        last_error: str = "Unknown error"

        for model in self._models:
            for attempt in range(3):
                try:
                    async with httpx.AsyncClient(timeout=90) as client:
                        resp = await client.post(
                            _OPENROUTER_URL,
                            headers={
                                "Authorization": f"Bearer {self._api_key}",
                                "HTTP-Referer":  "https://aiss-platform.local",
                                "X-Title":       "AISS Security Platform",
                                "Content-Type":  "application/json",
                            },
                            json={
                                "model":       model,
                                "messages":    messages,
                                "max_tokens":  max_tokens,
                                "temperature": temperature,
                            },
                        )

                    # Bad API key — fail immediately, no point retrying
                    if resp.status_code == 401:
                        return (
                            "[LLM Error] OpenRouter returned 401 Unauthorized. "
                            "Check OPENROUTER_API_KEY in .env."
                        )

                    # Model-specific quota/rate — try next model
                    if resp.status_code in (402, 429, 503):
                        last_error = f"HTTP {resp.status_code} on model {model}"
                        logger.warning("LLMRouter: %s → trying next model", last_error)
                        break

                    resp.raise_for_status()
                    content = resp.json()["choices"][0]["message"]["content"]
                    if model != self._models[0]:
                        logger.info("LLMRouter: used fallback model '%s'", model)
                    return content.strip()

                except (httpx.TimeoutException, httpx.RequestError) as e:
                    last_error = str(e)
                    if attempt < 2:
                        wait = (attempt + 1) * 3
                        logger.warning(
                            "LLMRouter: model '%s' attempt %d/3 failed (%s), retry in %ds",
                            model, attempt + 1, e, wait,
                        )
                        await asyncio.sleep(wait)
                    else:
                        logger.warning("LLMRouter: model '%s' exhausted retries", model)

                except Exception as e:
                    last_error = str(e)
                    logger.warning("LLMRouter: model '%s' error: %s", model, e)
                    break

        return f"[LLM Error] All models failed. Last error: {last_error}"


# Application-wide singleton
llm_router = LLMRouter()
