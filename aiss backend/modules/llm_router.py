"""AISS - LLM Router (Multi-Provider via LiteLLM)
Unified interface to all available LLM providers with automatic fallback.

Priority order (auto-detected from env keys):
  1. Anthropic Claude (ANTHROPIC_API_KEY)
  2. OpenAI GPT (OPENAI_API_KEY)
  3. Groq (GROQ_API_KEY) — ultra-fast
  4. Google Gemini (GOOGLE_API_KEY / GEMINI_API_KEY)
  5. Local Llama (LLAMA_MODEL_PATH) — offline fallback

Usage:
    from modules.llm_router import llm_router
    text = await llm_router.complete("Analyse this threat: ...")
    result = await llm_router.complete_json("Classify this as JSON", schema=MyModel)
"""
import asyncio
import json
import os
import re
from typing import Any, Optional, Type

from utils.logger import setup_logger

logger = setup_logger("llm_router")


def _build_provider_list() -> list[tuple[str, str]]:
    """
    Returns [(litellm_model_name, description), ...] in priority order
    based on which API keys are set.
    """
    providers = []
    if os.environ.get("ANTHROPIC_API_KEY"):
        model = os.environ.get("ANTHROPIC_MODEL", "claude-sonnet-4-20250514")
        providers.append((f"anthropic/{model}", "Anthropic Claude"))
    if os.environ.get("OPENAI_API_KEY"):
        model = os.environ.get("OPENAI_MODEL", "gpt-4o-mini")
        providers.append((f"openai/{model}", "OpenAI GPT"))
    if os.environ.get("GROQ_API_KEY"):
        model = os.environ.get("GROQ_MODEL", "llama3-70b-8192")
        providers.append((f"groq/{model}", "Groq (fast)"))
    if os.environ.get("GOOGLE_API_KEY") or os.environ.get("GEMINI_API_KEY"):
        model = os.environ.get("GEMINI_MODEL", "gemini/gemini-1.5-flash")
        providers.append((model, "Google Gemini"))
    return providers


class LLMRouter:
    """
    Multi-provider LLM with fallback chain via LiteLLM.
    Falls back to offline Llama if all cloud providers fail.
    """

    def __init__(self):
        self._providers = _build_provider_list()
        self._litellm   = None
        self._llama     = None
        self._tried     = False

    def _lazy_init(self):
        if self._tried:
            return
        self._tried = True
        try:
            from core.lib_registry import lib_registry
            if lib_registry.is_enabled("litellm"):
                import litellm
                self._litellm = litellm
            if lib_registry.is_enabled("llama_cpp"):
                self._llama = lib_registry.get("llama_cpp")
        except Exception as e:
            logger.debug(f"LLMRouter lazy init: {e}")

    async def complete(
        self,
        prompt: str,
        system: str = "You are a cybersecurity AI assistant.",
        max_tokens: int = 1200,
        temperature: float = 0.1,
    ) -> str:
        """
        Complete a prompt using the best available provider.
        Tries each provider in order; falls back to Llama on failure.
        Returns the text response.
        """
        self._lazy_init()

        messages = [
            {"role": "system",  "content": system},
            {"role": "user",    "content": prompt},
        ]

        # Count tokens and log estimated cost
        try:
            from utils.token_counter import count_tokens, estimate_cost
            model_name = self._providers[0][0].split("/")[-1] if self._providers else "gpt-4o-mini"
            input_tokens = count_tokens(system + "\n" + prompt, model=model_name)
            logger.debug(f"LLMRouter: ~{input_tokens} input tokens")
        except Exception:
            pass

        # ── Try cloud providers via LiteLLM ───────────────────────────
        if self._litellm and self._providers:
            for model, desc in self._providers:
                try:
                    loop = asyncio.get_event_loop()
                    resp = await loop.run_in_executor(
                        None,
                        lambda m=model: self._litellm.completion(
                            model=m,
                            messages=messages,
                            max_tokens=max_tokens,
                            temperature=temperature,
                        )
                    )
                    text = resp.choices[0].message.content
                    # Track LLM metrics
                    try:
                        from core.metrics import inc_llm_request, inc_llm_tokens
                        from utils.token_counter import count_tokens
                        provider_label = desc.split()[0].lower()
                        inc_llm_request(provider_label)
                        inc_llm_tokens(
                            provider_label,
                            count_tokens(system + "\n" + prompt),
                            count_tokens(text),
                        )
                    except Exception:
                        pass
                    logger.debug(f"LLMRouter: used {desc}")
                    return text
                except Exception as e:
                    logger.warning(f"LLMRouter: {desc} failed ({e}), trying next...")
                    continue

        # ── Fallback: local Llama ─────────────────────────────────────
        if self._llama:
            try:
                loop   = asyncio.get_event_loop()
                result = await loop.run_in_executor(
                    None,
                    lambda: self._llama.create_chat_completion(
                        messages=messages,
                        max_tokens=max_tokens,
                        temperature=temperature,
                    )
                )
                text = result["choices"][0]["message"]["content"]
                logger.info("LLMRouter: used local Llama (offline)")
                return text
            except Exception as e:
                logger.warning(f"LLMRouter: Llama fallback failed: {e}")

        return f"[LLMRouter: no provider available. Prompt: {prompt[:80]}...]"

    async def complete_json(
        self,
        prompt: str,
        system: str = "Respond ONLY with valid JSON. No markdown.",
        max_tokens: int = 1000,
    ) -> dict:
        """Complete and parse the result as JSON."""
        text = await self.complete(prompt, system=system, max_tokens=max_tokens)
        # Strip markdown code fences if present
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

    def available_providers(self) -> list[str]:
        return [desc for _, desc in self._providers]

    def is_available(self) -> bool:
        self._lazy_init()
        return bool(self._providers and self._litellm) or bool(self._llama)

    def get_stats(self) -> dict:
        self._lazy_init()
        return {
            "providers":        self.available_providers(),
            "litellm_ready":    self._litellm is not None,
            "llama_ready":      self._llama is not None,
            "total_providers":  len(self._providers),
        }


# Singleton
llm_router = LLMRouter()
