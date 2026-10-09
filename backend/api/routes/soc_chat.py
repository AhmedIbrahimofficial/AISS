"""AISS — AI SOC Chat (OpenRouter)

Uses OpenRouter via the shared llm_router singleton.
Set OPENROUTER_API_KEY in .env — no other AI key required.
"""
from __future__ import annotations

from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel, Field

from core.dependencies import get_engine
from core.threat_engine import ThreatEngine
from modules.llm_router import llm_router
from utils.logger import setup_logger

router = APIRouter()
logger = setup_logger("soc_chat")

SOC_SYSTEM_PROMPT = (
    "You are AISS's AI SOC (Security Operations Center) Assistant. "
    "You help security analysts understand threats, CVEs, attack vectors, and mitigations. "
    "Be concise and practical. Include CVE numbers when relevant. "
    "Give step-by-step mitigation guidance. "
    "Use severity ratings (CRITICAL/HIGH/MEDIUM/LOW). "
    "Never fabricate threat data or invent incidents that were not described to you."
)


class ChatRequest(BaseModel):
    message:   str
    threat_id: str = ""
    history:   list[dict] = Field(default_factory=list)
    # api_key and provider kept for backward compat — ignored, OpenRouter is used
    api_key:   str = ""
    provider:  str = "auto"


class ToolCallInfo(BaseModel):
    tool:   str
    args:   dict = Field(default_factory=dict)
    result: dict = Field(default_factory=dict)


class ChatResponse(BaseModel):
    response:   str
    provider:   str = "openrouter"
    tool_calls: list[ToolCallInfo] = Field(default_factory=list)


# ── simple chat (no agent tools) ─────────────────────────────────────

async def _simple_chat(
    req: ChatRequest,
    engine: ThreatEngine,
) -> ChatResponse:
    """Plain LLM chat without tool-calling."""
    # Attach real threat context if a threat_id was provided
    context = ""
    if req.threat_id:
        threat = engine.active_threats.get(req.threat_id)
        if threat:
            context = (
                f"THREAT CONTEXT:\n"
                f"Type: {threat.type} | Severity: {threat.severity} | Source: {threat.source}\n"
                f"Description: {threat.description} | Status: {threat.status}\n\n"
            )

    # Build messages list from conversation history
    messages: list[dict] = [{"role": "system", "content": SOC_SYSTEM_PROMPT}]
    for h in req.history[-20:]:  # keep last 20 turns
        role = h.get("role", "user")
        content = h.get("text", h.get("content", ""))
        if role in ("user", "assistant") and content:
            messages.append({"role": role, "content": content})

    messages.append({"role": "user", "content": f"{context}Analyst question: {req.message}"})

    try:
        reply = await llm_router._call(messages, max_tokens=900, temperature=0.2)
    except Exception as exc:
        logger.error("SOC chat error: %s", exc)
        raise HTTPException(status_code=500, detail=f"AI service error: {exc}")

    return ChatResponse(response=reply, provider="openrouter")


@router.post("/soc/chat", response_model=ChatResponse)
async def soc_chat(req: ChatRequest, engine: ThreatEngine = Depends(get_engine)):
    if not llm_router.is_available():
        raise HTTPException(
            status_code=503,
            detail=(
                "AI service is temporarily unavailable. "
                "Please contact your AISS administrator."
            ),
        )

    # Try agentic chat first, fall back to simple chat
    try:
        from modules.soc_agent import soc_agent
        if soc_agent.is_available():
            result = await soc_agent.chat(
                user_message=req.message,
                history=req.history,
                threat_engine=engine,
            )
            return result
    except ImportError:
        pass
    except Exception as exc:
        logger.warning("SOCAgent failed, falling back to simple chat: %s", exc)

    return await _simple_chat(req, engine)


# Alias route so both /api/soc-chat and /api/soc/chat work
@router.post("/soc-chat", response_model=ChatResponse)
async def soc_chat_alias(req: ChatRequest, engine: ThreatEngine = Depends(get_engine)):
    return await soc_chat(req, engine)
