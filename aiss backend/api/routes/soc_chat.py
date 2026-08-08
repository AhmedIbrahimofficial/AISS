"""AISS - AI SOC Assistant
Supports both Anthropic Claude and OpenAI GPT via the unified AIAnalyst provider.
"""
import os
import httpx
from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel
from core.dependencies import get_engine
from core.threat_engine import ThreatEngine
from utils.logger import setup_logger

router = APIRouter()
logger = setup_logger("soc_chat")

SOC_SYSTEM_PROMPT = """You are an AI SOC (Security Operations Center) Assistant for AISS Platform.
You help security analysts understand threats, CVEs, and mitigations.
Be concise and practical. Include CVE numbers when relevant. Give step-by-step mitigation.
Use severity ratings (CRITICAL/HIGH/MEDIUM/LOW). Format with clear sections."""


class ChatRequest(BaseModel):
    message:   str
    threat_id: str  = ""
    api_key:   str  = ""
    provider:  str  = "auto"   # "auto" | "claude" | "openai"


class ChatResponse(BaseModel):
    reply:    str
    provider: str = ""


@router.post("/soc/chat", response_model=ChatResponse)
async def soc_chat(req: ChatRequest, engine: ThreatEngine = Depends(get_engine)):
    # Resolve API key: prefer explicit, then env
    api_key = req.api_key.strip()
    if not api_key:
        api_key = os.environ.get("ANTHROPIC_API_KEY", "") or os.environ.get("OPENAI_API_KEY", "")
    if not api_key:
        raise HTTPException(400, "No AI API key configured. Set ANTHROPIC_API_KEY or OPENAI_API_KEY in .env")

    # Build threat context
    ctx = ""
    if req.threat_id:
        t = engine.active_threats.get(req.threat_id)
        if t:
            ctx = (f"THREAT CONTEXT:\n"
                   f"Type: {t.type} | Severity: {t.severity} | Source: {t.source}\n"
                   f"Description: {t.description}\nStatus: {t.status}\n\n")

    from modules.ai_analyst import AIAnalyst
    analyst = AIAnalyst(api_key=api_key, provider=req.provider)

    try:
        reply = await analyst._complete(
            user_prompt=f"{ctx}User question: {req.message}",
            system=SOC_SYSTEM_PROMPT,
            max_tokens=800,
        )
    except Exception as e:
        logger.error(f"SOC chat error [{analyst.provider}]: {e}")
        raise HTTPException(500, f"AI service error: {e}")

    return ChatResponse(reply=reply, provider=analyst.provider)
