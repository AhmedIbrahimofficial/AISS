"""
Cybersecurity - AI SOC Assistant
Answers security questions about detected threats.
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

CLAUDE_API_URL = "https://api.anthropic.com/v1/messages"
CLAUDE_MODEL   = "claude-sonnet-4-20250514"

SOC_SYSTEM_PROMPT = """You are an AI SOC (Security Operations Center) Assistant for CyberSec Platform.
You help security analysts understand threats, CVEs, and mitigations.

When answering:
- Be concise and practical
- Include CVE numbers when relevant
- Give step-by-step mitigation
- Use severity ratings (CRITICAL/HIGH/MEDIUM/LOW)
- Format with clear sections

You have access to the current threat context provided in the user message."""


class ChatRequest(BaseModel):
    message:   str
    threat_id: str = ""   # optional — attach specific threat context
    api_key:   str = ""


class ChatResponse(BaseModel):
    reply:      str
    threat_id:  str = ""


@router.post("/soc/chat", response_model=ChatResponse)
async def soc_chat(
    req:    ChatRequest,
    engine: ThreatEngine = Depends(get_engine),
):
    api_key = req.api_key or os.environ.get("ANTHROPIC_API_KEY", "")
    if not api_key:
        raise HTTPException(400, "ANTHROPIC_API_KEY required")

    # Build context from threat if provided
    threat_context = ""
    if req.threat_id:
        threat = engine.active_threats.get(req.threat_id)
        if threat:
            threat_context = f"""
CURRENT THREAT CONTEXT:
- Type: {threat.type}
- Severity: {threat.severity}
- Description: {threat.description}
- Source: {threat.source}
- Module: {threat.module}
- Detected: {threat.detected_at}
- Status: {threat.status}

"""

    full_message = f"{threat_context}User question: {req.message}"

    try:
        async with httpx.AsyncClient(timeout=30) as client:
            res = await client.post(
                CLAUDE_API_URL,
                headers={
                    "x-api-key":         api_key,
                    "anthropic-version": "2023-06-01",
                    "Content-Type":      "application/json",
                },
                json={
                    "model":      CLAUDE_MODEL,
                    "max_tokens": 800,
                    "system":     SOC_SYSTEM_PROMPT,
                    "messages":   [{"role": "user", "content": full_message}],
                },
            )
            data  = res.json()
            reply = data["content"][0]["text"]
    except Exception as e:
        logger.error(f"SOC chat error: {e}")
        raise HTTPException(500, f"AI service error: {e}")

    return ChatResponse(reply=reply, threat_id=req.threat_id)
