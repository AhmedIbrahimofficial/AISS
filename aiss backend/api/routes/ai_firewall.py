"""CyberSentinel - AI Firewall API Routes"""
from fastapi import APIRouter, HTTPException, Request, Depends
from pydantic import BaseModel
from core.dependencies import get_engine
from core.threat_engine import ThreatEngine
from modules.ai_firewall import inspect, get_stats
from utils.logger import setup_logger

router = APIRouter()
logger = setup_logger("ai_firewall_route")


class InspectRequest(BaseModel):
    text: str


class InspectResponse(BaseModel):
    blocked:     bool
    attack_type: str
    reason:      str
    risk:        str
    timestamp:   str


@router.post("/ai-firewall/inspect", response_model=InspectResponse)
async def inspect_prompt(
    req:     InspectRequest,
    request: Request,
    engine:  ThreatEngine = Depends(get_engine),
):
    """
    Inspect any text for AI attacks before sending to an AI model.
    If blocked=True, do NOT forward to the AI.
    """
    ip     = request.client.host if request.client else "unknown"
    result = inspect(req.text, source_ip=ip)

    # Register as threat if blocked
    if result.blocked:
        from models.threat import Threat, ThreatType, ThreatSeverity
        severity_map = {
            "CRITICAL": ThreatSeverity.CRITICAL,
            "HIGH":     ThreatSeverity.HIGH,
            "MEDIUM":   ThreatSeverity.MEDIUM,
            "LOW":      ThreatSeverity.LOW,
        }
        threat = Threat(
            type        = ThreatType.INTRUSION,
            description = f"AI Firewall: {result.attack_type} — {result.reason}",
            severity    = severity_map.get(result.risk, ThreatSeverity.HIGH),
            source      = ip,
            module      = "AIFirewall",
            metadata    = {
                "attack_type": result.attack_type,
                "reason":      result.reason,
                "text_preview": req.text[:100],
            },
        )
        await engine.register_threat(threat)

    return InspectResponse(**result.to_dict())


@router.get("/ai-firewall/stats")
async def firewall_stats():
    """Rate-limit stats per IP."""
    return {"rate_limits": get_stats()}


@router.post("/ai-firewall/safe-chat")
async def safe_chat(
    req:     InspectRequest,
    request: Request,
    engine:  ThreatEngine = Depends(get_engine),
):
    """
    Inspect prompt → if clean, forward to Claude AI.
    One-shot safe endpoint that combines firewall + AI.
    """
    import os
    ip     = request.client.host if request.client else "unknown"
    result = inspect(req.text, source_ip=ip)

    if result.blocked:
        from models.threat import Threat, ThreatType, ThreatSeverity
        threat = Threat(
            type        = ThreatType.INTRUSION,
            description = f"AI Firewall BLOCKED: {result.attack_type} — {result.reason}",
            severity    = ThreatSeverity.CRITICAL if result.risk == "CRITICAL" else ThreatSeverity.HIGH,
            source      = ip,
            module      = "AIFirewall",
            metadata    = result.to_dict(),
        )
        await engine.register_threat(threat)
        raise HTTPException(
            status_code = 403,
            detail      = f"Blocked by AI Firewall: {result.attack_type} — {result.reason}",
        )

    # Clean — forward to Claude
    api_key = os.environ.get("ANTHROPIC_API_KEY", "")
    if not api_key:
        raise HTTPException(400, "ANTHROPIC_API_KEY not set")

    import httpx
    async with httpx.AsyncClient(timeout=30) as client:
        res = await client.post(
            "https://api.anthropic.com/v1/messages",
            headers={
                "x-api-key":         api_key,
                "anthropic-version": "2023-06-01",
                "Content-Type":      "application/json",
            },
            json={
                "model":    "claude-sonnet-4-20250514",
                "max_tokens": 500,
                "messages": [{"role": "user", "content": req.text}],
            },
        )

    data = res.json()
    return {
        "firewall": result.to_dict(),
        "response": data.get("content", [{}])[0].get("text", ""),
    }
