"""AISS — Remote Agents API Routes
Endpoints for managing and monitoring connected remote agents.
"""
from fastapi import APIRouter, HTTPException, WebSocket, Depends
from pydantic import BaseModel
from typing import Optional
from core.dependencies import get_engine_authenticated
from core.threat_engine import ThreatEngine

router = APIRouter()


# ── List all agents ───────────────────────────────────────────────────

@router.get("/")
async def list_agents():
    """List all connected and previously-seen remote agents."""
    from modules.remote_agent import agent_manager
    return {
        "agents": agent_manager.get_all_agents(),
        "stats":  agent_manager.get_stats(),
    }


@router.get("/stats")
async def agent_stats():
    """Summary statistics for all agents."""
    from modules.remote_agent import agent_manager
    return agent_manager.get_stats()


# ── Individual agent ──────────────────────────────────────────────────

@router.get("/{agent_id}")
async def get_agent(agent_id: str):
    """Get details and live metrics for a specific agent."""
    from modules.remote_agent import agent_manager
    agent = agent_manager.get_agent(agent_id)
    if not agent:
        raise HTTPException(status_code=404, detail=f"Agent {agent_id} not found")
    return agent.to_dict()


@router.get("/{agent_id}/threats")
async def get_agent_threats(agent_id: str, limit: int = 50):
    """Get threats detected by a specific agent."""
    from modules.remote_agent import agent_manager
    return {
        "agent_id": agent_id,
        "threats":  agent_manager.get_agent_threats(agent_id, limit),
    }


# ── Token management ─────────────────────────────────────────────────

class TokenRequest(BaseModel):
    label: str = "agent"


@router.post("/token/generate",
             dependencies=[Depends(get_engine_authenticated)])
async def generate_token(req: TokenRequest):
    """
    Generate a new agent authentication token.
    Share this token with the remote machine running aiss_agent.py.
    """
    from modules.remote_agent import generate_agent_token
    result = generate_agent_token(req.label)
    return {
        **result,
        "usage": (
            f"On the remote machine run:\n"
            f"  python aiss_agent.py "
            f"--server ws://YOUR_AISS_IP:8000 "
            f"--token {result['token']}"
        ),
    }


@router.get("/tokens/list",
            dependencies=[Depends(get_engine_authenticated)])
async def list_tokens():
    """List all active agent tokens (hashes only — no plaintext)."""
    from modules.remote_agent import agent_manager
    return {"tokens": agent_manager.list_tokens()}


class RevokeRequest(BaseModel):
    label: str


@router.post("/tokens/revoke",
             dependencies=[Depends(get_engine_authenticated)])
async def revoke_token(req: RevokeRequest):
    """Revoke all tokens with the given label."""
    from modules.remote_agent import agent_manager
    n = agent_manager.revoke_token(req.label)
    return {"revoked": n, "label": req.label}


# ── Commands ──────────────────────────────────────────────────────────

class CommandRequest(BaseModel):
    command: str
    params:  dict = {}


@router.post("/{agent_id}/command",
             dependencies=[Depends(get_engine_authenticated)])
async def send_command(agent_id: str, req: CommandRequest):
    """Send a command to a connected agent."""
    from modules.remote_agent import agent_manager
    sent = await agent_manager.send_command(agent_id, req.command, req.params)
    if not sent:
        raise HTTPException(
            status_code=404,
            detail=f"Agent {agent_id} not connected or not found"
        )
    return {"sent": True, "agent_id": agent_id, "command": req.command}


# ── Setup wizard endpoint (serves questions to frontend popup) ────────

@router.get("/setup/questions")
async def get_setup_questions():
    """Return setup wizard questions for the frontend popup system."""
    from modules.setup_wizard import setup_wizard
    return setup_wizard.get_questions()


@router.post("/setup/answers")
async def submit_setup_answers(answers: dict):
    """Process setup wizard answers and apply configuration."""
    from modules.setup_wizard import setup_wizard
    result = await setup_wizard.apply_answers(answers)
    return result
