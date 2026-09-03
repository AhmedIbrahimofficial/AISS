"""AISS - FastAPI Dependencies
Centralized dependency injection for engine, auth, db session, etc.
Use these with FastAPI's Depends() instead of global set_engine() calls.
"""

from fastapi import Depends, HTTPException, status
from typing import TYPE_CHECKING
from sqlalchemy.ext.asyncio import AsyncSession

from core.auth import get_current_user
from core.database import get_db
from core.threat_engine import ThreatEngine
from core.websocket_manager import WebSocketManager

if TYPE_CHECKING:
    from agents.orchestrator import AgentOrchestrator
    from agents.scheduler import SchedulerEngine

# ── Singleton instances (set once in main.py lifespan) ───────────────
_threat_engine: ThreatEngine | None = None
_ws_manager: WebSocketManager | None = None
_orchestrator: "AgentOrchestrator | None" = None
_scheduler: "SchedulerEngine | None" = None


def init_services(engine: ThreatEngine, ws_manager: WebSocketManager):
    """Called once during app startup to register singleton instances."""
    global _threat_engine, _ws_manager
    _threat_engine = engine
    _ws_manager = ws_manager


def init_agent_services(orchestrator: "AgentOrchestrator", scheduler: "SchedulerEngine") -> None:
    """Called once during app startup to register agent singletons."""
    global _orchestrator, _scheduler
    _orchestrator = orchestrator
    _scheduler = scheduler


# ── Engine dependency ─────────────────────────────────────────────────
def get_engine() -> ThreatEngine:
    if _threat_engine is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Threat engine not initialized"
        )
    return _threat_engine


# ── WebSocket manager dependency ──────────────────────────────────────
def get_ws_manager() -> WebSocketManager:
    if _ws_manager is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="WebSocket manager not initialized"
        )
    return _ws_manager


# ── Agent orchestrator dependency ─────────────────────────────────────
def get_orchestrator() -> "AgentOrchestrator":
    if _orchestrator is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Agent orchestrator not initialized",
        )
    return _orchestrator


def get_scheduler() -> "SchedulerEngine":
    if _scheduler is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Scheduler not initialized",
        )
    return _scheduler


# ── Authenticated engine — requires valid JWT ─────────────────────────
def get_engine_authenticated(
    engine: ThreatEngine = Depends(get_engine),
    user: dict = Depends(get_current_user),
) -> ThreatEngine:
    """Returns engine only if request carries a valid JWT."""
    return engine


# ── Role-based access ─────────────────────────────────────────────────
def require_role(*roles: str):
    """
    Dependency factory — restricts endpoint to specific roles.
    """
    def _check(user: dict = Depends(get_current_user)) -> dict:
        if user.get("role") not in roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Access denied. Required role: {' or '.join(roles)}"
            )
        return user
    return _check


# ── DB session shorthand ──────────────────────────────────────────────
get_db_session = get_db
