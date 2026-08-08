"""AISS - FastAPI Dependencies
Centralized dependency injection for engine, auth, db session, etc.
Use these with FastAPI's Depends() instead of global set_engine() calls.
"""

from fastapi import Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from core.auth import get_current_user
from core.database import get_db
from core.threat_engine import ThreatEngine
from core.websocket_manager import WebSocketManager

# ── Singleton instances (set once in main.py lifespan) ───────────────
_threat_engine: ThreatEngine | None = None
_ws_manager: WebSocketManager | None = None


def init_services(engine: ThreatEngine, ws_manager: WebSocketManager):
    """Called once during app startup to register singleton instances."""
    global _threat_engine, _ws_manager
    _threat_engine = engine
    _ws_manager = ws_manager


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

    Usage:
        @router.delete("/clear")
        async def clear(user=Depends(require_role("admin"))):
            ...
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
# Re-export so routes only need to import from core.dependencies
get_db_session = get_db
