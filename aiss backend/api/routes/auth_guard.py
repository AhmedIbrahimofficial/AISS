"""AISS - Auth Guard API Routes"""
from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel
from core.dependencies import get_engine, get_engine_authenticated
from core.threat_engine import ThreatEngine

router = APIRouter()


@router.get("/status")
async def auth_guard_status(engine: ThreatEngine = Depends(get_engine)):
    from modules.auth_monitor import _failed_attempts, BRUTE_FORCE_THRESHOLD, BRUTE_FORCE_WINDOW_SECS
    return {
        "status": "monitoring",
        "platform": __import__("sys").platform,
        "threshold": BRUTE_FORCE_THRESHOLD,
        "window_seconds": BRUTE_FORCE_WINDOW_SECS,
        "tracked_ips": len(_failed_attempts),
    }


@router.get("/failed-logins")
async def get_failed_logins(engine: ThreatEngine = Depends(get_engine)):
    from modules.auth_monitor import _failed_attempts
    return {
        "tracked": [
            {"key": k, "attempts": len(v)}
            for k, v in _failed_attempts.items()
            if len(v) > 0
        ],
        "total_tracked": len(_failed_attempts),
    }


@router.get("/threats")
async def get_auth_threats(engine: ThreatEngine = Depends(get_engine)):
    auth_types = {"Brute Force Attack", "Privilege Escalation", "Credential Stuffing"}
    threats = [t for t in engine.get_all_threats() if t.get("type") in auth_types]
    return {"threats": threats, "count": len(threats)}


@router.post("/reset")
async def reset_failed_attempts(engine: ThreatEngine = Depends(get_engine_authenticated)):
    from modules.auth_monitor import _failed_attempts
    _failed_attempts.clear()
    return {"status": "cleared", "message": "Failed login attempt counters reset."}


class AuthConfig(BaseModel):
    threshold: int = 5
    window_seconds: int = 60

@router.post("/config")
async def update_auth_config(
    config: AuthConfig,
    engine: ThreatEngine = Depends(get_engine_authenticated),
):
    import modules.auth_monitor as am

    if not (1 <= config.threshold <= 100):
        raise HTTPException(status_code=400, detail="threshold must be between 1 and 100")
    if not (10 <= config.window_seconds <= 3600):
        raise HTTPException(status_code=400, detail="window_seconds must be between 10 and 3600")

    am.BRUTE_FORCE_THRESHOLD = config.threshold
    am.BRUTE_FORCE_WINDOW_SECS = config.window_seconds

    return {
        "status": "updated",
        "threshold": am.BRUTE_FORCE_THRESHOLD,
        "window_seconds": am.BRUTE_FORCE_WINDOW_SECS,
    }
