"""AISS - Scanner API Routes
Uses the ScanService + Repository pattern — no business logic in routes.
"""
from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from core.dependencies import get_engine, get_engine_authenticated, get_db_session
from core.threat_engine import ThreatEngine
from services.scan_service import ScanService

router = APIRouter()


class ScanRequest(BaseModel):
    target:    str
    scan_type: str = "full"
    user_id:   str = ""   # forwarded from the Next.js BFF via X-User-Id header


class SimulateRequest(BaseModel):
    count: int = 3
    delay: float = 1.0


@router.post("/scan")
async def run_scan(
    request: ScanRequest,
    engine:  ThreatEngine  = Depends(get_engine_authenticated),
    db:      AsyncSession  = Depends(get_db_session),
):
    """
    Full scan flow:
      Validate → ScanService.run() → persist → return JSON
    FastAPI does the scanning; the service persists results to PostgreSQL.
    """
    from fastapi import Request as _Request
    service = ScanService(db=db, engine=engine)

    try:
        result = await service.run(
            target    = request.target,
            scan_type = request.scan_type,
            user_id   = request.user_id or None,
        )
        return result
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


@router.get("/status")
async def scanner_status(engine: ThreatEngine = Depends(get_engine)):
    return {
        "status": "ready",
        "monitoring": engine.monitoring,
        "active_threats": len(engine.get_active_threats()),
    }


@router.post("/simulate")
async def simulate_threats(
    request: SimulateRequest,
    engine:  ThreatEngine = Depends(get_engine_authenticated),
):
    """Inject simulated threats for demo/testing. count: 1–12, delay: seconds between each."""
    count = max(1, min(request.count, 12))
    delay = max(0.1, min(request.delay, 10.0))

    from modules.simulator import simulate_attack_wave
    import asyncio
    asyncio.create_task(simulate_attack_wave(engine, count=count, delay=delay))

    return {
        "status": "simulation_started",
        "threats_queued": count,
        "delay_seconds": delay,
        "message": f"Injecting {count} simulated threats — watch the WebSocket feed."
    }
