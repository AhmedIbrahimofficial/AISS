"""Cybersecurity - Scanner API Routes"""
from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel
from core.dependencies import get_engine, get_engine_authenticated
from core.threat_engine import ThreatEngine

router = APIRouter()


class ScanRequest(BaseModel):
    target: str
    scan_type: str = "full"


class SimulateRequest(BaseModel):
    count: int = 3
    delay: float = 1.0


@router.post("/scan")
async def run_scan(
    request: ScanRequest,
    engine: ThreatEngine = Depends(get_engine_authenticated),
):
    return {
        "status": "scanning",
        "target": request.target,
        "scan_type": request.scan_type,
        "message": f"Scanning {request.target}..."
    }


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
    engine: ThreatEngine = Depends(get_engine_authenticated),
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
