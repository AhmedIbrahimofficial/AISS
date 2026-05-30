"""Cybersecurity - Threats API Routes"""
from fastapi import APIRouter, HTTPException, Depends
from core.dependencies import get_engine, get_engine_authenticated
from core.threat_engine import ThreatEngine

router = APIRouter()


@router.get("/")
async def get_all_threats(engine: ThreatEngine = Depends(get_engine)):
    return {"threats": engine.get_all_threats()}


@router.get("/active")
async def get_active_threats(engine: ThreatEngine = Depends(get_engine)):
    return {"threats": engine.get_active_threats()}


@router.get("/stats")
async def get_threat_stats(engine: ThreatEngine = Depends(get_engine)):
    return engine.get_stats()


@router.post("/{threat_id}/resolve")
async def resolve_threat(
    threat_id: str,
    note: str = "Manually resolved",
    engine: ThreatEngine = Depends(get_engine_authenticated),
):
    success = await engine.resolve_threat(threat_id, note)
    if not success:
        raise HTTPException(status_code=404, detail="Threat not found")
    return {"status": "resolved", "threat_id": threat_id, "message": "✅ Threat successfully neutralized!"}


@router.delete("/clear")
async def clear_all_threats(engine: ThreatEngine = Depends(get_engine_authenticated)):
    engine.active_threats.clear()
    from core import database
    await database.delete_all_threats()
    return {"status": "cleared"}
