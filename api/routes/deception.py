"""Cybersecurity - Deception / Honeypot Alert Routes"""
from fastapi import APIRouter, Depends
from core.dependencies import get_engine
from core.threat_engine import ThreatEngine

router = APIRouter()


@router.get("/honeypot/alerts")
async def get_honeypot_alerts(engine: ThreatEngine = Depends(get_engine)):
    """Return all honeypot-triggered threats."""
    threats = [
        t for t in engine.get_all_threats()
        if "HONEYPOT" in t.get("description", "").upper()
        or t.get("module") == "Deception"
    ]
    return {"alerts": threats, "count": len(threats)}


@router.get("/honeypot/status")
async def honeypot_status():
    """List all active honeypot assets."""
    from modules.deception import HONEYPOT_FILES, HONEYPOT_PORTS
    import os
    files = [
        {"file": name, "active": os.path.exists(name)}
        for name in HONEYPOT_FILES
    ]
    ports = [
        {"port": port, "service": name}
        for port, name in HONEYPOT_PORTS.items()
    ]
    return {
        "honeypot_files": files,
        "honeypot_ports": ports,
        "fake_admin_panel": "/admin",
    }
