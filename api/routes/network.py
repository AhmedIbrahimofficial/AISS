"""AISS - Network Monitor API Routes"""
from fastapi import APIRouter

router = APIRouter()


@router.get("/connections")
async def get_active_connections():
    from modules.network_monitor import get_connections_raw
    try:
        lines = get_connections_raw()
        return {"connections": lines}
    except Exception as e:
        return {"connections": [], "error": str(e)}


@router.get("/listening-ports")
async def get_listening_ports():
    from modules.network_monitor import get_connections_raw
    try:
        lines = get_connections_raw()
        return {"ports": lines}
    except Exception as e:
        return {"ports": [], "error": str(e)}
