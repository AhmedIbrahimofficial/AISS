"""
DEVICE tool handlers — reads/manages connected devices via auth models.
HIGH/CRITICAL operations require approval before execution.
"""
from __future__ import annotations
from typing import Any

_NA = "No real data available for {tool}"


async def get_devices(**kwargs: Any) -> dict:
    try:
        from core.database import AsyncSessionLocal
        from auth.models import AuthUser
        from sqlalchemy import select
        async with AsyncSessionLocal() as db:
            result = await db.execute(select(AuthUser).where(AuthUser.is_active == True))
            users = result.scalars().all()
            devices = [
                {"id": u.id, "username": u.username, "role": u.role,
                 "is_active": u.is_active, "last_login": u.last_login.isoformat() if u.last_login else None}
                for u in users
            ]
        return {"status": "ok", "count": len(devices), "devices": devices}
    except Exception as e:
        return {"status": "error", "error": str(e), "message": _NA.format(tool="get_devices")}


async def get_device_status(device_id: str, **_: Any) -> dict:
    try:
        from core.database import AsyncSessionLocal
        from auth.models import AuthUser
        from sqlalchemy import select
        async with AsyncSessionLocal() as db:
            result = await db.execute(select(AuthUser).where(AuthUser.id == device_id))
            user = result.scalar_one_or_none()
            if not user:
                return {"status": "error", "message": f"Device {device_id} not found"}
            return {"status": "ok", "device": {
                "id": user.id, "username": user.username,
                "is_active": user.is_active, "role": user.role,
                "last_login": user.last_login.isoformat() if user.last_login else None,
            }}
    except Exception as e:
        return {"status": "error", "error": str(e), "message": _NA.format(tool="get_device_status")}


async def authorize_device(device_id: str, **_: Any) -> dict:
    """HIGH risk — requires approval gate before execution."""
    try:
        from core.database import AsyncSessionLocal
        from auth.models import AuthUser
        from sqlalchemy import select
        from datetime import datetime
        async with AsyncSessionLocal() as db:
            result = await db.execute(select(AuthUser).where(AuthUser.id == device_id))
            user = result.scalar_one_or_none()
            if not user:
                return {"status": "error", "message": f"Device {device_id} not found"}
            user.is_active = True
            await db.commit()
            return {"status": "ok", "device_id": device_id, "action": "authorized"}
    except Exception as e:
        return {"status": "error", "error": str(e), "message": _NA.format(tool="authorize_device")}


async def revoke_device(device_id: str, **_: Any) -> dict:
    """HIGH risk — requires approval gate before execution."""
    try:
        from core.database import AsyncSessionLocal
        from auth.models import AuthUser
        from sqlalchemy import select
        async with AsyncSessionLocal() as db:
            result = await db.execute(select(AuthUser).where(AuthUser.id == device_id))
            user = result.scalar_one_or_none()
            if not user:
                return {"status": "error", "message": f"Device {device_id} not found"}
            user.is_active = False
            await db.commit()
            return {"status": "ok", "device_id": device_id, "action": "revoked"}
    except Exception as e:
        return {"status": "error", "error": str(e), "message": _NA.format(tool="revoke_device")}


async def connect_device(device_id: str, **_: Any) -> dict:
    return await authorize_device(device_id=device_id)


async def disconnect_device(device_id: str, **_: Any) -> dict:
    return await revoke_device(device_id=device_id)
