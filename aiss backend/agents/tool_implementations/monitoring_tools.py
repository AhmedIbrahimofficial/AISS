"""
MONITORING tool handlers — wraps existing threat engine monitoring.
"""
from __future__ import annotations
from typing import Any

_NA = "No real data available for {tool}"

# In-process monitoring state
_monitoring_active: bool = False


async def start_monitoring(**_: Any) -> dict:
    global _monitoring_active
    _monitoring_active = True
    return {"status": "ok", "monitoring": True, "message": "Monitoring started"}


async def stop_monitoring(**_: Any) -> dict:
    global _monitoring_active
    _monitoring_active = False
    return {"status": "ok", "monitoring": False, "message": "Monitoring stopped"}


async def get_monitoring_status(**_: Any) -> dict:
    return {"status": "ok", "active": _monitoring_active}


async def get_recent_events(**kwargs: Any) -> dict:
    try:
        from core.database import AsyncSessionLocal
        from core.models import ThreatLog, SystemEvent
        from sqlalchemy import select, desc, union_all
        limit = kwargs.get("limit", 50)
        async with AsyncSessionLocal() as db:
            threats_result = await db.execute(
                select(ThreatLog).order_by(desc(ThreatLog.detected_at)).limit(limit // 2)
            )
            events_result = await db.execute(
                select(SystemEvent).order_by(desc(SystemEvent.created_at)).limit(limit // 2)
            )
            events = [
                {"type": "threat", **t.to_dict()}
                for t in threats_result.scalars().all()
            ] + [
                {"type": "system_event", **e.to_dict()}
                for e in events_result.scalars().all()
            ]
            events.sort(key=lambda x: x.get("detected_at") or x.get("created_at") or "", reverse=True)
        return {"status": "ok", "count": len(events), "events": events[:limit]}
    except Exception as e:
        return {"status": "error", "error": str(e), "message": _NA.format(tool="get_recent_events")}
