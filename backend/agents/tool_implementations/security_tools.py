"""
SECURITY tool handlers — delegate to existing threat engine and scanner modules.
Never fabricates data. Returns explicit gap message if backend unavailable.
"""
from __future__ import annotations
import hashlib
import os
from typing import Any

_NA = "No real data available for {tool}"


async def scan_system(**_: Any) -> dict:
    try:
        from core.threat_engine import ThreatEngine
        engine = ThreatEngine()
        result = await engine.quick_scan()
        return {"status": "ok", "scan_result": result}
    except Exception as e:
        return {"status": "error", "error": str(e), "message": _NA.format(tool="scan_system")}


async def scan_file(file_path: str, **_: Any) -> dict:
    try:
        if not os.path.exists(file_path):
            return {"status": "error", "message": f"File not found: {file_path}"}
        with open(file_path, "rb") as f:
            data = f.read()
        sha256 = hashlib.sha256(data).hexdigest()
        md5 = hashlib.md5(data).hexdigest()
        return {"status": "ok", "file_path": file_path,
                "size_bytes": len(data), "sha256": sha256, "md5": md5}
    except Exception as e:
        return {"status": "error", "error": str(e), "message": _NA.format(tool="scan_file")}


async def analyze_file(file_path: str, **_: Any) -> dict:
    try:
        if not os.path.exists(file_path):
            return {"status": "error", "message": f"File not found: {file_path}"}
        import magic
        mime = magic.from_file(file_path, mime=True)
        with open(file_path, "rb") as f:
            data = f.read()
        return {"status": "ok", "file_path": file_path, "mime_type": mime,
                "size_bytes": len(data),
                "sha256": hashlib.sha256(data).hexdigest(),
                "md5": hashlib.md5(data).hexdigest()}
    except Exception as e:
        return {"status": "error", "error": str(e), "message": _NA.format(tool="analyze_file")}


async def calculate_file_hash(file_path: str, algorithm: str = "sha256", **_: Any) -> dict:
    try:
        h = hashlib.new(algorithm)
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
        return {"status": "ok", "file_path": file_path, "algorithm": algorithm, "hash": h.hexdigest()}
    except Exception as e:
        return {"status": "error", "error": str(e), "message": _NA.format(tool="calculate_file_hash")}


async def malware_scan(**kwargs: Any) -> dict:
    try:
        target = kwargs.get("target", "/")
        import yara
        # Attempt to load any installed YARA rules
        rules_path = os.environ.get("YARA_RULES_PATH", "")
        if rules_path and os.path.exists(rules_path):
            rules = yara.load(rules_path)
            matches = rules.match(target)
            return {"status": "ok", "target": target,
                    "matches": [str(m) for m in matches]}
        return {"status": "ok", "target": target, "matches": [],
                "note": "No YARA rules loaded. Set YARA_RULES_PATH to enable."}
    except Exception as e:
        return {"status": "error", "error": str(e), "message": _NA.format(tool="malware_scan")}


async def vulnerability_scan(**_: Any) -> dict:
    try:
        from core.threat_engine import ThreatEngine
        engine = ThreatEngine()
        result = await engine.vulnerability_scan()
        return {"status": "ok", "vulnerabilities": result}
    except Exception as e:
        return {"status": "error", "error": str(e), "message": _NA.format(tool="vulnerability_scan")}


async def get_vulnerabilities(**kwargs: Any) -> dict:
    try:
        from core.database import AsyncSessionLocal
        from core.models import ThreatLog
        from sqlalchemy import select
        limit = kwargs.get("limit", 50)
        async with AsyncSessionLocal() as db:
            result = await db.execute(
                select(ThreatLog)
                .where(ThreatLog.threat_type.like("%vuln%"))
                .limit(limit)
            )
            vulns = [t.to_dict() for t in result.scalars().all()]
        return {"status": "ok", "count": len(vulns), "vulnerabilities": vulns}
    except Exception as e:
        return {"status": "error", "error": str(e), "message": _NA.format(tool="get_vulnerabilities")}


async def get_security_events(**kwargs: Any) -> dict:
    try:
        from core.database import AsyncSessionLocal
        from core.models import SystemEvent
        from sqlalchemy import select, desc
        limit = kwargs.get("limit", 50)
        async with AsyncSessionLocal() as db:
            result = await db.execute(
                select(SystemEvent).order_by(desc(SystemEvent.created_at)).limit(limit)
            )
            events = [e.to_dict() for e in result.scalars().all()]
        return {"status": "ok", "count": len(events), "events": events}
    except Exception as e:
        return {"status": "error", "error": str(e), "message": _NA.format(tool="get_security_events")}


async def get_alerts(**kwargs: Any) -> dict:
    try:
        from core.database import AsyncSessionLocal
        from core.models import ThreatLog
        from sqlalchemy import select, desc
        limit = kwargs.get("limit", 50)
        async with AsyncSessionLocal() as db:
            result = await db.execute(
                select(ThreatLog)
                .where(ThreatLog.status == "active")
                .order_by(desc(ThreatLog.detected_at))
                .limit(limit)
            )
            alerts = [t.to_dict() for t in result.scalars().all()]
        return {"status": "ok", "count": len(alerts), "alerts": alerts}
    except Exception as e:
        return {"status": "error", "error": str(e), "message": _NA.format(tool="get_alerts")}


async def investigate_alert(alert_id: str, **_: Any) -> dict:
    try:
        from core.database import AsyncSessionLocal
        from core.models import ThreatLog
        from sqlalchemy import select
        async with AsyncSessionLocal() as db:
            result = await db.execute(select(ThreatLog).where(ThreatLog.id == alert_id))
            threat = result.scalar_one_or_none()
            if not threat:
                return {"status": "error", "message": f"Alert {alert_id} not found"}
            return {"status": "ok", "alert": threat.to_dict()}
    except Exception as e:
        return {"status": "error", "error": str(e), "message": _NA.format(tool="investigate_alert")}


async def analyze_threat(threat_id: str, **_: Any) -> dict:
    return await investigate_alert(alert_id=threat_id)


async def query_audit_logs(**kwargs: Any) -> dict:
    try:
        from core.database import AsyncSessionLocal
        from agents.models import AgentAuditEvent
        from sqlalchemy import select, desc
        limit = kwargs.get("limit", 50)
        async with AsyncSessionLocal() as db:
            result = await db.execute(
                select(AgentAuditEvent)
                .order_by(desc(AgentAuditEvent.created_at))
                .limit(limit)
            )
            events = []
            for e in result.scalars().all():
                events.append({
                    "id": e.id, "event_type": e.event_type,
                    "severity": e.severity, "tool_name": e.tool_name,
                    "risk_level": e.risk_level, "created_at": e.created_at.isoformat(),
                })
        return {"status": "ok", "count": len(events), "audit_events": events}
    except Exception as e:
        return {"status": "error", "error": str(e), "message": _NA.format(tool="query_audit_logs")}
