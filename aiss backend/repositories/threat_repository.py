"""AISS - Threat Log Repository

WHY THIS EXISTS:
    All ThreatLog database operations in one place.
    Routes call services. Services call repositories. Repositories call the DB.
    This is the Repository Pattern — it enforces clean separation.

USAGE:
    repo = ThreatRepository(db)
    log  = await repo.log_threat(threat_dict, scan_id="scan_abc")
    logs = await repo.get_active(limit=50)
"""

from datetime import datetime
from typing import Optional

from sqlalchemy import select, desc, and_
from sqlalchemy.ext.asyncio import AsyncSession

from core.models import ThreatLog


class ThreatRepository:
    """Repository for ThreatLog CRUD — persistent threat record storage."""

    def __init__(self, db: AsyncSession):
        self.db = db

    async def log_threat(
        self,
        threat_data: dict,
        scan_id:     Optional[str] = None,
    ) -> ThreatLog:
        """
        Persist a threat detected by FastAPI into PostgreSQL.
        Called after FastAPI returns a scan result.

        threat_data is the dict from FastAPI's /api/threats/active response.
        """
        log = ThreatLog(
            threat_type     = threat_data.get("type", "Unknown"),
            severity        = threat_data.get("severity", "low"),
            status          = threat_data.get("status", "active"),
            source_ip       = threat_data.get("source"),
            description     = threat_data.get("description", ""),
            raw_data        = threat_data,
            ai_analysis     = threat_data.get("ai_analysis"),
            module          = threat_data.get("module"),
            detected_at     = datetime.utcnow(),
        )
        self.db.add(log)
        await self.db.flush()
        return log

    async def get_active(self, limit: int = 100) -> list[ThreatLog]:
        result = await self.db.execute(
            select(ThreatLog)
            .where(ThreatLog.status == "active")
            .order_by(desc(ThreatLog.detected_at))
            .limit(limit)
        )
        return list(result.scalars().all())

    async def get_by_severity(self, severity: str, limit: int = 50) -> list[ThreatLog]:
        result = await self.db.execute(
            select(ThreatLog)
            .where(and_(ThreatLog.severity == severity, ThreatLog.status == "active"))
            .order_by(desc(ThreatLog.detected_at))
            .limit(limit)
        )
        return list(result.scalars().all())

    async def resolve(
        self,
        threat_id: str,
        note:      str = "Resolved",
    ) -> Optional[ThreatLog]:
        result = await self.db.execute(
            select(ThreatLog).where(ThreatLog.id == threat_id)
        )
        log = result.scalar_one_or_none()
        if not log:
            return None

        log.status          = "resolved"
        log.resolved_at     = datetime.utcnow()
        log.resolution_note = note
        await self.db.flush()
        return log

    async def stats(self) -> dict:
        """Aggregate stats — mirrors FastAPI's /api/threats/stats but from PostgreSQL."""
        from sqlalchemy import func

        counts = await self.db.execute(
            select(ThreatLog.severity, func.count(ThreatLog.id))
            .group_by(ThreatLog.severity)
        )
        by_sev = dict(counts.all())

        total_result    = await self.db.execute(select(func.count(ThreatLog.id)))
        active_result   = await self.db.execute(
            select(func.count(ThreatLog.id)).where(ThreatLog.status == "active")
        )
        resolved_result = await self.db.execute(
            select(func.count(ThreatLog.id)).where(ThreatLog.status == "resolved")
        )

        return {
            "total":    total_result.scalar() or 0,
            "active":   active_result.scalar() or 0,
            "resolved": resolved_result.scalar() or 0,
            "critical": by_sev.get("critical", 0),
            "high":     by_sev.get("high", 0),
            "medium":   by_sev.get("medium", 0),
            "low":      by_sev.get("low", 0),
        }
