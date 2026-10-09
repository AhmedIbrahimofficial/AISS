"""AISS - Scan Result Repository

WHY THIS EXISTS:
    Repository Pattern — all database operations for scan_results go through
    this class. No raw SQL in routes. No SQLAlchemy queries in controllers.

    This separates the "how we store data" from "what the API does".
    If you switch from SQLite to PostgreSQL, only this file changes.

USAGE:
    from repositories.scan_repository import ScanRepository
    from core.database import get_db

    @router.post("/scan")
    async def scan(db: AsyncSession = Depends(get_db)):
        repo = ScanRepository(db)
        job = await repo.create(scan_type="full", target="192.168.1.1", initiated_by="user123")
        ...
        await repo.complete(job.id, threats_found=3, findings=[...])
"""

from datetime import datetime
from typing import Optional

from sqlalchemy import select, desc
from sqlalchemy.ext.asyncio import AsyncSession

from core.models import ScanResult


class ScanRepository:
    """Repository for ScanResult CRUD operations."""

    def __init__(self, db: AsyncSession):
        # Dependency injected — no globals, fully testable
        self.db = db

    async def create(
        self,
        scan_type:    str,
        target:       str,
        initiated_by: Optional[str] = None,
    ) -> ScanResult:
        """
        Insert a new scan job in 'running' state.
        Call complete() or fail() when the FastAPI scan finishes.
        """
        job = ScanResult(
            scan_type    = scan_type,
            target       = target,
            status       = "running",
            initiated_by = initiated_by,
            started_at   = datetime.utcnow(),
        )
        self.db.add(job)
        await self.db.flush()   # assigns ID without committing
        return job

    async def complete(
        self,
        scan_id:       str,
        threats_found: int,
        findings:      list,
        duration_secs: Optional[float] = None,
    ) -> Optional[ScanResult]:
        """Mark a scan as completed and persist findings."""
        job = await self._get(scan_id)
        if not job:
            return None

        job.status        = "completed"
        job.threats_found = threats_found
        job.findings      = findings
        job.completed_at  = datetime.utcnow()

        if duration_secs is not None:
            job.duration_secs = duration_secs
        elif job.started_at:
            job.duration_secs = (datetime.utcnow() - job.started_at).total_seconds()

        await self.db.flush()
        return job

    async def fail(
        self,
        scan_id:       str,
        error_message: str,
    ) -> Optional[ScanResult]:
        """Mark a scan as failed with an error message."""
        job = await self._get(scan_id)
        if not job:
            return None

        job.status        = "failed"
        job.error_message = error_message
        job.completed_at  = datetime.utcnow()
        await self.db.flush()
        return job

    async def get_by_id(self, scan_id: str) -> Optional[ScanResult]:
        return await self._get(scan_id)

    async def list_by_user(
        self,
        initiated_by: str,
        limit:        int = 20,
        offset:       int = 0,
    ) -> list[ScanResult]:
        """Paginated list of scans for a specific user."""
        result = await self.db.execute(
            select(ScanResult)
            .where(ScanResult.initiated_by == initiated_by)
            .order_by(desc(ScanResult.started_at))
            .limit(limit)
            .offset(offset)
        )
        return list(result.scalars().all())

    async def list_recent(self, limit: int = 50) -> list[ScanResult]:
        """Most recent scans across all users (admin view)."""
        result = await self.db.execute(
            select(ScanResult)
            .order_by(desc(ScanResult.started_at))
            .limit(limit)
        )
        return list(result.scalars().all())

    # ── Private helpers ───────────────────────────────────────────────

    async def _get(self, scan_id: str) -> Optional[ScanResult]:
        result = await self.db.execute(
            select(ScanResult).where(ScanResult.id == scan_id)
        )
        return result.scalar_one_or_none()
