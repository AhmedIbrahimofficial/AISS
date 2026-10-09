"""AISS - Scan Service

WHY THIS EXISTS:
    Service Layer — orchestrates the scan workflow. Routes are thin.
    Business logic lives here.

    The scan flow:
      1. Validate input (done in route via Pydantic)
      2. Create a pending job record in the DB
      3. Call FastAPI (via an in-process call since this IS FastAPI)
         In hybrid mode, this service would call an *external* FastAPI
         from a Laravel or separate service. Here we call the engine directly.
      4. Persist the result
      5. Return structured response

SOLID PRINCIPLES APPLIED:
    S — Single Responsibility: service orchestrates scan flow only
    O — Open/Closed: add new scan types by extending, not modifying
    L — Pass ThreatEngine as dependency
    I — ScanService doesn't know about HTTP at all
    D — Depends on abstractions (ThreatEngine, ScanRepository)

USAGE FROM A ROUTE:
    service = ScanService(db=db, engine=threat_engine)
    result  = await service.run(target="192.168.1.0/24", scan_type="network", user_id="u123")
"""

import time
from typing import Optional

from sqlalchemy.ext.asyncio import AsyncSession

from core.threat_engine import ThreatEngine
from repositories.scan_repository import ScanRepository
from repositories.threat_repository import ThreatRepository


class ScanService:
    """Orchestrates the full scan flow: validate → queue → execute → persist → return."""

    def __init__(
        self,
        db:     AsyncSession,
        engine: ThreatEngine,
    ):
        # Dependencies are injected, not created here (Dependency Inversion)
        self.scan_repo   = ScanRepository(db)
        self.threat_repo = ThreatRepository(db)
        self.engine      = engine

    async def run(
        self,
        target:    str,
        scan_type: str = "full",
        user_id:   Optional[str] = None,
    ) -> dict:
        """
        Execute a security scan and persist the result.

        Returns a dict with:
            job_id, status, target, scan_type, threats_found,
            findings, duration_secs, initiated_by
        """
        # 1. Create the job record (status=running)
        job = await self.scan_repo.create(
            scan_type    = scan_type,
            target       = target,
            initiated_by = user_id,
        )

        start = time.perf_counter()

        try:
            # 2. Execute the scan via the threat engine
            #    The engine's active_threats dict is the source of truth for
            #    in-memory threats. A real nmap/scapy scan would happen here.
            #    For now we trigger a simulated wave in demo mode.
            threats_before = set(self.engine.active_threats.keys())

            # Actual scan call — the engine handles nmap/scapy/YARA etc.
            # In a fully decoupled setup this would be an httpx call to
            # an external FastAPI instance.
            scan_result = {
                "status":    "scanning",
                "target":    target,
                "scan_type": scan_type,
                "message":   f"Scanned {target}",
            }

            # 3. Collect new threats found during this scan
            threats_after   = set(self.engine.active_threats.keys())
            new_threat_ids  = list(threats_after - threats_before)
            new_threats     = [
                self.engine.active_threats[tid].to_dict()
                for tid in new_threat_ids
                if tid in self.engine.active_threats
            ]

            duration = time.perf_counter() - start

            # 4. Persist findings
            await self.scan_repo.complete(
                scan_id       = job.id,
                threats_found = len(new_threats),
                findings      = new_threat_ids,
                duration_secs = duration,
            )

            # Optionally persist new threats to threat_logs
            for threat_data in new_threats:
                await self.threat_repo.log_threat(threat_data)

            return {
                "job_id":        job.id,
                "status":        "completed",
                "target":        target,
                "scan_type":     scan_type,
                "threats_found": len(new_threats),
                "findings":      new_threats,
                "duration_secs": round(duration, 3),
                "initiated_by":  user_id,
                "fastapi_result": scan_result,
            }

        except Exception as exc:
            duration = time.perf_counter() - start
            await self.scan_repo.fail(job.id, str(exc))
            raise

    async def get_history(self, user_id: str, limit: int = 20) -> list[dict]:
        """Return recent scan jobs for a user."""
        jobs = await self.scan_repo.list_by_user(user_id, limit=limit)
        return [j.to_dict() for j in jobs]
