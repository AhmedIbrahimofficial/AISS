"""
Cybersecurity - Core Threat Engine
Central brain that coordinates all detection modules and dispatches alerts.
Threats are persisted to PostgreSQL so history survives server restarts.
"""

import asyncio
import uuid
from datetime import datetime
from typing import Optional
from utils.logger import setup_logger
from models.threat import Threat, ThreatSeverity, ThreatStatus, ThreatType
from core.websocket_manager import WebSocketManager
from core import database

logger = setup_logger("threat_engine")


class ThreatEngine:
    def __init__(self, ws_manager: WebSocketManager):
        self.ws_manager = ws_manager
        self.monitoring = False
        self.active_threats: dict[str, Threat] = {}
        self._monitor_task: Optional[asyncio.Task] = None
        self._ai_api_key: str = ""

    # ------------------------------------------------------------------
    # Startup
    # ------------------------------------------------------------------

    async def startup(self):
        """Initialize DB and reload persisted threats into memory."""
        await database.init_db()
        rows = await database.load_all_threats()
        for row in rows:
            threat = Threat(
                id=row["id"],
                type=ThreatType(row["type"]),
                description=row["description"],
                severity=ThreatSeverity(row["severity"]),
                source=row["source"],
                module=row["module"],
                status=ThreatStatus(row["status"]),
                detected_at=row["detected_at"],
                resolved_at=row["resolved_at"],
                resolution_note=row["resolution_note"],
                metadata=row["metadata"],
                ai_analysis=row["ai_analysis"],
                recommended_action=row["recommended_action"],
            )
            self.active_threats[threat.id] = threat
        logger.info(f"📂 Loaded {len(rows)} threats from database")

    # ------------------------------------------------------------------
    # Monitoring
    # ------------------------------------------------------------------

    async def start_monitoring(self):
        if self.monitoring:
            return
        self.monitoring = True
        logger.info("🛡️ Cybersecurity monitoring STARTED")
        self._monitor_task = asyncio.create_task(self._monitor_loop())
        await self.ws_manager.broadcast({
            "event": "monitoring_started",
            "timestamp": datetime.utcnow().isoformat(),
            "message": "Cybersecurity is now actively monitoring your system"
        })

    async def stop_monitoring(self):
        self.monitoring = False
        if self._monitor_task:
            self._monitor_task.cancel()
        logger.info("🔴 Cybersecurity monitoring STOPPED")
        await self.ws_manager.broadcast({
            "event": "monitoring_stopped",
            "timestamp": datetime.utcnow().isoformat(),
        })

    async def _monitor_loop(self):
        """Main monitoring loop — polls all detection modules every 5 seconds."""
        from modules.network_monitor import NetworkMonitor
        from modules.auth_monitor import AuthMonitor
        from modules.file_monitor import FileMonitor
        from modules.malware_scanner import MalwareScanner

        monitors = [
            NetworkMonitor(self),
            AuthMonitor(self),
            FileMonitor(self),
            MalwareScanner(self),
        ]

        while self.monitoring:
            for monitor in monitors:
                try:
                    await monitor.scan()
                except Exception as e:
                    logger.error(f"Monitor error [{monitor.__class__.__name__}]: {e}")
            await asyncio.sleep(5)

    # ------------------------------------------------------------------
    # Threat lifecycle
    # ------------------------------------------------------------------

    async def register_threat(self, threat: Threat):
        """Register a detected threat, persist it, and broadcast to all clients."""
        self.active_threats[threat.id] = threat
        await database.save_threat(threat.to_dict())
        logger.warning(
            f"🚨 THREAT DETECTED: [{threat.type}] {threat.description} | Severity: {threat.severity}"
        )
        await self.ws_manager.broadcast({
            "event": "threat_detected",
            "threat": threat.to_dict()
        })

    async def resolve_threat(self, threat_id: str, resolution_note: str = ""):
        """Mark threat as resolved, persist the update, and notify clients."""
        threat = self.active_threats.get(threat_id)
        if not threat:
            return False

        threat.status = ThreatStatus.RESOLVED
        threat.resolved_at = datetime.utcnow().isoformat()
        threat.resolution_note = resolution_note

        await database.update_threat_status(
            threat_id, ThreatStatus.RESOLVED, threat.resolved_at, resolution_note
        )

        logger.info(f"✅ THREAT RESOLVED: {threat_id} — {resolution_note}")
        await self.ws_manager.broadcast({
            "event": "threat_resolved",
            "threat_id": threat_id,
            "resolution_note": resolution_note,
            "message": f"✅ Threat [{threat.type}] has been neutralized successfully!",
            "timestamp": datetime.utcnow().isoformat()
        })
        return True

    async def auto_respond(self, threat: Threat):
        """Automatically respond to a threat based on its type and severity."""
        from modules.response_engine import ResponseEngine
        engine = ResponseEngine(self)
        await engine.respond(threat)

    # ------------------------------------------------------------------
    # Queries
    # ------------------------------------------------------------------

    def get_all_threats(self) -> list[dict]:
        return [t.to_dict() for t in self.active_threats.values()]

    def get_active_threats(self) -> list[dict]:
        return [
            t.to_dict() for t in self.active_threats.values()
            if t.status == ThreatStatus.ACTIVE
        ]

    def get_stats(self) -> dict:
        threats = list(self.active_threats.values())
        return {
            "total": len(threats),
            "active": sum(1 for t in threats if t.status == ThreatStatus.ACTIVE),
            "resolved": sum(1 for t in threats if t.status == ThreatStatus.RESOLVED),
            "critical": sum(1 for t in threats if t.severity == ThreatSeverity.CRITICAL),
            "high": sum(1 for t in threats if t.severity == ThreatSeverity.HIGH),
            "medium": sum(1 for t in threats if t.severity == ThreatSeverity.MEDIUM),
            "low": sum(1 for t in threats if t.severity == ThreatSeverity.LOW),
        }
