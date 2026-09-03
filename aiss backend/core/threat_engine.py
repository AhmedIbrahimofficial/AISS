"""
AISS - Core Threat Engine (UPGRADED)
─────────────────────────────────────
Advanced features added:
  - Threat deduplication: same type + same source within 60s = skip duplicate
  - Threat correlation: same source IP in 2+ threats within 5min = Campaign threat
  - Attack chain detection: brute_force → privilege_esc from same IP = APT indicator
  - Priority queue (heapq): CRITICAL=1, HIGH=2, MEDIUM=3, LOW=4
  - TTL-based auto-resolve: LOW threats auto-resolve after 1 hour if no new activity
  - Stats history: last 24h snapshots every 5 minutes
  - All existing DB persistence, WebSocket, monitoring loop preserved
"""

import asyncio
import heapq
import time
from collections import defaultdict
from datetime import datetime, timedelta
from typing import Optional

from utils.logger import setup_logger
from models.threat import Threat, ThreatSeverity, ThreatStatus, ThreatType
from core.websocket_manager import WebSocketManager

logger = setup_logger("threat_engine")

# ── Priority map ──────────────────────────────────────────────────────
_SEVERITY_PRIORITY = {
    ThreatSeverity.CRITICAL: 1,
    ThreatSeverity.HIGH:     2,
    ThreatSeverity.MEDIUM:   3,
    ThreatSeverity.LOW:      4,
}

# ── Deduplication window (seconds) ───────────────────────────────────
DEDUP_WINDOW_SECS    = 60

# ── Correlation window (seconds) ─────────────────────────────────────
CORRELATION_WINDOW   = 300   # 5 minutes

# ── TTL for auto-resolve (LOW threats) ───────────────────────────────
LOW_TTL_SECS         = 3600  # 1 hour

# ── Stats snapshot interval ───────────────────────────────────────────
STATS_SNAPSHOT_SECS  = 600   # every 10 minutes
STATS_HISTORY_MAX    = 288   # 24h worth at 5-min intervals

# ── Attack chain definitions ──────────────────────────────────────────
# Each chain: list of threat types that form an APT pattern if same source
ATTACK_CHAINS = [
    # Credential compromise → privilege escalation
    [ThreatType.BRUTE_FORCE, ThreatType.PRIVILEGE_ESC],
    # Port scan → intrusion → C2 (classic kill chain)
    [ThreatType.PORT_SCAN, ThreatType.INTRUSION, ThreatType.C2_TRAFFIC],
    # Trojan → C2 → data exfiltration
    [ThreatType.TROJAN, ThreatType.C2_TRAFFIC, ThreatType.DATA_EXFIL],
    # Brute force → credential stuffing → intrusion
    [ThreatType.BRUTE_FORCE, ThreatType.CREDENTIAL_STUFF, ThreatType.INTRUSION],
    # Malware delivery → privilege escalation → lateral movement
    [ThreatType.MALICIOUS_SCRIPT, ThreatType.PRIVILEGE_ESC, ThreatType.WORM],
]


class ThreatEngine:
    """
    Central threat orchestration engine with correlation, deduplication,
    priority queuing, and attack chain detection.
    """

    def __init__(self, ws_manager: WebSocketManager):
        self.ws_manager    = ws_manager
        self.monitoring    = False
        self.active_threats: dict[str, Threat] = {}
        self._monitor_task: Optional[asyncio.Task] = None
        self._ttl_task: Optional[asyncio.Task]     = None
        self._stats_task: Optional[asyncio.Task]   = None
        self._ai_api_key: str = ""

        # ── Deduplication: {(type, source) → last_seen_timestamp} ────
        self._dedup_cache: dict[tuple, float] = {}

        # ── Correlation: {source_ip → [(type, timestamp, threat_id)]} ─
        self._source_events: dict[str, list] = defaultdict(list)

        # ── Campaign IDs already created: {frozenset of threat_ids} ──
        self._campaigns_created: set[frozenset] = set()

        # ── Stats history: list of {timestamp, stats_dict} ───────────
        self._stats_history: list[dict] = []

        # ── Priority queue: [(priority, timestamp, threat_id)] ────────
        self._priority_queue: list[tuple] = []

    # ══════════════════════════════════════════════════════════════════
    # Startup
    # ══════════════════════════════════════════════════════════════════

    async def startup(self) -> None:
        """Reload persisted threats from DB into memory on startup."""
        from core.database import AsyncSessionLocal
        from sqlalchemy import text
        import json

        try:
            async with AsyncSessionLocal() as db:
                result = await db.execute(
                    text("SELECT * FROM threats ORDER BY detected_at DESC")
                )
                rows = result.mappings().all()
            for row in rows:
                meta = row["metadata"]
                if isinstance(meta, str):
                    meta = json.loads(meta)
                try:
                    threat = Threat(
                        id                 = row["id"],
                        type               = ThreatType(row["type"]),
                        description        = row["description"],
                        severity           = ThreatSeverity(row["severity"]),
                        source             = row["source"],
                        module             = row["module"],
                        status             = ThreatStatus(row["status"]),
                        detected_at        = row["detected_at"],
                        resolved_at        = row["resolved_at"] or "",
                        resolution_note    = row["resolution_note"] or "",
                        metadata           = meta,
                        ai_analysis        = row["ai_analysis"] or "",
                        recommended_action = row["recommended_action"] or "",
                    )
                    self.active_threats[threat.id] = threat
                    # Re-populate priority queue from DB
                    pri = _SEVERITY_PRIORITY.get(threat.severity, 4)
                    heapq.heappush(self._priority_queue, (pri, time.time(), threat.id))
                except Exception as e:
                    logger.debug(f"Skipped threat row: {e}")

            logger.info(f"📂 Loaded {len(self.active_threats)} threats from database")

        except Exception as e:
            logger.warning(f"Could not load threats on startup: {e}")

        # Start background maintenance tasks
        self._ttl_task   = asyncio.create_task(self._ttl_auto_resolve_loop())
        self._stats_task = asyncio.create_task(self._stats_snapshot_loop())

    # ══════════════════════════════════════════════════════════════════
    # Monitoring
    # ══════════════════════════════════════════════════════════════════

    async def start_monitoring(self) -> None:
        """Start the main monitoring loop."""
        if self.monitoring:
            return
        self.monitoring = True
        logger.info("🛡️ AISS monitoring STARTED")
        self._monitor_task = asyncio.create_task(self._monitor_loop())
        await self.ws_manager.broadcast({
            "event":     "monitoring_started",
            "timestamp": datetime.utcnow().isoformat(),
            "message":   "AISS is now actively monitoring your system",
        })

    async def stop_monitoring(self) -> None:
        """Stop the main monitoring loop."""
        self.monitoring = False
        if self._monitor_task:
            self._monitor_task.cancel()
        logger.info("🔴 AISS monitoring STOPPED")
        await self.ws_manager.broadcast({
            "event":     "monitoring_stopped",
            "timestamp": datetime.utcnow().isoformat(),
        })

    async def _monitor_loop(self) -> None:
        """Main monitoring loop — polls all detection modules every 5 seconds.

        Each monitor runs in its own concurrent task so a slow or blocking
        scan cannot stall the others. A per-monitor timeout prevents any single
        monitor from hanging the loop indefinitely.
        """
        from modules.network_monitor import NetworkMonitor
        from modules.auth_monitor   import AuthMonitor
        from modules.file_monitor   import FileMonitor
        from modules.malware_scanner import MalwareScanner

        monitors = [
            NetworkMonitor(self),
            AuthMonitor(self),
            FileMonitor(self),
            MalwareScanner(self),
        ]

        while self.monitoring:
            async def _run_one(monitor) -> None:
                name = monitor.__class__.__name__
                _t0 = time.time()
                try:
                    await asyncio.wait_for(monitor.scan(), timeout=25.0)
                except asyncio.TimeoutError:
                    logger.warning(f"Monitor timeout [{name}]: scan exceeded 25s")
                except Exception as e:
                    logger.error(f"Monitor error [{name}]: {e}")
                finally:
                    try:
                        from core.metrics import observe_scan
                        observe_scan(name.lower(), time.time() - _t0)
                    except Exception:
                        pass

            await asyncio.gather(*(_run_one(m) for m in monitors), return_exceptions=True)
            await asyncio.sleep(15)

    # ══════════════════════════════════════════════════════════════════
    # Threat lifecycle
    # ══════════════════════════════════════════════════════════════════

    async def register_threat(self, threat: Threat) -> None:
        """
        Register a detected threat.

        Pipeline:
          1. Deduplication check
          2. Store + persist + broadcast
          3. Correlation analysis
          4. Attack chain detection
          5. Priority queue insertion
        """
        # ── 1. Deduplication ──────────────────────────────────────────
        dedup_key = (str(threat.type), threat.source)
        last_seen = self._dedup_cache.get(dedup_key, 0)
        if time.time() - last_seen < DEDUP_WINDOW_SECS:
            logger.debug(
                f"Deduplicated threat: [{threat.type}] from {threat.source} "
                f"(seen {time.time()-last_seen:.0f}s ago)"
            )
            return
        self._dedup_cache[dedup_key] = time.time()

        # ── 2. Store + persist + broadcast ────────────────────────────
        self.active_threats[threat.id] = threat

        # ── Geo enrichment ────────────────────────────────────────────
        try:
            from modules.geo_lookup import enrich_threat
            enrich_threat(threat.metadata if isinstance(threat.metadata, dict) else {})
            # Also enrich the threat dict directly
            if hasattr(threat, "metadata") and isinstance(threat.metadata, dict):
                from modules.geo_lookup import lookup_ip
                import re as _re
                source = threat.source
                if _re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", source):
                    geo = lookup_ip(source)
                    if geo:
                        threat.metadata["geo"] = geo
        except Exception:
            pass

        # ── Threat intel enrichment (fire-and-forget) ─────────────────
        try:
            import re as _re
            source = threat.source
            if _re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", source):
                asyncio.create_task(self._enrich_with_intel(threat))
        except Exception:
            pass

        await self._persist_threat(threat.to_dict())
        logger.warning(
            f"🚨 THREAT: [{threat.type}] {threat.description[:80]} | {threat.severity}"
        )
        await self.ws_manager.broadcast({
            "event":  "threat_detected",
            "threat": threat.to_dict(),
        })

        # ── Prometheus metrics ────────────────────────────────────────
        try:
            from core.metrics import inc_threat, set_active_count
            inc_threat(str(threat.severity), str(threat.type))
            set_active_count(len([t for t in self.active_threats.values()
                                  if t.status == ThreatStatus.ACTIVE]))
        except Exception:
            pass

        # ── 3. Priority queue ─────────────────────────────────────────
        pri = _SEVERITY_PRIORITY.get(threat.severity, 4)
        heapq.heappush(self._priority_queue, (pri, time.time(), threat.id))

        # ── 4. Multi-channel alert (CRITICAL / HIGH) ──────────────────
        if threat.severity in (ThreatSeverity.CRITICAL, ThreatSeverity.HIGH):
            from modules.alert_manager import alert_manager
            asyncio.create_task(alert_manager.send_threat_alert(threat))

        # ── 5. Semantic threat store (vector embedding) ───────────────
        asyncio.create_task(self._store_semantic(threat))

        # ── 6. IOC extraction (fire-and-forget) ──────────────────────
        asyncio.create_task(self._extract_iocs(threat))

        # ── 7. Online anomaly detector — learn from this event ────────
        asyncio.create_task(self._feed_online_detector(threat))

        # ── 8. Voice alert (CRITICAL only) ───────────────────────────
        if threat.severity == ThreatSeverity.CRITICAL:
            asyncio.create_task(self._speak_threat(threat))

        # ── 9. Correlation ────────────────────────────────────────────
        await self._correlate(threat)

        # ── 10. Attack chain detection ────────────────────────────────
        await self._detect_attack_chain(threat)

    async def resolve_threat(self, threat_id: str, resolution_note: str = "") -> bool:
        """Mark threat as resolved, persist, and notify clients."""
        threat = self.active_threats.get(threat_id)
        if not threat:
            return False

        threat.status          = ThreatStatus.RESOLVED
        threat.resolved_at     = datetime.utcnow().isoformat()
        threat.resolution_note = resolution_note

        await self._update_threat_status(
            threat_id,
            str(ThreatStatus.RESOLVED),
            threat.resolved_at,
            resolution_note,
        )

        logger.info(f"✅ RESOLVED: {threat_id[:8]} — {resolution_note[:60]}")
        await self.ws_manager.broadcast({
            "event":           "threat_resolved",
            "threat_id":       threat_id,
            "resolution_note": resolution_note,
            "message":         f"✅ [{threat.type}] neutralized",
            "timestamp":       datetime.utcnow().isoformat(),
        })

        # ── Prometheus metrics ────────────────────────────────────────
        try:
            from core.metrics import inc_resolved, set_active_count
            inc_resolved()
            set_active_count(len([t for t in self.active_threats.values()
                                  if t.status == ThreatStatus.ACTIVE]))
        except Exception:
            pass

        return True

    async def _store_semantic(self, threat: Threat) -> None:
        """Store threat embedding in ChromaDB for semantic search."""
        try:
            from modules.semantic_threat_store import semantic_store
            await semantic_store.add_threat(threat.to_dict())
        except Exception as e:
            logger.debug(f"Semantic store error: {e}")

    async def _extract_iocs(self, threat: Threat) -> None:
        """Extract IOCs from threat description and enrich metadata."""
        try:
            from modules.ioc_extractor import ioc_extractor
            iocs = ioc_extractor.extract_from_threat(threat.to_dict())
            if iocs:
                if isinstance(threat.metadata, dict):
                    threat.metadata["iocs"] = iocs
                # Update DB with enriched metadata
                await self._persist_threat(threat.to_dict())
        except Exception as e:
            logger.debug(f"IOC extraction error: {e}")

    async def _feed_online_detector(self, threat: Threat) -> None:
        """Feed threat features to the online ML anomaly detector."""
        try:
            from modules.online_anomaly_detector import online_detector
            meta = threat.metadata if isinstance(threat.metadata, dict) else {}
            event = {
                "duration":      meta.get("duration", 0),
                "src_bytes":     meta.get("src_bytes", 0),
                "dst_bytes":     meta.get("dst_bytes", 0),
                "src_port":      meta.get("src_port", 0),
                "dst_port":      meta.get("dst_port", 0),
                "conn_count":    meta.get("connection_count", 1),
                "failed_logins": meta.get("failed_logins", 0),
            }
            online_detector.learn_and_score(event)
        except Exception as e:
            logger.debug(f"Online detector feed error: {e}")

    async def _speak_threat(self, threat: Threat) -> None:
        """Announce a CRITICAL threat via text-to-speech."""
        try:
            from modules.voice_alerts import voice_alerts
            await voice_alerts.speak_threat(threat.to_dict())
        except Exception as e:
            logger.debug(f"Voice alert error: {e}")

    # ══════════════════════════════════════════════════════════════════
    # Correlation engine
    # ══════════════════════════════════════════════════════════════════

    async def _correlate(self, threat: Threat) -> None:
        """
        Correlation: if same source IP appears in 2+ threats within 5 minutes,
        create a synthetic 'Campaign' threat linking all related IDs.
        """
        source = threat.source
        now    = time.time()

        # Track this event
        self._source_events[source].append(
            (str(threat.type), now, threat.id)
        )

        # Prune events older than correlation window
        self._source_events[source] = [
            e for e in self._source_events[source]
            if now - e[1] < CORRELATION_WINDOW
        ]

        events = self._source_events[source]
        if len(events) < 2:
            return

        # Build frozenset of threat IDs in this cluster
        threat_ids = frozenset(e[2] for e in events)

        # Don't create the same campaign twice
        if threat_ids in self._campaigns_created:
            return

        # Check if there's already a campaign that covers a superset of these IDs
        for existing in self._campaigns_created:
            if threat_ids.issubset(existing):
                return

        self._campaigns_created.add(threat_ids)

        types_seen = list({e[0] for e in events})
        campaign   = Threat(
            type        = ThreatType.INTRUSION,
            description = (
                f"CAMPAIGN DETECTED — source {source} linked to {len(events)} threats "
                f"in {CORRELATION_WINDOW//60}min: {', '.join(types_seen)}"
            ),
            severity    = ThreatSeverity.CRITICAL,
            source      = source,
            module      = "ThreatEngine.Correlation",
            metadata    = {
                "campaign":       True,
                "linked_threats": list(threat_ids),
                "types":          types_seen,
                "source":         source,
                "window_secs":    CORRELATION_WINDOW,
            },
        )

        # Register without going through dedup (it's a meta-threat)
        self.active_threats[campaign.id] = campaign
        await self._persist_threat(campaign.to_dict())
        logger.warning(
            f"🔗 CAMPAIGN: {source} — {len(events)} related threats correlated"
        )
        await self.ws_manager.broadcast({
            "event":    "campaign_detected",
            "campaign": campaign.to_dict(),
        })

        # Fire multi-channel campaign alert
        from modules.alert_manager import alert_manager
        asyncio.create_task(alert_manager.send_campaign_alert(campaign.to_dict()))

    # ══════════════════════════════════════════════════════════════════
    # Attack chain detection
    # ══════════════════════════════════════════════════════════════════

    async def _detect_attack_chain(self, threat: Threat) -> None:
        """
        Detect multi-stage APT attack chains.
        Checks if this threat completes a known attack sequence from same source.
        """
        source = threat.source
        events = self._source_events.get(source, [])
        if len(events) < 2:
            return

        types_from_source = [ThreatType(e[0]) for e in events if e[2] != threat.id]
        types_from_source.append(threat.type)

        for chain in ATTACK_CHAINS:
            # Check if all chain steps are present (order-insensitive)
            if all(step in types_from_source for step in chain):
                chain_key = f"chain:{source}:{','.join(str(c) for c in chain)}"
                if chain_key not in self._dedup_cache:
                    self._dedup_cache[chain_key] = time.time()
                    apt_threat = Threat(
                        type        = ThreatType.ZERO_DAY,
                        description = (
                            f"APT ATTACK CHAIN DETECTED from {source}: "
                            f"{' → '.join(str(c) for c in chain)}"
                        ),
                        severity    = ThreatSeverity.CRITICAL,
                        source      = source,
                        module      = "ThreatEngine.ChainDetection",
                        metadata    = {
                            "apt_chain":      [str(c) for c in chain],
                            "source":         source,
                            "chain_complete": True,
                        },
                    )
                    self.active_threats[apt_threat.id] = apt_threat
                    await self._persist_threat(apt_threat.to_dict())
                    logger.critical(
                        f"⚡ APT CHAIN: {source} — "
                        f"{' → '.join(str(c) for c in chain)}"
                    )
                    await self.ws_manager.broadcast({
                        "event":  "apt_chain_detected",
                        "threat": apt_threat.to_dict(),
                    })

                    # Fire multi-channel APT alert
                    from modules.alert_manager import alert_manager
                    asyncio.create_task(alert_manager.send_apt_chain_alert(apt_threat.to_dict()))
                    break

    # ══════════════════════════════════════════════════════════════════
    # TTL auto-resolve
    # ══════════════════════════════════════════════════════════════════

    async def _ttl_auto_resolve_loop(self) -> None:
        """
        Background task: auto-resolve LOW severity threats after TTL expires
        with no new activity from the same source.
        """
        while True:
            try:
                await asyncio.sleep(300)  # check every 5 minutes
                now = time.time()

                for tid, threat in list(self.active_threats.items()):
                    if threat.status != ThreatStatus.ACTIVE:
                        continue
                    if threat.severity != ThreatSeverity.LOW:
                        continue

                    # Parse detected_at
                    try:
                        detected = datetime.fromisoformat(threat.detected_at)
                        age_secs = (datetime.utcnow() - detected).total_seconds()
                    except Exception:
                        continue

                    if age_secs > LOW_TTL_SECS:
                        # Check if source has had recent activity
                        source_events = self._source_events.get(threat.source, [])
                        recent = [e for e in source_events if now - e[1] < 600]
                        if not recent:
                            await self.resolve_threat(
                                tid,
                                f"TTL auto-resolve: no new activity from {threat.source} "
                                f"in {LOW_TTL_SECS//3600}h"
                            )
                            logger.info(f"⏰ TTL auto-resolved: {tid[:8]} [{threat.type}]")

            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.debug(f"TTL loop error: {e}")

    # ══════════════════════════════════════════════════════════════════
    # Stats history
    # ══════════════════════════════════════════════════════════════════

    async def _stats_snapshot_loop(self) -> None:
        """Take a stats snapshot every 5 minutes and keep the last 24h."""
        while True:
            try:
                await asyncio.sleep(STATS_SNAPSHOT_SECS)
                snapshot = {
                    "timestamp": datetime.utcnow().isoformat(),
                    **self.get_stats(),
                }
                self._stats_history.append(snapshot)
                # Keep only last 24h
                if len(self._stats_history) > STATS_HISTORY_MAX:
                    self._stats_history.pop(0)
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.debug(f"Stats snapshot error: {e}")

    def get_stats_history(self) -> list[dict]:
        """Return the last 24h of stats snapshots."""
        return list(self._stats_history)

    def get_priority_queue(self) -> list[dict]:
        """Return active threats ordered by priority (CRITICAL first)."""
        result = []
        for pri, ts, tid in sorted(self._priority_queue):
            t = self.active_threats.get(tid)
            if t and t.status == ThreatStatus.ACTIVE:
                result.append({
                    "priority":    pri,
                    "threat_id":   tid,
                    "type":        str(t.type),
                    "severity":    str(t.severity),
                    "description": t.description[:80],
                    "source":      t.source,
                })
        return result

    async def _enrich_with_intel(self, threat: "Threat") -> None:
        """Fire-and-forget: enrich threat source IP with VT + Shodan data."""
        try:
            from modules.threat_intel import enrich_ip
            enrichment = await enrich_ip(threat.source)
            if enrichment:
                if isinstance(threat.metadata, dict):
                    threat.metadata["threat_intel"] = enrichment
                # Re-persist with enrichment
                await self._persist_threat(threat.to_dict())
                logger.info(f"Intel enrichment for {threat.source}: "
                            f"VT malicious={enrichment.get('vt', {}).get('malicious', 0)}")
        except Exception as e:
            logger.debug(f"Intel enrichment failed for {threat.source}: {e}")

    # ══════════════════════════════════════════════════════════════════
    # Auto-respond
    # ══════════════════════════════════════════════════════════════════

    async def auto_respond(self, threat: Threat) -> None:
        """Automatically respond to a threat using the response engine."""
        from modules.response_engine import ResponseEngine
        engine = ResponseEngine(self)
        await engine.respond(threat)

    # ══════════════════════════════════════════════════════════════════
    # Queries
    # ══════════════════════════════════════════════════════════════════

    def get_all_threats(self) -> list[dict]:
        """Return all threats as dicts."""
        return [t.to_dict() for t in self.active_threats.values()]

    def get_active_threats(self) -> list[dict]:
        """Return only active (unresolved) threats."""
        return [
            t.to_dict() for t in self.active_threats.values()
            if t.status == ThreatStatus.ACTIVE
        ]

    def get_stats(self) -> dict:
        """Return current threat statistics."""
        threats = list(self.active_threats.values())
        return {
            "total":    len(threats),
            "active":   sum(1 for t in threats if t.status == ThreatStatus.ACTIVE),
            "resolved": sum(1 for t in threats if t.status == ThreatStatus.RESOLVED),
            "critical": sum(1 for t in threats if t.severity == ThreatSeverity.CRITICAL),
            "high":     sum(1 for t in threats if t.severity == ThreatSeverity.HIGH),
            "medium":   sum(1 for t in threats if t.severity == ThreatSeverity.MEDIUM),
            "low":      sum(1 for t in threats if t.severity == ThreatSeverity.LOW),
        }

    # ══════════════════════════════════════════════════════════════════
    # DB persistence (unchanged)
    # ══════════════════════════════════════════════════════════════════

    async def _persist_threat(self, t: dict) -> None:
        """Upsert threat into the threats table — MySQL / PostgreSQL / SQLite compatible."""
        from core.database import AsyncSessionLocal, IS_MYSQL, IS_SQLITE
        from sqlalchemy import text
        import json
        try:
            meta = json.dumps(t.get("metadata", {}))
            params = {**t, "metadata": meta}

            async with AsyncSessionLocal() as db:
                if IS_MYSQL:
                    # MySQL: INSERT ... ON DUPLICATE KEY UPDATE
                    await db.execute(text("""
                        INSERT INTO threats
                            (id,type,description,severity,source,module,status,
                             detected_at,resolved_at,resolution_note,metadata,
                             ai_analysis,recommended_action)
                        VALUES
                            (:id,:type,:description,:severity,:source,:module,:status,
                             :detected_at,:resolved_at,:resolution_note,:metadata,
                             :ai_analysis,:recommended_action)
                        ON DUPLICATE KEY UPDATE
                            status             = VALUES(status),
                            resolved_at        = VALUES(resolved_at),
                            resolution_note    = VALUES(resolution_note),
                            ai_analysis        = VALUES(ai_analysis),
                            recommended_action = VALUES(recommended_action)
                    """), params)
                elif IS_SQLITE:
                    # SQLite: INSERT OR REPLACE
                    await db.execute(text("""
                        INSERT OR REPLACE INTO threats
                            (id,type,description,severity,source,module,status,
                             detected_at,resolved_at,resolution_note,metadata,
                             ai_analysis,recommended_action)
                        VALUES
                            (:id,:type,:description,:severity,:source,:module,:status,
                             :detected_at,:resolved_at,:resolution_note,:metadata,
                             :ai_analysis,:recommended_action)
                    """), params)
                else:
                    # PostgreSQL: ON CONFLICT DO UPDATE
                    await db.execute(text("""
                        INSERT INTO threats
                            (id,type,description,severity,source,module,status,
                             detected_at,resolved_at,resolution_note,metadata,
                             ai_analysis,recommended_action)
                        VALUES
                            (:id,:type,:description,:severity,:source,:module,:status,
                             :detected_at,:resolved_at,:resolution_note,:metadata,
                             :ai_analysis,:recommended_action)
                        ON CONFLICT (id) DO UPDATE SET
                            status             = EXCLUDED.status,
                            resolved_at        = EXCLUDED.resolved_at,
                            resolution_note    = EXCLUDED.resolution_note,
                            ai_analysis        = EXCLUDED.ai_analysis,
                            recommended_action = EXCLUDED.recommended_action
                    """), params)
                await db.commit()
        except Exception as e:
            logger.error(f"Failed to persist threat {t.get('id')}: {e}")

    async def _update_threat_status(
        self, threat_id: str, status: str, resolved_at: str, note: str
    ) -> None:
        """Update threat status in DB."""
        from core.database import AsyncSessionLocal
        from sqlalchemy import text
        try:
            async with AsyncSessionLocal() as db:
                await db.execute(
                    text("UPDATE threats SET status=:s, resolved_at=:r, "
                         "resolution_note=:n WHERE id=:id"),
                    {"s": status, "r": resolved_at, "n": note, "id": threat_id},
                )
                await db.commit()
        except Exception as e:
            logger.error(f"Failed to update threat {threat_id}: {e}")
