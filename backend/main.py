"""AISS - AI-Powered Threat Detection & Response Platform
Main FastAPI Application Entry Point
"""

from contextlib import asynccontextmanager
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from slowapi import Limiter
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware
from starlette.exceptions import HTTPException as StarletteHTTPException
from pathlib import Path
import asyncio
import json
import os
import time
import uvicorn
from datetime import datetime

from api.routes import threats, scanner, network, files, ai_analyst
from api.routes import auth_guard as onboarding_routes  # onboarding + device pairing
from api.routes import soc_chat as soc_chat_routes
from api.routes import kill_chain as kill_chain_routes
from api.routes import ai_firewall as ai_firewall_routes
from api.routes import learning as learning_routes
from api.routes import keyword_learning as keyword_learning_routes
from api.routes import dataset as dataset_routes
from api.routes import system_health as system_health_routes
from api.routes import system_config as system_config_routes
from api.routes import network_discovery as network_discovery_routes
from api.routes import intel as intel_routes
from api.routes import agents as agents_routes
from api.routes import orchestrator as orchestrator_routes
from api.routes import topology as topology_routes
from api.routes import live_system as live_system_routes
from api.routes import auth as oauth_routes
from api.routes import sso as sso_routes
from api.routes import security_orchestrator as security_orchestrator_routes
from auth.router import router as new_auth_router
from core.websocket_manager import WebSocketManager
from core.threat_engine import ThreatEngine
from core.auth import verify_token
from core.dependencies import init_services, init_agent_services
from core.database import init_db, close_db
from utils.logger import setup_logger
from modules.live_monitor import (
    print_startup_box,
    live_threat_line,
    live_resolve_line,
)
from core.lib_registry import lib_registry
from core import metrics as _metrics
from core.security_config import security_config
from core.licensing import license_manager
from core.startup_validator import run_startup_checks

logger = setup_logger("main")

# â”€â”€ Rate Limiter â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
limiter = Limiter(key_func=get_remote_address, default_limits=["200/minute"])

# â”€â”€ Core services â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
ws_manager    = WebSocketManager()
threat_engine = ThreatEngine(ws_manager)


@asynccontextmanager
async def lifespan(app: FastAPI):
    # â”€â”€ Security config & key validation (FIRST â€” before everything) â”€
    # ── Phase 1: Critical startup (must complete before accepting requests) ──
    import time as _t
    _boot = _t.monotonic()

    # Run startup checks + DB init concurrently — they are independent.
    # startup_checks already validates security_config + license internally.
    await asyncio.gather(
        run_startup_checks(),
        init_db(),
    )
    logger.info(f"Phase 1 ready in {_t.monotonic() - _boot:.1f}s")

    # â”€â”€ Sentry init (if configured) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    sentry_dsn = os.environ.get("SENTRY_DSN", "")
    if sentry_dsn:
        try:
            import sentry_sdk
            sentry_sdk.init(
                dsn=sentry_dsn,
                traces_sample_rate=0.1,
                environment=os.environ.get("ENVIRONMENT", "production"),
            )
            logger.info(f"âœ… Sentry initialized: {sentry_dsn[:30]}...")
        except Exception as e:
            logger.warning(f"Sentry init failed: {e}")

    # â”€â”€ Library registry â€” detect & init all installed libraries â”€â”€â”€â”€â”€
    # Runs as a background task so it never blocks startup.
    # ── Library registry ─────────────────────────────────────────────────────
    # Run ALL library inits in a thread-pool executor so heavy CPU-bound imports
    # (spaCy, sentence-transformers, transformers, etc.) never block the async
    # event loop. The HTTP server starts accepting connections immediately.
    # Libraries become available in the background within ~60-120s.
    async def _init_libraries_bg():
        try:
            import concurrent.futures as _cf
            _executor = _cf.ThreadPoolExecutor(max_workers=1, thread_name_prefix="lib_init")
            loop = asyncio.get_event_loop()

            def _run_sync_init():
                """Run the registry init in its own event loop in the thread."""
                _loop = asyncio.new_event_loop()
                asyncio.set_event_loop(_loop)
                try:
                    _loop.run_until_complete(lib_registry.init_all(timeout_secs=120.0, skip_heavy=True))
                finally:
                    _loop.close()

            await loop.run_in_executor(_executor, _run_sync_init)
            logger.info(f"Library registry ready: {lib_registry.summary()}")

            # Warm up modules that depend on the registry
            for _mod, _attr in [
                ("modules.online_anomaly_detector", "online_detector"),
                ("modules.ioc_extractor",           "ioc_extractor"),
                ("modules.llm_router",              "llm_router"),
                ("modules.report_exporter",         "report_exporter"),
                ("utils.oauth_helper",              "oauth_helper"),
            ]:
                try:
                    import importlib as _il
                    _m = _il.import_module(_mod)
                    _obj = getattr(_m, _attr, None)
                    if _obj and hasattr(_obj, "_lazy_init"):
                        _obj._lazy_init()
                    elif _obj and hasattr(_obj, "_ensure_ready"):
                        _obj._ensure_ready()
                except Exception:
                    pass

            try:
                from utils.token_counter import is_available as _tc
                if _tc():
                    logger.info("tiktoken: token counting active")
            except Exception:
                pass
        except Exception as _e:
            logger.warning(f"Library registry init failed (non-fatal): {_e}")

    asyncio.create_task(_init_libraries_bg())

    # Core dependency injection (instant)
    init_services(threat_engine, ws_manager)
    from modules.security_orchestrator import security_orchestrator
    security_orchestrator.ws_manager = ws_manager

    _bg = {}  # shared dict for background-init objects (scheduler, etc.)

    # ── Phase 2: Background heavy init — server accepts requests NOW ─────
    async def _phase2_bg():
        """Everything that doesn't need to block the HTTP server."""
        try:
            await threat_engine.startup()
            logger.info("Threat engine: persisted threats loaded")
        except Exception as e:
            logger.warning(f"Threat engine startup failed (non-fatal): {e}")

        # Agent Orchestrator init (heavy: ~15 module imports)
        try:
            from agents.audit_logger import AuditLogger
            from agents.security_filter import SecurityFilter
            from agents.memory_store import AgentMemoryStore
            from agents.ai_service import AIService
            from agents.permission_engine import PermissionEngine
            from agents.tool_registry import get_registry
            from agents.tool_registrations import register_all_tools
            from agents.approval_manager import ApprovalManager
            from agents.orchestrator import AgentOrchestrator
            from agents.scheduler import SchedulerEngine
            from agents.report_generator import ReportGenerator

            register_all_tools()
            _audit_logger = AuditLogger()
            _security_filter = SecurityFilter()
            _memory_store = AgentMemoryStore()
            _ai_service = AIService()
            _permission_engine = PermissionEngine()
            _registry = get_registry()
            _approval_manager = ApprovalManager(ws_manager, _audit_logger)
            _orchestrator = AgentOrchestrator(
                ai_service=_ai_service,
                tool_registry=_registry,
                permission_engine=_permission_engine,
                approval_manager=_approval_manager,
                audit_logger=_audit_logger,
                memory_store=_memory_store,
                security_filter=_security_filter,
                ws_manager=ws_manager,
            )
            _agent_scheduler = SchedulerEngine(_orchestrator)
            from core.database import AsyncSessionLocal as _asl
            _agent_scheduler.set_db_factory(_asl)
            init_agent_services(_orchestrator, _agent_scheduler)
            async with _asl() as _seed_db:
                await _agent_scheduler.seed_defaults(_seed_db)
            await _agent_scheduler.start()
            logger.info("Agent Orchestrator initialized with %d tools", len(_registry.get_all()))
        except Exception as _agent_err:
            logger.warning("Agent Orchestrator init failed (non-fatal): %s", _agent_err)

        from apscheduler.schedulers.asyncio import AsyncIOScheduler
        scheduler = AsyncIOScheduler()

        # Stats snapshot every 10 minutes (replaces threat_engine._stats_snapshot_loop)
        async def _stats_snapshot_job():
            try:
                snapshot = {
                    "timestamp": datetime.utcnow().isoformat(),
                    **threat_engine.get_stats(),
                }
                threat_engine._stats_history.append(snapshot)
                if len(threat_engine._stats_history) > 288:
                    threat_engine._stats_history.pop(0)
            except Exception as e:
                logger.debug(f"Stats snapshot job error: {e}")

        scheduler.add_job(_stats_snapshot_job, "interval", minutes=10, id="stats_snapshot")

        # TTL auto-resolve LOW threats every 5 minutes
        async def _ttl_auto_resolve_job():
            try:
                now = time.time()
                for tid, threat in list(threat_engine.active_threats.items()):
                    if threat.status != "active" or threat.severity != "low":
                        continue
                    try:
                        from datetime import datetime as dt
                        detected = dt.fromisoformat(threat.detected_at)
                        age_secs = (dt.utcnow() - detected).total_seconds()
                    except Exception:
                        continue
                    if age_secs > 3600:
                        source_events = threat_engine._source_events.get(threat.source, [])
                        recent = [e for e in source_events if now - e[1] < 600]
                        if not recent:
                            await threat_engine.resolve_threat(
                                tid,
                                f"TTL auto-resolve: no new activity from {threat.source} in 1h"
                            )
            except Exception as e:
                logger.debug(f"TTL auto-resolve job error: {e}")

        scheduler.add_job(_ttl_auto_resolve_job, "interval", minutes=5, id="ttl_auto_resolve")

        # STIX/TAXII feed ingestion every 6 hours (if configured)
        async def _taxii_ingest_job():
            try:
                from modules.threat_intel_feeds import ingest_from_taxii
                count = await ingest_from_taxii()
                if count > 0:
                    logger.info(f"TAXII ingestion job: {count} indicators loaded")
            except Exception as e:
                logger.debug(f"TAXII ingestion job error: {e}")

        scheduler.add_job(_taxii_ingest_job, "interval", hours=6, id="taxii_ingest")

        # â”€â”€ Topology: refresh network interfaces â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
        async def _topology_refresh_job():
            try:
                from modules.network_topology import topology_manager
                await topology_manager.refresh_interfaces()
            except Exception as e:
                logger.debug(f"Topology refresh error: {e}")

        scheduler.add_job(_topology_refresh_job, "interval", minutes=15, id="topology_refresh")
        # Run once at startup (non-blocking)
        asyncio.create_task(_topology_refresh_job())

        # â”€â”€ Agent health check every 60s â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
        async def _agent_health_job():
            try:
                import time
                from modules.remote_agent import _agent_registry
                from datetime import datetime
                now = time.time()
                for agent in list(_agent_registry.values()):
                    try:
                        last = datetime.fromisoformat(
                            agent.last_seen.replace("Z", "+00:00")
                        )
                        if (now - last.timestamp()) > 60 and agent.status == "connected":
                            agent.status = "idle"
                    except Exception:
                        pass
            except Exception as e:
                logger.debug(f"Agent health job error: {e}")

        scheduler.add_job(_agent_health_job, "interval", seconds=60, id="agent_health")

        scheduler.start()
        logger.info("âœ… APScheduler: 5 background jobs scheduled")


        from modules.dataset_loader import dataset_loader
        from pathlib import Path
        import asyncio as _asyncio
        import time

        async def _load_datasets_bg():
            try:
                datasets_exist = any(Path("datasets").glob("*.csv"))
                patterns_exist = Path("data/dataset_patterns.json").exists()
                if datasets_exist and not patterns_exist:
                    logger.info("ðŸ“Š Computing dataset patterns...")
                    loop = _asyncio.get_event_loop()
                    await loop.run_in_executor(None, dataset_loader.load_all_datasets)
                    logger.info("ðŸ“Š Dataset patterns ready")
                elif patterns_exist:
                    logger.info(f"ðŸ“Š Dataset patterns loaded ({dataset_loader.patterns.get('total_rows_processed', 0)} rows)")
            except Exception as e:
                logger.warning(f"ðŸ“Š Dataset load skipped: {e}")

        _asyncio.create_task(_load_datasets_bg())

        # Expose scheduler + agent scheduler for shutdown
        try:
            _bg["scheduler"] = scheduler
            _bg["_agent_scheduler"] = _agent_scheduler
        except NameError:
            pass

    try:
        _bg_task = asyncio.create_task(_phase2_bg())
    except Exception as _e:
        logger.warning(f"Phase 2 background init failed (non-fatal): {_e}")
    # â”€â”€ Patch ThreatEngine to emit live feed lines â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    _orig_register = threat_engine.register_threat
    _orig_resolve  = threat_engine.resolve_threat

    async def _patched_register(threat):
        await _orig_register(threat)
        live_threat_line(threat.to_dict())

    async def _patched_resolve(threat_id: str, resolution_note: str = ""):
        result = await _orig_resolve(threat_id, resolution_note)
        if result:
            t = threat_engine.active_threats.get(threat_id)
            t_type = t.type if t else "Unknown"
            live_resolve_line(threat_id, str(t_type))
        return result

    threat_engine.register_threat = _patched_register
    threat_engine.resolve_threat  = _patched_resolve

    # â”€â”€ Startup box â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    # Auto-monitoring is NOT auto-started on startup.
    # The scan loop is CPU-intensive and would block HTTP requests.
    # Start monitoring manually from the dashboard or via WebSocket:
    #   {action: "start_monitoring"}
    logger.info("Shield: Monitoring ready — start from dashboard when needed")

    print_startup_box(threat_engine)

    logger.info("ðŸš€ AISS started â€” all systems active")
    yield

    # â”€â”€ Shutdown â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    _sched = _bg.get("scheduler")
    if _sched:
        _sched.shutdown(wait=False)
    _as = _bg.get("_agent_scheduler")
    if _as:
        try:
            await _as.shutdown()
        except Exception:
            pass
    await close_db()
    logger.info("AISS shutdown complete")


app = FastAPI(
    title       = "AISS API",
    description = "AI-Powered Threat Detection & Response Platform",
    version     = "1.0.0",
    lifespan    = lifespan,
)

# â”€â”€ Prometheus instrumentation â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
try:
    from prometheus_fastapi_instrumentator import Instrumentator
    Instrumentator().instrument(app).expose(app, endpoint="/metrics")
    logger.info("âœ… Prometheus: /metrics endpoint exposed")
except Exception as e:
    logger.warning(f"Prometheus instrumentation failed: {e}")

# â”€â”€ Custom AISS Prometheus metrics â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
_metrics.init()

# â”€â”€ Rate limiter â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
app.state.limiter = limiter
app.add_middleware(SlowAPIMiddleware)

# â”€â”€ Custom middleware â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
# Order matters: added last = runs first on the way in.
from core.middleware import (
    InternalServiceMiddleware,
    AuditLogMiddleware,
    SecurityHeadersMiddleware,
    RequestSizeLimitMiddleware,
    InputSanitizationMiddleware,
    LicenseValidationMiddleware,
)
app.add_middleware(SecurityHeadersMiddleware)
app.add_middleware(AuditLogMiddleware)
app.add_middleware(InternalServiceMiddleware)
app.add_middleware(RequestSizeLimitMiddleware)
app.add_middleware(InputSanitizationMiddleware)
app.add_middleware(LicenseValidationMiddleware)

# â”€â”€ Exception handlers â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
@app.exception_handler(RateLimitExceeded)
async def rate_limit_handler(request: Request, exc: RateLimitExceeded):
    logger.warning(f"Rate limit: {request.client.host} â€” {request.url.path}")
    return JSONResponse(status_code=429, content={"error": "Too many requests. Slow down."})

@app.exception_handler(StarletteHTTPException)
async def http_exception_handler(request: Request, exc: StarletteHTTPException):
    return JSONResponse(status_code=exc.status_code, content={"error": exc.detail})

@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    logger.error(f"Unhandled {type(exc).__name__} on {request.method} {request.url.path}: {exc}")
    return JSONResponse(status_code=500, content={"error": "Internal server error"})

# â”€â”€ Static files â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
app.mount("/static", StaticFiles(directory="static"), name="static")

# â”€â”€ CORS â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
_raw_origins = os.environ.get("ALLOWED_ORIGINS", "http://localhost:3000,http://localhost:5173,http://localhost:4173")
ALLOWED_ORIGINS = [o.strip() for o in _raw_origins.split(",") if o.strip()]

app.add_middleware(
    CORSMiddleware,
    allow_origins     = ALLOWED_ORIGINS,
    allow_credentials = True,
    allow_methods     = ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers     = ["Authorization", "Content-Type"],
)

# â”€â”€ Routers â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
app.include_router(new_auth_router,              prefix="/api")
app.include_router(threats.router,               prefix="/api/threats",    tags=["Threats"])
app.include_router(scanner.router,               prefix="/api/scanner",    tags=["Scanner"])
app.include_router(network.router,               prefix="/api/network",    tags=["Network"])
app.include_router(files.router,                 prefix="/api/files",      tags=["File Inspector"])
app.include_router(ai_analyst.router,            prefix="/api/ai",         tags=["AI Analyst"])
app.include_router(soc_chat_routes.router,       prefix="/api",            tags=["SOC Assistant"])
app.include_router(kill_chain_routes.router,     prefix="/api",            tags=["Kill Chain"])
app.include_router(ai_firewall_routes.router,    prefix="/api",            tags=["AI Firewall"])
app.include_router(learning_routes.router,         prefix="/api/learn",         tags=["Self Learning"])
app.include_router(keyword_learning_routes.router, prefix="/api/keyword-learn", tags=["Keyword Learning"])
app.include_router(dataset_routes.router,          prefix="/api/dataset",        tags=["Datasets"])
app.include_router(system_health_routes.router,    prefix="/api/system",         tags=["System Health"])
app.include_router(system_config_routes.router,    prefix="/api",                tags=["System Config"])
app.include_router(network_discovery_routes.router, prefix="/api/network-discovery", tags=["Network Discovery"])
app.include_router(intel_routes.router,            prefix="/api/intel",          tags=["Threat Intelligence"])
app.include_router(agents_routes.router,           prefix="/api/remote-agents",  tags=["Remote Agents"])
app.include_router(orchestrator_routes.router,      prefix="/api",                tags=["Agent Orchestrator"])
app.include_router(security_orchestrator_routes.router, prefix="/api",           tags=["Autonomous Security Orchestrator"])
app.include_router(topology_routes.router,         prefix="/api/topology",        tags=["Network Topology"])
app.include_router(live_system_routes.router,      prefix="/api/live",            tags=["Live System"])
app.include_router(oauth_routes.router,            prefix="/api",                 tags=["OAuth"])
app.include_router(sso_routes.router,              prefix="/api",                 tags=["SSO"])
app.include_router(onboarding_routes.router,       prefix="/api",                 tags=["Onboarding & Devices"])


# â”€â”€ WebSocket â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    """
    Secure WebSocket â€” JWT required in first message.
    Flow: connect â†’ send {action:"auth", token:"<jwt>"} â†’ start using
    Also triggers the setup wizard popup batch for the frontend on first connect.
    """
    await websocket.accept()

    try:
        raw = await websocket.receive_text()
        msg = json.loads(raw)
    except (json.JSONDecodeError, Exception):
        await websocket.send_text('{"error": "First message must be valid JSON"}')
        await websocket.close(code=1008)
        return

    if msg.get("action") != "auth" or not msg.get("token"):
        await websocket.send_text('{"error": "Send: {action: auth, token: <jwt>}"}')
        await websocket.close(code=1008)
        return

    payload = verify_token(msg["token"])
    if payload is None:
        await websocket.send_text('{"error": "Invalid or expired token"}')
        await websocket.close(code=1008)
        logger.warning(f"WS rejected â€” bad token from {websocket.client.host}")
        return

    user = payload.get("sub")
    ws_manager.active_connections.append(websocket)
    await websocket.send_text(json.dumps({"status": "authenticated", "user": user}))
    logger.info(f"WS connected: user={user}")

    # â”€â”€ Auto-send wizard popups to frontend on first connect â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    try:
        from modules.frontend_bridge import (
            register_frontend_socket, unregister_frontend_socket,
            send_wizard_to_frontend
        )
        register_frontend_socket(websocket)
        # Send wizard questions as popups (only unanswered ones)
        asyncio.create_task(send_wizard_to_frontend(websocket))
    except Exception:
        pass

    try:
        while True:
            data = await websocket.receive_text()
            try:
                msg = json.loads(data)
            except json.JSONDecodeError:
                await websocket.send_text('{"error": "Invalid JSON"}')
                continue

            action = msg.get("action")
            if action == "start_monitoring":
                await threat_engine.start_monitoring()
            elif action == "stop_monitoring":
                await threat_engine.stop_monitoring()
            elif action == "popup_answer":
                # Frontend answered a popup question
                try:
                    from modules.frontend_bridge import record_answer
                    record_answer(msg.get("question_id", ""), msg.get("value", ""))
                    await websocket.send_text(json.dumps({
                        "event": "popup_answered",
                        "question_id": msg.get("question_id"),
                    }))
                except Exception:
                    pass
            elif action == "popup_dismiss":
                try:
                    from modules.frontend_bridge import dismiss_popup
                    dismiss_popup(msg.get("question_id", ""))
                except Exception:
                    pass
            else:
                await websocket.send_text(json.dumps({"error": f"Unknown action: {action}"}))

    except WebSocketDisconnect:
        ws_manager.disconnect(websocket)
        try:
            from modules.frontend_bridge import unregister_frontend_socket
            unregister_frontend_socket(websocket)
        except Exception:
            pass
        logger.info(f"WS disconnected: user={user}")


@app.websocket("/ws/monitor")
async def websocket_monitor(websocket: WebSocket):
    """
    Public read-only WebSocket for the local dashboard.
    No auth required â€” only broadcasts threat events, no control.
    Only accessible from localhost.
    """
    client_host = websocket.client.host if websocket.client else ""
    if client_host not in ("127.0.0.1", "::1", "localhost"):
        await websocket.close(code=1008)
        return

    await websocket.accept()
    ws_manager.active_connections.append(websocket)
    await websocket.send_text(json.dumps({"status": "connected", "mode": "monitor"}))

    try:
        while True:
            # Keep alive â€” just receive pings
            await websocket.receive_text()
    except WebSocketDisconnect:
        ws_manager.disconnect(websocket)


@app.websocket("/ws/agent")
async def websocket_agent(websocket: WebSocket):
    """
    Remote agent WebSocket endpoint.
    Remote machines running aiss_agent.py connect here to:
      - Send heartbeat metrics
      - Forward detected threats
      - Receive commands from AISS server
    Authentication: token-based (first message must contain valid agent token)
    """
    from modules.remote_agent import agent_manager
    await agent_manager.handle_connection(websocket)


# â”€â”€ Basic routes â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
@app.get("/favicon.ico", include_in_schema=False)
async def favicon():
    return FileResponse("static/favicon.ico")

@app.get("/")
@limiter.limit("30/minute")
async def root(request: Request):
    return {"status": "AISS Online", "version": "1.0.0"}

@app.get("/api/health")
@limiter.limit("60/minute")
async def health(request: Request):
    return {
        "status":   "healthy",
        "modules":  ["scanner", "network", "auth_guard", "file_inspector", "ai_analyst"],
        "platform": __import__("sys").platform,
    }


if __name__ == "__main__":
    import socket as _socket

    # Check if port 8000 is already in use
    with _socket.socket(_socket.AF_INET, _socket.SOCK_STREAM) as _s:
        if _s.connect_ex(("127.0.0.1", 8000)) == 0:
            print("\033[93m  âš   Port 8000 is already in use.\033[0m")
            print("\033[93m  Killing existing process and restarting...\033[0m")
            import subprocess, sys
            subprocess.call(
                ["powershell", "-Command",
                 "Get-NetTCPConnection -LocalPort 8000 -ErrorAction SilentlyContinue | "
                 "ForEach-Object { Stop-Process -Id $_.OwningProcess -Force -ErrorAction SilentlyContinue }"],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
            )
            import time
            time.sleep(1)

    uvicorn.run(
        "main:app",
        host=os.environ.get("AISS_BIND_HOST", "127.0.0.1"),
        port=int(os.environ.get("AISS_BACKEND_PORT", "8000")),
        reload=False,
        workers=1,
        log_level="warning",
    )


