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

from api.routes import threats, scanner, network, auth_guard, files, ai_analyst
from api.routes import soc_chat as soc_chat_routes
from api.routes import kill_chain as kill_chain_routes
from api.routes import ai_firewall as ai_firewall_routes
from api.routes import learning as learning_routes
from api.routes import keyword_learning as keyword_learning_routes
from api.routes import dataset as dataset_routes
from api.routes import system_health as system_health_routes
from api.routes import network_discovery as network_discovery_routes
from api.routes import intel as intel_routes
from api.routes import agents as agents_routes
from api.routes import topology as topology_routes
from auth.router import router as new_auth_router
from core.websocket_manager import WebSocketManager
from core.threat_engine import ThreatEngine
from core.auth import verify_token
from core.dependencies import init_services
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

# ── Rate Limiter ──────────────────────────────────────────────────────
limiter = Limiter(key_func=get_remote_address, default_limits=["200/minute"])

# ── Core services ─────────────────────────────────────────────────────
ws_manager    = WebSocketManager()
threat_engine = ThreatEngine(ws_manager)


@asynccontextmanager
async def lifespan(app: FastAPI):
    # ── Security config & key validation (FIRST — before everything) ─
    await security_config.validate()

    # ── License validation ─────────────────────────────────────────────
    await license_manager.validate()

    # ── Startup checks ────────────────────────────────────────────────
    await run_startup_checks()

    # ── Sentry init (if configured) ───────────────────────────────────
    sentry_dsn = os.environ.get("SENTRY_DSN", "")
    if sentry_dsn:
        try:
            import sentry_sdk
            sentry_sdk.init(
                dsn=sentry_dsn,
                traces_sample_rate=0.1,
                environment=os.environ.get("ENVIRONMENT", "production"),
            )
            logger.info(f"✅ Sentry initialized: {sentry_dsn[:30]}...")
        except Exception as e:
            logger.warning(f"Sentry init failed: {e}")

    # ── Library registry — detect & init all installed libraries ─────
    # Runs as a background task so it never blocks startup.
    # Heavy libs (model downloads) have individual timeouts.
    async def _init_libraries_bg():
        try:
            await lib_registry.init_all(timeout_secs=120.0)
            logger.info(f"📦 {lib_registry.summary()}")
            # After registry ready, warm up singleton modules that depend on it
            try:
                from modules.online_anomaly_detector import online_detector
                online_detector._ensure_ready()
            except Exception:
                pass
            try:
                from modules.ioc_extractor import ioc_extractor
                ioc_extractor._lazy_init()
            except Exception:
                pass
            try:
                from modules.llm_router import llm_router
                llm_router._lazy_init()
            except Exception:
                pass
            # Warm up report exporter (lazy matplotlib init)
            try:
                from modules.report_exporter import report_exporter
                report_exporter._lazy_init()
            except Exception:
                pass
            # Warm up oauth helper
            try:
                from utils.oauth_helper import oauth_helper
                oauth_helper._lazy_init()
            except Exception:
                pass
            # Verify token counter
            try:
                from utils.token_counter import is_available as tc_available
                if tc_available():
                    logger.info("✅ tiktoken: token counting active")
            except Exception:
                pass
        except Exception as e:
            logger.warning(f"Library registry init failed (non-fatal): {e}")

    asyncio.create_task(_init_libraries_bg())

    # ── Database + engine init ────────────────────────────────────────
    await init_db()
    await threat_engine.startup()
    init_services(threat_engine, ws_manager)

    # ── APScheduler setup ─────────────────────────────────────────────
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

    # ── Topology: refresh network interfaces ─────────────────────────
    async def _topology_refresh_job():
        try:
            from modules.network_topology import topology_manager
            await topology_manager.refresh_interfaces()
        except Exception as e:
            logger.debug(f"Topology refresh error: {e}")

    scheduler.add_job(_topology_refresh_job, "interval", minutes=15, id="topology_refresh")
    # Run once at startup (non-blocking)
    asyncio.create_task(_topology_refresh_job())

    # ── Agent health check every 60s ─────────────────────────────────
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
    logger.info("✅ APScheduler: 5 background jobs scheduled")

    # ── Dataset patterns load (non-blocking) ─────────────────────────
    from modules.dataset_loader import dataset_loader
    from pathlib import Path
    import asyncio as _asyncio
    import time

    async def _load_datasets_bg():
        try:
            datasets_exist = any(Path("datasets").glob("*.csv"))
            patterns_exist = Path("data/dataset_patterns.json").exists()
            if datasets_exist and not patterns_exist:
                logger.info("📊 Computing dataset patterns...")
                loop = _asyncio.get_event_loop()
                await loop.run_in_executor(None, dataset_loader.load_all_datasets)
                logger.info("📊 Dataset patterns ready")
            elif patterns_exist:
                logger.info(f"📊 Dataset patterns loaded ({dataset_loader.patterns.get('total_rows_processed', 0)} rows)")
        except Exception as e:
            logger.warning(f"📊 Dataset load skipped: {e}")

    _asyncio.create_task(_load_datasets_bg())

    # ── Patch ThreatEngine to emit live feed lines ────────────────────
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

    # ── Startup box ───────────────────────────────────────────────────
    print_startup_box(threat_engine)

    logger.info("🚀 AISS started — all systems active")
    yield

    # ── Shutdown ──────────────────────────────────────────────────────
    scheduler.shutdown(wait=False)
    await close_db()
    logger.info("🔌 AISS shutdown complete")


app = FastAPI(
    title       = "AISS API",
    description = "AI-Powered Threat Detection & Response Platform",
    version     = "1.0.0",
    lifespan    = lifespan,
)

# ── Prometheus instrumentation ────────────────────────────────────────
try:
    from prometheus_fastapi_instrumentator import Instrumentator
    Instrumentator().instrument(app).expose(app, endpoint="/metrics")
    logger.info("✅ Prometheus: /metrics endpoint exposed")
except Exception as e:
    logger.warning(f"Prometheus instrumentation failed: {e}")

# ── Custom AISS Prometheus metrics ────────────────────────────────────
_metrics.init()

# ── Rate limiter ──────────────────────────────────────────────────────
app.state.limiter = limiter
app.add_middleware(SlowAPIMiddleware)

# ── Custom middleware ─────────────────────────────────────────────────
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

# ── Exception handlers ────────────────────────────────────────────────
@app.exception_handler(RateLimitExceeded)
async def rate_limit_handler(request: Request, exc: RateLimitExceeded):
    logger.warning(f"Rate limit: {request.client.host} — {request.url.path}")
    return JSONResponse(status_code=429, content={"error": "Too many requests. Slow down."})

@app.exception_handler(StarletteHTTPException)
async def http_exception_handler(request: Request, exc: StarletteHTTPException):
    return JSONResponse(status_code=exc.status_code, content={"error": exc.detail})

@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    logger.error(f"Unhandled {type(exc).__name__} on {request.method} {request.url.path}: {exc}")
    return JSONResponse(status_code=500, content={"error": "Internal server error"})

# ── Static files ──────────────────────────────────────────────────────
app.mount("/static", StaticFiles(directory="static"), name="static")

# ── CORS ──────────────────────────────────────────────────────────────
_raw_origins = os.environ.get("ALLOWED_ORIGINS", "http://localhost:3000,http://localhost:5173,http://localhost:4173")
ALLOWED_ORIGINS = [o.strip() for o in _raw_origins.split(",") if o.strip()]

app.add_middleware(
    CORSMiddleware,
    allow_origins     = ALLOWED_ORIGINS,
    allow_credentials = True,
    allow_methods     = ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers     = ["Authorization", "Content-Type"],
)

# ── Routers ───────────────────────────────────────────────────────────
app.include_router(new_auth_router,              prefix="/api")
app.include_router(threats.router,               prefix="/api/threats",    tags=["Threats"])
app.include_router(scanner.router,               prefix="/api/scanner",    tags=["Scanner"])
app.include_router(network.router,               prefix="/api/network",    tags=["Network"])
app.include_router(auth_guard.router,            prefix="/api/auth-guard", tags=["Auth Guard"])
app.include_router(files.router,                 prefix="/api/files",      tags=["File Inspector"])
app.include_router(ai_analyst.router,            prefix="/api/ai",         tags=["AI Analyst"])
app.include_router(soc_chat_routes.router,       prefix="/api",            tags=["SOC Assistant"])
app.include_router(kill_chain_routes.router,     prefix="/api",            tags=["Kill Chain"])
app.include_router(ai_firewall_routes.router,    prefix="/api",            tags=["AI Firewall"])
app.include_router(learning_routes.router,         prefix="/api/learn",         tags=["Self Learning"])
app.include_router(keyword_learning_routes.router, prefix="/api/keyword-learn", tags=["Keyword Learning"])
app.include_router(dataset_routes.router,          prefix="/api/dataset",        tags=["Datasets"])
app.include_router(system_health_routes.router,    prefix="/api/system",         tags=["System Health"])
app.include_router(network_discovery_routes.router, prefix="/api/network-discovery", tags=["Network Discovery"])
app.include_router(intel_routes.router,            prefix="/api/intel",          tags=["Threat Intelligence"])
app.include_router(agents_routes.router,           prefix="/api/agents",         tags=["Remote Agents"])
app.include_router(topology_routes.router,         prefix="/api/topology",        tags=["Network Topology"])


# ── WebSocket ─────────────────────────────────────────────────────────
@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    """
    Secure WebSocket — JWT required in first message.
    Flow: connect → send {action:"auth", token:"<jwt>"} → start using
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
        logger.warning(f"WS rejected — bad token from {websocket.client.host}")
        return

    user = payload.get("sub")
    ws_manager.active_connections.append(websocket)
    await websocket.send_text(json.dumps({"status": "authenticated", "user": user}))
    logger.info(f"WS connected: user={user}")

    # ── Auto-send wizard popups to frontend on first connect ──────────
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
    No auth required — only broadcasts threat events, no control.
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
            # Keep alive — just receive pings
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


# ── Basic routes ──────────────────────────────────────────────────────
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
            print("\033[93m  ⚠  Port 8000 is already in use.\033[0m")
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
        host="0.0.0.0",
        port=8000,
        reload=False,
        workers=1,
        log_level="warning",
    )
