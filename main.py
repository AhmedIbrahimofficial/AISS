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
import asyncio
import json
import os
import uvicorn

from api.routes import threats, scanner, network, auth_guard, files, ai_analyst
from api.routes import deception as deception_routes
from api.routes import soc_chat as soc_chat_routes
from api.routes import kill_chain as kill_chain_routes
from api.routes import ai_firewall as ai_firewall_routes
from api.routes import learning as learning_routes
from api.routes import keyword_learning as keyword_learning_routes
from api.routes import dataset as dataset_routes
from api.routes import system_health as system_health_routes
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
from modules.self_test import self_test_loop
from modules.usb_monitor import usb_monitor_loop

logger = setup_logger("main")

# ── Rate Limiter ──────────────────────────────────────────────────────
limiter = Limiter(key_func=get_remote_address, default_limits=["200/minute"])

# ── Core services ─────────────────────────────────────────────────────
ws_manager    = WebSocketManager()
threat_engine = ThreatEngine(ws_manager)


@asynccontextmanager
async def lifespan(app: FastAPI):
    # ── Database + engine init ────────────────────────────────────────
    await init_db()
    await threat_engine.startup()
    init_services(threat_engine, ws_manager)

    # ── Dataset patterns load (non-blocking) ─────────────────────────
    from modules.dataset_loader import dataset_loader
    from pathlib import Path
    import asyncio as _asyncio

    async def _load_datasets_bg():
        """Load datasets in background so startup is not delayed."""
        try:
            datasets_exist = any(Path("datasets").glob("*.csv"))
            patterns_exist = Path("data/dataset_patterns.json").exists()
            if datasets_exist and not patterns_exist:
                # First run — load and compute thresholds
                logger.info("📊 Dataset patterns not found — computing from CSVs...")
                loop = _asyncio.get_event_loop()
                await loop.run_in_executor(None, dataset_loader.load_all_datasets)
                logger.info("📊 Dataset patterns computed and saved")
            elif patterns_exist:
                logger.info(f"📊 Dataset patterns loaded "
                            f"({dataset_loader.patterns.get('total_rows_processed', 0)} rows)")
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

    # ── Deception Technology ──────────────────────────────────────────
    from modules.deception import (
        drop_honeypot_files, watch_honeypot_files,
        start_port_honeypots, set_alert_callback,
    )
    from models.threat import Threat, ThreatType, ThreatSeverity

    async def honeypot_alert(asset: str, detail: str, ip: str):
        threat = Threat(
            type        = ThreatType.INTRUSION,
            description = f"HONEYPOT TRIGGERED — {asset}: {detail}",
            severity    = ThreatSeverity.CRITICAL,
            source      = ip,
            module      = "Deception",
            metadata    = {"asset": asset, "detail": detail, "source_ip": ip},
        )
        await threat_engine.register_threat(threat)

    set_alert_callback(honeypot_alert)
    honeypot_files = drop_honeypot_files(".")
    watch_honeypot_files(honeypot_files)
    start_port_honeypots()
    logger.info("🍯 Deception layer active — honeypots deployed")
    # ─────────────────────────────────────────────────────────────────

    # ── Feature 1: Startup proof box (minimal, no loop) ────────────
    print_startup_box(threat_engine)

    # ── Background tasks (only essential ones) ───────────────────────
    # scanner_task removed — high CPU usage, psutil per-process scan
    selftest_task = asyncio.create_task(self_test_loop(threat_engine))
    usb_task      = asyncio.create_task(usb_monitor_loop(threat_engine))
    # sysmon removed — covered by /api/system/health endpoint polling

    logger.info("🚀 AISS started — all systems active")
    yield

    # ── Shutdown ──────────────────────────────────────────────────────
    selftest_task.cancel()
    usb_task.cancel()
    await close_db()
    logger.info("🔌 AISS shutdown complete")


app = FastAPI(
    title       = "AISS API",
    description = "AI-Powered Threat Detection & Response Platform",
    version     = "1.0.0",
    lifespan    = lifespan,
)

# ── Rate limiter ──────────────────────────────────────────────────────
app.state.limiter = limiter
app.add_middleware(SlowAPIMiddleware)

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
_raw_origins = os.environ.get("ALLOWED_ORIGINS", "http://localhost:3000")
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
app.include_router(deception_routes.router,      prefix="/api",            tags=["Deception"])
app.include_router(soc_chat_routes.router,       prefix="/api",            tags=["SOC Assistant"])
app.include_router(kill_chain_routes.router,     prefix="/api",            tags=["Kill Chain"])
app.include_router(ai_firewall_routes.router,    prefix="/api",            tags=["AI Firewall"])
app.include_router(learning_routes.router,         prefix="/api/learn",         tags=["Self Learning"])
app.include_router(keyword_learning_routes.router, prefix="/api/keyword-learn", tags=["Keyword Learning"])
app.include_router(dataset_routes.router,          prefix="/api/dataset",        tags=["Datasets"])
app.include_router(system_health_routes.router,    prefix="/api/system",         tags=["System Health"])

# Fake admin panel — no prefix, lives at /admin
from modules.deception import get_fake_admin_router
app.include_router(get_fake_admin_router())


# ── WebSocket ─────────────────────────────────────────────────────────
@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    """
    Secure WebSocket — JWT required in first message.
    Flow: connect → send {action:"auth", token:"<jwt>"} → start using
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
            else:
                await websocket.send_text(json.dumps({"error": f"Unknown action: {action}"}))

    except WebSocketDisconnect:
        ws_manager.disconnect(websocket)
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

    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=False)
