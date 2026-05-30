"""
Cybersecurity - AI-Powered Threat Detection & Response Platform
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
import json
import os
import uvicorn

from api.routes import threats, scanner, network, auth_guard, files, ai_analyst
from api.routes import auth as auth_routes
from core.websocket_manager import WebSocketManager
from core.threat_engine import ThreatEngine
from core.auth import verify_token
from core.dependencies import init_services
from core import database
from core.database import init_db, close_db
from utils.logger import setup_logger

logger = setup_logger("main")

# ── Rate Limiter ──────────────────────────────────────────────────────
limiter = Limiter(key_func=get_remote_address, default_limits=["200/minute"])

# ── Core services ─────────────────────────────────────────────────────
ws_manager = WebSocketManager()
threat_engine = ThreatEngine(ws_manager)


@asynccontextmanager
async def lifespan(app: FastAPI):
    # ── Startup ──────────────────────────────────────────────
    await init_db()                                # create all tables
    await threat_engine.startup()                  # load threats from DB
    init_services(threat_engine, ws_manager)       # register Depends() singletons
    logger.info("🚀 Cybersecurity started — threat history loaded from database")

    yield  # app is running

    # ── Shutdown ─────────────────────────────────────────────
    await close_db()
    logger.info("🔌 Cybersecurity shutdown complete")


app = FastAPI(
    title="Cybersecurity API",
    description="AI-Powered Threat Detection & Response Platform",
    version="1.0.0",
    lifespan=lifespan,
)

# ── Rate limiter ──────────────────────────────────────────────────────
app.state.limiter = limiter
app.add_middleware(SlowAPIMiddleware)

# ── Exception handlers (specific → general, order matters) ───────────
@app.exception_handler(RateLimitExceeded)
async def rate_limit_handler(request: Request, exc: RateLimitExceeded):
    logger.warning(f"Rate limit exceeded: {request.client.host} — {request.url.path}")
    return JSONResponse(status_code=429, content={"error": "Too many requests. Slow down."})


@app.exception_handler(StarletteHTTPException)
async def http_exception_handler(request: Request, exc: StarletteHTTPException):
    return JSONResponse(status_code=exc.status_code, content={"error": exc.detail})


@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    logger.error(
        f"Unhandled error on {request.method} {request.url.path} "
        f"— {type(exc).__name__}: {exc}"
    )
    return JSONResponse(status_code=500, content={"error": "Internal server error"})


# ── Static files ──────────────────────────────────────────────────────
app.mount("/static", StaticFiles(directory="static"), name="static")

# ── CORS ──────────────────────────────────────────────────────────────
_raw_origins = os.environ.get("ALLOWED_ORIGINS", "http://localhost:3000")
ALLOWED_ORIGINS = [o.strip() for o in _raw_origins.split(",") if o.strip()]

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type"],
)

# ── Routers (no more set_engine — Depends() handles injection) ────────
app.include_router(auth_routes.router, prefix="/api/auth",       tags=["Auth"])
app.include_router(threats.router,     prefix="/api/threats",    tags=["Threats"])
app.include_router(scanner.router,     prefix="/api/scanner",    tags=["Scanner"])
app.include_router(network.router,     prefix="/api/network",    tags=["Network"])
app.include_router(auth_guard.router,  prefix="/api/auth-guard", tags=["Auth Guard"])
app.include_router(files.router,       prefix="/api/files",      tags=["File Inspector"])
app.include_router(ai_analyst.router,  prefix="/api/ai",         tags=["AI Analyst"])


# ── WebSocket — header-based auth (token NOT in URL) ─────────────────
@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    """
    WebSocket endpoint — JWT token required in first message.

    Connect flow:
      1. ws = new WebSocket("ws://localhost:8000/ws")
      2. ws.send(JSON.stringify({ action: "auth", token: "<jwt>" }))
      3. On success → {"status": "authenticated"}
      4. Then send { action: "start_monitoring" } etc.
    """
    await websocket.accept()

    # ── Step 1: wait for auth message ────────────────────────
    try:
        raw = await websocket.receive_text()
        msg = json.loads(raw)
    except (json.JSONDecodeError, Exception):
        await websocket.send_text('{"error": "First message must be valid JSON auth payload"}')
        await websocket.close(code=1008)
        return

    if msg.get("action") != "auth" or not msg.get("token"):
        await websocket.send_text('{"error": "First message must be: {action: auth, token: <jwt>}"}')
        await websocket.close(code=1008)
        return

    payload = verify_token(msg["token"])
    if payload is None:
        await websocket.send_text('{"error": "Invalid or expired token"}')
        await websocket.close(code=1008)
        logger.warning(f"WebSocket rejected — invalid token from {websocket.client.host}")
        return

    # ── Step 2: authenticated — start normal loop ─────────────
    user = payload.get("sub")
    ws_manager.active_connections.append(websocket)
    await websocket.send_text(json.dumps({"status": "authenticated", "user": user}))
    logger.info(f"WebSocket authenticated: user={user}")

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
                await websocket.send_text(
                    json.dumps({"error": f"Unknown action: {action}"})
                )
    except WebSocketDisconnect:
        ws_manager.disconnect(websocket)
        logger.info(f"WebSocket disconnected: user={user}")


# ── Basic routes ──────────────────────────────────────────────────────
@app.get("/favicon.ico", include_in_schema=False)
async def favicon():
    return FileResponse("static/favicon.ico")


@app.get("/")
@limiter.limit("30/minute")
async def root(request: Request):
    return {"status": "Cybersecurity Online", "version": "1.0.0"}


@app.get("/api/health")
@limiter.limit("60/minute")
async def health(request: Request):
    return {
        "status": "healthy",
        "modules": ["scanner", "network", "auth_guard", "file_inspector", "ai_analyst"],
        "platform": __import__("sys").platform,
    }


if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
