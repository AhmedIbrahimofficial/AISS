"""
AISS Launcher — Single command to start the full AISS platform.

Usage:
    python aiss_launcher.py              # start backend + frontend
    python aiss_launcher.py --dev        # frontend via Vite dev server (hot-reload)
    python aiss_launcher.py --backend-only  # skip frontend
    python aiss_launcher.py --no-browser    # don't open browser automatically

Environment overrides:
    AISS_BACKEND_PORT   default 8000
    AISS_FRONTEND_PORT  default 8081  (dev mode uses 5173)
    AISS_RESTART_MAX    default 3

What happens:
    1.  Port conflict check — kills any process already on the target ports.
    2.  Backend starts (uvicorn, localhost-only binding).
    3.  Health check — waits for /api/health to return 200 before continuing.
    4.  Frontend starts:
          • Production mode  → serves pre-built .output/server/index.mjs via Node
          • Dev mode (--dev) → runs `npm run dev` via Vite (hot-reload, port 5173)
    5.  Frontend health check — waits for the UI to respond.
    6.  Browser opens automatically when both services are ready.
    7.  Crash monitor threads watch each process and restart on unexpected exit.
    8.  Ctrl-C / SIGTERM cleanly terminates both processes.

Authentication:
    The dashboard requires explicit login — it does NOT auto-login with
    hardcoded credentials. Users must enter their credentials on the login page
    or use Google OAuth (if configured). This is enforced by the launcher
    injecting VITE_DISABLE_AUTO_LOGIN=true into the frontend environment.
"""
from __future__ import annotations

import argparse
import logging
import os
import signal
import socket
import subprocess
import sys
import threading
import time
import webbrowser
from pathlib import Path

# ── Base directories ──────────────────────────────────────────────────
if getattr(sys, "frozen", False):
    BASE_DIR = Path(sys.executable).parent
else:
    BASE_DIR = Path(__file__).parent

BACKEND_DIR     = BASE_DIR
FRONTEND_DIR    = BASE_DIR.parent / "frontend"   # d:\aiss\frontend
NODE_EXE        = BASE_DIR / "node" / "node.exe"
BUILT_SERVER    = FRONTEND_DIR / ".output" / "server" / "index.mjs"

BACKEND_PORT    = int(os.environ.get("AISS_BACKEND_PORT",  "8000"))
FRONTEND_PORT   = int(os.environ.get("AISS_FRONTEND_PORT", "8081"))
DEV_PORT        = 5173   # Vite dev server default
MAX_RESTARTS    = int(os.environ.get("AISS_RESTART_MAX",   "3"))

# ── Logging ───────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] [AISS] %(levelname)s  %(message)s",
    datefmt="%H:%M:%S",
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler(BASE_DIR / "launcher.log", encoding="utf-8"),
    ],
)
log = logging.getLogger("aiss.launcher")

# ── State ─────────────────────────────────────────────────────────────
_procs: dict[str, subprocess.Popen] = {}
_restart_counts: dict[str, int] = {}
_shutdown_flag = threading.Event()
_dev_mode = False


# ─────────────────────────────────────────────────────────────────────
# Port utilities
# ─────────────────────────────────────────────────────────────────────

def _port_in_use(port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(0.5)
        return s.connect_ex(("127.0.0.1", port)) == 0


def _wait_for_port(port: int, timeout: int = 60) -> bool:
    start = time.time()
    while time.time() - start < timeout:
        if _port_in_use(port):
            return True
        time.sleep(0.5)
    return False


def _kill_on_port(port: int) -> None:
    try:
        if sys.platform == "win32":
            r = subprocess.run(
                ["powershell", "-NoProfile", "-Command",
                 f"(Get-NetTCPConnection -LocalPort {port} -ErrorAction SilentlyContinue"
                 f" | Select-Object -ExpandProperty OwningProcess)"],
                capture_output=True, text=True, timeout=10,
            )
            for pid in r.stdout.strip().splitlines():
                pid = pid.strip()
                if pid:
                    subprocess.run(["taskkill", "/F", "/PID", pid],
                                   capture_output=True, timeout=5)
                    log.info(f"  Killed PID {pid} on port {port}")
        else:
            r = subprocess.run(["lsof", "-t", f"-i:{port}"],
                               capture_output=True, text=True, timeout=5)
            for pid in r.stdout.strip().splitlines():
                try:
                    os.kill(int(pid), signal.SIGKILL)
                    log.info(f"  Killed PID {pid} on port {port}")
                except Exception:
                    pass
    except Exception as e:
        log.debug(f"Port kill failed: {e}")


def _check_and_free_port(port: int, name: str) -> None:
    if _port_in_use(port):
        log.warning(f"Port {port} ({name}) already in use — freeing it …")
        _kill_on_port(port)
        time.sleep(1.5)
        if _port_in_use(port):
            log.error(
                f"Port {port} is still occupied. "
                "Free it manually and restart."
            )
            sys.exit(1)
        log.info(f"Port {port} is free")


# ─────────────────────────────────────────────────────────────────────
# Health checks
# ─────────────────────────────────────────────────────────────────────

def _http_ok(url: str) -> bool:
    try:
        import urllib.request
        req = urllib.request.Request(url,
                                     headers={"User-Agent": "AISS-Launcher/2.0"})
        with urllib.request.urlopen(req, timeout=3) as r:
            return r.status < 500
    except Exception:
        return False


def _wait_for_health(port: int, path: str = "/api/health",
                     timeout: int = 90, label: str = "") -> bool:
    url = f"http://127.0.0.1:{port}{path}"
    start = time.time()
    dots = 0
    while time.time() - start < timeout:
        if _http_ok(url):
            return True
        time.sleep(1)
        dots += 1
        if dots % 10 == 0:
            elapsed = int(time.time() - start)
            log.info(f"  Still waiting for {label or path} … ({elapsed}s)")
    return False


# ─────────────────────────────────────────────────────────────────────
# Service builders
# ─────────────────────────────────────────────────────────────────────

def _backend_env() -> dict:
    """Build the environment for the backend process."""
    env = os.environ.copy()
    env["PYTHONPATH"] = str(BACKEND_DIR)

    fe_port = DEV_PORT if _dev_mode else FRONTEND_PORT
    origin  = f"http://localhost:{fe_port}"

    env.setdefault("DATABASE_URL",
                   f"sqlite+aiosqlite:///{BACKEND_DIR / 'logs' / 'aiss.db'}")

    # Combine any existing ALLOWED_ORIGINS with the frontend origin
    existing = env.get("ALLOWED_ORIGINS", "")
    if origin not in existing:
        env["ALLOWED_ORIGINS"] = f"{existing},{origin}".lstrip(",")

    # So OAuth callback redirects point to the correct frontend port
    env["FRONTEND_URL"] = origin

    return env


def _frontend_env() -> dict:
    """Build the environment for the frontend process."""
    env = os.environ.copy()
    env["VITE_AISS_API_URL"]       = f"http://localhost:{BACKEND_PORT}"
    # CRITICAL: disable hardcoded auto-login — user must log in explicitly
    env["VITE_DISABLE_AUTO_LOGIN"] = "true"
    return env


def _start_backend() -> subprocess.Popen:
    log.info(f"Starting backend on 127.0.0.1:{BACKEND_PORT} …")
    env = _backend_env()

    # Find the Python executable to use
    venv_python = BACKEND_DIR / ".venv" / "Scripts" / "python.exe"
    if not venv_python.exists():
        venv_python = BACKEND_DIR / ".venv" / "bin" / "python"
    if not venv_python.exists():
        venv_python = Path(sys.executable)

    cmd = [
        str(venv_python), "-m", "uvicorn", "main:app",
        "--host", "127.0.0.1",
        "--port", str(BACKEND_PORT),
        "--log-level", "warning",
        "--no-access-log",
    ]

    cflags = subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0
    proc = subprocess.Popen(
        cmd,
        cwd=str(BACKEND_DIR),
        env=env,
        creationflags=cflags,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    _procs["backend"] = proc
    log.info(f"  Backend PID {proc.pid}")
    return proc


def _start_frontend_prod() -> subprocess.Popen | None:
    """Start the pre-built TanStack Start / Nitro server."""
    if not BUILT_SERVER.exists():
        log.warning(
            f"Built frontend not found at {BUILT_SERVER}. "
            "Run 'npm run build' inside the frontend directory first, "
            "or start with --dev flag for Vite dev server."
        )
        return None

    node = str(NODE_EXE) if NODE_EXE.exists() else "node"
    log.info(f"Starting frontend (production) on 127.0.0.1:{FRONTEND_PORT} …")

    env = _frontend_env()
    env["PORT"]       = str(FRONTEND_PORT)
    env["HOST"]       = "127.0.0.1"
    env["NITRO_HOST"] = "127.0.0.1"
    env["NITRO_PORT"] = str(FRONTEND_PORT)

    cflags = subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0
    proc = subprocess.Popen(
        [node, str(BUILT_SERVER)],
        cwd=str(FRONTEND_DIR / ".output"),
        env=env,
        creationflags=cflags,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    _procs["frontend"] = proc
    log.info(f"  Frontend PID {proc.pid}")
    return proc


def _start_frontend_dev() -> subprocess.Popen | None:
    """Start the Vite dev server (hot-reload, port 5173)."""
    npm = "npm.cmd" if sys.platform == "win32" else "npm"
    if not FRONTEND_DIR.exists():
        log.error(f"Frontend directory not found: {FRONTEND_DIR}")
        return None

    log.info(f"Starting frontend (dev/Vite) on 127.0.0.1:{DEV_PORT} …")

    env = _frontend_env()
    env["VITE_PORT"] = str(DEV_PORT)

    cflags = 0  # dev server needs visible output on Windows too
    proc = subprocess.Popen(
        [npm, "run", "dev", "--", "--host", "127.0.0.1", "--port", str(DEV_PORT)],
        cwd=str(FRONTEND_DIR),
        env=env,
        creationflags=cflags,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    _procs["frontend"] = proc
    log.info(f"  Frontend dev PID {proc.pid}")
    return proc


# ─────────────────────────────────────────────────────────────────────
# Crash monitor
# ─────────────────────────────────────────────────────────────────────

def _monitor(name: str, starter) -> None:
    while not _shutdown_flag.is_set():
        proc = _procs.get(name)
        if proc and proc.poll() is not None:
            code = proc.returncode
            n    = _restart_counts.get(name, 0)
            if n < MAX_RESTARTS:
                log.warning(
                    f"[{name}] exited (code {code}) — "
                    f"restarting ({n+1}/{MAX_RESTARTS}) …"
                )
                _restart_counts[name] = n + 1
                time.sleep(2)
                try:
                    starter()
                except Exception as exc:
                    log.error(f"[{name}] restart failed: {exc}")
            else:
                log.error(
                    f"[{name}] crashed {n} times — giving up. "
                    "Check launcher.log for details."
                )
                break
        time.sleep(2)


# ─────────────────────────────────────────────────────────────────────
# Shutdown
# ─────────────────────────────────────────────────────────────────────

def _shutdown(sig=None, _frame=None) -> None:
    if _shutdown_flag.is_set():
        return
    _shutdown_flag.set()
    log.info("Shutting down AISS …")
    for name, proc in list(_procs.items()):
        try:
            proc.terminate()
            log.info(f"  [{name}] SIGTERM sent (PID {proc.pid})")
        except Exception:
            pass
    time.sleep(2)
    for name, proc in list(_procs.items()):
        if proc.poll() is None:
            try:
                proc.kill()
                log.info(f"  [{name}] SIGKILL sent")
            except Exception:
                pass
    log.info("AISS stopped")
    sys.exit(0)


# ─────────────────────────────────────────────────────────────────────
# Entry point
# ─────────────────────────────────────────────────────────────────────

def main() -> None:
    global _dev_mode, FRONTEND_PORT

    parser = argparse.ArgumentParser(
        description="AISS — AI Integrated Security System launcher",
        formatter_class=argparse.RawTextHelpFormatter,
    )
    parser.add_argument("--dev",          action="store_true",
                        help="Use Vite dev server (hot-reload) instead of built frontend")
    parser.add_argument("--backend-only", action="store_true",
                        help="Start backend only, skip frontend")
    parser.add_argument("--no-browser",   action="store_true",
                        help="Do not open browser automatically")
    args = parser.parse_args()

    _dev_mode = args.dev
    no_browser = args.no_browser or os.environ.get("AISS_NO_BROWSER") == "1"
    backend_only = args.backend_only

    # In dev mode the frontend runs on 5173
    fe_port = DEV_PORT if _dev_mode else FRONTEND_PORT

    # ── Banner ────────────────────────────────────────────────────────
    log.info("=" * 60)
    log.info("  AISS — AI Integrated Security System  v2.0.0")
    log.info("=" * 60)
    log.info(f"  Mode           : {'DEV (Vite)' if _dev_mode else 'PRODUCTION'}")
    log.info(f"  Backend        : http://localhost:{BACKEND_PORT}")
    if not backend_only:
        log.info(f"  Frontend       : http://localhost:{fe_port}")
    log.info(f"  Auto-login     : DISABLED (explicit login required)")
    log.info("=" * 60)

    signal.signal(signal.SIGINT,  _shutdown)
    signal.signal(signal.SIGTERM, _shutdown)

    # ── 1. Port conflict check ────────────────────────────────────────
    _check_and_free_port(BACKEND_PORT, "backend")
    if not backend_only:
        _check_and_free_port(fe_port, "frontend")

    # ── 2. Start + health-check backend ──────────────────────────────
    _start_backend()
    log.info("Waiting for backend to be ready …")
    if not _wait_for_health(BACKEND_PORT, path="/api/health",
                            timeout=90, label="backend"):
        log.error(
            "Backend failed to start within 90 s.\n"
            f"  Check {BASE_DIR / 'launcher.log'} for details."
        )
        _shutdown()
        return

    log.info(f"✅ Backend ready   → http://localhost:{BACKEND_PORT}")
    threading.Thread(target=_monitor, args=("backend", _start_backend),
                     daemon=True).start()

    # ── 3. Start + health-check frontend ─────────────────────────────
    frontend_ok = False
    if not backend_only:
        if _dev_mode:
            fe_proc = _start_frontend_dev()
        else:
            fe_proc = _start_frontend_prod()

        if fe_proc:
            log.info("Waiting for frontend to be ready …")
            frontend_ok = _wait_for_health(
                fe_port, path="/",
                timeout=60 if _dev_mode else 45,
                label="frontend",
            )
            if frontend_ok:
                log.info(f"✅ Frontend ready  → http://localhost:{fe_port}")
            else:
                log.warning(
                    "Frontend did not respond in time. "
                    "Continuing in backend-only mode."
                )

            starter = _start_frontend_dev if _dev_mode else _start_frontend_prod
            threading.Thread(target=_monitor, args=("frontend", starter),
                             daemon=True).start()

    # ── 4. Open browser ───────────────────────────────────────────────
    if not no_browser:
        url = (
            f"http://localhost:{fe_port}"
            if frontend_ok
            else f"http://localhost:{BACKEND_PORT}/docs"
        )
        log.info(f"Opening browser → {url}")
        try:
            webbrowser.open(url)
        except Exception:
            pass

    # ── 5. Ready summary ──────────────────────────────────────────────
    log.info("-" * 60)
    log.info(f"  Backend API    → http://localhost:{BACKEND_PORT}")
    log.info(f"  API Docs       → http://localhost:{BACKEND_PORT}/docs")
    if frontend_ok:
        log.info(f"  Dashboard      → http://localhost:{fe_port}")
        log.info( "  Login page     → please use your credentials")
    log.info("-" * 60)
    log.info("  Press Ctrl+C to stop all services")
    log.info("-" * 60)

    # ── 6. Keep alive ─────────────────────────────────────────────────
    try:
        while not _shutdown_flag.is_set():
            time.sleep(5)
    except KeyboardInterrupt:
        _shutdown()


if __name__ == "__main__":
    main()
