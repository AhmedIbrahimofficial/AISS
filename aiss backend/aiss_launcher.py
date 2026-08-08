"""
AISS Launcher — Single executable entry point.
Starts the FastAPI backend AND the frontend Node server,
then opens the browser automatically.
"""
import os
import sys
import subprocess
import threading
import time
import webbrowser
import signal
from pathlib import Path

# ── Determine base directory (works both in dev and frozen exe) ──────
if getattr(sys, "frozen", False):
    BASE_DIR = Path(sys.executable).parent
else:
    BASE_DIR = Path(__file__).parent

BACKEND_DIR  = BASE_DIR
FRONTEND_DIR = BASE_DIR / "frontend"
NODE_EXE     = BASE_DIR / "node" / "node.exe"
FRONTEND_SERVER = FRONTEND_DIR / ".output" / "server" / "index.mjs"

BACKEND_PORT  = 8000
FRONTEND_PORT = 8081

_procs: list[subprocess.Popen] = []


def _print(msg: str):
    print(f"[AISS] {msg}", flush=True)


def _start_backend():
    _print("Starting backend on port 8000...")
    env = os.environ.copy()
    env["PYTHONPATH"] = str(BACKEND_DIR)
    env.setdefault("DATABASE_URL", f"sqlite+aiosqlite:///{BACKEND_DIR / 'logs' / 'aiss.db'}")
    env.setdefault("ALLOWED_ORIGINS", f"http://localhost:{FRONTEND_PORT}")

    if getattr(sys, "frozen", False):
        # Running as bundled exe — use the embedded Python
        proc = subprocess.Popen(
            [sys.executable, str(BACKEND_DIR / "main.py")],
            cwd=str(BACKEND_DIR),
            env=env,
            creationflags=subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0,
        )
    else:
        proc = subprocess.Popen(
            [sys.executable, "main.py"],
            cwd=str(BACKEND_DIR),
            env=env,
        )
    _procs.append(proc)
    return proc


def _start_frontend():
    _print("Starting frontend on port 8081...")
    node = str(NODE_EXE) if NODE_EXE.exists() else "node"
    env = os.environ.copy()
    env["PORT"] = str(FRONTEND_PORT)
    env["HOST"] = "0.0.0.0"
    env["VITE_AISS_API_URL"] = f"http://localhost:{BACKEND_PORT}"

    proc = subprocess.Popen(
        [node, str(FRONTEND_SERVER)],
        cwd=str(FRONTEND_DIR / ".output"),
        env=env,
        creationflags=subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0,
    )
    _procs.append(proc)
    return proc


def _wait_for_port(port: int, timeout: int = 30) -> bool:
    import socket
    start = time.time()
    while time.time() - start < timeout:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=1):
                return True
        except OSError:
            time.sleep(0.5)
    return False


def _open_browser():
    time.sleep(2)
    _print("Waiting for services to start...")
    backend_ok  = _wait_for_port(BACKEND_PORT, 30)
    frontend_ok = _wait_for_port(FRONTEND_PORT, 30)
    if backend_ok and frontend_ok:
        _print(f"Opening browser at http://localhost:{FRONTEND_PORT}")
        webbrowser.open(f"http://localhost:{FRONTEND_PORT}")
    elif frontend_ok:
        webbrowser.open(f"http://localhost:{FRONTEND_PORT}")
    elif backend_ok:
        _print("Warning: Frontend didn't start. Opening backend API docs.")
        webbrowser.open(f"http://localhost:{BACKEND_PORT}/docs")
    else:
        _print("Warning: Services didn't start in time. Check logs.")


def _shutdown(sig=None, frame=None):
    _print("Shutting down AISS...")
    for p in _procs:
        try:
            p.terminate()
        except Exception:
            pass
    time.sleep(1)
    for p in _procs:
        try:
            p.kill()
        except Exception:
            pass
    sys.exit(0)


def main():
    _print("=" * 50)
    _print("  AISS — AI Integrated Security System v2.0")
    _print("=" * 50)
    _print(f"Base directory: {BASE_DIR}")

    # Register shutdown handlers
    signal.signal(signal.SIGINT,  _shutdown)
    signal.signal(signal.SIGTERM, _shutdown)

    # Start backend
    _start_backend()

    # Start frontend (if Node is available)
    if NODE_EXE.exists() or FRONTEND_SERVER.exists():
        _start_frontend()
    else:
        _print("Frontend server not found — backend only mode")

    # Open browser in background thread
    t = threading.Thread(target=_open_browser, daemon=True)
    t.start()

    _print(f"Backend  → http://localhost:{BACKEND_PORT}")
    _print(f"Frontend → http://localhost:{FRONTEND_PORT}")
    _print(f"API Docs → http://localhost:{BACKEND_PORT}/docs")
    _print("Press Ctrl+C to stop AISS")

    # Wait for processes
    try:
        while True:
            for p in _procs:
                if p.poll() is not None:
                    _print(f"Process {p.pid} exited with code {p.returncode}")
            time.sleep(2)
    except KeyboardInterrupt:
        _shutdown()


if __name__ == "__main__":
    main()
