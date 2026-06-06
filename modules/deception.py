"""
Cybersecurity - Deception Technology Module
Honeypots that detect attackers by luring them into fake assets.

Deception assets:
  1. Fake admin panel (HTTP endpoint)
  2. Fake database credentials file
  3. Fake API keys file
  4. Honeypot network ports (SSH:2222, FTP:2121, Telnet:2323)

ANY interaction = instant alert (real users never touch these)
"""

import asyncio
import os
import socket
import threading
from datetime import datetime
from utils.logger import setup_logger

logger = setup_logger("deception")

# ── Honeypot files dropped on disk ───────────────────────────────────
HONEYPOT_FILES = {
    "fake_credentials.txt": (
        "# Database Credentials (INTERNAL USE ONLY)\n"
        "DB_HOST=192.168.1.100\n"
        "DB_USER=admin\n"
        "DB_PASS=Adm1n@2024!\n"
        "DB_NAME=prod_customers\n"
    ),
    "fake_api_keys.txt": (
        "# API Keys - DO NOT SHARE\n"
        "STRIPE_KEY=sk_live_FAKE_HONEYPOT_KEY_12345\n"
        "AWS_ACCESS_KEY=AKIAFAKEKEY123456789\n"
        "AWS_SECRET=FakeSecretKey/HONEYPOT/abcdefgh\n"
    ),
    "admin_passwords.txt": (
        "# Admin Passwords Backup\n"
        "admin: S3cur3P@ss!\n"
        "root: R00t@dmin2024\n"
        "superuser: Sup3r!User#99\n"
    ),
}

_alert_callback = None   # set by engine at startup


def set_alert_callback(cb):
    """Register the function to call when a honeypot is triggered."""
    global _alert_callback
    _alert_callback = cb


def _fire_alert(asset: str, detail: str, ip: str = "local"):
    """Log and broadcast honeypot trigger."""
    msg = f"HONEYPOT TRIGGERED — Asset: {asset} | Detail: {detail} | Source: {ip}"
    logger.critical(f"🍯 {msg}")
    if _alert_callback:
        try:
            asyncio.run_coroutine_threadsafe(
                _alert_callback(asset, detail, ip),
                asyncio.get_event_loop(),
            )
        except Exception:
            pass  # callback fire best-effort


# ─────────────────────────────────────────────────────────────────────
# 1. HONEYPOT FILES — drop fake credentials on disk
# ─────────────────────────────────────────────────────────────────────

def drop_honeypot_files(directory: str = ".") -> list[str]:
    """
    Create honeypot files in the given directory.
    Returns list of created file paths.
    """
    created = []
    for filename, content in HONEYPOT_FILES.items():
        path = os.path.join(directory, filename)
        if not os.path.exists(path):
            with open(path, "w") as f:
                f.write(content)
            logger.info(f"🍯 Honeypot file dropped: {path}")
        created.append(path)
    return created


def watch_honeypot_files(paths: list[str], interval: int = 5):
    """
    Monitor honeypot files in a background thread.
    Alert if any file is read/modified (mtime or atime change).
    """
    baseline = {}
    for p in paths:
        try:
            stat = os.stat(p)
            baseline[p] = (stat.st_mtime, stat.st_atime)
        except Exception:
            pass

    def _watch():
        while True:
            for p in paths:
                try:
                    stat = os.stat(p)
                    cur  = (stat.st_mtime, stat.st_atime)
                    if p in baseline and cur != baseline[p]:
                        _fire_alert(
                            asset  = os.path.basename(p),
                            detail = f"File accessed or modified at {datetime.utcnow().isoformat()}",
                        )
                        baseline[p] = cur
                except Exception:
                    pass
            import time; time.sleep(interval)

    t = threading.Thread(target=_watch, daemon=True)
    t.start()
    logger.info(f"🍯 Watching {len(paths)} honeypot files")


# ─────────────────────────────────────────────────────────────────────
# 2. HONEYPOT PORTS — fake SSH / FTP / Telnet listeners
# ─────────────────────────────────────────────────────────────────────

HONEYPOT_PORTS = {
    2222: "Fake SSH",
    2121: "Fake FTP",
    2323: "Fake Telnet",
}


def _start_port_honeypot(port: int, service_name: str):
    """Listen on a port — alert on any connection attempt."""
    def _serve():
        try:
            srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            srv.bind(("0.0.0.0", port))
            srv.listen(5)
            logger.info(f"🍯 {service_name} honeypot listening on port {port}")

            while True:
                try:
                    conn, addr = srv.accept()
                    ip = addr[0]
                    _fire_alert(
                        asset  = service_name,
                        detail = f"Connection attempt on port {port}",
                        ip     = ip,
                    )
                    # Send a realistic banner then close
                    banners = {
                        2222: b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6\r\n",
                        2121: b"220 FTP Server Ready\r\n",
                        2323: b"\xff\xfd\x18\xff\xfd\x20\xff\xfd#\xff\xfd'Telnet\r\n",
                    }
                    conn.sendall(banners.get(port, b""))
                    conn.close()
                except Exception:
                    pass
        except OSError as e:
            logger.warning(f"Honeypot port {port} unavailable: {e}")

    t = threading.Thread(target=_serve, daemon=True, name=f"honeypot-{port}")
    t.start()


def start_port_honeypots():
    """Start all honeypot port listeners."""
    for port, name in HONEYPOT_PORTS.items():
        _start_port_honeypot(port, name)


# ─────────────────────────────────────────────────────────────────────
# 3. FAKE ADMIN PANEL — FastAPI route (registered in main.py)
# ─────────────────────────────────────────────────────────────────────

def get_fake_admin_router():
    """
    Returns a FastAPI router with a fake admin panel.
    ANY request to /admin/* triggers an alert.
    """
    from fastapi import APIRouter, Request
    from fastapi.responses import HTMLResponse

    router = APIRouter()

    FAKE_LOGIN_PAGE = """
    <!DOCTYPE html>
    <html>
    <head><title>Admin Panel</title>
    <style>
      body { background:#1a1a2e; color:#eee; font-family:Arial; display:flex;
             justify-content:center; align-items:center; height:100vh; margin:0; }
      .box { background:#16213e; padding:40px; border-radius:8px; width:320px; }
      h2   { color:#e94560; margin-bottom:24px; }
      input { width:100%; padding:10px; margin:8px 0; border:1px solid #444;
              background:#0f3460; color:#eee; border-radius:4px; box-sizing:border-box; }
      button { width:100%; padding:12px; background:#e94560; color:#fff;
               border:none; border-radius:4px; cursor:pointer; font-size:14px; }
    </style></head>
    <body>
      <div class="box">
        <h2>🔒 Admin Panel</h2>
        <form method="post">
          <input type="text"     name="username" placeholder="Username" required />
          <input type="password" name="password" placeholder="Password" required />
          <button type="submit">Login</button>
        </form>
      </div>
    </body>
    </html>
    """

    @router.get("/admin", response_class=HTMLResponse, include_in_schema=False)
    @router.get("/admin/", response_class=HTMLResponse, include_in_schema=False)
    async def fake_admin_get(request: Request):
        ip = request.client.host if request.client else "unknown"
        _fire_alert("Fake Admin Panel", f"GET /admin from {ip}", ip)
        return HTMLResponse(FAKE_LOGIN_PAGE)

    @router.post("/admin", response_class=HTMLResponse, include_in_schema=False)
    @router.post("/admin/", response_class=HTMLResponse, include_in_schema=False)
    async def fake_admin_post(request: Request):
        ip   = request.client.host if request.client else "unknown"
        form = await request.form()
        user = form.get("username", "")
        _fire_alert(
            "Fake Admin Panel",
            f"LOGIN ATTEMPT — username='{user}' from {ip}",
            ip,
        )
        # Always show "invalid" — never grant access
        return HTMLResponse(
            FAKE_LOGIN_PAGE.replace(
                "<h2>🔒 Admin Panel</h2>",
                "<h2>🔒 Admin Panel</h2><p style='color:#e94560'>Invalid credentials</p>",
            )
        )

    return router
