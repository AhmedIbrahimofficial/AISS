"""
AISS - Deception Technology Module (UPGRADED)
──────────────────────────────────────────────
Advanced features:
  - All existing honeypot files + ports preserved
  - Interaction logging: timestamp, IP, action, data, headers
  - Attacker fingerprinting: UA, headers, timing, behavior profile
  - Port honeypot enhancement: capture first 1024 bytes attacker sends
  - Fake credentials rotation: every hour (make attacker think fresh creds)
  - Honeypot interaction replay: last 100 interactions in memory
  - More honeypot files: backup.zip, database.sql, private_key.pem (all fake)
  - Fake DB endpoint: /db-backup.sql returns fake SQL dump + alerts
  - Config file honeypots: config.json, .env.backup
"""

import asyncio
import json
import os
import re
import socket
import threading
import time
from collections import deque
from datetime import datetime
from typing import Callable, Optional

from utils.logger import setup_logger

logger = setup_logger("deception")

# ── Honeypot files ────────────────────────────────────────────────────
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
    "backup.zip.txt": (
        "# This file represents a backup archive\n"
        "# Contents: customer_data_2024.sql, employee_records.csv\n"
        "# Size: 2.3 GB\n"
        "# Created: 2024-12-01\n"
    ),
    "database.sql.txt": (
        "-- Production Database Dump\n"
        "-- Host: 192.168.1.100\n"
        "-- Database: prod_customers\n"
        "CREATE TABLE users (id INT, username VARCHAR(50), password_hash VARCHAR(128));\n"
        "INSERT INTO users VALUES (1, 'admin', '$2b$12$FAKEHASH_HONEYPOT_DO_NOT_USE');\n"
    ),
    "private_key.pem.txt": (
        "-----BEGIN RSA PRIVATE KEY-----\n"
        "HONEYPOT_FAKE_KEY_DO_NOT_USE\n"
        "MIIEpAIBAAKCAQEA0Z3VS5JJcds3xHn/ygWep4KmUAIBAQIBAQIBAQIBAQ==\n"
        "HONEYPOT_FAKE_KEY_END\n"
        "-----END RSA PRIVATE KEY-----\n"
    ),
    "config.json.txt": json.dumps({
        "database": {
            "host": "192.168.1.100",
            "port": 5432,
            "name": "prod_db",
            "user": "dbadmin",
            "password": "Pr0d_DB_P@ss!"
        },
        "redis": {"host": "192.168.1.101", "port": 6379, "password": "r3dis_p@ss"},
        "jwt_secret": "HONEYPOT_FAKE_JWT_SECRET_32chars!!",
    }, indent=2),
    ".env.backup.txt": (
        "DATABASE_URL=postgresql://admin:Pr0d_P@ss@192.168.1.100:5432/prod\n"
        "SECRET_KEY=HONEYPOT_FAKE_SECRET_KEY_do_not_use\n"
        "STRIPE_SECRET=sk_live_HONEYPOT_FAKE_KEY\n"
        "AWS_SECRET_ACCESS_KEY=FAKE_HONEYPOT_AWS_KEY\n"
    ),
}

# Fake creds that rotate every hour
_ROTATING_CREDS = [
    ("admin", "S3cur3P@ss!"),
    ("root", "R00t@dmin2024"),
    ("superuser", "Sup3r!User#99"),
    ("sysadmin", "Sy5@dmin!2024"),
    ("dbadmin", "DB_@dmin_2024"),
]

# ── Module state ──────────────────────────────────────────────────────
_alert_callback: Optional[Callable] = None
_interactions: deque = deque(maxlen=100)          # last 100 interactions
_attacker_profiles: dict[str, dict] = {}          # {ip → profile}
_cred_rotation_idx: int = 0
_last_rotation: float = time.time()


def set_alert_callback(cb: Callable) -> None:
    """Register the callback to invoke when a honeypot is triggered."""
    global _alert_callback
    _alert_callback = cb


# ══════════════════════════════════════════════════════════════════════
# Interaction logging & attacker fingerprinting
# ══════════════════════════════════════════════════════════════════════

def _log_interaction(
    asset: str,
    action: str,
    ip: str,
    data: str = "",
    headers: dict = None,
    detail: str = "",
) -> None:
    """
    Log a honeypot interaction and update attacker fingerprint profile.
    """
    interaction = {
        "timestamp":  datetime.utcnow().isoformat(),
        "asset":      asset,
        "action":     action,
        "ip":         ip,
        "data":       data[:512] if data else "",
        "headers":    {k: v for k, v in (headers or {}).items()
                       if k.lower() not in ("authorization", "cookie")},
        "detail":     detail,
    }
    _interactions.append(interaction)

    # Update attacker profile
    profile = _attacker_profiles.setdefault(ip, {
        "first_seen":   interaction["timestamp"],
        "last_seen":    interaction["timestamp"],
        "hit_count":    0,
        "assets_hit":   [],
        "actions":      [],
        "user_agents":  [],
        "risk_score":   0,
    })
    profile["last_seen"]  = interaction["timestamp"]
    profile["hit_count"] += 1
    if asset not in profile["assets_hit"]:
        profile["assets_hit"].append(asset)
    profile["actions"].append(action)

    ua = (headers or {}).get("user-agent", "")
    if ua and ua not in profile["user_agents"]:
        profile["user_agents"].append(ua)

    # Risk score: more assets hit = higher score
    profile["risk_score"] = min(100, profile["hit_count"] * 10 + len(profile["assets_hit"]) * 15)


def _fire_alert(asset: str, detail: str, ip: str = "local", data: str = "") -> None:
    """Log interaction and trigger alert callback."""
    _log_interaction(asset=asset, action="triggered", ip=ip, data=data, detail=detail)

    msg = f"HONEYPOT TRIGGERED — Asset: {asset} | Detail: {detail} | Source: {ip}"
    logger.critical(f"🍯 {msg}")

    if _alert_callback:
        try:
            asyncio.run_coroutine_threadsafe(
                _alert_callback(asset, detail, ip),
                asyncio.get_event_loop(),
            )
        except Exception:
            pass


# ══════════════════════════════════════════════════════════════════════
# Credential rotation
# ══════════════════════════════════════════════════════════════════════

def _rotate_credentials() -> None:
    """
    Rotate the fake credentials in honeypot files every hour.
    Makes attackers think they found fresh credentials.
    """
    global _cred_rotation_idx, _last_rotation
    now = time.time()
    if now - _last_rotation < 3600:
        return

    _cred_rotation_idx = (_cred_rotation_idx + 1) % len(_ROTATING_CREDS)
    user, pwd = _ROTATING_CREDS[_cred_rotation_idx]
    _last_rotation = now

    # Regenerate the passwords file
    new_content = (
        f"# Admin Passwords Backup — Rotated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M')}\n"
        f"{user}: {pwd}\n"
        f"backup_admin: Bkp_@dmin_2024\n"
    )
    path = "admin_passwords.txt"
    if os.path.exists(path):
        with open(path, "w") as f:
            f.write(new_content)
    logger.debug(f"🍯 Honeypot credentials rotated to user: {user}")


def _credential_rotation_thread() -> None:
    """Background thread to rotate credentials every hour."""
    while True:
        time.sleep(60)
        try:
            _rotate_credentials()
        except Exception:
            pass


# ══════════════════════════════════════════════════════════════════════
# 1. HONEYPOT FILES
# ══════════════════════════════════════════════════════════════════════

def drop_honeypot_files(directory: str = ".") -> list[str]:
    """Create all honeypot files in the given directory."""
    created = []
    for filename, content in HONEYPOT_FILES.items():
        path = os.path.join(directory, filename)
        if not os.path.exists(path):
            with open(path, "w", encoding="utf-8") as f:
                f.write(content)
            logger.info(f"🍯 Honeypot file dropped: {path}")
        created.append(path)

    # Start credential rotation thread
    t = threading.Thread(target=_credential_rotation_thread, daemon=True)
    t.start()

    return created


def watch_honeypot_files(paths: list[str], interval: int = 5) -> None:
    """
    Monitor honeypot files in background thread.
    Alert on any mtime/atime change.
    """
    baseline: dict[str, tuple] = {}
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
            time.sleep(interval)

    t = threading.Thread(target=_watch, daemon=True)
    t.start()
    logger.info(f"🍯 Watching {len(paths)} honeypot files")


# ══════════════════════════════════════════════════════════════════════
# 2. HONEYPOT PORTS — enhanced with payload capture
# ══════════════════════════════════════════════════════════════════════

HONEYPOT_PORTS = {
    2222: "Fake SSH",
    2121: "Fake FTP",
    2323: "Fake Telnet",
}

_BANNERS = {
    2222: b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6\r\n",
    2121: b"220 FTP Server Ready (vsftpd 3.0.5)\r\n",
    2323: b"\xff\xfd\x18\xff\xfd\x20\xff\xfd#\xff\xfd'Linux login: ",
}


def _start_port_honeypot(port: int, service_name: str) -> None:
    """Listen on a port — capture attacker data and alert."""
    def _serve():
        try:
            srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            srv.bind(("0.0.0.0", port))
            srv.listen(10)
            logger.info(f"🍯 {service_name} honeypot listening on port {port}")

            while True:
                try:
                    conn, addr = srv.accept()
                    ip = addr[0]

                    # Send realistic banner
                    banner = _BANNERS.get(port, b"")
                    if banner:
                        conn.sendall(banner)

                    # Capture what attacker sends (first 1024 bytes)
                    conn.settimeout(3.0)
                    received_data = ""
                    try:
                        raw = conn.recv(1024)
                        if raw:
                            # Try to decode; redact common patterns
                            received_data = raw.decode("utf-8", errors="replace")
                            received_data = re.sub(r"[^\x20-\x7E\n\r\t]", ".", received_data)
                    except Exception:
                        pass

                    _fire_alert(
                        asset  = service_name,
                        detail = f"Connection on port {port} | "
                                 f"Data: {received_data[:100] if received_data else '(none)'}",
                        ip     = ip,
                        data   = received_data,
                    )

                    # Log interaction with captured data
                    _log_interaction(
                        asset   = service_name,
                        action  = f"port_{port}_connect",
                        ip      = ip,
                        data    = received_data,
                        detail  = f"Port {port} connection with payload capture",
                    )

                    conn.close()
                except Exception:
                    pass
        except OSError as e:
            logger.warning(f"Honeypot port {port} unavailable: {e}")

    t = threading.Thread(target=_serve, daemon=True, name=f"honeypot-{port}")
    t.start()


def start_port_honeypots() -> None:
    """Start all honeypot port listeners."""
    for port, name in HONEYPOT_PORTS.items():
        _start_port_honeypot(port, name)


# ══════════════════════════════════════════════════════════════════════
# 3. FASTAPI ROUTES — fake admin + fake DB endpoint
# ══════════════════════════════════════════════════════════════════════

FAKE_LOGIN_PAGE = """<!DOCTYPE html>
<html>
<head><title>Admin Panel</title>
<style>
  body{background:#1a1a2e;color:#eee;font-family:Arial;display:flex;
       justify-content:center;align-items:center;height:100vh;margin:0}
  .box{background:#16213e;padding:40px;border-radius:8px;width:320px}
  h2{color:#e94560;margin-bottom:24px}
  input{width:100%;padding:10px;margin:8px 0;border:1px solid #444;
        background:#0f3460;color:#eee;border-radius:4px;box-sizing:border-box}
  button{width:100%;padding:12px;background:#e94560;color:#fff;
         border:none;border-radius:4px;cursor:pointer;font-size:14px}
  .err{color:#ff6b6b;font-size:12px;margin-top:8px}
</style></head>
<body><div class="box">
  <h2>🔒 Admin Panel</h2>
  <form method="post">
    <input type="text" name="username" placeholder="Username" required/>
    <input type="password" name="password" placeholder="Password" required/>
    <button type="submit">Login</button>
  </form>
</div></body></html>"""

FAKE_SQL_DUMP = """-- MySQL dump 10.13  Distrib 8.0.35, for Linux (x86_64)
-- Host: 192.168.1.100    Database: prod_customers
-- HONEYPOT: This file is a trap. Your IP has been logged.
-- ------------------------------------------------------

CREATE TABLE `users` (
  `id` int NOT NULL AUTO_INCREMENT,
  `username` varchar(50) NOT NULL,
  `email` varchar(100) NOT NULL,
  `password_hash` varchar(128) NOT NULL,
  `role` enum('admin','user','moderator') DEFAULT 'user',
  PRIMARY KEY (`id`)
) ENGINE=InnoDB;

INSERT INTO `users` VALUES
(1,'admin','admin@company.com','$2b$12$HONEYPOT_HASH_DO_NOT_USE','admin'),
(2,'john.doe','john@company.com','$2b$12$HONEYPOT_HASH2','user'),
(3,'jane.smith','jane@company.com','$2b$12$HONEYPOT_HASH3','moderator');

CREATE TABLE `payment_cards` (
  `id` int NOT NULL AUTO_INCREMENT,
  `user_id` int NOT NULL,
  `card_number` varchar(16) NOT NULL,
  `cvv` varchar(4) NOT NULL,
  `expiry` varchar(7) NOT NULL
) ENGINE=InnoDB;

INSERT INTO `payment_cards` VALUES
(1,1,'4111111111111111','123','12/26'),
(2,2,'5500005555555559','456','06/25');
"""


def get_fake_admin_router():
    """Returns a FastAPI router with fake admin panel + fake DB endpoint."""
    from fastapi import APIRouter, Request
    from fastapi.responses import HTMLResponse, PlainTextResponse

    router = APIRouter()

    @router.get("/admin", response_class=HTMLResponse, include_in_schema=False)
    @router.get("/admin/", response_class=HTMLResponse, include_in_schema=False)
    async def fake_admin_get(request: Request):
        ip      = request.client.host if request.client else "unknown"
        headers = dict(request.headers)
        _log_interaction("Fake Admin Panel", "GET /admin", ip, headers=headers)
        _fire_alert("Fake Admin Panel", f"GET /admin from {ip}", ip)
        return HTMLResponse(FAKE_LOGIN_PAGE)

    @router.post("/admin", response_class=HTMLResponse, include_in_schema=False)
    @router.post("/admin/", response_class=HTMLResponse, include_in_schema=False)
    async def fake_admin_post(request: Request):
        ip      = request.client.host if request.client else "unknown"
        headers = dict(request.headers)
        form    = await request.form()
        user    = form.get("username", "")
        pwd     = form.get("password", "")

        _log_interaction(
            "Fake Admin Panel", "POST /admin",
            ip, data=f"username={user}&password={'*'*len(pwd)}",
            headers=headers,
            detail=f"Login attempt: user='{user}'",
        )
        _fire_alert(
            "Fake Admin Panel",
            f"LOGIN ATTEMPT — username='{user}' from {ip}",
            ip,
            data=f"username={user}",
        )
        return HTMLResponse(
            FAKE_LOGIN_PAGE.replace(
                "<button", '<p class="err">Invalid credentials. Try again.</p><button'
            )
        )

    @router.get("/db-backup.sql", include_in_schema=False)
    async def fake_db_backup(request: Request):
        """Fake database backup endpoint — any access triggers CRITICAL alert."""
        ip      = request.client.host if request.client else "unknown"
        headers = dict(request.headers)
        _log_interaction(
            "Fake DB Backup", "GET /db-backup.sql",
            ip, headers=headers,
            detail="Database backup file accessed",
        )
        _fire_alert(
            "Fake DB Backup",
            f"Database backup accessed from {ip} — possible data exfiltration attempt",
            ip,
        )
        return PlainTextResponse(FAKE_SQL_DUMP, media_type="text/plain")

    @router.get("/.env", include_in_schema=False)
    @router.get("/.env.backup", include_in_schema=False)
    @router.get("/config.json", include_in_schema=False)
    async def fake_config(request: Request):
        """Fake config endpoints."""
        ip   = request.client.host if request.client else "unknown"
        path = request.url.path
        _fire_alert(f"Fake Config ({path})", f"Config file accessed: {path} from {ip}", ip)
        content = HONEYPOT_FILES.get(".env.backup.txt", "")
        return PlainTextResponse(content or "", media_type="text/plain")

    return router


# ══════════════════════════════════════════════════════════════════════
# 4. Query functions for API routes
# ══════════════════════════════════════════════════════════════════════

def get_interactions(limit: int = 50) -> list[dict]:
    """Return the last N honeypot interactions."""
    interactions = list(_interactions)
    return interactions[-limit:]


def get_attacker_profiles() -> dict[str, dict]:
    """Return all attacker fingerprint profiles."""
    return dict(_attacker_profiles)


def get_high_risk_attackers(min_score: int = 50) -> list[dict]:
    """Return attacker profiles with risk score >= min_score."""
    return [
        {"ip": ip, **profile}
        for ip, profile in _attacker_profiles.items()
        if profile.get("risk_score", 0) >= min_score
    ]
