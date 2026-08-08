#!/usr/bin/env python3
"""
AISS Remote Agent — runs on any monitored computer
Connects back to your AISS server over LAN / WAN / VPN / MAN

Usage:
    python aiss_agent.py --server ws://192.168.1.100:8000 --token YOUR_TOKEN
    python aiss_agent.py --server wss://your-domain.com --token YOUR_TOKEN

The agent:
  - Authenticates with AISS server using a token
  - Sends heartbeat every 5 seconds (CPU, RAM, disk, processes)
  - Monitors for threats locally and forwards them to AISS
  - Receives commands from AISS server
  - Works on Windows, Linux, macOS
"""
import asyncio
import json
import os
import platform
import socket
import sys
import time
import uuid
import argparse
import subprocess
import signal
from pathlib import Path
from datetime import datetime, timezone

VERSION = "2.0.0"

# ── Colours ───────────────────────────────────────────────────────────
IS_WIN = platform.system() == "Windows"
if IS_WIN:
    try:
        import ctypes
        ctypes.windll.kernel32.SetConsoleMode(ctypes.windll.kernel32.GetStdHandle(-11), 7)
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

def c(t, code): return f"\033[{code}m{t}\033[0m"
def ok(m):   print(c(f"  ✔  {m}", "92"))
def info(m): print(c(f"  →  {m}", "96"))
def warn(m): print(c(f"  ⚠  {m}", "93"))
def err(m):  print(c(f"  ✘  {m}", "91"))


# ── Bootstrap — ensure websockets is installed ────────────────────────
def _ensure_websockets():
    try:
        import websockets
        return True
    except ImportError:
        info("Installing websockets ...")
        subprocess.run([sys.executable, "-m", "pip", "install", "websockets",
                       "psutil", "--quiet"], check=False)
        return True


# ── System info ────────────────────────────────────────────────────────
def _get_local_ips() -> list:
    ips = []
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ips.append(s.getsockname()[0])
        s.close()
    except Exception:
        pass
    try:
        ips.extend(socket.gethostbyname_ex(socket.gethostname())[2])
    except Exception:
        pass
    return list(set(ips))


def _get_system_info() -> dict:
    return {
        "id":          _load_or_create_agent_id(),
        "hostname":    socket.gethostname(),
        "os_name":     platform.system(),
        "os_version":  platform.version(),
        "python_ver":  platform.python_version(),
        "aiss_ver":    VERSION,
        "local_ips":   _get_local_ips(),
        "capabilities":["process_monitor", "network_monitor",
                        "file_monitor", "metrics"],
    }


def _load_or_create_agent_id() -> str:
    id_file = Path(os.path.expanduser("~/.aiss_agent_id"))
    if id_file.exists():
        return id_file.read_text().strip()
    agent_id = str(uuid.uuid4())
    id_file.write_text(agent_id)
    return agent_id


# ── Metrics collection ─────────────────────────────────────────────────
def _collect_metrics() -> dict:
    metrics = {
        "cpu_percent":   0.0,
        "ram_percent":   0.0,
        "ram_used_mb":   0,
        "disk_percent":  0.0,
        "process_count": 0,
        "timestamp":     datetime.now(timezone.utc).isoformat(),
    }
    try:
        import psutil
        metrics["cpu_percent"]   = psutil.cpu_percent(interval=0)
        vm = psutil.virtual_memory()
        metrics["ram_percent"]   = vm.percent
        metrics["ram_used_mb"]   = vm.used // 1024 // 1024
        metrics["disk_percent"]  = psutil.disk_usage("/").percent
        metrics["process_count"] = len(psutil.pids())
    except ImportError:
        pass
    return metrics


# ── Threat detection (lightweight — no full AISS stack) ───────────────
def _scan_for_threats() -> list:
    """Lightweight threat scan for remote agents."""
    threats = []
    try:
        import psutil

        # Check for suspicious processes
        SUSPICIOUS = {"xmrig", "minerd", "mimikatz", "njrat", "meterpreter",
                      "darkcomet", "nanocore", "remcos"}
        for proc in psutil.process_iter(attrs=["pid", "name", "cpu_percent"]):
            try:
                name = proc.info["name"].lower()
                if any(s in name for s in SUSPICIOUS):
                    threats.append({
                        "type":        "trojan",
                        "severity":    "critical",
                        "description": f"Suspicious process detected: {name}",
                        "metadata":    {"pid": proc.info["pid"], "process": name},
                    })

                # CPU spike detection
                cpu = proc.info.get("cpu_percent", 0) or 0
                if cpu > 85.0:
                    threats.append({
                        "type":        "cryptominer",
                        "severity":    "high",
                        "description": f"High CPU process: {name} ({cpu:.0f}%)",
                        "metadata":    {"pid": proc.info["pid"], "cpu": cpu},
                    })
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass

    except ImportError:
        pass
    return threats


# ── Main agent loop ────────────────────────────────────────────────────
class AissAgent:
    def __init__(self, server_url: str, token: str, heartbeat: int = 5):
        self.server_url  = server_url
        self.token       = token
        self.heartbeat   = heartbeat
        self.agent_id    = None
        self._running    = True
        self._sys_info   = _get_system_info()
        self.agent_id    = self._sys_info["id"]

    async def run(self):
        info(f"Connecting to AISS server: {self.server_url}")
        import websockets

        while self._running:
            try:
                async with websockets.connect(
                    f"{self.server_url}/ws/agent",
                    ping_interval=20,
                    ping_timeout=30,
                    open_timeout=15,
                ) as ws:
                    ok(f"Connected to AISS server")

                    # Authenticate
                    await ws.send(json.dumps({
                        "action": "auth",
                        "token":  self.token,
                        "info":   self._sys_info,
                    }))

                    raw  = await ws.recv()
                    resp = json.loads(raw)
                    if "error" in resp:
                        err(f"Authentication failed: {resp['error']}")
                        return

                    self.agent_id = resp.get("agent_id", self.agent_id)
                    ok(f"Authenticated. Agent ID: {self.agent_id[:8]}...")
                    ok(f"Now monitoring: {socket.gethostname()}")
                    info(f"Sending heartbeat every {self.heartbeat}s")
                    print()

                    # Message loop
                    last_threat_scan = 0
                    async def _send_heartbeats():
                        nonlocal last_threat_scan
                        while self._running:
                            metrics = _collect_metrics()
                            await ws.send(json.dumps({
                                "action":  "heartbeat",
                                "metrics": metrics,
                            }))

                            # Threat scan every 30s
                            if time.time() - last_threat_scan > 30:
                                threats = _scan_for_threats()
                                for t in threats:
                                    await ws.send(json.dumps({
                                        "action": "threat",
                                        "threat": t,
                                    }))
                                last_threat_scan = time.time()

                            await asyncio.sleep(self.heartbeat)

                    async def _recv_commands():
                        async for raw in ws:
                            try:
                                msg = json.loads(raw)
                                await self._handle_command(ws, msg)
                            except Exception:
                                pass

                    await asyncio.gather(
                        _send_heartbeats(),
                        _recv_commands(),
                        return_exceptions=True,
                    )

            except Exception as e:
                warn(f"Connection lost: {e}")
                info("Reconnecting in 10 seconds ...")
                await asyncio.sleep(10)

    async def _handle_command(self, ws, msg: dict):
        cmd = msg.get("command", "")
        if cmd == "ping":
            await ws.send(json.dumps({"action": "pong", "ts": time.time()}))
        elif cmd == "get_processes":
            procs = []
            try:
                import psutil
                for p in psutil.process_iter(attrs=["pid", "name", "cpu_percent", "status"]):
                    try:
                        procs.append(p.info)
                    except Exception:
                        pass
            except ImportError:
                pass
            await ws.send(json.dumps({"action": "processes", "data": procs[:50]}))
        elif cmd == "get_connections":
            conns = []
            try:
                import psutil
                for c in psutil.net_connections(kind="tcp"):
                    if c.raddr:
                        conns.append({
                            "local":  f"{c.laddr.ip}:{c.laddr.port}" if c.laddr else "",
                            "remote": f"{c.raddr.ip}:{c.raddr.port}",
                            "status": c.status,
                            "pid":    c.pid,
                        })
            except ImportError:
                pass
            await ws.send(json.dumps({"action": "connections", "data": conns[:50]}))

    def stop(self):
        self._running = False


def main():
    print()
    print(c("  ╔══════════════════════════════════════════╗", "96;1"))
    print(c("  ║  AISS Remote Agent v2.0.0               ║", "96;1"))
    print(c("  ║  Connect this machine to your AISS server║", "96"))
    print(c("  ╚══════════════════════════════════════════╝", "96;1"))
    print()

    parser = argparse.ArgumentParser(description="AISS Remote Agent")
    parser.add_argument("--server",     required=True,
                        help="AISS server WebSocket URL (e.g. ws://192.168.1.100:8000)")
    parser.add_argument("--token",      required=True,
                        help="Agent authentication token from AISS server")
    parser.add_argument("--heartbeat",  type=int, default=5,
                        help="Heartbeat interval in seconds (default: 5)")
    args = parser.parse_args()

    _ensure_websockets()
    agent = AissAgent(args.server, args.token, args.heartbeat)

    # Graceful shutdown
    def _sigint(*_):
        agent.stop()
        print(f"\n  {c('Agent stopped.', '93')}\n")
        sys.exit(0)

    signal.signal(signal.SIGINT, _sigint)
    if hasattr(signal, "SIGTERM"):
        signal.signal(signal.SIGTERM, _sigint)

    info(f"Hostname: {socket.gethostname()}")
    info(f"Local IPs: {', '.join(_get_local_ips())}")
    info(f"OS: {platform.system()} {platform.version()[:40]}")
    print()

    asyncio.run(agent.run())


if __name__ == "__main__":
    main()
