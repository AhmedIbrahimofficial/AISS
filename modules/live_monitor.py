"""
AISS Live Monitor (UPGRADED)
─────────────────────────────
Feature 1 : Startup proof box  — updates every 5s with threat count + uptime (HH:MM:SS)
Feature 2 : Live threat feed   — colored terminal line per threat/resolve
Feature 3 : External connection scanner — psutil-based, protocol detection, bandwidth per process
Feature 4 : System health metrics — every 30s: CPU, RAM, NET, THREATS, uptime
Feature 5 : Threat rate indicator — threats/hour calculation
"""

import asyncio
import collections
import ipaddress
import os
import sys
import time
from datetime import datetime, timedelta
from typing import Optional

try:
    import psutil
    _PSUTIL = True
except ImportError:
    _PSUTIL = False

from utils.logger import setup_logger

logger = setup_logger("live_monitor")

# ── ANSI colours ──────────────────────────────────────────────────────
R   = "\033[91m"   # red
Y   = "\033[93m"   # yellow
C   = "\033[96m"   # cyan
G   = "\033[92m"   # green
W   = "\033[97m"   # white
DIM = "\033[2m"
B   = "\033[94m"   # blue
RST = "\033[0m"

# ── Suspicious ports ──────────────────────────────────────────────────
SUSPICIOUS_PORTS = {4444, 1337, 31337, 9999, 6666, 5555, 12345, 31338, 6667}

# ── Suspicious IP prefixes ────────────────────────────────────────────
SUSPICIOUS_IP_PREFIXES = (
    "185.220.",   # Tor exit nodes
    "185.130.",
    "198.96.",
    "192.42.",
    "199.87.",
)

# Ports that belong to AISS itself
AISS_PORTS = {8000, 2222, 2121, 2323}

# ── Startup time ──────────────────────────────────────────────────────
_start_time: float = time.time()

# ── Connection tracking ───────────────────────────────────────────────
_seen_conns: set[tuple] = set()

# ── Threat rate tracking: [timestamp of each threat] ─────────────────
_threat_timestamps: collections.deque = collections.deque(maxlen=1000)

# ── Network I/O baseline for bandwidth calculation ───────────────────
_net_io_baseline: Optional[dict] = None
_last_net_sample: float = 0.0

# ── Per-process bandwidth tracker: {pid → (bytes_sent, bytes_recv, timestamp)} ──
_proc_bandwidth: dict[int, tuple] = {}

# ── System health print interval ─────────────────────────────────────
_last_health_print: float = 0.0
HEALTH_INTERVAL_SECS = 30


# ══════════════════════════════════════════════════════════════════════
# Uptime formatting
# ══════════════════════════════════════════════════════════════════════

def _format_uptime(seconds: float) -> str:
    """Format uptime as HH:MM:SS."""
    s = int(seconds)
    h, rem = divmod(s, 3600)
    m, sec = divmod(rem, 60)
    return f"{h:02d}:{m:02d}:{sec:02d}"


# ══════════════════════════════════════════════════════════════════════
# FEATURE 1 — PROOF BOX (updates every 5 seconds)
# ══════════════════════════════════════════════════════════════════════

def print_startup_box(threat_engine=None) -> None:
    """Print the AISS-is-running proof box to stdout."""
    pid       = os.getpid()
    host      = "0.0.0.0:8000"
    uptime    = _format_uptime(time.time() - _start_time)
    threat_ct = len(threat_engine.active_threats) if threat_engine else 0

    active_ct = 0
    if threat_engine:
        from models.threat import ThreatStatus
        active_ct = sum(1 for t in threat_engine.active_threats.values()
                        if t.status == ThreatStatus.ACTIVE)

    box = f"""
{W}┌─────────────────────────────────────────────────────┐
│{G}           AISS IS RUNNING — SYSTEM ACTIVE           {W}│
│                                                     │
│  PID      : {G}{pid:<10}{W}  (actual process ID)       │
│  HOST     : {G}{host:<20}{W}                   │
│  UPTIME   : {G}{uptime:<10}{W}  HH:MM:SS                  │
│  STATUS   : {G}MONITORING ACTIVE{W}                       │
│  THREATS  : {Y}{threat_ct:<5}{W} total  │  {R}{active_ct:<5}{W} active          │
└─────────────────────────────────────────────────────┘{RST}
"""
    print(box, flush=True)


async def startup_box_loop(threat_engine) -> None:
    """
    Background task: re-prints the startup box every 5 seconds
    to keep threat count and uptime current.
    """
    # Initial print after warmup
    await asyncio.sleep(2)
    print_startup_box(threat_engine)

    while True:
        await asyncio.sleep(5)
        try:
            print_startup_box(threat_engine)
        except Exception as e:
            logger.debug(f"Startup box update error: {e}")


# ══════════════════════════════════════════════════════════════════════
# FEATURE 2 — LIVE THREAT FEED
# ══════════════════════════════════════════════════════════════════════

_SEVERITY_FMT = {
    "critical": f"{R}🔴 CRITICAL{RST}",
    "high":     f"{Y}⚠  HIGH    {RST}",
    "medium":   f"{C}🟡 MEDIUM  {RST}",
    "low":      f"{G}🔵 LOW     {RST}",
    "resolved": f"{G}✅ RESOLVED{RST}",
}


def live_threat_line(threat_dict: dict) -> None:
    """Print one [AISS LIVE] line for a detected threat."""
    now      = datetime.now().strftime("%H:%M:%S")
    severity = threat_dict.get("severity", "low").lower()
    sev_fmt  = _SEVERITY_FMT.get(severity, severity.upper())
    t_type   = threat_dict.get("type",     "Unknown")[:18]
    source   = threat_dict.get("source",   "—")
    meta     = threat_dict.get("metadata", {}) or {}
    tid      = threat_dict.get("id",       "")[:8]

    # Build context suffix from metadata
    parts = []
    if meta.get("remote_ip"):
        parts.append(f"src: {meta['remote_ip']}")
    elif source and source not in ("—", "", "local"):
        parts.append(f"src: {source}")
    if meta.get("remote_port"):
        parts.append(f"port: {meta['remote_port']}")
    if meta.get("pid"):
        parts.append(f"pid: {meta['pid']}")
    if meta.get("process"):
        parts.append(f"process: {meta['process']}")
    if meta.get("path"):
        parts.append(f"file: {meta['path'][:40]}")
    if meta.get("domain"):
        parts.append(f"domain: {meta['domain']}")
    if meta.get("attempts") or meta.get("attempt_count"):
        parts.append(f"attempts: {meta.get('attempts') or meta.get('attempt_count')}")
    if not parts:
        parts.append(f"id: {tid}")

    suffix = " | ".join(parts)
    print(
        f"{DIM}[AISS LIVE]{RST} {W}{now}{RST} | {sev_fmt} | "
        f"{W}{t_type:<18}{RST} | {suffix}",
        flush=True,
    )

    # Track threat timestamp for rate calculation
    _threat_timestamps.append(time.time())


def live_resolve_line(threat_id: str, t_type: str) -> None:
    """Print a [AISS LIVE] RESOLVED line."""
    now = datetime.now().strftime("%H:%M:%S")
    print(
        f"{DIM}[AISS LIVE]{RST} {W}{now}{RST} | {_SEVERITY_FMT['resolved']} "
        f"| {W}{t_type:<18}{RST} | threat_id: {threat_id[:8]}",
        flush=True,
    )


def _get_threat_rate() -> float:
    """Calculate threats per hour based on last hour of data."""
    now    = time.time()
    cutoff = now - 3600
    recent = [t for t in _threat_timestamps if t > cutoff]
    return len(recent)


# ══════════════════════════════════════════════════════════════════════
# FEATURE 4 — SYSTEM HEALTH METRICS
# ══════════════════════════════════════════════════════════════════════

def _get_net_speed() -> tuple[float, float]:
    """
    Calculate network speed (MB/s) since last call.
    Returns (bytes_sent_per_sec, bytes_recv_per_sec).
    """
    global _net_io_baseline, _last_net_sample
    if not _PSUTIL:
        return 0.0, 0.0

    try:
        now  = time.time()
        io   = psutil.net_io_counters()
        if _net_io_baseline is None or now - _last_net_sample < 1:
            _net_io_baseline = {"sent": io.bytes_sent, "recv": io.bytes_recv}
            _last_net_sample = now
            return 0.0, 0.0

        elapsed = now - _last_net_sample
        up_mb   = (io.bytes_sent - _net_io_baseline["sent"]) / elapsed / 1024 / 1024
        down_mb = (io.bytes_recv - _net_io_baseline["recv"]) / elapsed / 1024 / 1024

        _net_io_baseline = {"sent": io.bytes_sent, "recv": io.bytes_recv}
        _last_net_sample = now
        return max(0.0, up_mb), max(0.0, down_mb)
    except Exception:
        return 0.0, 0.0


def print_system_health(threat_engine=None) -> None:
    """
    Print one system health line to terminal.
    Format: [AISS SYS] HH:MM:SS | CPU: X% | RAM: X.XGB/XGB | NET: ↑X.X MB/s ↓X.X MB/s | THREATS: X active
    """
    if not _PSUTIL:
        return

    try:
        now     = datetime.now().strftime("%H:%M:%S")
        cpu_pct = psutil.cpu_percent(interval=None)
        vm      = psutil.virtual_memory()
        ram_used_gb  = vm.used / 1024 / 1024 / 1024
        ram_total_gb = vm.total / 1024 / 1024 / 1024
        up_mb, down_mb = _get_net_speed()

        threat_ct = 0
        if threat_engine:
            from models.threat import ThreatStatus
            threat_ct = sum(1 for t in threat_engine.active_threats.values()
                            if t.status == ThreatStatus.ACTIVE)

        threat_rate = _get_threat_rate()
        uptime      = _format_uptime(time.time() - _start_time)

        print(
            f"{DIM}[AISS SYS ]{RST} {W}{now}{RST} | "
            f"CPU: {Y}{cpu_pct:.0f}%{RST} | "
            f"RAM: {C}{ram_used_gb:.1f}GB{RST}/{ram_total_gb:.0f}GB | "
            f"NET: {G}↑{up_mb:.1f}MB/s{RST} {C}↓{down_mb:.1f}MB/s{RST} | "
            f"THREATS: {R if threat_ct > 0 else G}{threat_ct} active{RST} | "
            f"RATE: {Y}{threat_rate:.0f}/hr{RST} | "
            f"UP: {DIM}{uptime}{RST}",
            flush=True,
        )
    except Exception as e:
        logger.debug(f"System health print error: {e}")


# ══════════════════════════════════════════════════════════════════════
# FEATURE 3+5 — CONNECTION SCANNER + BANDWIDTH
# ══════════════════════════════════════════════════════════════════════

def _is_private(ip: str) -> bool:
    """Return True if IP is private/local."""
    try:
        addr = ipaddress.ip_address(ip)
        return (
            addr.is_private
            or addr.is_loopback
            or addr.is_unspecified
            or addr.is_link_local
            or addr.is_multicast
        )
    except ValueError:
        return True


def _detect_protocol(rport: int, lport: int) -> str:
    """
    Detect protocol from port numbers.
    Returns: HTTP, HTTPS, SSH, FTP, DNS, SMTP, UNKNOWN
    """
    port_protocols = {
        80: "HTTP", 8080: "HTTP", 8000: "HTTP", 8008: "HTTP",
        443: "HTTPS", 8443: "HTTPS",
        22: "SSH", 2222: "SSH",
        21: "FTP", 2121: "FTP",
        53: "DNS",
        25: "SMTP", 587: "SMTP", 465: "SMTP",
        110: "POP3", 143: "IMAP",
        3306: "MySQL", 5432: "PostgreSQL", 27017: "MongoDB",
        6379: "Redis", 5672: "AMQP",
        9200: "Elasticsearch", 9300: "Elasticsearch",
    }
    return (
        port_protocols.get(rport)
        or port_protocols.get(lport)
        or ("SUSPICIOUS" if rport in SUSPICIOUS_PORTS or lport in SUSPICIOUS_PORTS else "UNKNOWN")
    )


def _get_proc_bandwidth(pid: int) -> tuple[float, float]:
    """
    Get per-process bandwidth (MB/s sent, MB/s recv) since last sample.
    Returns (up_mb_s, down_mb_s).
    """
    if not _PSUTIL or not pid:
        return 0.0, 0.0
    try:
        proc = psutil.Process(pid)
        try:
            io = proc.io_counters()
        except AttributeError:
            return 0.0, 0.0

        now   = time.time()
        prev  = _proc_bandwidth.get(pid)
        bytes_sent = getattr(io, "write_bytes", 0)
        bytes_recv = getattr(io, "read_bytes", 0)

        if prev:
            prev_sent, prev_recv, prev_time = prev
            elapsed  = max(now - prev_time, 0.1)
            up_mb    = (bytes_sent - prev_sent) / elapsed / 1024 / 1024
            down_mb  = (bytes_recv - prev_recv) / elapsed / 1024 / 1024
        else:
            up_mb = down_mb = 0.0

        _proc_bandwidth[pid] = (bytes_sent, bytes_recv, now)
        return max(0.0, up_mb), max(0.0, down_mb)
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        return 0.0, 0.0


def _assess_connection(conn_info: dict) -> tuple[str, str]:
    """
    Assess a connection.
    Returns (verdict, reason): 'clean' | 'suspicious' | 'malicious'
    """
    rip   = conn_info.get("remote_ip", "")
    rport = int(conn_info.get("remote_port", 0))
    proc  = conn_info.get("process", "").lower()

    reasons = []

    if rport in SUSPICIOUS_PORTS:
        reasons.append(f"port {rport} is a known malware/RAT port")

    if any(rip.startswith(pfx) for pfx in SUSPICIOUS_IP_PREFIXES):
        reasons.append(f"IP {rip} matches known bad prefix")

    if not proc or proc in ("", "unknown", "system idle process"):
        reasons.append("no identifiable process name")

    suspicious_proc_keywords = [
        "xmrig", "minerd", "njrat", "darkcomet", "mirai",
        "revshell", "netcat", "ncat", "socat", "meterpreter",
    ]
    if any(kw in proc for kw in suspicious_proc_keywords):
        reasons.append(f"process '{proc}' matches malware signature")

    if not reasons:
        return "clean", ""

    verdict = "malicious" if len(reasons) >= 2 else "suspicious"
    return verdict, "; ".join(reasons)


async def _deep_inspect_and_block(
    conn_info: dict, verdict: str, reason: str, engine
) -> None:
    """Deep inspect + auto-respond to a suspicious/malicious connection."""
    from models.threat import Threat, ThreatType, ThreatSeverity

    rip      = conn_info.get("remote_ip", "")
    rport    = conn_info.get("remote_port", "")
    proc     = conn_info.get("process", "unknown")
    pid      = conn_info.get("pid")
    protocol = conn_info.get("protocol", "UNKNOWN")
    now      = datetime.now().strftime("%H:%M:%S")

    severity = ThreatSeverity.CRITICAL if verdict == "malicious" else ThreatSeverity.HIGH

    threat = Threat(
        type=ThreatType.C2_TRAFFIC,
        description=(
            f"{'Malicious' if verdict == 'malicious' else 'Suspicious'} connection "
            f"[{protocol}] — {proc} → {rip}:{rport} | {reason}"
        ),
        severity=severity,
        source=rip,
        module="LiveMonitor",
        metadata={**conn_info, "reason": reason, "verdict": verdict},
    )
    await engine.register_threat(threat)

    color = R if verdict == "malicious" else Y
    label = "🔴 MALICIOUS " if verdict == "malicious" else "⚠  SUSPICIOUS"
    print(
        f"{DIM}[AISS NET ]{RST} {W}{now}{RST} | {color}{label}{RST} "
        f"| PID: {pid} | Process: {proc:<20} | [{protocol}] {rip}:{rport}",
        flush=True,
    )
    print(
        f"{DIM}[AISS NET ]{RST} {Y}   ↳ Reason : {reason}{RST}",
        flush=True,
    )

    # Auto-respond: kill malicious process
    if verdict == "malicious" and _PSUTIL and pid:
        try:
            p = psutil.Process(int(pid))
            children = p.children(recursive=True)
            for child in children:
                try:
                    child.kill()
                except Exception:
                    pass
            p.terminate()
            print(
                f"{DIM}[AISS NET ]{RST} {R}   ↳ ACTION : Process {pid} ({proc}) + "
                f"{len(children)} children terminated.{RST}",
                flush=True,
            )
            logger.warning(f"Terminated malicious process tree PID={pid} ({proc})")
        except (psutil.NoSuchProcess, psutil.AccessDenied, ValueError) as e:
            print(
                f"{DIM}[AISS NET ]{RST} {Y}   ↳ ACTION : Could not terminate PID {pid}: {e}{RST}",
                flush=True,
            )


async def connection_scanner_loop(engine) -> None:
    """
    Async background loop — runs every 10 seconds.
    Scans all ESTABLISHED TCP connections via psutil.
    Includes protocol detection, bandwidth monitoring.
    Prints system health every 30 seconds.
    """
    global _last_health_print

    if not _PSUTIL:
        logger.warning("psutil not installed — external connection scanner disabled.")
        return

    logger.info("🔌 External connection scanner started (interval: 10s)")

    while True:
        try:
            await asyncio.sleep(10)
            now_str = datetime.now().strftime("%H:%M:%S")
            now     = time.time()

            # ── System health every 30 seconds ─────────────────────────
            if now - _last_health_print >= HEALTH_INTERVAL_SECS:
                print_system_health(engine)
                _last_health_print = now

            conns = psutil.net_connections(kind="tcp")
            for c in conns:
                if c.status != "ESTABLISHED":
                    continue
                if not c.raddr:
                    continue

                rip   = c.raddr.ip
                rport = c.raddr.port
                lport = c.laddr.port if c.laddr else 0
                pid   = c.pid

                if _is_private(rip):
                    continue
                if lport in AISS_PORTS or rport in AISS_PORTS:
                    continue

                conn_key = (pid, lport, rip, rport)
                if conn_key in _seen_conns:
                    continue
                _seen_conns.add(conn_key)

                # Resolve process name
                proc_name = "unknown"
                try:
                    if pid:
                        proc_name = psutil.Process(pid).name()
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass

                # Protocol detection
                protocol = _detect_protocol(rport, lport)

                # Per-process bandwidth
                up_mb, down_mb = _get_proc_bandwidth(pid or 0)
                bw_str = f"↑{up_mb:.2f}MB/s ↓{down_mb:.2f}MB/s" if (up_mb or down_mb) else ""

                conn_info = {
                    "pid":         pid,
                    "process":     proc_name,
                    "local_port":  lport,
                    "remote_ip":   rip,
                    "remote_port": rport,
                    "protocol":    protocol,
                }

                verdict, reason = _assess_connection(conn_info)

                if verdict == "clean":
                    bw_part = f" | {DIM}{bw_str}{RST}" if bw_str else ""
                    print(
                        f"{DIM}[AISS NET ]{RST} {W}{now_str}{RST} | {G}NEW CONNECTION{RST}"
                        f"| PID: {pid} | Process: {proc_name:<20} "
                        f"| [{protocol}] {rip}:{rport}{bw_part}",
                        flush=True,
                    )
                else:
                    await _deep_inspect_and_block(conn_info, verdict, reason, engine)

        except Exception as e:
            logger.debug(f"Connection scanner iteration error: {e}")
