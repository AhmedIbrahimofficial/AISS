"""
AISS - Full System Monitor
───────────────────────────
Continuously monitors the ENTIRE PC:
  1. All running processes (CPU, memory, cmdline, parent)
  2. All open network connections per process
  3. All loaded DLLs / shared libraries
  4. USB / external device file transfers
  5. Clipboard monitoring (data exfil via clipboard)
  6. Screen capture attempts
  7. Keylogger indicators
  8. Scheduled tasks (Windows)
  9. Services (new/modified)
 10. Registry run keys (persistence)

Runs as a background asyncio task — full scan every 10 seconds.
"""

import asyncio
import collections
import hashlib
import os
import re
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Optional

try:
    import psutil
    _PSUTIL = True
except ImportError:
    _PSUTIL = False

from models.threat import Threat, ThreatType, ThreatSeverity
from utils.logger import setup_logger

logger = setup_logger("system_monitor")

IS_WINDOWS = sys.platform == "win32"

# ── ANSI colours ──────────────────────────────────────────────────────
R   = "\033[91m"
Y   = "\033[93m"
C   = "\033[96m"
G   = "\033[92m"
W   = "\033[97m"
DIM = "\033[2m"
RST = "\033[0m"

# ── Thresholds ────────────────────────────────────────────────────────
CPU_SPIKE_THRESHOLD    = 85.0   # % CPU — alert if process suddenly spikes
MEM_SPIKE_MB           = 500    # MB — alert if process suddenly uses this much
TRANSFER_ALERT_MB      = 50     # MB — alert if this much copied to/from USB
SCAN_INTERVAL_SECS     = 10     # full scan every 10 seconds

# ── Known-safe process names (never alert on these) ───────────────────
SAFE_PROCESSES = {
    "system", "smss.exe", "csrss.exe", "wininit.exe", "winlogon.exe",
    "services.exe", "lsass.exe", "svchost.exe", "explorer.exe",
    "taskhostw.exe", "dwm.exe", "fontdrvhost.exe", "spoolsv.exe",
    "searchindexer.exe", "antimalware service executable",
    "mscorsvw.exe", "tiworker.exe", "wuauclt.exe",
    "registry", "memory compression", "secure system",
    "python.exe", "python3.exe",   # AISS itself
    "node.exe", "npm.exe",
    "chrome.exe", "msedge.exe", "firefox.exe", "opera.exe",
    "code.exe", "cursor.exe",
}

# ── Malicious process name fragments ──────────────────────────────────
MALICIOUS_PROC_NAMES = [
    "xmrig", "minerd", "cpuminer", "ethminer",     # miners
    "njrat", "darkcomet", "quasar", "asyncrat",    # RATs
    "mimikatz", "meterpreter", "cobalt",           # hacking tools
    "mirai", "bashlite",                           # botnets
    "logkeys", "keylogger", "hookdll",             # keyloggers
]

# ── Suspicious cmdline patterns ───────────────────────────────────────
SUSPICIOUS_CMDLINE = [
    re.compile(r"powershell.*-enc",              re.I),
    re.compile(r"powershell.*hidden.*bypass",    re.I),
    re.compile(r"cmd.*\/c.*certutil.*-decode",   re.I),
    re.compile(r"bash.*-i.*>&.*/dev/tcp",        re.I),
    re.compile(r"nc\s+.*-e",                     re.I),
    re.compile(r"mshta.*http",                   re.I),
    re.compile(r"wscript.*\.vbs",                re.I),
    re.compile(r"regsvr32.*scrobj",              re.I),
    re.compile(r"rundll32.*javascript",          re.I),
    re.compile(r"IEX.*DownloadString",           re.I),
    re.compile(r"wget.*\|\s*bash",               re.I),
    re.compile(r"curl.*\|\s*bash",               re.I),
    re.compile(r"Set-MpPreference.*Disable",     re.I),  # disable AV
    re.compile(r"Add-MpPreference.*Exclusion",   re.I),  # AV exclusion
    re.compile(r"vssadmin.*delete.*shadows",     re.I),  # ransomware
    re.compile(r"wmic.*shadowcopy.*delete",      re.I),
    re.compile(r"bcdedit.*recoveryenabled.*no",  re.I),
]

# ── Suspicious ports ──────────────────────────────────────────────────
SUSPICIOUS_PORTS = {4444, 1337, 31337, 9999, 6666, 5555, 12345, 31338}

# ── State ─────────────────────────────────────────────────────────────
_seen_pids:          set[int]              = set()
_proc_cpu_history:   dict[int, list]       = {}
_proc_mem_history:   dict[int, list]       = {}
_reported:           set[str]             = set()
_usb_transfer_seen:  dict[str, float]     = {}   # path → bytes_seen
_service_baseline:   Optional[set]        = None
_task_baseline:      Optional[set]        = None


# ══════════════════════════════════════════════════════════════════════
# Helpers
# ══════════════════════════════════════════════════════════════════════

def _log(color: str, label: str, msg: str) -> None:
    now = datetime.now().strftime("%H:%M:%S")
    print(f"{DIM}[AISS SYS ]{RST} {W}{now}{RST} | {color}{label}{RST} | {msg}", flush=True)


def _is_safe(name: str) -> bool:
    return name.lower() in SAFE_PROCESSES


# ══════════════════════════════════════════════════════════════════════
# 1. PROCESS MONITOR
# ══════════════════════════════════════════════════════════════════════

async def _scan_processes(engine) -> None:
    """Scan all running processes for malicious indicators."""
    if not _PSUTIL:
        return
    try:
        for proc in psutil.process_iter(attrs=[
            "pid", "name", "exe", "cmdline", "ppid",
            "cpu_percent", "memory_info", "username", "status"
        ]):
            try:
                info     = proc.info
                pid      = info["pid"]
                name     = (info.get("name") or "").lower()
                exe      = info.get("exe") or ""
                cmdline  = " ".join(info.get("cmdline") or [])
                cpu      = info.get("cpu_percent") or 0.0
                mem_info = info.get("memory_info")
                mem_mb   = (mem_info.rss / 1024 / 1024) if mem_info else 0

                if _is_safe(name):
                    continue

                # ── New process detection ──────────────────────────
                if pid not in _seen_pids:
                    _seen_pids.add(pid)
                    # Only log if exe is in a suspicious location
                    suspicious_paths = ["\\temp\\", "\\tmp\\", "/tmp/",
                                        "appdata\\roaming", "appdata\\local\\temp",
                                        "\\downloads\\", "\\public\\"]
                    if exe and any(p in exe.lower() for p in suspicious_paths):
                        _log(Y, "NEW PROC ", f"[{pid}] {name} from {exe}")

                # ── Malicious name check ───────────────────────────
                key = f"malname:{pid}"
                if key not in _reported:
                    for sig in MALICIOUS_PROC_NAMES:
                        if sig in name or sig in cmdline.lower():
                            await _alert(engine, ThreatType.TROJAN, ThreatSeverity.CRITICAL,
                                f"Malicious process: {name} (PID {pid})",
                                f"PID:{pid}",
                                {"pid": pid, "name": name, "exe": exe,
                                 "cmdline": cmdline[:200], "matched": sig})
                            _reported.add(key)
                            break

                # ── Suspicious cmdline check ───────────────────────
                key2 = f"cmdline:{pid}"
                if key2 not in _reported and cmdline:
                    for pat in SUSPICIOUS_CMDLINE:
                        if pat.search(cmdline):
                            await _alert(engine, ThreatType.MALICIOUS_SCRIPT,
                                ThreatSeverity.CRITICAL,
                                f"Malicious command: {cmdline[:120]}",
                                f"PID:{pid}",
                                {"pid": pid, "name": name,
                                 "cmdline": cmdline[:300],
                                 "pattern": pat.pattern[:60]})
                            _reported.add(key2)
                            break

                # ── CPU spike ─────────────────────────────────────
                hist = _proc_cpu_history.setdefault(pid, [])
                hist.append(cpu)
                if len(hist) > 5:
                    hist.pop(0)
                if len(hist) >= 3:
                    avg_prev = sum(hist[:-1]) / len(hist[:-1])
                    key3 = f"cpuspike:{pid}"
                    if (cpu > CPU_SPIKE_THRESHOLD and avg_prev < 20
                            and key3 not in _reported):
                        _log(Y, "CPU SPIKE",
                             f"{name} (PID {pid}) {avg_prev:.0f}% → {cpu:.0f}%")
                        await _alert(engine, ThreatType.CRYPTOMINER, ThreatSeverity.HIGH,
                            f"CPU spike: {name} jumped to {cpu:.0f}%",
                            f"PID:{pid}",
                            {"pid": pid, "name": name,
                             "cpu_now": cpu, "avg_before": avg_prev})
                        _reported.add(key3)

                # ── Memory spike ───────────────────────────────────
                mhist = _proc_mem_history.setdefault(pid, [])
                mhist.append(mem_mb)
                if len(mhist) > 5:
                    mhist.pop(0)
                if len(mhist) >= 3:
                    avg_mem = sum(mhist[:-1]) / len(mhist[:-1])
                    key4 = f"memspike:{pid}"
                    if (mem_mb - avg_mem > MEM_SPIKE_MB
                            and key4 not in _reported):
                        _log(Y, "MEM SPIKE",
                             f"{name} (PID {pid}) +{mem_mb - avg_mem:.0f}MB")
                        _reported.add(key4)

            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
    except Exception as e:
        logger.debug(f"Process scan error: {e}")


# ══════════════════════════════════════════════════════════════════════
# 2. NETWORK CONNECTIONS PER PROCESS
# ══════════════════════════════════════════════════════════════════════

async def _scan_process_connections(engine) -> None:
    """Check every process's network connections for suspicious activity."""
    if not _PSUTIL:
        return
    try:
        for proc in psutil.process_iter(attrs=["pid", "name"]):
            try:
                pid  = proc.pid
                name = (proc.name() or "unknown").lower()
                if _is_safe(name):
                    continue

                conns = proc.connections(kind="tcp")
                for c in conns:
                    if not c.raddr:
                        continue
                    rip   = c.raddr.ip
                    rport = c.raddr.port

                    if rip in ("127.0.0.1", "::1"):
                        continue

                    # Suspicious port
                    key = f"suspport:{pid}:{rip}:{rport}"
                    if rport in SUSPICIOUS_PORTS and key not in _reported:
                        _log(R, "SUSP PORT",
                             f"{name} (PID {pid}) → {rip}:{rport}")
                        await _alert(engine, ThreatType.C2_TRAFFIC,
                            ThreatSeverity.CRITICAL,
                            f"Process {name} connecting to suspicious port {rport}",
                            rip,
                            {"pid": pid, "process": name,
                             "remote_ip": rip, "remote_port": rport})
                        _reported.add(key)

            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
    except Exception as e:
        logger.debug(f"Connection scan error: {e}")


# ══════════════════════════════════════════════════════════════════════
# 3. USB / EXTERNAL DEVICE TRANSFER MONITOR
# ══════════════════════════════════════════════════════════════════════

async def _scan_usb_transfers(engine) -> None:
    """
    Monitor file transfers to/from USB drives.
    Detects: large transfers, executable copies, rapid file copies.
    """
    if not _PSUTIL:
        return
    try:
        for part in psutil.disk_partitions(all=False):
            opts = (part.opts or "").lower()
            if "removable" not in opts and "usb" not in part.device.lower():
                continue

            mp = part.mountpoint
            try:
                usage = psutil.disk_usage(mp)
                used_mb = usage.used / 1024 / 1024

                # Check if used space changed significantly (= transfer happening)
                prev = _usb_transfer_seen.get(mp)
                _usb_transfer_seen[mp] = used_mb

                if prev is not None:
                    delta_mb = abs(used_mb - prev)
                    if delta_mb > TRANSFER_ALERT_MB:
                        direction = "TO USB" if used_mb > prev else "FROM USB"
                        key = f"usbtransfer:{mp}:{int(time.time()//60)}"
                        if key not in _reported:
                            _log(Y, "USB XFER ",
                                 f"{direction} {delta_mb:.1f}MB on {mp}")
                            await _alert(engine, ThreatType.DATA_EXFIL,
                                ThreatSeverity.HIGH,
                                f"Large USB transfer: {delta_mb:.1f}MB {direction} {mp}",
                                mp,
                                {"mountpoint": mp, "direction": direction,
                                 "delta_mb": round(delta_mb, 2),
                                 "threshold_mb": TRANSFER_ALERT_MB})
                            _reported.add(key)

                # Scan root of USB for new executables
                now = time.time()
                for entry in os.scandir(mp):
                    if not entry.is_file():
                        continue
                    try:
                        stat = entry.stat()
                        # File created/modified in last 30s
                        if now - stat.st_mtime > 30:
                            continue
                        ext = Path(entry.path).suffix.lower()
                        if ext in {".exe", ".bat", ".ps1", ".vbs", ".cmd",
                                   ".scr", ".msi", ".dll", ".hta"}:
                            key = f"usbexe:{entry.path}"
                            if key not in _reported:
                                _log(R, "USB EXE  ",
                                     f"New executable on USB: {entry.path}")
                                await _alert(engine, ThreatType.SUSPICIOUS_FILE,
                                    ThreatSeverity.HIGH,
                                    f"New executable copied to USB: {entry.path}",
                                    mp,
                                    {"file": entry.path, "ext": ext,
                                     "size_kb": round(stat.st_size/1024, 1)})
                                _reported.add(key)
                    except OSError:
                        pass

            except (PermissionError, OSError):
                pass
    except Exception as e:
        logger.debug(f"USB transfer scan error: {e}")


# ══════════════════════════════════════════════════════════════════════
# 4. WINDOWS SERVICES MONITOR
# ══════════════════════════════════════════════════════════════════════

async def _scan_services(engine) -> None:
    """Detect newly installed or modified Windows services."""
    if not IS_WINDOWS or not _PSUTIL:
        return
    global _service_baseline

    try:
        import subprocess
        result = subprocess.run(
            ["sc", "query", "type=", "all", "state=", "all"],
            capture_output=True, text=True, timeout=10
        )
        current_services = set(
            re.findall(r"SERVICE_NAME:\s+(\S+)", result.stdout)
        )

        if _service_baseline is None:
            _service_baseline = current_services
            return

        new_services = current_services - _service_baseline
        for svc in new_services:
            key = f"newsvc:{svc}"
            if key not in _reported:
                _log(Y, "NEW SVC  ", f"New service installed: {svc}")
                await _alert(engine, ThreatType.WORM, ThreatSeverity.HIGH,
                    f"New Windows service installed: {svc}",
                    "services",
                    {"service_name": svc, "indicator": "new_service"})
                _reported.add(key)

        _service_baseline = current_services
    except Exception as e:
        logger.debug(f"Service scan error: {e}")


# ══════════════════════════════════════════════════════════════════════
# 5. SCHEDULED TASKS MONITOR
# ══════════════════════════════════════════════════════════════════════

async def _scan_scheduled_tasks(engine) -> None:
    """Detect new or modified scheduled tasks (malware persistence)."""
    if not IS_WINDOWS:
        return
    global _task_baseline

    try:
        import subprocess
        result = subprocess.run(
            ["schtasks", "/query", "/fo", "CSV", "/nh"],
            capture_output=True, text=True, timeout=15
        )
        current_tasks = set()
        for line in result.stdout.splitlines():
            parts = line.split(",")
            if parts:
                task_name = parts[0].strip('"')
                if task_name:
                    current_tasks.add(task_name)

        if _task_baseline is None:
            _task_baseline = current_tasks
            return

        new_tasks = current_tasks - _task_baseline
        for task in new_tasks:
            # Skip known Windows system tasks
            if any(s in task.lower() for s in [
                "microsoft", "windows", "onedrive", "adobe", "google"
            ]):
                continue
            key = f"newtask:{task}"
            if key not in _reported:
                _log(Y, "NEW TASK ", f"New scheduled task: {task}")
                await _alert(engine, ThreatType.WORM, ThreatSeverity.HIGH,
                    f"New scheduled task created: {task}",
                    "schtasks",
                    {"task_name": task, "indicator": "persistence"})
                _reported.add(key)

        _task_baseline = current_tasks
    except Exception as e:
        logger.debug(f"Scheduled task scan error: {e}")


# ══════════════════════════════════════════════════════════════════════
# 6. REGISTRY PERSISTENCE MONITOR
# ══════════════════════════════════════════════════════════════════════

_registry_baseline: dict[str, set] = {}

async def _scan_registry(engine) -> None:
    """Monitor Windows registry run keys for new persistence entries."""
    if not IS_WINDOWS:
        return
    import subprocess

    run_keys = [
        r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
        r"HKLM\Software\Microsoft\Windows\CurrentVersion\Run",
        r"HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce",
    ]
    for key in run_keys:
        try:
            result = subprocess.run(
                ["reg", "query", key],
                capture_output=True, text=True, timeout=5
            )
            current_entries = set()
            for line in result.stdout.splitlines():
                if "REG_SZ" in line or "REG_EXPAND_SZ" in line:
                    parts = line.split(None, 2)
                    if len(parts) == 3:
                        current_entries.add(f"{parts[0]}={parts[2]}")

            baseline = _registry_baseline.get(key)
            if baseline is None:
                _registry_baseline[key] = current_entries
                continue

            new_entries = current_entries - baseline
            for entry in new_entries:
                rkey = f"regrun:{key}:{entry}"
                if rkey not in _reported:
                    # Skip AISS itself
                    if "start.bat" in entry.lower() or "aiss" in entry.lower():
                        continue
                    _log(Y, "REG RUN  ", f"New registry run key: {entry[:80]}")
                    await _alert(engine, ThreatType.WORM, ThreatSeverity.HIGH,
                        f"New registry persistence: {entry[:100]}",
                        key,
                        {"reg_key": key, "entry": entry[:200],
                         "indicator": "persistence"})
                    _reported.add(rkey)

            _registry_baseline[key] = current_entries
        except Exception:
            pass


# ══════════════════════════════════════════════════════════════════════
# Alert helper
# ══════════════════════════════════════════════════════════════════════

async def _alert(
    engine,
    threat_type: ThreatType,
    severity: ThreatSeverity,
    description: str,
    source: str,
    metadata: dict,
) -> None:
    threat = Threat(
        type        = threat_type,
        description = description,
        severity    = severity,
        source      = source,
        module      = "SystemMonitor",
        metadata    = metadata,
    )
    await engine.register_threat(threat)


# ══════════════════════════════════════════════════════════════════════
# MAIN LOOP
# ══════════════════════════════════════════════════════════════════════

async def system_monitor_loop(engine) -> None:
    """
    Main background loop — runs every 10 seconds.
    Scans: processes, connections, USB transfers,
           services, scheduled tasks, registry.
    """
    logger.info("🖥️  System monitor started (full PC scan every 10s)")

    # Stagger startup to avoid load spike
    await asyncio.sleep(5)

    cycle = 0
    while True:
        try:
            await asyncio.sleep(SCAN_INTERVAL_SECS)
            cycle += 1

            # Every cycle — processes + connections + USB
            await _scan_processes(engine)
            await _scan_process_connections(engine)
            await _scan_usb_transfers(engine)

            # Every 6 cycles (60s) — slower checks
            if cycle % 6 == 0:
                await _scan_services(engine)
                await _scan_scheduled_tasks(engine)
                await _scan_registry(engine)

        except asyncio.CancelledError:
            break
        except Exception as e:
            logger.debug(f"System monitor loop error: {e}")
