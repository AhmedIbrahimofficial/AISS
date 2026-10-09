"""
AISS — Live System Data API
Returns real data about the current machine:
  - Running processes
  - File system listing (user dirs, suspicious paths)
  - Network stats
  - Recent activity
"""
import asyncio
import os
import sys
import time
from pathlib import Path
from fastapi import APIRouter

router = APIRouter()

# Simple cache to avoid hammering psutil on every request
_proc_cache: dict = {"data": None, "ts": 0.0}
_PROC_TTL = 8.0  # seconds


def _gather_processes() -> dict:
    """Synchronously gather process list — called via run_in_executor."""
    procs = []
    try:
        import psutil
        # Collect without waiting for cpu_percent (instantaneous, fast)
        for p in psutil.process_iter(
            ["pid", "name", "username", "cpu_percent", "memory_percent",
             "status", "create_time", "exe", "cmdline"]
        ):
            try:
                info = p.info
                cmd = " ".join(info.get("cmdline") or [])[:120]
                procs.append({
                    "pid":    info["pid"],
                    "name":   info["name"] or "unknown",
                    "user":   info.get("username") or "",
                    "cpu":    round(info.get("cpu_percent") or 0, 1),
                    "mem":    round(info.get("memory_percent") or 0, 1),
                    "status": info.get("status") or "",
                    "exe":    info.get("exe") or "",
                    "cmd":    cmd,
                    "started": int(info.get("create_time") or 0),
                    "suspicious": _is_suspicious_process(info),
                })
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
    except ImportError:
        pass

    procs.sort(key=lambda x: x["mem"], reverse=True)
    return {
        "processes": procs[:80],
        "total": len(procs),
        "suspicious_count": sum(1 for p in procs if p["suspicious"]),
    }


@router.get("/processes")
async def get_processes():
    """Return running processes (non-blocking, cached 8s)."""
    global _proc_cache
    now = time.monotonic()
    if _proc_cache["data"] is not None and (now - _proc_cache["ts"]) < _PROC_TTL:
        return _proc_cache["data"]

    loop = asyncio.get_event_loop()
    try:
        data = await asyncio.wait_for(loop.run_in_executor(None, _gather_processes), timeout=10.0)
        _proc_cache["data"] = data
        _proc_cache["ts"]   = time.monotonic()
        return data
    except asyncio.TimeoutError:
        if _proc_cache["data"] is not None:
            return _proc_cache["data"]
        return {"processes": [], "total": 0, "suspicious_count": 0}



def _is_suspicious_process(info: dict) -> bool:
    """Flag processes that look anomalous."""
    name = (info.get("name") or "").lower()
    exe  = (info.get("exe") or "").lower()
    cmd  = " ".join(info.get("cmdline") or []).lower()

    # Known malware names / tools often abused
    suspicious_names = {
        "mimikatz", "meterpreter", "nc.exe", "ncat", "netcat",
        "psexec", "wce", "procdump", "cobaltstrike",
        "powercat", "empire", "lazagne", "wdigest",
    }
    if name in suspicious_names:
        return True

    # Encoded powershell
    if "powershell" in name and ("-enc" in cmd or "-encodedcommand" in cmd):
        return True

    # Process running from temp / appdata
    if exe and any(p in exe for p in ["\\temp\\", "\\tmp\\", "\\appdata\\local\\temp\\"]):
        return True

    return False


@router.get("/files")
async def get_filesystem():
    """Scan common user directories and return files with metadata."""
    target_dirs = [
        Path.home(),
        Path.home() / "Downloads",
        Path.home() / "Documents",
        Path.home() / "Desktop",
        Path.home() / "AppData" / "Roaming",
        Path("C:/Windows/Temp"),
        Path("C:/Temp"),
    ]

    files = []
    scanned_dirs = 0
    suspicious = []

    # High-risk extensions
    risky_ext = {
        ".exe", ".bat", ".ps1", ".vbs", ".js", ".jar",
        ".scr", ".pif", ".cmd", ".com", ".hta", ".lnk",
    }

    for base in target_dirs:
        if not base.exists():
            continue
        try:
            for entry in base.iterdir():
                if not entry.is_file():
                    continue
                try:
                    stat = entry.stat()
                    ext  = entry.suffix.lower()
                    risk = ext in risky_ext
                    item = {
                        "name":     entry.name,
                        "path":     str(entry),
                        "dir":      str(base),
                        "size":     stat.st_size,
                        "ext":      ext,
                        "modified": int(stat.st_mtime),
                        "risk":     risk,
                    }
                    files.append(item)
                    if risk:
                        suspicious.append(item)
                except (PermissionError, OSError):
                    pass
            scanned_dirs += 1
        except (PermissionError, OSError):
            pass

    # Sort by modified desc (newest first)
    files.sort(key=lambda x: x["modified"], reverse=True)

    return {
        "files":           files[:200],
        "total_found":     len(files),
        "scanned_dirs":    scanned_dirs,
        "suspicious":      suspicious[:30],
        "suspicious_count": len(suspicious),
        "dirs_scanned":    [str(d) for d in target_dirs if d.exists()],
    }


@router.get("/network-stats")
async def get_network_stats():
    """Return real-time network I/O stats."""
    try:
        import psutil

        # Two samples 0.5s apart to compute per-second rate
        n1 = psutil.net_io_counters()
        time.sleep(0.4)
        n2 = psutil.net_io_counters()

        sent_ps  = max(0, (n2.bytes_sent - n1.bytes_sent) / 0.4)
        recv_ps  = max(0, (n2.bytes_recv - n1.bytes_recv) / 0.4)

        conns = psutil.net_connections(kind="inet")
        established = sum(1 for c in conns if c.status == "ESTABLISHED")
        listening   = sum(1 for c in conns if c.status == "LISTEN")

        # Estimate "blocked" as connections that were SYN_SENT or CLOSE_WAIT
        blocked_states = {"SYN_SENT", "CLOSE_WAIT", "TIME_WAIT"}
        blocked = sum(1 for c in conns if c.status in blocked_states)

        ifaces = psutil.net_if_stats()
        iface_list = [
            {"name": k, "speed": v.speed, "mtu": v.mtu, "up": v.isup}
            for k, v in ifaces.items()
        ]

        return {
            "connections":    established,
            "listening":      listening,
            "blocked":        blocked,
            "total_conns":    len(conns),
            "throughput_mb":  round(recv_ps / 1024 / 1024, 3),
            "sent_mb_s":      round(sent_ps / 1024 / 1024, 3),
            "recv_mb_s":      round(recv_ps / 1024 / 1024, 3),
            "total_sent_mb":  round(n2.bytes_sent / 1024 / 1024, 1),
            "total_recv_mb":  round(n2.bytes_recv / 1024 / 1024, 1),
            "interfaces":     iface_list,
        }
    except Exception as e:
        return {
            "connections": 0, "blocked": 0,
            "throughput_mb": 0.0, "sent_mb_s": 0.0, "recv_mb_s": 0.0,
            "error": str(e),
        }


@router.get("/disk")
async def get_disk_info():
    """Return disk partitions and usage."""
    try:
        import psutil
        partitions = []
        for p in psutil.disk_partitions():
            try:
                usage = psutil.disk_usage(p.mountpoint)
                partitions.append({
                    "device":    p.device,
                    "mountpoint": p.mountpoint,
                    "fstype":    p.fstype,
                    "total_gb":  round(usage.total / 1e9, 1),
                    "used_gb":   round(usage.used  / 1e9, 1),
                    "free_gb":   round(usage.free  / 1e9, 1),
                    "percent":   usage.percent,
                })
            except (PermissionError, OSError):
                pass
        return {"partitions": partitions}
    except Exception as e:
        return {"partitions": [], "error": str(e)}
