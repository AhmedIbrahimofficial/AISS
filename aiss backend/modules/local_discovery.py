"""AISS - Automatic Local Machine Discovery

Collects real system and network telemetry about the host AISS is running on.
All operations are offloaded to threads so they never block the asyncio event loop.
"""

from __future__ import annotations

import asyncio
import json
import os
import platform
import socket
import sys
from datetime import datetime
from pathlib import Path
from typing import Any

from utils.logger import setup_logger

logger = setup_logger("local_discovery")

IS_WINDOWS = sys.platform == "win32"


def _safe_get(d: dict, key: str, default: Any = None) -> Any:
    try:
        return d.get(key, default)
    except Exception:
        return default


async def _to_thread(func, *args, **kwargs):
    """Run a synchronous callable in a thread pool."""
    return await asyncio.to_thread(func, *args, **kwargs)


def _collect_local_info_sync() -> dict[str, Any]:
    """Synchronous local discovery. Returns a dict of asset information."""
    info: dict[str, Any] = {
        "discovered_at": datetime.utcnow().isoformat(),
        "hostname": platform.node(),
        "os": platform.system(),
        "os_version": platform.version(),
        "os_release": platform.release(),
        "architecture": platform.machine(),
        "processor": platform.processor(),
        "python_version": platform.python_version(),
        "username": os.getlogin() if hasattr(os, "getlogin") else None,
    }

    try:
        import psutil

        # CPU / memory / disk
        info["cpu_count"] = psutil.cpu_count()
        info["cpu_percent"] = psutil.cpu_percent(interval=0.1)
        vm = psutil.virtual_memory()
        info["memory"] = {
            "total_gb": round(vm.total / 1e9, 2),
            "used_gb": round(vm.used / 1e9, 2),
            "percent": vm.percent,
        }
        info["disks"] = []
        for p in psutil.disk_partitions():
            try:
                usage = psutil.disk_usage(p.mountpoint)
                info["disks"].append({
                    "device": p.device,
                    "mountpoint": p.mountpoint,
                    "fstype": p.fstype,
                    "total_gb": round(usage.total / 1e9, 2),
                    "used_gb": round(usage.used / 1e9, 2),
                    "percent": usage.percent,
                })
            except Exception as e:
                logger.debug(f"Disk usage failed for {p.mountpoint}: {e}")

        # Network interfaces
        info["interfaces"] = []
        for name, addrs in psutil.net_if_addrs().items():
            iface = {"name": name, "addresses": [], "mac": None}
            for addr in addrs:
                if addr.family == socket.AF_INET:
                    iface["addresses"].append({
                        "type": "ipv4",
                        "address": addr.address,
                        "netmask": addr.netmask,
                        "broadcast": addr.broadcast,
                    })
                elif addr.family == socket.AF_INET6:
                    iface["addresses"].append({
                        "type": "ipv6",
                        "address": addr.address,
                        "netmask": addr.netmask,
                    })
                elif addr.family == -1 and IS_WINDOWS:
                    iface["mac"] = addr.address
            info["interfaces"].append(iface)

        # Listening ports and active connections
        info["listening_ports"] = []
        try:
            for c in psutil.net_connections(kind="inet"):
                if c.status == "LISTEN" and c.laddr:
                    info["listening_ports"].append({
                        "protocol": "tcp",
                        "address": c.laddr.ip,
                        "port": c.laddr.port,
                        "pid": c.pid,
                    })
        except Exception as e:
            logger.debug(f"Listening ports enumeration failed: {e}")

        # Running processes (summary, capped to avoid excessive runtime)
        info["processes"] = []
        try:
            procs = []
            for p in psutil.process_iter([
                "pid", "name", "exe", "username", "status",
                "cpu_percent", "memory_percent", "create_time",
            ]):
                try:
                    procs.append(p.info)
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass
            # Sort by memory_percent descending and keep top 200
            procs = sorted(
                [p for p in procs if p.get("memory_percent") is not None],
                key=lambda x: x["memory_percent"],
                reverse=True,
            )[:200]
            info["processes"] = procs
        except Exception as e:
            logger.debug(f"Process enumeration failed: {e}")

        # Services (running only, capped)
        info["services"] = []
        if IS_WINDOWS:
            try:
                count = 0
                for svc in psutil.win_service_iter():
                    try:
                        if svc.status() == "running":
                            info["services"].append({
                                "name": svc.name(),
                                "display_name": svc.display_name(),
                                "status": svc.status(),
                                "start_type": svc.start_type(),
                            })
                            count += 1
                            if count >= 100:
                                break
                    except Exception:
                        pass
            except Exception as e:
                logger.debug(f"Windows service enumeration failed: {e}")

        # Startup items (Windows)
        info["startup_items"] = []
        if IS_WINDOWS:
            try:
                import winreg
                keys = [
                    (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run"),
                    (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Run"),
                ]
                for hkey, path in keys:
                    try:
                        with winreg.OpenKey(hkey, path) as key:
                            for i in range(winreg.QueryInfoKey(key)[1]):
                                try:
                                    name, value, _ = winreg.EnumValue(key, i)
                                    info["startup_items"].append({
                                        "name": name, "command": value, "hive": "HKLM" if hkey == winreg.HKEY_LOCAL_MACHINE else "HKCU",
                                    })
                                except Exception:
                                    pass
                    except Exception as e:
                        logger.debug(f"Registry read failed for {path}: {e}")
            except Exception as e:
                logger.debug(f"Startup enumeration failed: {e}")

        # Installed software (capped; PowerShell can be slow on some systems)
        info["installed_software"] = []
        try:
            if IS_WINDOWS:
                import subprocess
                result = subprocess.run(
                    [
                        "powershell", "-NoProfile", "-Command",
                        "Get-ItemProperty HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\* | "
                        "Where-Object { $_.DisplayName } | "
                        "Select-Object -First 200 DisplayName,DisplayVersion,Publisher | "
                        "ConvertTo-Json -Compress",
                    ],
                    capture_output=True, text=True, timeout=15,
                )
                if result.stdout:
                    data = json.loads(result.stdout)
                    if isinstance(data, dict):
                        data = [data]
                    info["installed_software"] = [
                        {k: v for k, v in item.items() if v}
                        for item in data if isinstance(item, dict) and item.get("DisplayName")
                    ][:200]
            else:
                result = subprocess.run(
                    ["dpkg", "--list"], capture_output=True, text=True, timeout=15
                )
                info["installed_software"] = [
                    {"name": l.split()[1], "version": l.split()[2]}
                    for l in result.stdout.splitlines()
                    if l.startswith("ii")
                ][:200]
        except Exception as e:
            logger.debug(f"Software inventory failed: {e}")

    except ImportError:
        logger.warning("psutil not installed — local discovery limited")
    except Exception as e:
        logger.warning(f"Local discovery error: {e}")

    return info


async def discover_local_asset() -> dict[str, Any]:
    """Asynchronously discover local machine information."""
    return await _to_thread(_collect_local_info_sync)


def get_default_scan_directories() -> list[str]:
    """Return security-sensitive directories to scan by default."""
    if IS_WINDOWS:
        user = os.path.expanduser("~")
        return [
            os.path.join(user, "Downloads"),
            os.path.join(user, "Desktop"),
            os.path.join(user, "Documents"),
            os.environ.get("TEMP", os.path.join(user, "AppData", "Local", "Temp")),
            os.path.join(user, "AppData", "Roaming"),
        ]
    return [
        os.path.expanduser("~/Downloads"),
        os.path.expanduser("~/Desktop"),
        os.path.expanduser("~/Documents"),
        "/tmp",
        "/var/tmp",
    ]


def get_local_subnets() -> list[str]:
    """Return local IPv4 subnets that can be safely scanned."""
    try:
        import psutil
        subnets = []
        for name, addrs in psutil.net_if_addrs().items():
            for addr in addrs:
                if addr.family != socket.AF_INET:
                    continue
                ip = addr.address
                mask = addr.netmask
                if not ip or not mask:
                    continue
                if ip.startswith("127.") or ip.startswith("169.254."):
                    continue
                # Convert mask to CIDR
                try:
                    bits = sum(bin(int(x)).count("1") for x in mask.split("."))
                    network = ".".join(ip.split(".")[:3]) + ".0"
                    subnets.append(f"{network}/{bits}")
                except Exception:
                    pass
        return subnets
    except Exception as e:
        logger.debug(f"Subnet detection failed: {e}")
        return []
