"""
SYSTEM tool handlers — delegate to psutil and existing core modules.
Returns real data; never fabricates. If unavailable returns explicit gap message.
"""
from __future__ import annotations
import asyncio
import platform
import subprocess
from typing import Any

_NA = "No real data available for {tool}"


async def get_system_status(**_: Any) -> dict:
    try:
        import psutil
        return {
            "status": "ok",
            "cpu_percent": psutil.cpu_percent(interval=0.1),
            "memory_percent": psutil.virtual_memory().percent,
            "disk_percent": psutil.disk_usage("/").percent,
            "platform": platform.system(),
            "uptime_seconds": None,
        }
    except Exception as e:
        return {"status": "error", "error": str(e), "message": _NA.format(tool="get_system_status")}


async def get_system_information(**_: Any) -> dict:
    try:
        import psutil
        return {
            "status": "ok",
            "platform": platform.platform(),
            "node": platform.node(),
            "machine": platform.machine(),
            "processor": platform.processor(),
            "python_version": platform.python_version(),
            "cpu_count": psutil.cpu_count(),
            "total_memory_gb": round(psutil.virtual_memory().total / 1e9, 2),
        }
    except Exception as e:
        return {"status": "error", "error": str(e), "message": _NA.format(tool="get_system_information")}


async def get_cpu_usage(**_: Any) -> dict:
    try:
        import psutil
        return {"status": "ok", "cpu_percent": psutil.cpu_percent(interval=0.2),
                "per_cpu": psutil.cpu_percent(interval=0.1, percpu=True)}
    except Exception as e:
        return {"status": "error", "error": str(e), "message": _NA.format(tool="get_cpu_usage")}


async def get_memory_usage(**_: Any) -> dict:
    try:
        import psutil
        vm = psutil.virtual_memory()
        return {"status": "ok", "total_gb": round(vm.total/1e9,2),
                "used_gb": round(vm.used/1e9,2), "percent": vm.percent}
    except Exception as e:
        return {"status": "error", "error": str(e), "message": _NA.format(tool="get_memory_usage")}


async def get_disk_usage(**_: Any) -> dict:
    try:
        import psutil
        parts = []
        for p in psutil.disk_partitions():
            try:
                usage = psutil.disk_usage(p.mountpoint)
                parts.append({"device": p.device, "mountpoint": p.mountpoint,
                               "total_gb": round(usage.total/1e9,2),
                               "used_gb": round(usage.used/1e9,2),
                               "percent": usage.percent})
            except Exception:
                pass
        return {"status": "ok", "partitions": parts}
    except Exception as e:
        return {"status": "error", "error": str(e), "message": _NA.format(tool="get_disk_usage")}


async def get_running_processes(**_: Any) -> dict:
    try:
        import psutil
        procs = []
        for p in psutil.process_iter(["pid","name","username","status","cpu_percent","memory_percent"]):
            try:
                procs.append(p.info)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
        return {"status": "ok", "count": len(procs), "processes": procs[:200]}
    except Exception as e:
        return {"status": "error", "error": str(e), "message": _NA.format(tool="get_running_processes")}


async def get_installed_software(**_: Any) -> dict:
    try:
        import json
        if platform.system() == "Windows":
            result = await asyncio.to_thread(
                subprocess.run,
                ["powershell","-Command",
                 "Get-ItemProperty HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\* | "
                 "Select-Object DisplayName,DisplayVersion,Publisher | ConvertTo-Json -Compress"],
                capture_output=True, text=True, timeout=30)
            software = json.loads(result.stdout) if result.stdout else []
        else:
            result = await asyncio.to_thread(
                subprocess.run, ["dpkg","--list"], capture_output=True, text=True, timeout=30
            )
            lines = [l for l in result.stdout.splitlines() if l.startswith("ii")]
            software = [{"name": l.split()[1], "version": l.split()[2]} for l in lines[:200]]
        return {"status": "ok", "count": len(software), "software": software[:200]}
    except Exception as e:
        return {"status": "error", "error": str(e), "message": _NA.format(tool="get_installed_software")}


async def get_system_services(**_: Any) -> dict:
    try:
        import psutil
        services = []
        if platform.system() == "Windows":
            for svc in psutil.win_service_iter():
                try:
                    services.append({"name": svc.name(), "status": svc.status(),
                                     "start_type": svc.start_type()})
                except Exception:
                    pass
        else:
            result = await asyncio.to_thread(
                subprocess.run,
                ["systemctl","list-units","--type=service","--no-pager","--plain"],
                capture_output=True, text=True, timeout=30
            )
            for line in result.stdout.splitlines()[1:]:
                parts = line.split()
                if parts:
                    services.append({"name": parts[0], "status": parts[2] if len(parts)>2 else "unknown"})
        return {"status": "ok", "count": len(services), "services": services[:200]}
    except Exception as e:
        return {"status": "error", "error": str(e), "message": _NA.format(tool="get_system_services")}
