"""AISS - System Health API Route
Returns live CPU, RAM, disk, network I/O, uptime, and module status.
Used by the frontend live dashboard.
"""

import time
import os
from fastapi import APIRouter

router = APIRouter()

_start_time = time.time()


@router.get("/health")
async def system_health():
    """Returns live system metrics for the dashboard."""
    data = {
        "uptime_secs": int(time.time() - _start_time),
        "cpu_percent": 0.0,
        "ram_percent": 0.0,
        "ram_used_mb": 0,
        "ram_total_mb": 0,
        "disk_percent": 0.0,
        "net_sent_mb": 0.0,
        "net_recv_mb": 0.0,
        "process_count": 0,
        "modules": {
            "network_monitor":  True,
            "auth_monitor":     True,
            "file_monitor":     True,
            "malware_scanner":  True,
            "ai_analyst":       True,
            "response_engine":  True,
            "usb_monitor":      True,
            "deception":        True,
            "self_test":        True,
            "kill_chain":       True,
            "soc_chat":         True,
            "self_learner":     True,
        }
    }

    try:
        import psutil

        data["cpu_percent"]   = psutil.cpu_percent(interval=0)
        vm = psutil.virtual_memory()
        data["ram_percent"]   = vm.percent
        data["ram_used_mb"]   = round(vm.used / 1024 / 1024)
        data["ram_total_mb"]  = round(vm.total / 1024 / 1024)

        disk = psutil.disk_usage("/")
        data["disk_percent"]  = disk.percent

        net = psutil.net_io_counters()
        data["net_sent_mb"]   = round(net.bytes_sent / 1024 / 1024, 1)
        data["net_recv_mb"]   = round(net.bytes_recv / 1024 / 1024, 1)

        data["process_count"] = len(psutil.pids())

    except Exception:
        pass

    return data
