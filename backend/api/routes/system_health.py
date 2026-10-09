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


@router.get("/libraries")
async def library_status():
    """
    Returns the status of every installed library integration.
    Shows which are enabled, their versions, and any init error notes.
    """
    try:
        from core.lib_registry import lib_registry
        statuses = lib_registry.status()
        enabled  = sum(1 for s in statuses if s["enabled"])
        return {
            "total":    len(statuses),
            "enabled":  enabled,
            "disabled": len(statuses) - enabled,
            "libraries": statuses,
        }
    except Exception as e:
        return {"error": str(e), "libraries": []}


@router.get("/anomaly-detector")
async def anomaly_detector_status():
    """Returns online ML anomaly detector statistics."""
    try:
        from modules.online_anomaly_detector import online_detector
        return online_detector.get_stats()
    except Exception as e:
        return {"error": str(e), "ready": False}


@router.get("/llm-providers")
async def llm_providers():
    """Returns available LLM providers via the LLM router."""
    try:
        from modules.llm_router import llm_router
        stats = llm_router.get_stats()
        return {
            "providers":      [stats["primary_model"]] if stats["available"] else [],
            "total_providers": stats.get("fallback_count", 0) if stats["available"] else 0,
            "available":      stats["available"],
            "primary_model":  stats.get("primary_model", ""),
            "provider":       stats.get("provider", "openrouter"),
        }
    except Exception as e:
        return {"error": str(e), "providers": [], "total_providers": 0, "available": False}


@router.get("/semantic-store")
async def semantic_store_status():
    """Returns vector threat store statistics."""
    try:
        from modules.semantic_threat_store import semantic_store
        count = await semantic_store.count()
        return {
            "available": semantic_store.is_available(),
            "threat_count": count,
        }
    except Exception as e:
        return {"error": str(e), "available": False}


@router.get("/popup-status")
async def popup_wizard_status():
    """Return setup wizard popup state — how many answered, pending, etc."""
    try:
        from modules.frontend_bridge import get_popup_status
        return get_popup_status()
    except Exception as e:
        return {"error": str(e), "answered_count": 0}


@router.post("/popup-answer")
async def submit_popup_answer(data: dict):
    """Submit an answer to a setup wizard popup question (REST fallback)."""
    try:
        from modules.frontend_bridge import record_answer
        from modules.setup_wizard import setup_wizard
        qid   = data.get("question_id", "")
        value = data.get("value", "")
        if not qid:
            from fastapi import HTTPException
            raise HTTPException(status_code=400, detail="question_id required")
        record_answer(qid, value)
        return {"recorded": True, "question_id": qid}
    except Exception as e:
        return {"error": str(e)}


@router.get("/wizard")
async def get_wizard_questions():
    """Get all setup wizard questions with current values pre-filled."""
    try:
        from modules.setup_wizard import setup_wizard
        return setup_wizard.get_questions()
    except Exception as e:
        return {"error": str(e)}


@router.post("/wizard/apply")
async def apply_wizard_answers(answers: dict):
    """Apply wizard answers and update .env configuration."""
    try:
        from modules.setup_wizard import setup_wizard
        return await setup_wizard.apply_answers(answers)
    except Exception as e:
        return {"error": str(e)}
