"""AISS - Autonomous Security Orchestrator API Routes

Endpoints:
  POST /api/security/full-scan          - Start a full autonomous security scan
  POST /api/security/eicar-test         - Start a scan with an EICAR test artifact
  POST /api/security/verify-pipeline    - Lightweight EICAR verification (synchronous)
  GET  /api/security/tasks/{task_id}    - Get scan task status and findings
  POST /api/security/tasks/{task_id}/cancel - Cancel a running scan
  GET  /api/security/tasks              - List recent security scan tasks
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy import desc, select
from sqlalchemy.ext.asyncio import AsyncSession

from auth.dependencies import get_current_verified_user
from core.database import get_db
from core.dependencies import get_ws_manager
from core.websocket_manager import WebSocketManager
from agents.models import AgentTask, SecurityFinding
from modules.security_orchestrator import security_orchestrator

router = APIRouter(tags=["Autonomous Security Orchestrator"])


class FullScanRequest(BaseModel):
    description: str = Field(default="Autonomous Full Security Scan", max_length=512)
    target_dirs: list[str] = Field(default_factory=list)
    eicar_test: bool = Field(default=False)


class StartScanResponse(BaseModel):
    task_id: str
    status: str
    message: str


@router.post("/security/full-scan", response_model=StartScanResponse)
async def start_full_scan(
    req: FullScanRequest,
    user=Depends(get_current_verified_user),
    ws_manager: WebSocketManager = Depends(get_ws_manager),
):
    """Start a full autonomous security scan."""
    security_orchestrator.ws_manager = ws_manager
    task_id = await security_orchestrator.start_full_scan(
        user_id=str(user.id),
        description=req.description,
        eicar_test=req.eicar_test,
        target_dirs=req.target_dirs or None,
    )
    return StartScanResponse(
        task_id=task_id,
        status="running",
        message="Full security scan started. Monitor progress via WebSocket or /security/tasks/{task_id}.",
    )


@router.post("/security/eicar-test", response_model=StartScanResponse)
async def start_eicar_test(
    user=Depends(get_current_verified_user),
    ws_manager: WebSocketManager = Depends(get_ws_manager),
):
    """Start a security scan that plants the EICAR test file and verifies detection."""
    security_orchestrator.ws_manager = ws_manager
    task_id = await security_orchestrator.start_full_scan(
        user_id=str(user.id),
        description="EICAR test scan",
        eicar_test=True,
    )
    return StartScanResponse(
        task_id=task_id,
        status="running",
        message="EICAR test scan started. The test artifact will be planted and must be detected.",
    )


@router.post("/security/verify-pipeline")
async def verify_pipeline(
    user=Depends(get_current_verified_user),
):
    """Run a lightweight EICAR-only pipeline verification.

    Plants the EICAR test file, scans for it, verifies detection, and cleans up.
    Returns results synchronously (60s timeout).
    """
    result = await security_orchestrator.verify_pipeline(user_id=str(user.id))
    return {"status": "ok", "data": result}


@router.get("/security/tasks/{task_id}")
async def get_task_status(
    task_id: str,
    user=Depends(get_current_verified_user),
):
    """Get the status, progress, and findings of a security scan task."""
    status_info = await security_orchestrator.get_task_status(task_id)
    if not status_info:
        raise HTTPException(status_code=404, detail="Task not found")
    return {"status": "ok", "data": status_info}


@router.post("/security/tasks/{task_id}/cancel")
async def cancel_task(
    task_id: str,
    user=Depends(get_current_verified_user),
):
    """Cancel a running security scan task."""
    cancelled = await security_orchestrator.cancel_task(task_id)
    if not cancelled:
        raise HTTPException(status_code=400, detail="Task is not running or already complete")
    return {"status": "ok", "message": "Task cancellation requested"}


@router.get("/security/tasks")
async def list_scan_tasks(
    user=Depends(get_current_verified_user),
    db: AsyncSession = Depends(get_db),
    limit: int = 50,
):
    """List recent security scan tasks with finding counts."""
    result = await db.execute(
        select(AgentTask)
        .where(AgentTask.user_id == str(user.id))
        .order_by(desc(AgentTask.created_at))
        .limit(limit)
    )
    tasks = result.scalars().all()

    task_ids = [t.id for t in tasks]
    findings_result = await db.execute(
        select(SecurityFinding).where(SecurityFinding.task_id.in_(task_ids))
    )
    findings_by_task: dict[str, list] = {}
    for f in findings_result.scalars().all():
        findings_by_task.setdefault(f.task_id, []).append(f)

    return {
        "status": "ok",
        "data": [
            {
                "id": t.id,
                "status": t.status,
                "description": t.description,
                "created_at": t.created_at.isoformat() if t.created_at else None,
                "completed_at": t.completed_at.isoformat() if t.completed_at else None,
                "findings_count": len(findings_by_task.get(t.id, [])),
            }
            for t in tasks
        ],
    }
