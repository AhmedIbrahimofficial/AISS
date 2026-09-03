"""
Agentic AI Orchestrator — FastAPI Routes

All /agent/*, /reports/*, and /scheduled-tasks/* endpoints.
All routes enforce JWT authentication via get_current_verified_user.

Requirements: 17.1–17.20
"""
from __future__ import annotations

import os
from datetime import datetime, timedelta
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.responses import FileResponse
from sqlalchemy import desc, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from agents.exceptions import RateLimitExceededError
from agents.models import (
    AgentAuditEvent, AgentExecution, AgentTask, Approval,
    Report, ScheduledTask, ToolExecution,
)
from agents.schemas import (
    ApiResponse, ApprovalResponse, ChatRequest, ChatResponse,
    CreateScheduledTaskRequest, CreateTaskRequest,
    ExecutionDetailResponse, ExecutionSummary, GenerateReportRequest,
    OrchestratorStatusResponse, PaginatedExecutionsResponse,
    PaginatedReportsResponse, ReportResponse, ScheduledTaskResponse,
    ScheduledTasksListResponse, StatusResponse, TaskDetailResponse,
    TaskResponse, ToolCatalogueResponse, ToolExecutionDetail,
    ApprovalSummary,
)
from auth.dependencies import get_current_verified_user
from core.database import get_db
from core.dependencies import get_orchestrator, get_scheduler

router = APIRouter(tags=["Agent Orchestrator"])


def _ok(data: Any) -> dict:
    return {"status": "ok", "data": data, "error": None}


def _err(msg: str, code: int = 400) -> HTTPException:
    return HTTPException(status_code=code, detail=msg)


# ===========================================================================
# AGENT CHAT
# ===========================================================================

@router.post("/agent/chat")
async def agent_chat(
    req: ChatRequest,
    user=Depends(get_current_verified_user),
    db: AsyncSession = Depends(get_db),
    orchestrator=Depends(get_orchestrator),
):
    """POST /agent/chat — submit a natural-language request to the AI agent."""
    # Rate limit check
    sf = orchestrator._filter
    allowed = await sf.check_rate_limit(user.id)
    if not allowed:
        try:
            await orchestrator._audit.log(
                db, user_id=user.id, event_type="rate_limit_exceeded",
                severity="warning",
            )
        except Exception:
            pass
        raise _err("Rate limit exceeded. Maximum 60 requests per minute.", 429)

    response = await orchestrator.handle_chat(user, req.message, req.session_id, db)
    return _ok(response.model_dump())


# ===========================================================================
# AGENT TASKS
# ===========================================================================

@router.post("/agent/tasks")
async def create_task(
    req: CreateTaskRequest,
    user=Depends(get_current_verified_user),
    db: AsyncSession = Depends(get_db),
    orchestrator=Depends(get_orchestrator),
):
    """POST /agent/tasks — create a task or trigger a playbook."""
    if req.playbook:
        message = f"Run playbook: {req.playbook}"
    else:
        message = req.description or ""

    from agents.schemas import ChatRequest as _CR
    response = await orchestrator.handle_chat(
        user, message, None, db
    )
    return _ok(response.model_dump())


@router.get("/agent/tasks")
async def list_tasks(
    page: int = 1,
    page_size: int = 20,
    user=Depends(get_current_verified_user),
    db: AsyncSession = Depends(get_db),
):
    """GET /agent/tasks — paginated list of tasks for current user."""
    count_result = await db.execute(
        select(func.count(AgentTask.id)).where(AgentTask.user_id == user.id)
    )
    total = count_result.scalar() or 0

    result = await db.execute(
        select(AgentTask)
        .where(AgentTask.user_id == user.id)
        .order_by(desc(AgentTask.created_at))
        .offset((page - 1) * page_size)
        .limit(page_size)
    )
    tasks = result.scalars().all()

    return _ok({
        "tasks": [
            {
                "id": t.id,
                "status": t.status,
                "description": t.description,
                "playbook_name": t.playbook_name,
                "error_message": t.error_message,
                "created_at": t.created_at.isoformat() if t.created_at else None,
                "updated_at": t.updated_at.isoformat() if t.updated_at else None,
                "completed_at": t.completed_at.isoformat() if t.completed_at else None,
            }
            for t in tasks
        ],
        "total": total,
        "page": page,
        "page_size": page_size,
    })


@router.get("/agent/tasks/{task_id}")
async def get_task(
    task_id: str,
    user=Depends(get_current_verified_user),
    db: AsyncSession = Depends(get_db),
):
    """GET /agent/tasks/{id} — full task with executions and approvals."""
    result = await db.execute(
        select(AgentTask).where(
            AgentTask.id == task_id,
            AgentTask.user_id == user.id,
        )
    )
    task = result.scalar_one_or_none()
    if not task:
        raise _err("Task not found", 404)

    exec_result = await db.execute(
        select(AgentExecution).where(AgentExecution.task_id == task_id)
    )
    executions = [
        ExecutionSummary(
            id=e.id, status=e.status, started_at=e.started_at,
            completed_at=e.completed_at, duration_seconds=e.duration_seconds,
        )
        for e in exec_result.scalars().all()
    ]

    appr_result = await db.execute(
        select(Approval).where(Approval.task_id == task_id)
    )
    approvals = [
        ApprovalSummary(
            id=a.id, tool_name=a.tool_name, risk_level=a.risk_level,
            status=a.status, created_at=a.created_at,
        )
        for a in appr_result.scalars().all()
    ]

    data = TaskDetailResponse(
        id=task.id, status=task.status, description=task.description,
        created_at=task.created_at, updated_at=task.updated_at,
        plan_json=task.plan_json, playbook_name=task.playbook_name,
        error_message=task.error_message,
        executions=executions, approvals=approvals,
    )
    return _ok(data.model_dump())


@router.post("/agent/tasks/{task_id}/cancel")
async def cancel_task(
    task_id: str,
    user=Depends(get_current_verified_user),
    db: AsyncSession = Depends(get_db),
    orchestrator=Depends(get_orchestrator),
):
    """POST /agent/tasks/{id}/cancel — cancel a running task."""
    await orchestrator.cancel_task(task_id, user, db)
    return _ok({"task_id": task_id, "status": "cancelled"})


# ===========================================================================
# EXECUTIONS
# ===========================================================================

@router.get("/agent/executions")
async def list_executions(
    page: int = 1,
    page_size: int = 20,
    user=Depends(get_current_verified_user),
    db: AsyncSession = Depends(get_db),
):
    """GET /agent/executions — paginated list for current user."""
    # Get user's task IDs first
    task_result = await db.execute(
        select(AgentTask.id).where(AgentTask.user_id == user.id)
    )
    task_ids = [row[0] for row in task_result.all()]
    if not task_ids:
        return _ok(PaginatedExecutionsResponse(items=[], total=0, page=page, page_size=page_size).model_dump())

    count_result = await db.execute(
        select(func.count(AgentExecution.id)).where(AgentExecution.task_id.in_(task_ids))
    )
    total = count_result.scalar() or 0

    result = await db.execute(
        select(AgentExecution)
        .where(AgentExecution.task_id.in_(task_ids))
        .order_by(desc(AgentExecution.started_at))
        .offset((page - 1) * page_size)
        .limit(page_size)
    )
    items = [
        ExecutionSummary(
            id=e.id, status=e.status, started_at=e.started_at,
            completed_at=e.completed_at, duration_seconds=e.duration_seconds,
        )
        for e in result.scalars().all()
    ]
    return _ok(PaginatedExecutionsResponse(items=items, total=total, page=page, page_size=page_size).model_dump())


@router.get("/agent/executions/{exec_id}")
async def get_execution(
    exec_id: str,
    user=Depends(get_current_verified_user),
    db: AsyncSession = Depends(get_db),
):
    """GET /agent/executions/{id} — full execution with tool-level details."""
    result = await db.execute(
        select(AgentExecution).where(AgentExecution.id == exec_id)
    )
    execution = result.scalar_one_or_none()
    if not execution:
        raise _err("Execution not found", 404)

    # Verify ownership via task
    task_result = await db.execute(
        select(AgentTask).where(AgentTask.id == execution.task_id, AgentTask.user_id == user.id)
    )
    if not task_result.scalar_one_or_none():
        raise _err("Execution not found", 404)

    te_result = await db.execute(
        select(ToolExecution).where(ToolExecution.execution_id == exec_id)
    )
    tool_executions = [
        ToolExecutionDetail(
            id=te.id, tool_name=te.tool_name, category=te.category,
            risk_level=te.risk_level, arguments_json=te.arguments_json,
            result_json=te.result_json, status=te.status,
            started_at=te.started_at, completed_at=te.completed_at,
            duration_seconds=te.duration_seconds, error_message=te.error_message,
            retry_count=te.retry_count,
        )
        for te in te_result.scalars().all()
    ]

    data = ExecutionDetailResponse(
        id=execution.id, task_id=execution.task_id, status=execution.status,
        steps_json=execution.steps_json, started_at=execution.started_at,
        completed_at=execution.completed_at, duration_seconds=execution.duration_seconds,
        error_message=execution.error_message, tool_executions=tool_executions,
    )
    return _ok(data.model_dump())


# ===========================================================================
# APPROVALS
# ===========================================================================

@router.post("/agent/approvals/{approval_id}/approve")
async def approve_action(
    approval_id: str,
    user=Depends(get_current_verified_user),
    db: AsyncSession = Depends(get_db),
    orchestrator=Depends(get_orchestrator),
):
    """POST /agent/approvals/{id}/approve — approve a pending HIGH/CRITICAL operation."""
    try:
        await orchestrator._approval.approve(approval_id, user.id, db)
    except ValueError as e:
        raise _err(str(e), 404)
    return _ok({"approval_id": approval_id, "status": "approved"})


@router.post("/agent/approvals/{approval_id}/reject")
async def reject_action(
    approval_id: str,
    user=Depends(get_current_verified_user),
    db: AsyncSession = Depends(get_db),
    orchestrator=Depends(get_orchestrator),
):
    """POST /agent/approvals/{id}/reject — reject a pending operation."""
    try:
        await orchestrator._approval.reject(approval_id, user.id, db)
    except ValueError as e:
        raise _err(str(e), 404)
    return _ok({"approval_id": approval_id, "status": "rejected"})


# ===========================================================================
# TOOLS
# ===========================================================================

@router.get("/agent/tools")
async def list_tools(
    user=Depends(get_current_verified_user),
    orchestrator=Depends(get_orchestrator),
):
    """GET /agent/tools — full tool catalogue."""
    catalogue = orchestrator._registry.get_catalogue()
    return _ok(ToolCatalogueResponse(tools=catalogue).model_dump())


@router.get("/agent/status")
async def agent_status(
    user=Depends(get_current_verified_user),
    orchestrator=Depends(get_orchestrator),
):
    """GET /agent/status — orchestrator operational state."""
    return _ok(orchestrator.get_status().model_dump())


# ===========================================================================
# REPORTS
# ===========================================================================

@router.get("/reports")
async def list_reports(
    page: int = 1,
    page_size: int = 20,
    user=Depends(get_current_verified_user),
    db: AsyncSession = Depends(get_db),
):
    """GET /reports — paginated list of reports for current user."""
    count_result = await db.execute(
        select(func.count(Report.id)).where(Report.user_id == user.id)
    )
    total = count_result.scalar() or 0

    result = await db.execute(
        select(Report).where(Report.user_id == user.id)
        .order_by(desc(Report.generated_at))
        .offset((page - 1) * page_size).limit(page_size)
    )
    items = [_report_to_response(r) for r in result.scalars().all()]
    return _ok(PaginatedReportsResponse(items=items, total=total, page=page, page_size=page_size).model_dump())


@router.get("/reports/latest")
async def get_latest_report(
    user=Depends(get_current_verified_user),
    db: AsyncSession = Depends(get_db),
):
    """GET /reports/latest — most recently generated report."""
    result = await db.execute(
        select(Report).where(Report.user_id == user.id)
        .order_by(desc(Report.generated_at)).limit(1)
    )
    report = result.scalar_one_or_none()
    if not report:
        raise _err("No reports found", 404)
    return _ok(_report_to_response(report).model_dump())


@router.post("/reports/generate")
async def generate_report(
    req: GenerateReportRequest = GenerateReportRequest(),
    user=Depends(get_current_verified_user),
    db: AsyncSession = Depends(get_db),
):
    """POST /reports/generate — trigger on-demand report generation."""
    if user.role not in ("analyst", "admin"):
        raise _err("Insufficient role to generate reports", 403)

    from agents.report_generator import ReportGenerator
    period_end = req.period_end or datetime.utcnow()
    period_start = req.period_start or (period_end - timedelta(days=7))

    generator = ReportGenerator()
    report = await generator.generate(user, period_start, period_end, db)
    return _ok({"report_id": report.id, "status": report.status})


@router.get("/reports/{report_id}")
async def get_report(
    report_id: str,
    user=Depends(get_current_verified_user),
    db: AsyncSession = Depends(get_db),
):
    """GET /reports/{id} — report metadata."""
    report = await _get_user_report(report_id, user.id, db)
    return _ok(_report_to_response(report).model_dump())


@router.get("/reports/{report_id}/pdf")
async def download_report_pdf(
    report_id: str,
    user=Depends(get_current_verified_user),
    db: AsyncSession = Depends(get_db),
):
    """GET /reports/{id}/pdf — download PDF with integrity check."""
    report = await _get_user_report(report_id, user.id, db)

    if report.status != "ready" or not report.file_path:
        raise _err("PDF not available. Report status: " + report.status, 404)

    import os
    if not os.path.exists(report.file_path):
        raise _err("PDF file not found on disk", 404)

    # Integrity check
    from agents.report_generator import ReportGenerator
    gen = ReportGenerator()
    if not await gen.verify_integrity(report):
        try:
            from agents.audit_logger import AuditLogger
            from core.database import AsyncSessionLocal
            audit = AuditLogger()
            async with AsyncSessionLocal() as audit_db:
                await audit.log(
                    audit_db, user_id=user.id,
                    event_type="report_integrity_violation",
                    severity="critical",
                    request_summary=f"Integrity check failed for report {report_id}",
                )
        except Exception:
            pass
        raise HTTPException(status_code=409, detail="Report file integrity check failed. File may be corrupted.")

    return FileResponse(
        path=report.file_path,
        media_type="application/pdf",
        filename=f"report_{report_id}.pdf",
        headers={"Content-Disposition": f'attachment; filename="report_{report_id}.pdf"'},
    )


@router.delete("/reports/{report_id}")
async def delete_report(
    report_id: str,
    user=Depends(get_current_verified_user),
    db: AsyncSession = Depends(get_db),
):
    """DELETE /reports/{id} — admin only."""
    if user.role != "admin":
        raise _err("Only admins can delete reports", 403)
    report = await _get_user_report(report_id, user.id, db)
    await db.delete(report)
    await db.flush()
    return _ok({"report_id": report_id, "status": "deleted"})


# ===========================================================================
# SCHEDULED TASKS
# ===========================================================================

@router.get("/scheduled-tasks")
async def list_scheduled_tasks(
    user=Depends(get_current_verified_user),
    db: AsyncSession = Depends(get_db),
):
    """GET /scheduled-tasks — list all scheduled tasks for current user."""
    result = await db.execute(
        select(ScheduledTask).where(ScheduledTask.user_id == user.id)
    )
    items = [_scheduled_task_to_response(t) for t in result.scalars().all()]
    return _ok(ScheduledTasksListResponse(items=items).model_dump())


@router.post("/scheduled-tasks")
async def create_scheduled_task(
    req: CreateScheduledTaskRequest,
    user=Depends(get_current_verified_user),
    db: AsyncSession = Depends(get_db),
    scheduler=Depends(get_scheduler),
):
    """POST /scheduled-tasks — create a recurring task."""
    if user.role not in ("analyst", "admin"):
        raise _err("Insufficient role to create scheduled tasks", 403)

    st = ScheduledTask(
        user_id=user.id,
        name=req.name,
        description=req.description,
        tool_or_playbook=req.tool_or_playbook,
        arguments_json=req.arguments_json or {},
        schedule_expression=req.schedule_expression,
        enabled=req.enabled,
    )
    db.add(st)
    await db.flush()

    if st.enabled:
        try:
            await scheduler.add_job(st)
        except Exception as e:
            pass  # Job will be picked up on next scheduler restart

    return _ok(_scheduled_task_to_response(st).model_dump())


@router.delete("/scheduled-tasks/{task_id}")
async def delete_scheduled_task(
    task_id: str,
    user=Depends(get_current_verified_user),
    db: AsyncSession = Depends(get_db),
    scheduler=Depends(get_scheduler),
):
    """DELETE /scheduled-tasks/{id} — creator or admin only."""
    result = await db.execute(
        select(ScheduledTask).where(ScheduledTask.id == task_id)
    )
    st = result.scalar_one_or_none()
    if not st:
        raise _err("Scheduled task not found", 404)
    if st.user_id != user.id and user.role != "admin":
        raise _err("Not authorised to delete this task", 403)

    await scheduler.remove_job(task_id)
    await db.delete(st)
    await db.flush()
    return _ok({"task_id": task_id, "status": "deleted"})


# ===========================================================================
# Helpers
# ===========================================================================

def _report_to_response(r: Report) -> ReportResponse:
    return ReportResponse(
        id=r.id, user_id=r.user_id,
        period_start=r.period_start, period_end=r.period_end,
        status=r.status, generated_at=r.generated_at,
        file_size_bytes=r.file_size_bytes, sha256_hash=r.sha256_hash,
        error_message=r.error_message, scope_json=r.scope_json,
    )


def _scheduled_task_to_response(t: ScheduledTask) -> ScheduledTaskResponse:
    return ScheduledTaskResponse(
        id=t.id, name=t.name, description=t.description,
        tool_or_playbook=t.tool_or_playbook, arguments_json=t.arguments_json,
        schedule_expression=t.schedule_expression, enabled=t.enabled,
        last_run_at=t.last_run_at, next_run_at=t.next_run_at,
        created_at=t.created_at,
    )


async def _get_user_report(report_id: str, user_id: str, db: AsyncSession) -> Report:
    result = await db.execute(
        select(Report).where(Report.id == report_id, Report.user_id == user_id)
    )
    report = result.scalar_one_or_none()
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")
    return report
