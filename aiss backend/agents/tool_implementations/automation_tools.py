"""
AUTOMATION tool handlers — create/manage AgentTasks and ScheduledTasks.
"""
from __future__ import annotations
from typing import Any

_NA = "No real data available for {tool}"


async def create_task(description: str, user_id: str = "system", **_: Any) -> dict:
    try:
        from core.database import AsyncSessionLocal
        from agents.models import AgentTask
        async with AsyncSessionLocal() as db:
            task = AgentTask(user_id=user_id, description=description, status="pending")
            db.add(task)
            await db.commit()
            return {"status": "ok", "task_id": task.id}
    except Exception as e:
        return {"status": "error", "error": str(e), "message": _NA.format(tool="create_task")}


async def schedule_task(name: str, tool_or_playbook: str,
                        schedule_expression: str, user_id: str = "system",
                        arguments: dict | None = None, **_: Any) -> dict:
    try:
        from core.database import AsyncSessionLocal
        from agents.models import ScheduledTask
        async with AsyncSessionLocal() as db:
            task = ScheduledTask(
                user_id=user_id, name=name, tool_or_playbook=tool_or_playbook,
                schedule_expression=schedule_expression,
                arguments_json=arguments or {}, enabled=True,
            )
            db.add(task)
            await db.commit()
            return {"status": "ok", "scheduled_task_id": task.id}
    except Exception as e:
        return {"status": "error", "error": str(e), "message": _NA.format(tool="schedule_task")}


async def cancel_task(task_id: str, **_: Any) -> dict:
    try:
        from core.database import AsyncSessionLocal
        from agents.models import AgentTask
        from sqlalchemy import select
        from datetime import datetime
        async with AsyncSessionLocal() as db:
            result = await db.execute(select(AgentTask).where(AgentTask.id == task_id))
            task = result.scalar_one_or_none()
            if not task:
                return {"status": "error", "message": f"Task {task_id} not found"}
            task.status = "cancelled"
            task.updated_at = datetime.utcnow()
            await db.commit()
            return {"status": "ok", "task_id": task_id, "new_status": "cancelled"}
    except Exception as e:
        return {"status": "error", "error": str(e), "message": _NA.format(tool="cancel_task")}


async def get_scheduled_tasks(user_id: str = "", **_: Any) -> dict:
    try:
        from core.database import AsyncSessionLocal
        from agents.models import ScheduledTask
        from sqlalchemy import select
        async with AsyncSessionLocal() as db:
            q = select(ScheduledTask)
            if user_id:
                q = q.where(ScheduledTask.user_id == user_id)
            result = await db.execute(q)
            tasks = []
            for t in result.scalars().all():
                tasks.append({
                    "id": t.id, "name": t.name, "tool_or_playbook": t.tool_or_playbook,
                    "schedule_expression": t.schedule_expression, "enabled": t.enabled,
                    "last_run_at": t.last_run_at.isoformat() if t.last_run_at else None,
                    "next_run_at": t.next_run_at.isoformat() if t.next_run_at else None,
                })
        return {"status": "ok", "count": len(tasks), "scheduled_tasks": tasks}
    except Exception as e:
        return {"status": "error", "error": str(e), "message": _NA.format(tool="get_scheduled_tasks")}


async def run_playbook(playbook_name: str, user_id: str = "system", **_: Any) -> dict:
    try:
        from agents.playbooks import get_playbook
        plan = get_playbook(playbook_name)
        if not plan:
            return {"status": "error", "message": f"Playbook '{playbook_name}' not found"}
        return {"status": "ok", "playbook": playbook_name,
                "steps": len(plan.steps), "message": f"Playbook '{playbook_name}' queued"}
    except Exception as e:
        return {"status": "error", "error": str(e), "message": _NA.format(tool="run_playbook")}
