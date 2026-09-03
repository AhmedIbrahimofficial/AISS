"""
Agentic AI Orchestrator — SchedulerEngine

Wraps APScheduler AsyncIOScheduler to run recurring security tasks.
Default tasks seeded on first startup:
  - check_critical_vulns  every 24h
  - check_devices         every 6h
  - weekly_report         every 7d
  - investigate_suspicious on-demand trigger

Requirements: 12.1–12.7
"""
from __future__ import annotations

import asyncio
import logging
import os
from datetime import datetime
from typing import TYPE_CHECKING, Any

from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.cron import CronTrigger
from apscheduler.triggers.interval import IntervalTrigger
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from agents.models import AgentExecution, AgentTask, ScheduledTask

if TYPE_CHECKING:
    from agents.orchestrator import AgentOrchestrator

logger = logging.getLogger("agents.scheduler")

_MAX_CONCURRENT = 5

# Well-known UUID for the system user (created automatically if missing)
_SYSTEM_USER_UUID = "00000000-0000-0000-0000-000000000001"
_SYSTEM_USER_ID: str | None = None  # resolved at seed time


async def resolve_system_user_id(db: AsyncSession) -> str:
    """Ensure a system user exists in the users table and return its ID.

    If no admin/system user exists, create one with a well-known UUID.
    """
    from core.models import User

    # Try to find an existing admin user first
    admin = await db.scalar(select(User).where(User.role == "admin").limit(1))
    if admin:
        return admin.id

    # Fall back to any existing user
    any_user = await db.scalar(select(User).limit(1))
    if any_user:
        return any_user.id

    # No users at all — create a system user with the well-known UUID
    from auth.utils.password import hash_password
    system_user = User(
        id=_SYSTEM_USER_UUID,
        username="aiss-system",
        email="system@aiss-platform.com",
        hashed_password=hash_password("system-internal-only"),
        role="admin",
        is_active=True,
        is_verified=True,
    )
    db.add(system_user)
    await db.flush()
    logger.info("Created system user (id=%s) for scheduled tasks", _SYSTEM_USER_UUID)
    return _SYSTEM_USER_UUID

_DEFAULT_TASKS = [
    {
        "name": "check_critical_vulnerabilities",
        "description": "Daily check for critical vulnerabilities",
        "tool_or_playbook": "get_vulnerabilities",
        "arguments_json": {"limit": 100},
        "schedule_expression": "interval:86400",
        "enabled": True,
    },
    {
        "name": "check_connected_devices",
        "description": "Every 6 hours check for connected devices",
        "tool_or_playbook": "get_connected_devices",
        "arguments_json": {},
        "schedule_expression": "interval:21600",
        "enabled": True,
    },
    {
        "name": "weekly_security_report",
        "description": "Auto-generate weekly security PDF report",
        "tool_or_playbook": "generate_security_report",
        "arguments_json": {},
        "schedule_expression": "interval:604800",
        "enabled": True,
    },
    {
        "name": "investigate_suspicious_activity",
        "description": "Investigate suspicious security events",
        "tool_or_playbook": "get_security_events",
        "arguments_json": {"limit": 50},
        "schedule_expression": "interval:3600",
        "enabled": True,
    },
]


class SchedulerEngine:
    """APScheduler-based task engine with concurrency cap."""

    def __init__(self, orchestrator: "AgentOrchestrator") -> None:
        self._orchestrator = orchestrator
        self._scheduler = AsyncIOScheduler()
        self._semaphore = asyncio.Semaphore(_MAX_CONCURRENT)
        self._db_factory: Any = None  # set via init

    def set_db_factory(self, factory: Any) -> None:
        """Inject the AsyncSessionLocal factory."""
        self._db_factory = factory

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    async def start(self) -> None:
        self._scheduler.start()
        logger.info("SchedulerEngine started.")

    async def shutdown(self) -> None:
        self._scheduler.shutdown(wait=False)
        logger.info("SchedulerEngine shut down.")

    # ------------------------------------------------------------------
    # Default seed
    # ------------------------------------------------------------------

    async def seed_defaults(self, db: AsyncSession) -> None:
        """Insert default ScheduledTask rows if not already present."""
        global _SYSTEM_USER_ID
        _SYSTEM_USER_ID = await resolve_system_user_id(db)

        for task_def in _DEFAULT_TASKS:
            existing = await db.execute(
                select(ScheduledTask).where(ScheduledTask.name == task_def["name"])
            )
            if existing.scalar_one_or_none() is not None:
                continue

            st = ScheduledTask(
                user_id=_SYSTEM_USER_ID,
                name=task_def["name"],
                description=task_def["description"],
                tool_or_playbook=task_def["tool_or_playbook"],
                arguments_json=task_def["arguments_json"],
                schedule_expression=task_def["schedule_expression"],
                enabled=task_def["enabled"],
            )
            db.add(st)
            await db.flush()

            try:
                self._add_apscheduler_job(st)
                logger.info("Seeded default scheduled task: %s", st.name)
            except Exception as e:
                logger.warning("Failed to add APScheduler job for %s: %s", st.name, e)

        await db.commit()

    # ------------------------------------------------------------------
    # Job management
    # ------------------------------------------------------------------

    async def add_job(self, scheduled_task: ScheduledTask) -> str:
        """Add a new APScheduler job and return its job ID."""
        return self._add_apscheduler_job(scheduled_task)

    def _add_apscheduler_job(self, st: ScheduledTask) -> str:
        trigger = self._parse_trigger(st.schedule_expression)
        job_id = f"st_{st.id}"
        self._scheduler.add_job(
            func=self._run_scheduled_task,
            trigger=trigger,
            id=job_id,
            args=[st.id],
            replace_existing=True,
            misfire_grace_time=300,
        )
        return job_id

    async def remove_job(self, scheduled_task_id: str) -> None:
        job_id = f"st_{scheduled_task_id}"
        try:
            self._scheduler.remove_job(job_id)
        except Exception:
            pass

    # ------------------------------------------------------------------
    # Execution runner
    # ------------------------------------------------------------------

    async def _run_scheduled_task(self, scheduled_task_id: str) -> None:
        """Execute a scheduled task under the concurrency semaphore."""
        async with self._semaphore:
            if self._db_factory is None:
                logger.error("SchedulerEngine: db_factory not set")
                return
            try:
                async with self._db_factory() as db:
                    result = await db.execute(
                        select(ScheduledTask).where(ScheduledTask.id == scheduled_task_id)
                    )
                    st = result.scalar_one_or_none()
                    if st is None or not st.enabled:
                        return

                    # Resolve a valid user_id (must not be None for agent_tasks)
                    task_user_id = st.user_id or _SYSTEM_USER_ID
                    if not task_user_id:
                        task_user_id = await resolve_system_user_id(db)

                    # Create agent task
                    task = AgentTask(
                        user_id=task_user_id,
                        description=f"Scheduled: {st.name}",
                        status="running",
                        playbook_name=st.tool_or_playbook if st.tool_or_playbook.startswith("full_") else None,
                    )
                    db.add(task)
                    await db.flush()

                    # Create execution record
                    execution = AgentExecution(
                        task_id=task.id, status="running",
                        started_at=datetime.utcnow(),
                    )
                    db.add(execution)
                    await db.flush()

                    try:
                        # Run via tool registry directly (no LLM planning for scheduled tasks)
                        from agents.tool_registry import get_registry
                        registry = get_registry()
                        tool_def = registry.lookup(st.tool_or_playbook)
                        args = st.arguments_json or {}
                        result_data = await asyncio.wait_for(
                            tool_def.handler(**args),
                            timeout=tool_def.timeout_seconds,
                        )
                        execution.status = "completed"
                        task.status = "completed"
                    except Exception as exc:
                        logger.warning("Scheduled task %s failed: %s", st.name, exc)
                        execution.status = "failed"
                        execution.error_message = str(exc)
                        task.status = "failed"
                        task.error_message = str(exc)

                    now = datetime.utcnow()
                    execution.completed_at = now
                    execution.duration_seconds = (now - execution.started_at).total_seconds()
                    task.completed_at = now
                    task.updated_at = now
                    st.last_run_at = now
                    await db.commit()

            except Exception as exc:
                logger.error("SchedulerEngine._run_scheduled_task error for %s: %s",
                             scheduled_task_id, exc)

    # ------------------------------------------------------------------
    # Trigger parsing
    # ------------------------------------------------------------------

    @staticmethod
    def _parse_trigger(expression: str) -> Any:
        """
        Parse schedule expression:
          - "interval:<seconds>"  → IntervalTrigger
          - "cron:<expr>"         → CronTrigger (standard 5-field)
          - bare cron string      → CronTrigger
        """
        if expression.startswith("interval:"):
            seconds = int(expression.split(":", 1)[1])
            return IntervalTrigger(seconds=seconds)
        if expression.startswith("cron:"):
            expr = expression[5:]
        else:
            expr = expression
        parts = expr.split()
        if len(parts) == 5:
            minute, hour, day, month, dow = parts
            return CronTrigger(
                minute=minute, hour=hour, day=day,
                month=month, day_of_week=dow,
            )
        # Fallback: daily
        return IntervalTrigger(seconds=86400)
