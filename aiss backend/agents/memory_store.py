"""
Agentic AI Orchestrator — AgentMemoryStore

Manages two memory tiers:
  - Short-term: in-process dict keyed by task_id (discarded on terminal state)
  - Long-term: persistent DB queries for investigations and findings

Requirements: 7.1–7.6
"""
from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import select, desc
from sqlalchemy.ext.asyncio import AsyncSession

from agents.models import AgentTask, SecurityFinding
from agents.schemas import MemoryContext


class AgentMemoryStore:
    """
    Two-tier memory store for the Orchestrator.

    Short-term:  per-task dict of StepResult dicts, held in process memory.
                 Discarded immediately when a task reaches a terminal state.
    Long-term:   DB-persisted records (AgentTask plan_json summaries,
                 SecurityFinding records) queried at task-start to build context.

    Secrets are never stored: summaries are plain text and never contain
    raw credentials, API keys, or tokens.
    """

    def __init__(self) -> None:
        # task_id -> list of step-result dicts (in-process only)
        self._short_term: dict[str, list[dict[str, Any]]] = {}

    # ------------------------------------------------------------------
    # Long-term context retrieval
    # ------------------------------------------------------------------

    async def get_context(
        self,
        user_id: str,
        task_id: str,
        db: AsyncSession,
    ) -> MemoryContext:
        """
        Build a MemoryContext for injection into the LLM system prompt.

        Fetches:
        - recent_investigations: last 5 completed AgentTask records for the user
        - past_findings: last 10 SecurityFinding records across those tasks
        - known_threats: empty list (populated by security-tool results at runtime)
        """
        # Fetch last 5 completed tasks for this user
        task_result = await db.execute(
            select(AgentTask)
            .where(AgentTask.user_id == user_id)
            .where(AgentTask.status == "completed")
            .order_by(desc(AgentTask.created_at))
            .limit(5)
        )
        recent_tasks = task_result.scalars().all()

        recent_investigations = [
            {
                "id":           t.id,
                "description":  t.description,
                "status":       t.status,
                "created_at":   t.created_at.isoformat() if t.created_at else None,
                "playbook_name": t.playbook_name,
            }
            for t in recent_tasks
        ]

        # Fetch last 10 findings across those tasks
        past_findings: list[dict[str, Any]] = []
        if recent_tasks:
            task_ids = [t.id for t in recent_tasks]
            finding_result = await db.execute(
                select(SecurityFinding)
                .where(SecurityFinding.task_id.in_(task_ids))
                .order_by(desc(SecurityFinding.created_at))
                .limit(10)
            )
            findings = finding_result.scalars().all()
            past_findings = [
                {
                    "finding_type":      f.finding_type,
                    "severity":          f.severity,
                    "title":             f.title,
                    "affected_resource": f.affected_resource,
                    "mitre_technique":   f.mitre_technique,
                    "created_at":        f.created_at.isoformat() if f.created_at else None,
                }
                for f in findings
            ]

        return MemoryContext(
            user_id=user_id,
            recent_investigations=recent_investigations,
            known_threats=[],   # populated by threat-intelligence tool results
            past_findings=past_findings,
        )

    # ------------------------------------------------------------------
    # Short-term memory
    # ------------------------------------------------------------------

    def store_step_result(
        self,
        task_id: str,
        step_index: int,
        tool_name: str,
        result: dict[str, Any],
        status: str = "completed",
        error: str | None = None,
    ) -> None:
        """Store a step result in short-term in-process memory."""
        if task_id not in self._short_term:
            self._short_term[task_id] = []
        self._short_term[task_id].append(
            {
                "step_index": step_index,
                "tool_name":  tool_name,
                "result":     result,
                "status":     status,
                "error":      error,
                "timestamp":  datetime.utcnow().isoformat(),
            }
        )

    def get_short_term(self, task_id: str) -> list[dict[str, Any]]:
        """Return all short-term step results for a task (empty list if none)."""
        return list(self._short_term.get(task_id, []))

    def discard_short_term(self, task_id: str) -> None:
        """
        Remove short-term memory for a task when it reaches a terminal state
        (completed, failed, cancelled, timed_out, etc.).
        Called immediately — no grace period.
        """
        self._short_term.pop(task_id, None)

    # ------------------------------------------------------------------
    # Long-term persistence helpers
    # ------------------------------------------------------------------

    async def commit_investigation_summary(
        self,
        task_id: str,
        user_id: str,
        summary: str,
        risk_level: str,
        db: AsyncSession,
    ) -> None:
        """
        Persist investigation summary into the AgentTask's plan_json field
        under the key 'investigation_summary'.  This makes the summary
        available to future long-term context lookups.

        The summary must be plain text; it is NOT allowed to contain secrets.
        """
        result = await db.execute(
            select(AgentTask).where(
                AgentTask.id == task_id,
                AgentTask.user_id == user_id,
            )
        )
        task = result.scalar_one_or_none()
        if task is None:
            return

        existing_plan = task.plan_json or {}
        existing_plan["investigation_summary"] = summary
        existing_plan["risk_level"] = risk_level
        existing_plan["summary_at"] = datetime.utcnow().isoformat()

        task.plan_json = existing_plan
        task.updated_at = datetime.utcnow()
        await db.flush()
