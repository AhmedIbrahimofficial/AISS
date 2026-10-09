"""
Agentic AI Orchestrator — ApprovalManager

Manages the human-in-the-loop approval gate for HIGH/CRITICAL tools.
Uses asyncio.Event per approval to suspend task execution until the
user approves or rejects, or the timeout expires.

Requirements: 4.1–4.7
"""
from __future__ import annotations

import asyncio
import logging
from datetime import datetime
from typing import TYPE_CHECKING

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from agents.exceptions import ApprovalBypassAttemptError, ApprovalTimeoutError
from agents.models import Approval, AgentTask
from agents.schemas import ApprovalDecision

if TYPE_CHECKING:
    from core.websocket_manager import WebSocketManager
    from agents.audit_logger import AuditLogger
    from agents.tool_registry import ToolDefinition

logger = logging.getLogger("agents.approval_manager")


class ApprovalManager:
    """
    Manages pending approval gates.

    One asyncio.Event is stored per approval_id.  The orchestrator's
    execution loop suspends on `wait_for_decision()`.  The API route
    handler calls `approve()` or `reject()` which sets the event and
    resumes the loop.
    """

    def __init__(
        self,
        ws_manager: "WebSocketManager",
        audit_logger: "AuditLogger",
    ) -> None:
        self._ws_manager   = ws_manager
        self._audit_logger = audit_logger
        # approval_id -> asyncio.Event
        self._pending: dict[str, asyncio.Event] = {}
        # approval_id -> ApprovalDecision (set when event fires)
        self._decisions: dict[str, ApprovalDecision] = {}

    # ------------------------------------------------------------------
    # Create
    # ------------------------------------------------------------------

    async def create_approval(
        self,
        task: AgentTask,
        tool: "ToolDefinition",
        description: str,
        reason: str,
        affected_resource: str,
        db: AsyncSession,
        estimated_impact: str | None = None,
    ) -> "Approval":
        """
        Persist an Approval record and broadcast a WebSocket event.
        Stores an asyncio.Event keyed by the approval ID.
        Logs an audit event.
        """
        approval = Approval(
            task_id           = task.id,
            tool_name         = tool.name,
            risk_level        = tool.risk_level.value,
            description       = description,
            reason            = reason,
            affected_resource = affected_resource,
            estimated_impact  = estimated_impact,
            status            = "pending",
            created_at        = datetime.utcnow(),
        )
        db.add(approval)
        await db.flush()  # get the ID

        # Register event before broadcasting
        self._pending[approval.id] = asyncio.Event()

        # Broadcast to frontend
        try:
            await self._ws_manager.broadcast(
                user_id=task.user_id,
                data={
                    "event":             "agent_approval_required",
                    "task_id":           task.id,
                    "approval_id":       approval.id,
                    "tool_name":         tool.name,
                    "risk_level":        tool.risk_level.value,
                    "description":       description,
                    "reason":            reason,
                    "affected_resource": affected_resource,
                    "estimated_impact":  estimated_impact,
                },
            )
        except Exception as ws_err:
            logger.warning("ApprovalManager: WS broadcast failed: %s", ws_err)

        # Audit
        try:
            await self._audit_logger.log(
                db,
                user_id           = task.user_id,
                event_type        = "approval_created",
                severity          = "info",
                request_summary   = f"Approval required for tool '{tool.name}' on task {task.id}",
                tool_name         = tool.name,
                risk_level        = tool.risk_level.value,
                approval_status   = "pending",
            )
        except Exception as audit_err:
            logger.warning("ApprovalManager: audit log failed: %s", audit_err)

        return approval

    # ------------------------------------------------------------------
    # Wait
    # ------------------------------------------------------------------

    async def wait_for_decision(
        self,
        approval_id: str,
        timeout: int = 3600,
    ) -> ApprovalDecision:
        """
        Suspend until the user approves/rejects or the timeout expires.
        Returns ApprovalDecision.EXPIRED on timeout.
        """
        event = self._pending.get(approval_id)
        if event is None:
            raise ValueError(f"No pending approval found for id '{approval_id}'")

        try:
            await asyncio.wait_for(event.wait(), timeout=timeout)
            decision = self._decisions.get(approval_id, ApprovalDecision.REJECTED)
        except asyncio.TimeoutError:
            decision = ApprovalDecision.EXPIRED

        # Cleanup
        self._pending.pop(approval_id, None)
        self._decisions.pop(approval_id, None)

        return decision

    # ------------------------------------------------------------------
    # Approve
    # ------------------------------------------------------------------

    async def approve(
        self,
        approval_id: str,
        decided_by: str,
        db: AsyncSession,
    ) -> None:
        """Mark the approval as approved and wake the waiting coroutine."""
        result = await db.execute(select(Approval).where(Approval.id == approval_id))
        approval = result.scalar_one_or_none()
        if approval is None:
            raise ValueError(f"Approval '{approval_id}' not found.")
        if approval.status != "pending":
            raise ValueError(f"Approval '{approval_id}' is already '{approval.status}'.")

        approval.status     = "approved"
        approval.decided_at = datetime.utcnow()
        approval.decided_by = decided_by
        await db.flush()

        try:
            await self._audit_logger.log(
                db,
                user_id         = decided_by,
                event_type      = "approval_approved",
                severity        = "info",
                request_summary = f"Approval {approval_id} approved by {decided_by}",
                tool_name       = approval.tool_name,
                risk_level      = approval.risk_level,
                approval_status = "approved",
            )
        except Exception as e:
            logger.warning("ApprovalManager: audit log for approve failed: %s", e)

        self._decisions[approval_id] = ApprovalDecision.APPROVED
        if approval_id in self._pending:
            self._pending[approval_id].set()

    # ------------------------------------------------------------------
    # Reject
    # ------------------------------------------------------------------

    async def reject(
        self,
        approval_id: str,
        decided_by: str,
        db: AsyncSession,
    ) -> None:
        """Mark the approval as rejected and wake the waiting coroutine."""
        result = await db.execute(select(Approval).where(Approval.id == approval_id))
        approval = result.scalar_one_or_none()
        if approval is None:
            raise ValueError(f"Approval '{approval_id}' not found.")
        if approval.status != "pending":
            raise ValueError(f"Approval '{approval_id}' is already '{approval.status}'.")

        approval.status     = "rejected"
        approval.decided_at = datetime.utcnow()
        approval.decided_by = decided_by
        await db.flush()

        try:
            await self._audit_logger.log(
                db,
                user_id         = decided_by,
                event_type      = "approval_rejected",
                severity        = "info",
                request_summary = f"Approval {approval_id} rejected by {decided_by}",
                tool_name       = approval.tool_name,
                risk_level      = approval.risk_level,
                approval_status = "rejected",
            )
        except Exception as e:
            logger.warning("ApprovalManager: audit log for reject failed: %s", e)

        self._decisions[approval_id] = ApprovalDecision.REJECTED
        if approval_id in self._pending:
            self._pending[approval_id].set()
