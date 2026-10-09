"""
Agentic AI Orchestrator — AgentOrchestrator

Central coordinator that:
  1. Receives chat messages / task requests
  2. Calls AIService to build an ExecutionPlan
  3. Validates plan against PermissionEngine
  4. Executes each step with approval gates, retries, and audit logging
  5. Broadcasts progress via WebSocket
  6. Persists results in DB

Requirements: 1.1–1.5, 5.1–5.7, 6.1–6.6, 9.1–9.7
"""
from __future__ import annotations

import asyncio
import logging
import os
import time
from datetime import datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from agents.ai_service import AIService
from agents.approval_manager import ApprovalManager
from agents.audit_logger import AuditLogger
from agents.exceptions import (
    AuditPersistenceError,
    LLMUnavailableError,
    PermissionDeniedError,
    PlanParseError,
    PrivilegeEscalationError,
    ToolArgValidationError,
    ToolNotFoundError,
)
from agents.memory_store import AgentMemoryStore
from agents.models import AgentExecution, AgentTask, SecurityFinding, ToolExecution
from agents.permission_engine import PermissionEngine
from agents.playbooks import get_playbook
from agents.schemas import (
    ApprovalDecision,
    ChatResponse,
    ExecutionPlan,
    OrchestratorStatusResponse,
    PlanStep,
    StepResult,
    TaskStatus,
)
from agents.security_filter import SecurityFilter
from agents.tool_registry import ToolRegistry

logger = logging.getLogger("agents.orchestrator")

_MAX_TASK_TIMEOUT = int(os.environ.get("AGENT_MAX_TASK_TIMEOUT", "1800"))
_APPROVAL_TIMEOUT = int(os.environ.get("AGENT_APPROVAL_TIMEOUT", "3600"))
_RETRY_DELAYS = [2, 4, 8]


class AgentOrchestrator:
    """Central orchestration layer — bridges user requests to tool execution."""

    def __init__(
        self,
        ai_service: AIService,
        tool_registry: ToolRegistry,
        permission_engine: PermissionEngine,
        approval_manager: ApprovalManager,
        audit_logger: AuditLogger,
        memory_store: AgentMemoryStore,
        security_filter: SecurityFilter,
        ws_manager: Any,  # WebSocketManager
    ) -> None:
        self._ai = ai_service
        self._registry = tool_registry
        self._perm = permission_engine
        self._approval = approval_manager
        self._audit = audit_logger
        self._memory = memory_store
        self._filter = security_filter
        self._ws = ws_manager
        self._running_task_ids: set[str] = set()
        self._active = True

    # ------------------------------------------------------------------
    # Public: handle a chat message
    # ------------------------------------------------------------------

    async def handle_chat(
        self,
        user: Any,
        message: str,
        session_id: str | None,
        db: AsyncSession,
    ) -> ChatResponse:
        """Full pipeline: inject filter → LLM plan → execute → summarise."""

        # 1. Prompt injection check
        if self._filter.detect_injection(message):
            await self._audit.log(
                db, user_id=user.id, event_type="prompt_injection_attempt",
                severity="warning", request_summary=message[:2048],
            )
            return ChatResponse(
                task_id="", status="rejected",
                reply="Your message contains disallowed content and was rejected.",
                created_at=datetime.utcnow(),
            )

        # 2. Create task record
        task = AgentTask(
            user_id=user.id,
            description=message[:500],
            status="planning",
        )
        db.add(task)
        await db.flush()
        self._running_task_ids.add(task.id)

        await self._broadcast(user.id, {
            "event": "agent_task_created",
            "task_id": task.id, "status": "planning", "description": task.description,
        })

        try:
            # 3. Check if message maps to a playbook
            plan = self._detect_playbook(message)
            if plan:
                task.playbook_name = self._extract_playbook_name(message)
            else:
                # 4. LLM planning
                memory_ctx = await self._memory.get_context(user.id, task.id, db)
                catalogue = self._registry.get_catalogue()
                try:
                    plan = await self._ai.plan(message, catalogue, memory_ctx)
                except PlanParseError as exc:
                    await self._audit.log(
                        db, user_id=user.id, event_type="plan_parse_error",
                        severity="warning", request_summary=message[:2048],
                        ai_conclusion=str(exc),
                    )
                    task.status = "failed"
                    task.error_message = str(exc)
                    task.updated_at = datetime.utcnow()
                    await db.flush()
                    return ChatResponse(
                        task_id=task.id, status="failed",
                        reply=f"I couldn't create a valid plan for your request. Could you rephrase? ({exc.detail})",
                        created_at=task.created_at,
                    )
                except LLMUnavailableError as exc:
                    task.status = "degraded"
                    task.error_message = str(exc)
                    task.updated_at = datetime.utcnow()
                    await db.flush()
                    await self._broadcast(user.id, {"event": "agent_task_failed",
                                                    "task_id": task.id, "error": str(exc)})
                    return ChatResponse(
                        task_id=task.id, status="degraded",
                        reply="The AI planning service is temporarily unavailable. Please try again later.",
                        created_at=task.created_at,
                    )

            # 5. Validate plan scope (privilege escalation check)
            try:
                resolved_tools = [self._registry.lookup(s.tool_name) for s in plan.steps]
                self._perm.validate_tools_scope(resolved_tools, user)
            except ToolNotFoundError as exc:
                await self._audit.log(
                    db, user_id=user.id, event_type="tool_not_found",
                    severity="warning", request_summary=message[:2048],
                )
                task.status = "failed"
                task.error_message = str(exc)
                task.updated_at = datetime.utcnow()
                await db.flush()
                return ChatResponse(
                    task_id=task.id, status="failed",
                    reply=f"The plan references an unknown tool. {exc.detail}",
                    created_at=task.created_at,
                )
            except PrivilegeEscalationError as exc:
                await self._audit.log(
                    db, user_id=user.id, event_type="privilege_escalation_attempt",
                    severity="critical", request_summary=message[:2048],
                )
                task.status = "failed"
                task.error_message = str(exc)
                task.updated_at = datetime.utcnow()
                await db.flush()
                return ChatResponse(
                    task_id=task.id, status="failed",
                    reply="The plan requires permissions beyond your current role.",
                    created_at=task.created_at,
                )

            # 6. Update task to running
            task.status = "running"
            task.plan_json = plan.model_dump()
            task.updated_at = datetime.utcnow()
            await db.flush()

            # 7. Execute plan within timeout
            try:
                execution, step_results = await asyncio.wait_for(
                    self._execute_plan(task, plan, user, db),
                    timeout=_MAX_TASK_TIMEOUT,
                )
            except asyncio.TimeoutError:
                task.status = "timed_out"
                task.updated_at = datetime.utcnow()
                await db.flush()
                await self._audit.log(
                    db, user_id=user.id, event_type="task_timed_out",
                    severity="error", request_summary=message[:2048],
                )
                return ChatResponse(
                    task_id=task.id, status="timed_out",
                    reply="The task exceeded the maximum allowed execution time and was stopped.",
                    created_at=task.created_at,
                )

            # 8. AI summary
            summary = await self._ai.summarise(step_results, message)
            task.status = "completed"
            task.completed_at = datetime.utcnow()
            task.updated_at = datetime.utcnow()
            await db.flush()

            await self._memory.commit_investigation_summary(
                task.id, user.id, summary, "medium", db
            )
            self._memory.discard_short_term(task.id)

            await self._broadcast(user.id, {
                "event": "agent_task_complete",
                "task_id": task.id, "status": "completed", "summary": summary,
            })

            return ChatResponse(
                task_id=task.id, status="completed",
                reply=summary, created_at=task.created_at,
            )

        except AuditPersistenceError as exc:
            task.status = "failed"
            task.error_message = "Audit persistence failure — execution blocked."
            task.updated_at = datetime.utcnow()
            await db.flush()
            logger.error("AuditPersistenceError blocked execution: %s", exc)
            return ChatResponse(
                task_id=task.id, status="failed",
                reply="A critical audit logging error occurred. Execution was blocked for safety.",
                created_at=task.created_at,
            )
        finally:
            self._running_task_ids.discard(task.id)

    # ------------------------------------------------------------------
    # Execute plan steps
    # ------------------------------------------------------------------

    async def _execute_plan(
        self,
        task: AgentTask,
        plan: ExecutionPlan,
        user: Any,
        db: AsyncSession,
    ) -> tuple[AgentExecution, list[StepResult]]:
        """Run all steps in the plan, collecting results."""
        execution = AgentExecution(task_id=task.id, status="running", started_at=datetime.utcnow())
        db.add(execution)
        await db.flush()

        step_results: list[StepResult] = []
        steps_summary: list[dict] = []

        for step in plan.steps:
            result = await self._execute_step(task, execution, step, user, db)
            step_results.append(result)
            steps_summary.append(result.model_dump())

        execution.status = "completed"
        execution.completed_at = datetime.utcnow()
        execution.duration_seconds = (execution.completed_at - execution.started_at).total_seconds()
        execution.steps_json = steps_summary
        await db.flush()

        return execution, step_results

    async def _execute_step(
        self,
        task: AgentTask,
        execution: AgentExecution,
        step: PlanStep,
        user: Any,
        db: AsyncSession,
    ) -> StepResult:
        """Execute a single plan step with permission check, approval gate, and retry."""
        start = time.monotonic()

        # Resolve tool
        try:
            tool_def = self._registry.lookup(step.tool_name)
        except ToolNotFoundError as exc:
            await self._audit.log(
                db, user_id=user.id, event_type="tool_not_found",
                severity="warning", tool_name=step.tool_name,
            )
            return StepResult(step_index=step.step_index, tool_name=step.tool_name,
                              status="failed", error=str(exc))

        # Permission check
        try:
            perm = self._perm.check(user, tool_def)
        except PermissionDeniedError as exc:
            await self._audit.log(
                db, user_id=user.id, event_type="permission_denied",
                severity="warning", tool_name=step.tool_name,
                risk_level=tool_def.risk_level.value, auth_result="denied",
            )
            return StepResult(step_index=step.step_index, tool_name=step.tool_name,
                              status="permission_denied", error=str(exc))

        # Approval gate for HIGH/CRITICAL
        if perm.requires_approval:
            task.status = "awaiting_approval"
            task.updated_at = datetime.utcnow()
            await db.flush()

            approval = await self._approval.create_approval(
                task=task, tool=tool_def,
                description=f"Execute '{step.tool_name}': {step.rationale}",
                reason=f"Tool risk level is {tool_def.risk_level.value}. Human approval required.",
                affected_resource=str(step.arguments.get("target", "local system")),
                db=db,
            )
            decision = await self._approval.wait_for_decision(approval.id, _APPROVAL_TIMEOUT)

            if decision == ApprovalDecision.APPROVED:
                task.status = "running"
                task.updated_at = datetime.utcnow()
                await db.flush()
            else:
                task.status = "approval_rejected" if decision == ApprovalDecision.REJECTED else "failed"
                task.updated_at = datetime.utcnow()
                await db.flush()
                return StepResult(
                    step_index=step.step_index, tool_name=step.tool_name,
                    status="approval_" + decision.value,
                    error=f"Approval was {decision.value}.",
                )

        # Arg injection check
        _, injection = self._filter.sanitize_args(step.arguments)
        if injection:
            await self._audit.log(
                db, user_id=user.id, event_type="tool_injection_attempt",
                severity="warning", tool_name=step.tool_name,
                arguments_redacted=self._audit._redact_credentials(step.arguments),
            )
            return StepResult(step_index=step.step_index, tool_name=step.tool_name,
                              status="failed", error="Tool arguments contain injection patterns.")

        # Validate args
        try:
            self._registry.validate_args(tool_def, step.arguments)
        except ToolArgValidationError as exc:
            await self._audit.log(
                db, user_id=user.id, event_type="tool_arg_validation_error",
                severity="warning", tool_name=step.tool_name,
            )
            return StepResult(step_index=step.step_index, tool_name=step.tool_name,
                              status="validation_error", error=str(exc))

        # Pre-execution audit (blocks on failure)
        await self._audit.log(
            db, user_id=user.id, event_type="tool_execution_started",
            severity="info", tool_name=step.tool_name,
            risk_level=tool_def.risk_level.value,
            arguments_redacted=self._audit._redact_credentials(step.arguments),
            auth_result="approved",
        )

        # Broadcast step started
        await self._broadcast(user.id, {
            "event": "agent_step_started",
            "task_id": task.id, "step_index": step.step_index,
            "tool_name": step.tool_name,
        })

        # Execute with retry
        tool_exec = ToolExecution(
            execution_id=execution.id,
            tool_name=step.tool_name,
            category=tool_def.category.value,
            risk_level=tool_def.risk_level.value,
            arguments_json=self._audit._redact_credentials(step.arguments),
            status="running",
            started_at=datetime.utcnow(),
        )
        db.add(tool_exec)
        await db.flush()

        result_data: dict = {}
        error_msg: str | None = None
        final_status = "completed"

        for attempt, delay in enumerate(_RETRY_DELAYS, start=1):
            try:
                result_data = await asyncio.wait_for(
                    tool_def.handler(**step.arguments),
                    timeout=tool_def.timeout_seconds,
                )
                tool_exec.retry_count = attempt - 1
                break
            except asyncio.TimeoutError:
                error_msg = f"Tool '{step.tool_name}' timed out after {tool_def.timeout_seconds}s"
                final_status = "timed_out"
                if attempt < len(_RETRY_DELAYS):
                    await asyncio.sleep(delay)
                    continue
                break
            except Exception as exc:
                error_msg = str(exc)
                if attempt < len(_RETRY_DELAYS):
                    await asyncio.sleep(delay)
                    continue
                final_status = "failed"
                break

        duration = time.monotonic() - start
        tool_exec.status = final_status
        tool_exec.completed_at = datetime.utcnow()
        tool_exec.duration_seconds = duration
        tool_exec.result_json = result_data if result_data else None
        tool_exec.error_message = error_msg
        await db.flush()

        # Post-execution audit
        try:
            await self._audit.log(
                db, user_id=user.id, event_type="tool_execution_completed",
                severity="info" if final_status == "completed" else "warning",
                tool_name=step.tool_name,
                risk_level=tool_def.risk_level.value,
                execution_result_summary=str(result_data)[:500] if result_data else error_msg,
            )
        except AuditPersistenceError:
            pass  # Post-execution audit failure is logged but does not block

        # Store in short-term memory
        self._memory.store_step_result(
            task.id, step.step_index, step.tool_name,
            result_data, final_status, error_msg
        )

        # Persist findings if result contains threats/vulns
        await self._persist_findings(task, step.tool_name, result_data, db)

        # Broadcast step complete
        await self._broadcast(user.id, {
            "event": "agent_step_complete",
            "task_id": task.id, "step_index": step.step_index,
            "tool_name": step.tool_name, "status": final_status,
            "duration_ms": int(duration * 1000),
            "result_summary": str(result_data.get("status", ""))[:200] if result_data else error_msg,
        })

        return StepResult(
            step_index=step.step_index, tool_name=step.tool_name,
            status=final_status, result=result_data or None,
            error=error_msg, duration_seconds=duration,
        )

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    async def _persist_findings(
        self, task: AgentTask, tool_name: str, result: dict, db: AsyncSession
    ) -> None:
        """Extract threats/vulns from tool results and save as SecurityFindings."""
        try:
            items = result.get("vulnerabilities") or result.get("alerts") or result.get("threats") or []
            for item in items[:10]:  # cap at 10 per tool call
                if isinstance(item, dict):
                    finding = SecurityFinding(
                        task_id=task.id,
                        finding_type=item.get("type", tool_name),
                        severity=item.get("severity", "medium"),
                        title=str(item.get("description", item.get("name", "Finding")))[:512],
                        description=str(item)[:1000],
                        affected_resource=str(item.get("source", item.get("target", "")))[:512],
                    )
                    db.add(finding)
            await db.flush()
        except Exception:
            pass  # findings are best-effort

    def _detect_playbook(self, message: str) -> ExecutionPlan | None:
        """Check if the message maps directly to a known playbook."""
        msg_lower = message.lower()
        if any(kw in msg_lower for kw in [
            "full security assessment", "complete security assessment",
            "full_security_assessment", "security assessment",
        ]):
            return get_playbook("full_security_assessment")
        return None

    def _extract_playbook_name(self, message: str) -> str:
        msg_lower = message.lower()
        if "security assessment" in msg_lower:
            return "full_security_assessment"
        return "unknown"

    async def _broadcast(self, user_id: str, data: dict) -> None:
        try:
            await self._ws.broadcast(user_id=user_id, data=data)
        except Exception:
            pass

    # ------------------------------------------------------------------
    # Task cancellation
    # ------------------------------------------------------------------

    async def cancel_task(
        self, task_id: str, user: Any, db: AsyncSession
    ) -> None:
        """Cancel a running task. Best-effort — status always set to cancelled."""
        result = await db.execute(
            select(AgentTask).where(AgentTask.id == task_id, AgentTask.user_id == user.id)
        )
        task = result.scalar_one_or_none()
        if not task:
            return

        task.status = "cancelled"
        task.updated_at = datetime.utcnow()
        await db.flush()

        self._running_task_ids.discard(task_id)
        self._memory.discard_short_term(task_id)

        try:
            await self._audit.log(
                db, user_id=user.id, event_type="task_cancelled",
                severity="info", request_summary=f"Task {task_id} cancelled by user",
            )
        except Exception:
            pass  # cancellation audit failure is non-blocking

    # ------------------------------------------------------------------
    # Status
    # ------------------------------------------------------------------

    def get_status(self) -> OrchestratorStatusResponse:
        return OrchestratorStatusResponse(
            is_active=self._active,
            running_tasks=len(self._running_task_ids),
            degraded_subsystems=[],
            llm_model=self._ai.model,
        )
