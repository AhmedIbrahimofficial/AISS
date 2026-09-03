"""
Agentic AI Orchestrator — all Pydantic request/response schemas.

All JSON response models use the ApiResponse[T] envelope:
    { "status": "ok"|"error", "data": <T>|null, "error": <str>|null }

Uses Pydantic v2 syntax throughout (model_config, model_validator, etc.).
Requirements: 17.20
"""

from __future__ import annotations

import enum
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Generic, Literal, TypeVar

from pydantic import BaseModel, Field, model_validator
from pydantic import ConfigDict

# ---------------------------------------------------------------------------
# Generic envelope
# ---------------------------------------------------------------------------

T = TypeVar("T")


class ApiResponse(BaseModel, Generic[T]):
    """Standard JSON response envelope used by every agent endpoint."""

    status: Literal["ok", "error"]
    data: T | None = None
    error: str | None = None

    model_config = ConfigDict(arbitrary_types_allowed=True)


# ---------------------------------------------------------------------------
# Status / Enum types
# ---------------------------------------------------------------------------

TaskStatus = Literal[
    "pending",
    "planning",
    "running",
    "awaiting_approval",
    "completed",
    "failed",
    "cancelled",
    "approval_rejected",
    "timed_out",
    "degraded",
]


class ApprovalDecision(str, enum.Enum):
    """Possible outcomes for a human-approval gate."""

    APPROVED = "approved"
    REJECTED = "rejected"
    EXPIRED = "expired"


# ---------------------------------------------------------------------------
# LLM / Planning types
# ---------------------------------------------------------------------------


class PlanStep(BaseModel):
    """A single step in the LLM-generated execution plan."""

    step_index: int
    tool_name: str
    arguments: dict[str, Any]
    rationale: str

    model_config = ConfigDict(frozen=False)


class ExecutionPlan(BaseModel):
    """Full multi-step plan produced by the AI planning layer."""

    steps: list[PlanStep]
    overall_rationale: str
    requires_approval: list[str] = Field(
        default_factory=list,
        description="Tool names the planner expects to require approval.",
    )


class ToolSummary(BaseModel):
    """Lightweight tool descriptor exposed in the tool catalogue."""

    name: str
    description: str
    category: str
    risk_level: str
    input_schema: dict[str, Any]


class MemoryContext(BaseModel):
    """Agent memory context injected into the LLM system prompt."""

    user_id: str
    recent_investigations: list[dict[str, Any]] = Field(default_factory=list)
    known_threats: list[dict[str, Any]] = Field(default_factory=list)
    past_findings: list[dict[str, Any]] = Field(default_factory=list)


class StepResult(BaseModel):
    """Result record for a single executed plan step."""

    step_index: int
    tool_name: str
    status: str
    result: dict[str, Any] | None = None
    error: str | None = None
    duration_seconds: float | None = None


# ---------------------------------------------------------------------------
# Request schemas
# ---------------------------------------------------------------------------


class ChatRequest(BaseModel):
    """Body for POST /agent/chat."""

    message: str = Field(..., min_length=1, max_length=4096)
    session_id: str | None = None


class CreateTaskRequest(BaseModel):
    """Body for POST /agent/tasks — either description or playbook must be provided."""

    description: str | None = None
    playbook: str | None = None

    @model_validator(mode="after")
    def _at_least_one_provided(self) -> "CreateTaskRequest":
        if self.description is None and self.playbook is None:
            raise ValueError("At least one of 'description' or 'playbook' must be provided.")
        return self


class CreateScheduledTaskRequest(BaseModel):
    """Body for POST /scheduled-tasks."""

    name: str
    description: str | None = None
    tool_or_playbook: str
    arguments_json: dict[str, Any] | None = None
    schedule_expression: str
    enabled: bool = True


class GenerateReportRequest(BaseModel):
    """Optional body for POST /reports/generate."""

    period_start: datetime | None = None
    period_end: datetime | None = None


# ---------------------------------------------------------------------------
# Nested summary types (used inside detail responses)
# ---------------------------------------------------------------------------


class ExecutionSummary(BaseModel):
    """Compact execution record used inside TaskDetailResponse."""

    id: str
    status: str
    started_at: datetime
    completed_at: datetime | None = None
    duration_seconds: float | None = None

    model_config = ConfigDict(from_attributes=True)


class ApprovalSummary(BaseModel):
    """Compact approval record used inside TaskDetailResponse."""

    id: str
    tool_name: str
    risk_level: str
    status: str
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


# ---------------------------------------------------------------------------
# Response schemas
# ---------------------------------------------------------------------------


class ChatResponse(BaseModel):
    """Returned by POST /agent/chat."""

    task_id: str
    status: str
    reply: str
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class TaskResponse(BaseModel):
    """Basic task record returned by listing / creation endpoints."""

    id: str
    status: str
    description: str
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


class TaskDetailResponse(TaskResponse):
    """Full task record including plan, executions and approvals."""

    plan_json: dict[str, Any] | None = None
    playbook_name: str | None = None
    error_message: str | None = None
    executions: list[ExecutionSummary] = Field(default_factory=list)
    approvals: list[ApprovalSummary] = Field(default_factory=list)

    model_config = ConfigDict(from_attributes=True)


class ToolExecutionDetail(BaseModel):
    """Full tool-execution record returned inside ExecutionDetailResponse."""

    id: str
    tool_name: str
    category: str
    risk_level: str
    arguments_json: dict[str, Any] | None = None
    result_json: dict[str, Any] | None = None
    status: str
    started_at: datetime
    completed_at: datetime | None = None
    duration_seconds: float | None = None
    error_message: str | None = None
    retry_count: int

    model_config = ConfigDict(from_attributes=True)


class ExecutionDetailResponse(BaseModel):
    """Full execution record with all tool-level details."""

    id: str
    task_id: str
    status: str
    steps_json: list[Any] | None = None
    started_at: datetime
    completed_at: datetime | None = None
    duration_seconds: float | None = None
    error_message: str | None = None
    tool_executions: list[ToolExecutionDetail] = Field(default_factory=list)

    model_config = ConfigDict(from_attributes=True)


class ApprovalResponse(BaseModel):
    """Full approval record returned by approval endpoints."""

    id: str
    task_id: str
    tool_name: str
    risk_level: str
    description: str
    reason: str
    affected_resource: str | None = None
    estimated_impact: str | None = None
    status: str
    created_at: datetime
    decided_at: datetime | None = None
    decided_by: str | None = None

    model_config = ConfigDict(from_attributes=True)


class ToolCatalogueResponse(BaseModel):
    """Returned by GET /agent/tools."""

    tools: list[ToolSummary]


class OrchestratorStatusResponse(BaseModel):
    """Returned by GET /agent/status."""

    is_active: bool
    running_tasks: int
    degraded_subsystems: list[str] = Field(default_factory=list)
    llm_model: str


class PaginatedExecutionsResponse(BaseModel):
    """Paginated list of execution summaries."""

    items: list[ExecutionSummary]
    total: int
    page: int
    page_size: int


class ReportResponse(BaseModel):
    """Report metadata record."""

    id: str
    user_id: str
    period_start: datetime
    period_end: datetime
    status: str
    generated_at: datetime | None = None
    file_size_bytes: int | None = None
    sha256_hash: str | None = None
    error_message: str | None = None
    scope_json: dict[str, Any] | None = None

    model_config = ConfigDict(from_attributes=True)


class PaginatedReportsResponse(BaseModel):
    """Paginated list of report records."""

    items: list[ReportResponse]
    total: int
    page: int
    page_size: int


class ScheduledTaskResponse(BaseModel):
    """Single scheduled-task record."""

    id: str
    name: str
    description: str | None = None
    tool_or_playbook: str
    arguments_json: dict[str, Any] | None = None
    schedule_expression: str
    enabled: bool
    last_run_at: datetime | None = None
    next_run_at: datetime | None = None
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class ScheduledTasksListResponse(BaseModel):
    """List of all scheduled tasks for a user."""

    items: list[ScheduledTaskResponse]


class StatusResponse(BaseModel):
    """Generic status/acknowledgement response."""

    status: str
    message: str | None = None


# ---------------------------------------------------------------------------
# Report data collector (dataclass, not a Pydantic model)
# ---------------------------------------------------------------------------


@dataclass
class ReportData:
    """
    All data collected by ReportGenerator._collect_report_data before rendering.

    This is a plain dataclass (not a Pydantic BaseModel) because it is an
    internal transfer object and never serialised directly to JSON.
    """

    user_id: str
    period_start: datetime
    period_end: datetime

    # Collected security data
    security_events: list[dict[str, Any]] = field(default_factory=list)
    threats: list[dict[str, Any]] = field(default_factory=list)
    vulnerabilities: list[dict[str, Any]] = field(default_factory=list)
    findings: list[dict[str, Any]] = field(default_factory=list)
    device_status: list[dict[str, Any]] = field(default_factory=list)
    network_summary: dict[str, Any] = field(default_factory=dict)
    audit_summary: dict[str, Any] = field(default_factory=dict)
    mitre_mappings: list[dict[str, Any]] = field(default_factory=list)

    # Computed metrics
    security_score: int = 0
    recommendations: list[str] = field(default_factory=list)
