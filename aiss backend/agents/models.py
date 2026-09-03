"""AISS Platform — Agentic AI Orchestrator ORM Models

All models use core.models.Base (shared declarative base) and follow
the UUID-string primary key pattern established in the existing codebase.

Tables:
    agent_tasks, agent_executions, tool_executions, approvals,
    scheduled_tasks, reports, security_findings, agent_audit_events

Requirements: 14.1 – 14.8
"""

import uuid
from datetime import datetime

from sqlalchemy import (
    Boolean, Column, DateTime, Float, Integer,
    String, Text, JSON, ForeignKey, Index,
)
from sqlalchemy.orm import relationship

from core.models import Base


# ── Helpers ───────────────────────────────────────────────────────────────────

def _uuid() -> str:
    return str(uuid.uuid4())


def _now() -> datetime:
    return datetime.utcnow()


# ─────────────────────────────────────────────────────────────────────────────
# 1. AGENT TASKS   (Requirement 14.1)
# ─────────────────────────────────────────────────────────────────────────────

class AgentTask(Base):
    """Top-level unit of work submitted by a user.

    Status lifecycle:
        pending → planning → running → awaiting_approval
        → completed | failed | cancelled | approval_rejected | timed_out | degraded
    """

    __tablename__ = "agent_tasks"

    id            = Column(String(36),  primary_key=True, default=_uuid)
    user_id       = Column(String(36),  ForeignKey("users.id"), nullable=False, index=True)
    status        = Column(String(32),  nullable=False, default="pending", index=True)
    description   = Column(Text,        nullable=False)
    plan_json     = Column(JSON,        nullable=True)
    playbook_name = Column(String(128), nullable=True)
    error_message = Column(Text,        nullable=True)
    created_at    = Column(DateTime,    nullable=False, default=_now, index=True)
    updated_at    = Column(DateTime,    nullable=False, default=_now, onupdate=_now)
    completed_at  = Column(DateTime,    nullable=True)

    # Relationships
    executions = relationship(
        "AgentExecution",
        back_populates="task",
        cascade="all, delete-orphan",
    )
    approvals = relationship(
        "Approval",
        back_populates="task",
        cascade="all, delete-orphan",
    )
    findings = relationship(
        "SecurityFinding",
        back_populates="task",
        cascade="all, delete-orphan",
    )

    __table_args__ = (
        Index("ix_at_user_status", "user_id", "status"),
    )

    def __repr__(self) -> str:
        return f"<AgentTask {self.id} [{self.status}]>"


# ─────────────────────────────────────────────────────────────────────────────
# 2. AGENT EXECUTIONS   (Requirement 14.2)
# ─────────────────────────────────────────────────────────────────────────────

class AgentExecution(Base):
    """A single execution run for an AgentTask.

    Status: running | completed | failed | timed_out
    """

    __tablename__ = "agent_executions"

    id               = Column(String(36), primary_key=True, default=_uuid)
    task_id          = Column(String(36), ForeignKey("agent_tasks.id"), nullable=False, index=True)
    status           = Column(String(32), nullable=False, default="running")
    steps_json       = Column(JSON,       nullable=True)   # array of step summaries
    started_at       = Column(DateTime,   nullable=False, default=_now)
    completed_at     = Column(DateTime,   nullable=True)
    duration_seconds = Column(Float,      nullable=True)
    error_message    = Column(Text,       nullable=True)

    # Relationships
    task = relationship("AgentTask", back_populates="executions")
    tool_executions = relationship(
        "ToolExecution",
        back_populates="execution",
        cascade="all, delete-orphan",
    )

    def __repr__(self) -> str:
        return f"<AgentExecution {self.id} task={self.task_id} [{self.status}]>"


# ─────────────────────────────────────────────────────────────────────────────
# 3. TOOL EXECUTIONS   (Requirement 14.3)
# ─────────────────────────────────────────────────────────────────────────────

class ToolExecution(Base):
    """A single tool call within an AgentExecution.

    arguments_json contains tool arguments with secrets already redacted.
    Status: running | completed | failed | timed_out | validation_error
    """

    __tablename__ = "tool_executions"

    id               = Column(String(36),  primary_key=True, default=_uuid)
    execution_id     = Column(String(36),  ForeignKey("agent_executions.id"), nullable=False, index=True)
    tool_name        = Column(String(128), nullable=False, index=True)
    category         = Column(String(64),  nullable=False)
    risk_level       = Column(String(16),  nullable=False)
    arguments_json   = Column(JSON,        nullable=True)   # secrets already redacted
    result_json      = Column(JSON,        nullable=True)
    status           = Column(String(32),  nullable=False, default="running")
    started_at       = Column(DateTime,    nullable=False, default=_now)
    completed_at     = Column(DateTime,    nullable=True)
    duration_seconds = Column(Float,       nullable=True)
    error_message    = Column(Text,        nullable=True)
    retry_count      = Column(Integer,     nullable=False, default=0)

    # Relationships
    execution = relationship("AgentExecution", back_populates="tool_executions")

    def __repr__(self) -> str:
        return f"<ToolExecution {self.id} tool={self.tool_name} [{self.status}]>"


# ─────────────────────────────────────────────────────────────────────────────
# 4. APPROVALS   (Requirement 14.4)
# ─────────────────────────────────────────────────────────────────────────────

class Approval(Base):
    """Human-in-the-loop approval record for HIGH/CRITICAL tools.

    Status: pending | approved | rejected | expired
    decided_by stores the user_id of the approver/rejector.
    """

    __tablename__ = "approvals"

    id                = Column(String(36),  primary_key=True, default=_uuid)
    task_id           = Column(String(36),  ForeignKey("agent_tasks.id"), nullable=False, index=True)
    tool_name         = Column(String(128), nullable=False)
    risk_level        = Column(String(16),  nullable=False)
    description       = Column(Text,        nullable=False)
    reason            = Column(Text,        nullable=False)
    affected_resource = Column(String(512), nullable=True)
    estimated_impact  = Column(Text,        nullable=True)
    status            = Column(String(16),  nullable=False, default="pending", index=True)
    created_at        = Column(DateTime,    nullable=False, default=_now)
    decided_at        = Column(DateTime,    nullable=True)
    decided_by        = Column(String(36),  nullable=True)   # user_id

    # Relationships
    task = relationship("AgentTask", back_populates="approvals")

    def __repr__(self) -> str:
        return f"<Approval {self.id} tool={self.tool_name} [{self.status}]>"


# ─────────────────────────────────────────────────────────────────────────────
# 5. SCHEDULED TASKS   (Requirement 14.5)
# ─────────────────────────────────────────────────────────────────────────────

class ScheduledTask(Base):
    """A recurring security task managed by the APScheduler engine.

    schedule_expression accepts cron expressions or "interval:<seconds>".
    """

    __tablename__ = "scheduled_tasks"

    id                  = Column(String(36),  primary_key=True, default=_uuid)
    user_id             = Column(String(36),  ForeignKey("users.id"), nullable=True, index=True)
    name                = Column(String(256), nullable=False)
    description         = Column(Text,        nullable=True)
    tool_or_playbook    = Column(String(128), nullable=False)
    arguments_json      = Column(JSON,        nullable=True)
    schedule_expression = Column(String(128), nullable=False)   # cron expr or "interval:3600"
    enabled             = Column(Boolean,     nullable=False, default=True)
    last_run_at         = Column(DateTime,    nullable=True)
    next_run_at         = Column(DateTime,    nullable=True)
    created_at          = Column(DateTime,    nullable=False, default=_now)

    __table_args__ = (
        Index("ix_st_user_enabled", "user_id", "enabled"),
    )

    def __repr__(self) -> str:
        return f"<ScheduledTask {self.id} name={self.name!r} enabled={self.enabled}>"


# ─────────────────────────────────────────────────────────────────────────────
# 6. REPORTS   (Requirement 14.6)
# ─────────────────────────────────────────────────────────────────────────────

class Report(Base):
    """PDF security report generated by ReportGenerator.

    Status: generating | ready | failed
    sha256_hash stores the integrity hash of the generated PDF file.
    """

    __tablename__ = "reports"

    id              = Column(String(36),  primary_key=True, default=_uuid)
    user_id         = Column(String(36),  ForeignKey("users.id"), nullable=False, index=True)
    period_start    = Column(DateTime,    nullable=False)
    period_end      = Column(DateTime,    nullable=False)
    status          = Column(String(16),  nullable=False, default="generating")
    generated_at    = Column(DateTime,    nullable=True)
    file_path       = Column(String(512), nullable=True)
    file_size_bytes = Column(Integer,     nullable=True)
    sha256_hash     = Column(String(64),  nullable=True)
    error_message   = Column(Text,        nullable=True)
    scope_json      = Column(JSON,        nullable=True)

    __table_args__ = (
        Index("ix_rep_user_generated", "user_id", "generated_at"),
    )

    def __repr__(self) -> str:
        return f"<Report {self.id} user={self.user_id} [{self.status}]>"


# ─────────────────────────────────────────────────────────────────────────────
# 7. SECURITY FINDINGS   (Requirement 14.7)
# ─────────────────────────────────────────────────────────────────────────────

class SecurityFinding(Base):
    """A discrete security issue discovered during an agent task execution.

    mitre_technique stores the ATT&CK technique ID (e.g. "T1059.001").
    """

    __tablename__ = "security_findings"

    id                = Column(String(36),  primary_key=True, default=_uuid)
    task_id           = Column(String(36),  ForeignKey("agent_tasks.id"), nullable=False, index=True)
    finding_type      = Column(String(64),  nullable=False, index=True)
    severity          = Column(String(16),  nullable=False, index=True)
    title             = Column(String(512), nullable=False)
    description       = Column(Text,        nullable=True)
    affected_resource = Column(String(512), nullable=True)
    mitre_technique   = Column(String(64),  nullable=True)
    recommendation    = Column(Text,        nullable=True)
    created_at        = Column(DateTime,    nullable=False, default=_now)
    resolved_at       = Column(DateTime,    nullable=True)

    # Relationships
    task = relationship("AgentTask", back_populates="findings")

    def __repr__(self) -> str:
        return f"<SecurityFinding {self.id} type={self.finding_type} [{self.severity}]>"


# ─────────────────────────────────────────────────────────────────────────────
# 8. AGENT AUDIT EVENTS   (Requirement 14.8)
# ─────────────────────────────────────────────────────────────────────────────

class AgentAuditEvent(Base):
    """Immutable audit trail for every orchestrator action.

    Records are INSERT-only — no UPDATE or DELETE endpoints exist.
    request_summary is truncated to 2 048 characters before storage.
    AuditLogger._redact_credentials ensures no secrets appear in
    arguments_redacted_json.
    """

    __tablename__ = "agent_audit_events"

    id                       = Column(String(36),   primary_key=True, default=_uuid)
    user_id                  = Column(String(36),   ForeignKey("users.id"), nullable=False, index=True)
    event_type               = Column(String(64),   nullable=False, index=True)
    severity                 = Column(String(16),   nullable=False, default="info")
    request_summary          = Column(String(2048), nullable=True)
    plan_summary             = Column(Text,         nullable=True)
    tool_name                = Column(String(128),  nullable=True)
    arguments_redacted_json  = Column(JSON,         nullable=True)
    auth_result              = Column(String(64),   nullable=True)
    execution_result_summary = Column(Text,         nullable=True)
    risk_level               = Column(String(16),   nullable=True)
    approval_status          = Column(String(16),   nullable=True)
    ai_conclusion            = Column(Text,         nullable=True)
    created_at               = Column(DateTime,     nullable=False, default=_now, index=True)

    __table_args__ = (
        Index("ix_aae_user_event", "user_id", "event_type"),
        Index("ix_aae_created",    "created_at"),
    )

    def __repr__(self) -> str:
        return f"<AgentAuditEvent {self.id} type={self.event_type} [{self.severity}]>"
