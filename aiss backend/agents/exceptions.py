"""
Custom exception hierarchy for the Agentic AI Orchestrator.

Every exception carries a human-readable `detail` message.
Exceptions that must be recorded in the audit log also declare an
`audit_event_type` class attribute so callers can reference it without
hard-coding strings.
"""


class OrchestratorError(Exception):
    """Base class for all orchestrator exceptions."""

    audit_event_type: str | None = None

    def __init__(self, detail: str) -> None:
        self.detail = detail
        super().__init__(detail)

    def __str__(self) -> str:
        return self.detail


# ---------------------------------------------------------------------------
# LLM / Planning
# ---------------------------------------------------------------------------


class LLMUnavailableError(OrchestratorError):
    """Raised when the OpenRouter API is unreachable or returns an error.

    Requirement 9.2 — treat as critical service failure; do not fabricate output.
    """

    audit_event_type = "llm_unavailable"


class PlanParseError(OrchestratorError):
    """Raised when the LLM response cannot be parsed into a valid ExecutionPlan.

    Requirement 9.2 / 13.2 — invalid plan must be rejected and audited.
    """

    audit_event_type = "plan_parse_error"


# ---------------------------------------------------------------------------
# Tool Registry
# ---------------------------------------------------------------------------


class ToolNotFoundError(OrchestratorError):
    """Raised when the LLM plan references a tool name not in the Tool_Registry.

    Requirement 13.2 — non-existent tool references must be rejected with an audit event.
    """

    audit_event_type = "tool_not_found"


class ToolArgValidationError(OrchestratorError):
    """Raised when tool arguments fail JSON Schema validation.

    Requirements 2.3–2.4, 13.3 — invalid arguments must be rejected before execution.
    """

    audit_event_type = "tool_arg_validation_error"


# ---------------------------------------------------------------------------
# Permission / Security
# ---------------------------------------------------------------------------


class PermissionDeniedError(OrchestratorError):
    """Raised when a user's role does not meet the tool's `permission_required` level.

    Requirement 3.4 — denied execution must be logged as an audit event.
    """

    audit_event_type = "permission_denied"


class PrivilegeEscalationError(OrchestratorError):
    """Raised when an AI-generated plan attempts to grant elevated permissions.

    Requirement 3.5, 13.4 — privilege escalation attempts must be blocked and audited.
    """

    audit_event_type = "privilege_escalation_attempt"


class CrossUserAccessError(OrchestratorError):
    """Raised when a task attempts to access data scoped to a different user.

    Requirement 13.4 — cross-user access attempts must be logged with severity 'critical'.
    """

    audit_event_type = "cross_user_access_attempt"


class RateLimitExceededError(OrchestratorError):
    """Raised when a user exceeds the 60 requests/minute chat rate limit.

    Requirement 13.6 — rate limit breaches must be logged as an audit event.
    """

    audit_event_type = "rate_limit_exceeded"


# ---------------------------------------------------------------------------
# Approval
# ---------------------------------------------------------------------------


class ApprovalTimeoutError(OrchestratorError):
    """Raised when an approval is not acted upon within the 3 600-second window.

    Requirement 4.6 — expired approvals must be logged as an audit event.
    """

    audit_event_type = "approval_expired"


class ApprovalBypassAttemptError(OrchestratorError):
    """Raised when the planner attempts to skip the approval gate for a HIGH/CRITICAL tool.

    Requirement 4.7 — bypass attempts must be logged with event_type 'approval_bypass_attempt'
    and severity 'critical'.
    """

    audit_event_type = "approval_bypass_attempt"


# ---------------------------------------------------------------------------
# Audit / Data Integrity
# ---------------------------------------------------------------------------


class AuditPersistenceError(OrchestratorError):
    """Raised when writing an AgentAuditEvent to the database fails.

    Requirement 9.4 — tool execution must be blocked if the audit event cannot be persisted.
    """

    audit_event_type = "audit_persistence_error"


class OutputSchemaViolationError(OrchestratorError):
    """Raised when a tool's result fails output JSON Schema validation.

    Requirement 9.7 — schema violations must be logged and the result excluded from AI context.
    """

    audit_event_type = "output_schema_violation"
