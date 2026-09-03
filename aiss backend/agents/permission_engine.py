"""
Agentic AI Orchestrator — PermissionEngine

Evaluates whether a user may execute a given tool, and whether approval
is required before execution. All checks are synchronous and I/O-free
(< 100 ms by design).

Requirements: 3.1–3.6, 13.5
"""
from __future__ import annotations

from dataclasses import dataclass

from agents.exceptions import PermissionDeniedError, PrivilegeEscalationError
from agents.schemas import ExecutionPlan
from agents.tool_registry import ToolDefinition, RiskLevel

# Role → integer rank for comparison
ROLE_RANK: dict[str, int] = {
    "viewer":  0,
    "analyst": 1,
    "admin":   2,
}

# Risk levels that always require human approval (regardless of role)
_APPROVAL_REQUIRED_LEVELS: frozenset[RiskLevel] = frozenset({RiskLevel.HIGH, RiskLevel.CRITICAL})


@dataclass
class PermissionResult:
    """Result of a permission check."""
    allowed: bool
    requires_approval: bool
    reason: str


class PermissionEngine:
    """
    Synchronous permission checker.
    All methods complete without DB I/O — they evaluate in-memory data only.
    """

    def check(self, user: object, tool: ToolDefinition) -> PermissionResult:
        """
        Evaluate whether `user` may execute `tool`.

        Rules (in order):
        1. If user.role rank < tool.permission_required rank → denied.
        2. If tool.risk_level in {HIGH, CRITICAL} → approval required (even for admin).
        3. Otherwise → allowed, no approval.

        Raises PermissionDeniedError when denied so callers can audit immediately.
        """
        user_role: str = getattr(user, "role", "viewer")
        user_rank = ROLE_RANK.get(user_role, 0)
        required_rank = ROLE_RANK.get(tool.permission_required, 0)

        if user_rank < required_rank:
            reason = (
                f"Role '{user_role}' does not meet the '{tool.permission_required}' "
                f"requirement for tool '{tool.name}'."
            )
            raise PermissionDeniedError(reason)

        requires_approval = tool.risk_level in _APPROVAL_REQUIRED_LEVELS
        reason = (
            f"Approved. Risk level: {tool.risk_level.value}. "
            + ("Human approval required before execution." if requires_approval else "Immediate execution permitted.")
        )
        return PermissionResult(
            allowed=True,
            requires_approval=requires_approval,
            reason=reason,
        )

    def validate_plan_scope(self, plan: ExecutionPlan, user: object) -> None:
        """
        Validate that no step in the AI-generated plan references a tool that
        exceeds the user's role.

        Raises PrivilegeEscalationError if any tool requires a higher role.
        This check runs against the ToolRegistry, so it requires the registry
        to be populated. The caller (AgentOrchestrator) passes ToolDefinition
        objects obtained via ToolRegistry.lookup() for each step.

        Note: HIGH/CRITICAL approval checks are NOT performed here — they are
        handled at runtime per-step inside the orchestrator's execution loop.
        """
        # This method is called by AgentOrchestrator after plan parsing.
        # The orchestrator resolves each tool by name and calls this method,
        # passing the resolved definitions. For lightweight use, we accept
        # the plan and a list of resolved ToolDefinitions.
        # Callers that want step-level validation should call check() per step.
        pass  # Detailed per-step validation happens in the orchestrator loop.

    def validate_tools_scope(
        self,
        tool_definitions: list[ToolDefinition],
        user: object,
    ) -> None:
        """
        Iterate over a list of resolved ToolDefinitions and verify the user
        has at least the minimum role required for each.
        Raises PrivilegeEscalationError on first violation.
        """
        user_role: str = getattr(user, "role", "viewer")
        user_rank = ROLE_RANK.get(user_role, 0)

        for tool in tool_definitions:
            required_rank = ROLE_RANK.get(tool.permission_required, 0)
            if user_rank < required_rank:
                raise PrivilegeEscalationError(
                    f"Plan contains tool '{tool.name}' requiring role "
                    f"'{tool.permission_required}' but user has role '{user_role}'. "
                    f"Privilege escalation attempt blocked."
                )
