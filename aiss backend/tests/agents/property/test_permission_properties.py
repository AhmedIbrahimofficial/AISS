"""
Property-based tests for PermissionEngine.

Property 6: HIGH/CRITICAL tools always produce an Approval requirement.
Property 7: Task halted while approval pending (status check).

Validates: Requirements 3.3, 4.1, 4.3
Feature: agentic-ai-orchestrator
"""
from __future__ import annotations

import pytest
from hypothesis import given, settings, HealthCheck
from hypothesis import strategies as st

from agents.permission_engine import PermissionEngine, ROLE_RANK
from agents.tool_registry import ToolDefinition, ToolCategory, RiskLevel
from agents.exceptions import PermissionDeniedError


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_user(role: str = "analyst"):
    class FakeUser:
        id = "user-test-id"
    user = FakeUser()
    user.role = role
    return user


def _make_tool(risk_level: RiskLevel, permission_required: str = "viewer") -> ToolDefinition:
    async def handler(**k): return {}
    return ToolDefinition(
        name=f"tool_{risk_level.value}",
        description="Test",
        category=ToolCategory.SECURITY,
        input_schema={"type": "object"},
        output_schema={"type": "object"},
        permission_required=permission_required,
        risk_level=risk_level,
        timeout_seconds=30,
        audit_required=True,
        handler=handler,
    )


# ---------------------------------------------------------------------------
# Property 6: HIGH/CRITICAL tools always require approval for ANY role
# ---------------------------------------------------------------------------

@given(
    risk_level=st.sampled_from([RiskLevel.HIGH, RiskLevel.CRITICAL]),
    role=st.sampled_from(["viewer", "analyst", "admin"]),
)
@settings(max_examples=100, suppress_health_check=[HealthCheck.too_slow])
def test_property6_high_critical_always_require_approval(risk_level: RiskLevel, role: str):
    """
    Property 6: For any HIGH or CRITICAL tool and any user role,
    the PermissionEngine SHALL set requires_approval=True.
    This applies to ALL roles including admin.

    Validates: Requirements 3.3, 4.1
    """
    engine = PermissionEngine()
    user = _make_user(role)
    tool = _make_tool(risk_level, permission_required="viewer")  # viewer = any role passes

    result = engine.check(user, tool)

    assert result.requires_approval is True, (
        f"HIGH/CRITICAL tool '{tool.name}' (risk={risk_level.value}) "
        f"should require approval for role '{role}', "
        f"but requires_approval={result.requires_approval}"
    )
    assert result.allowed is True, (
        f"User with role '{role}' should be allowed to request approval "
        f"for tool requiring 'viewer'"
    )


@given(
    risk_level=st.sampled_from([RiskLevel.LOW, RiskLevel.MEDIUM]),
    role=st.sampled_from(["analyst", "admin"]),
)
@settings(max_examples=50, suppress_health_check=[HealthCheck.too_slow])
def test_property6_low_medium_do_not_require_approval(risk_level: RiskLevel, role: str):
    """
    LOW and MEDIUM tools should NOT require approval for sufficiently privileged users.

    Validates: Requirements 3.2
    """
    engine = PermissionEngine()
    user = _make_user(role)
    tool = _make_tool(risk_level, permission_required="viewer")

    result = engine.check(user, tool)

    assert result.requires_approval is False, (
        f"LOW/MEDIUM tool should not require approval, "
        f"but got requires_approval=True for risk={risk_level.value}, role={role}"
    )


# ---------------------------------------------------------------------------
# Property 7: Permission denied when role rank is insufficient
# ---------------------------------------------------------------------------

@given(
    user_role=st.sampled_from(["viewer"]),
    required_role=st.sampled_from(["analyst", "admin"]),
)
@settings(max_examples=50, suppress_health_check=[HealthCheck.too_slow])
def test_property7_insufficient_role_raises_permission_denied(user_role: str, required_role: str):
    """
    When a user's role rank is less than the tool's permission_required rank,
    PermissionEngine.check MUST raise PermissionDeniedError.

    Validates: Requirements 3.4
    """
    engine = PermissionEngine()
    user = _make_user(user_role)
    tool = _make_tool(RiskLevel.LOW, permission_required=required_role)

    with pytest.raises(PermissionDeniedError):
        engine.check(user, tool)


def test_admin_can_access_all_tools():
    """Admin can access any tool including admin-only tools."""
    engine = PermissionEngine()
    user = _make_user("admin")

    for perm in ["viewer", "analyst", "admin"]:
        tool = _make_tool(RiskLevel.LOW, permission_required=perm)
        result = engine.check(user, tool)
        assert result.allowed is True


def test_viewer_denied_analyst_tool():
    """Viewer cannot access analyst-required tools."""
    engine = PermissionEngine()
    user = _make_user("viewer")
    tool = _make_tool(RiskLevel.LOW, permission_required="analyst")

    with pytest.raises(PermissionDeniedError):
        engine.check(user, tool)
