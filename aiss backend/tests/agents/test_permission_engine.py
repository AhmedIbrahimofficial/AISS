"""Unit tests for PermissionEngine — Requirements 3.1–3.6"""
from __future__ import annotations
import pytest
from agents.permission_engine import PermissionEngine
from agents.tool_registry import ToolDefinition, ToolCategory, RiskLevel
from agents.exceptions import PermissionDeniedError, PrivilegeEscalationError
from agents.schemas import ExecutionPlan, PlanStep


def _user(role: str):
    class U: id = "uid"
    u = U(); u.role = role; return u


def _tool(risk: RiskLevel, perm: str = "viewer"):
    async def h(**k): return {}
    return ToolDefinition(
        name=f"t_{risk.value}", description="", category=ToolCategory.SECURITY,
        input_schema={"type": "object"}, output_schema={"type": "object"},
        permission_required=perm, risk_level=risk,
        timeout_seconds=30, audit_required=True, handler=h,
    )


def test_viewer_plus_admin_tool_denied():
    engine = PermissionEngine()
    with pytest.raises(PermissionDeniedError):
        engine.check(_user("viewer"), _tool(RiskLevel.LOW, "admin"))


def test_analyst_plus_analyst_tool_allowed():
    engine = PermissionEngine()
    result = engine.check(_user("analyst"), _tool(RiskLevel.MEDIUM, "analyst"))
    assert result.allowed is True


def test_high_tool_requires_approval_for_all():
    engine = PermissionEngine()
    for role in ["viewer", "analyst", "admin"]:
        result = engine.check(_user(role), _tool(RiskLevel.HIGH, "viewer"))
        assert result.requires_approval is True


def test_critical_tool_requires_approval_for_admin():
    engine = PermissionEngine()
    result = engine.check(_user("admin"), _tool(RiskLevel.CRITICAL, "viewer"))
    assert result.requires_approval is True


def test_plan_with_escalating_tool_raises():
    engine = PermissionEngine()
    from agents.tool_registry import ToolRegistry
    tools = [_tool(RiskLevel.LOW, "admin")]  # admin-only tool
    with pytest.raises(PrivilegeEscalationError):
        engine.validate_tools_scope(tools, _user("analyst"))
