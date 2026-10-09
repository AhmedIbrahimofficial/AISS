"""Unit tests for ToolRegistry — Requirements 2.1–2.6"""
from __future__ import annotations
import pytest
from agents.tool_registry import ToolRegistry, ToolDefinition, ToolCategory, RiskLevel
from agents.exceptions import ToolNotFoundError, ToolArgValidationError


def _make_tool(name: str = "test_tool") -> ToolDefinition:
    async def h(**k): return {}
    return ToolDefinition(
        name=name, description="Test", category=ToolCategory.SYSTEM,
        input_schema={"type": "object", "properties": {"x": {"type": "string"}}, "required": ["x"]},
        output_schema={"type": "object"},
        permission_required="viewer", risk_level=RiskLevel.LOW,
        timeout_seconds=30, audit_required=True, handler=h,
    )


def test_lookup_raises_on_unknown():
    r = ToolRegistry()
    with pytest.raises(ToolNotFoundError):
        r.lookup("nonexistent_tool")


def test_lookup_returns_registered_tool():
    r = ToolRegistry()
    t = _make_tool("my_tool")
    r.register(t)
    assert r.lookup("my_tool") is t


def test_validate_args_raises_on_invalid():
    r = ToolRegistry()
    t = _make_tool()
    r.register(t)
    with pytest.raises(ToolArgValidationError):
        r.validate_args(t, {})  # missing required "x"


def test_validate_args_passes_for_valid():
    r = ToolRegistry()
    t = _make_tool()
    r.register(t)
    r.validate_args(t, {"x": "hello"})  # should not raise


def test_catalogue_includes_all_tools():
    r = ToolRegistry()
    for i in range(3):
        r.register(_make_tool(f"tool_{i}"))
    catalogue = r.get_catalogue()
    assert len(catalogue) == 3
    names = [t.name for t in catalogue]
    assert "tool_0" in names and "tool_2" in names


def test_duplicate_registration_raises():
    r = ToolRegistry()
    t = _make_tool("dup_tool")
    r.register(t)
    with pytest.raises(ValueError):
        r.register(t)
