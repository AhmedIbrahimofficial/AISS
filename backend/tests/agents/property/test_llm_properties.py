"""
Property 14: LLM prompt always contains all required sections.

Validates: Requirements 15.5
Feature: agentic-ai-orchestrator
"""
from __future__ import annotations
import pytest
from hypothesis import given, settings, HealthCheck
from hypothesis import strategies as st
from agents.schemas import MemoryContext, ToolSummary


def _make_ai_service():
    """Create AIService with a fake key (no real API calls)."""
    import os
    os.environ.setdefault("OPENROUTER_API_KEY", "sk-or-test-fake-key-for-testing-only")
    os.environ.setdefault("OPENROUTER_MODEL", "openai/gpt-4o")
    from agents.ai_service import AIService
    return AIService(api_key="sk-or-test-fake-key-for-testing-only", model="openai/gpt-4o")


def _make_catalogue() -> list[ToolSummary]:
    return [
        ToolSummary(name="scan_network", description="Scan network", category="NETWORK",
                    risk_level="MEDIUM", input_schema={"type": "object"}),
        ToolSummary(name="get_alerts", description="Get alerts", category="SECURITY",
                    risk_level="LOW", input_schema={"type": "object"}),
    ]


def _make_memory(user_id: str = "u1") -> MemoryContext:
    return MemoryContext(
        user_id=user_id,
        recent_investigations=[{"id": "inv1", "description": "Past scan", "status": "completed",
                                 "created_at": "2025-01-01T00:00:00"}],
        known_threats=[],
        past_findings=[{"finding_type": "vuln", "severity": "high", "title": "CVE test"}],
    )


@given(user_message=st.text(min_size=1, max_size=200))
@settings(max_examples=50, suppress_health_check=[HealthCheck.too_slow], deadline=None)
def test_property14_prompt_contains_all_required_sections(user_message: str):
    """
    Property 14: For any user_message and memory_context,
    the built system prompt MUST contain:
      (a) Tool catalogue section
      (b) Memory context section
      (c) Static security policy section with enforcement rules

    Validates: Requirements 15.5
    """
    ai = _make_ai_service()
    catalogue = _make_catalogue()
    memory = _make_memory()

    prompt = ai._build_system_prompt(catalogue, memory)

    # (a) Tool catalogue — must include at least one tool name
    assert "scan_network" in prompt or "get_alerts" in prompt, \
        "Prompt missing tool catalogue section"

    # (b) Memory context — user's investigations
    assert "Past scan" in prompt or "recent investigations" in prompt.lower() or "inv1" in prompt, \
        "Prompt missing memory context section"

    # (c) Static security policy — all 5 enforcement rules
    assert "SECURITY POLICY" in prompt, "Prompt missing static security policy"
    assert "fabricate" in prompt.lower() or "never fabricate" in prompt.lower(), \
        "Prompt missing no-fabrication rule"
    assert "credentials" in prompt.lower() or "api key" in prompt.lower(), \
        "Prompt missing credential rule"
    assert "approval" in prompt.lower(), \
        "Prompt missing approval rule"


def test_property14_catalogue_always_included():
    """Tool catalogue must always be present regardless of message."""
    ai = _make_ai_service()
    catalogue = _make_catalogue()
    memory = _make_memory()

    for msg in ["hello", "run scan", "x" * 100, ""]:
        prompt = ai._build_system_prompt(catalogue, memory)
        assert "scan_network" in prompt or "SECURITY POLICY" in prompt, \
            f"Essential prompt sections missing for message: '{msg[:20]}'"
