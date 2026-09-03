"""
Agentic AI Orchestrator — Playbook Definitions

Pre-defined multi-step security workflow templates.
Each playbook is a list of PlanStep objects the Orchestrator executes
in sequence, passing outputs from prior steps as context to later ones.

Requirements: 6.1–6.6
"""
from __future__ import annotations

from agents.schemas import ExecutionPlan, PlanStep

# ---------------------------------------------------------------------------
# full_security_assessment — 15-step comprehensive security review
# ---------------------------------------------------------------------------

_FULL_SECURITY_ASSESSMENT_STEPS: list[dict] = [
    {
        "step_index": 0,
        "tool_name": "get_system_status",
        "arguments": {},
        "rationale": "Step 1: Check overall system health and baseline status.",
    },
    {
        "step_index": 1,
        "tool_name": "get_running_processes",
        "arguments": {},
        "rationale": "Step 2: Enumerate all running processes for suspicious activity.",
    },
    {
        "step_index": 2,
        "tool_name": "get_network_connections",
        "arguments": {},
        "rationale": "Step 3: Analyse active network connections for anomalies.",
    },
    {
        "step_index": 3,
        "tool_name": "scan_ports",
        "arguments": {"target": "127.0.0.1"},
        "rationale": "Step 4: Scan local open ports to identify exposed services.",
    },
    {
        "step_index": 4,
        "tool_name": "get_installed_software",
        "arguments": {},
        "rationale": "Step 5: Inspect installed software for outdated or vulnerable packages.",
    },
    {
        "step_index": 5,
        "tool_name": "vulnerability_scan",
        "arguments": {},
        "rationale": "Step 6: Run vulnerability assessment against the system.",
    },
    {
        "step_index": 6,
        "tool_name": "scan_system",
        "arguments": {},
        "rationale": "Step 7: Perform a full malware and file-integrity scan.",
    },
    {
        "step_index": 7,
        "tool_name": "get_security_events",
        "arguments": {"limit": 100},
        "rationale": "Step 8: Retrieve recent security events for analysis.",
    },
    {
        "step_index": 8,
        "tool_name": "query_audit_logs",
        "arguments": {"limit": 100},
        "rationale": "Step 9: Query the audit log for suspicious administrative actions.",
    },
    {
        "step_index": 9,
        "tool_name": "get_alerts",
        "arguments": {},
        "rationale": "Step 10: Retrieve active threat intelligence alerts.",
    },
    {
        "step_index": 10,
        "tool_name": "map_to_mitre_attack",
        "arguments": {},
        "rationale": "Step 11: Map detected threats and processes to MITRE ATT&CK techniques.",
    },
    {
        "step_index": 11,
        "tool_name": "get_connected_devices",
        "arguments": {},
        "rationale": "Step 12: Enumerate connected devices and correlate with known baselines.",
    },
    {
        "step_index": 12,
        "tool_name": "get_vulnerabilities",
        "arguments": {},
        "rationale": "Step 13: Retrieve full vulnerability list and compute risk score.",
    },
    {
        "step_index": 13,
        "tool_name": "get_recent_events",
        "arguments": {"limit": 50},
        "rationale": "Step 14: Review recent monitoring events for additional context.",
    },
    {
        "step_index": 14,
        "tool_name": "generate_security_report",
        "arguments": {},
        "rationale": "Step 15: Generate the final security assessment report.",
    },
]

# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------

PLAYBOOK_REGISTRY: dict[str, ExecutionPlan] = {
    "full_security_assessment": ExecutionPlan(
        steps=[PlanStep(**s) for s in _FULL_SECURITY_ASSESSMENT_STEPS],
        overall_rationale=(
            "Comprehensive 15-step security assessment covering system health, "
            "process analysis, network activity, vulnerability scanning, malware detection, "
            "threat intelligence, MITRE ATT&CK mapping, and final report generation."
        ),
        requires_approval=[],
    ),
}


def get_playbook(name: str) -> ExecutionPlan | None:
    """Return a copy of the named playbook, or None if not found."""
    plan = PLAYBOOK_REGISTRY.get(name)
    if plan is None:
        return None
    # Return a fresh copy so each execution gets independent step state
    return ExecutionPlan(
        steps=[PlanStep(**s.model_dump()) for s in plan.steps],
        overall_rationale=plan.overall_rationale,
        requires_approval=list(plan.requires_approval),
    )


def list_playbooks() -> list[str]:
    """Return all registered playbook names."""
    return list(PLAYBOOK_REGISTRY.keys())
