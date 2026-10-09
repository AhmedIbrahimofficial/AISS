"""
Tool Registration — populates the ToolRegistry singleton with all 40+ tools.
Call register_all_tools() once at application startup (in main.py lifespan).

Requirements: 2.1–2.14, 3.1 (risk level assignments)
"""
from __future__ import annotations

from agents.tool_registry import ToolDefinition, ToolCategory, RiskLevel, get_registry

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_EMPTY_SCHEMA: dict = {"type": "object", "properties": {}, "additionalProperties": True}
_RESULT_SCHEMA: dict = {"type": "object", "properties": {
    "status": {"type": "string"},
}, "additionalProperties": True}


def _schema(**props: dict) -> dict:
    return {"type": "object", "properties": props, "additionalProperties": True}


def _str_prop(desc: str = "") -> dict:
    return {"type": "string", "description": desc}


def _int_prop(desc: str = "", default: int = 50) -> dict:
    return {"type": "integer", "description": desc, "default": default}


# ---------------------------------------------------------------------------
# Registration
# ---------------------------------------------------------------------------

def register_all_tools() -> None:
    """Register all tools in the module-level ToolRegistry singleton."""
    from agents.tool_implementations import (
        system_tools, network_tools, security_tools,
        threat_intel_tools, device_tools, reporting_tools,
        monitoring_tools, automation_tools,
    )

    registry = get_registry()
    tools: list[ToolDefinition] = [

        # ── SYSTEM ────────────────────────────────────────────────────
        ToolDefinition(
            name="get_system_status", description="Get overall system health and resource usage.",
            category=ToolCategory.SYSTEM, input_schema=_EMPTY_SCHEMA, output_schema=_RESULT_SCHEMA,
            permission_required="viewer", risk_level=RiskLevel.LOW,
            timeout_seconds=30, audit_required=True, handler=system_tools.get_system_status,
        ),
        ToolDefinition(
            name="get_system_information", description="Get detailed OS and hardware information.",
            category=ToolCategory.SYSTEM, input_schema=_EMPTY_SCHEMA, output_schema=_RESULT_SCHEMA,
            permission_required="viewer", risk_level=RiskLevel.LOW,
            timeout_seconds=30, audit_required=True, handler=system_tools.get_system_information,
        ),
        ToolDefinition(
            name="get_cpu_usage", description="Get current CPU usage percentages.",
            category=ToolCategory.SYSTEM, input_schema=_EMPTY_SCHEMA, output_schema=_RESULT_SCHEMA,
            permission_required="viewer", risk_level=RiskLevel.LOW,
            timeout_seconds=15, audit_required=False, handler=system_tools.get_cpu_usage,
        ),
        ToolDefinition(
            name="get_memory_usage", description="Get current memory usage statistics.",
            category=ToolCategory.SYSTEM, input_schema=_EMPTY_SCHEMA, output_schema=_RESULT_SCHEMA,
            permission_required="viewer", risk_level=RiskLevel.LOW,
            timeout_seconds=15, audit_required=False, handler=system_tools.get_memory_usage,
        ),
        ToolDefinition(
            name="get_disk_usage", description="Get disk usage for all partitions.",
            category=ToolCategory.SYSTEM, input_schema=_EMPTY_SCHEMA, output_schema=_RESULT_SCHEMA,
            permission_required="viewer", risk_level=RiskLevel.LOW,
            timeout_seconds=15, audit_required=False, handler=system_tools.get_disk_usage,
        ),
        ToolDefinition(
            name="get_running_processes", description="List all running processes with resource usage.",
            category=ToolCategory.SYSTEM, input_schema=_EMPTY_SCHEMA, output_schema=_RESULT_SCHEMA,
            permission_required="analyst", risk_level=RiskLevel.LOW,
            timeout_seconds=30, audit_required=True, handler=system_tools.get_running_processes,
        ),
        ToolDefinition(
            name="get_installed_software", description="List installed software and versions.",
            category=ToolCategory.SYSTEM, input_schema=_EMPTY_SCHEMA, output_schema=_RESULT_SCHEMA,
            permission_required="analyst", risk_level=RiskLevel.LOW,
            timeout_seconds=60, audit_required=True, handler=system_tools.get_installed_software,
        ),
        ToolDefinition(
            name="get_system_services", description="List system services and their statuses.",
            category=ToolCategory.SYSTEM, input_schema=_EMPTY_SCHEMA, output_schema=_RESULT_SCHEMA,
            permission_required="analyst", risk_level=RiskLevel.LOW,
            timeout_seconds=30, audit_required=True, handler=system_tools.get_system_services,
        ),

        # ── NETWORK ───────────────────────────────────────────────────
        ToolDefinition(
            name="get_network_interfaces", description="List all network interfaces and addresses.",
            category=ToolCategory.NETWORK, input_schema=_EMPTY_SCHEMA, output_schema=_RESULT_SCHEMA,
            permission_required="viewer", risk_level=RiskLevel.LOW,
            timeout_seconds=15, audit_required=False, handler=network_tools.get_network_interfaces,
        ),
        ToolDefinition(
            name="get_network_connections", description="List active network connections.",
            category=ToolCategory.NETWORK, input_schema=_EMPTY_SCHEMA, output_schema=_RESULT_SCHEMA,
            permission_required="analyst", risk_level=RiskLevel.LOW,
            timeout_seconds=30, audit_required=True, handler=network_tools.get_network_connections,
        ),
        ToolDefinition(
            name="scan_network",
            description="Discover hosts on a network subnet.",
            category=ToolCategory.NETWORK,
            input_schema=_schema(target=_str_prop("Subnet or IP range, e.g. 192.168.1.0/24")),
            output_schema=_RESULT_SCHEMA,
            permission_required="analyst", risk_level=RiskLevel.MEDIUM,
            timeout_seconds=120, audit_required=True, handler=network_tools.scan_network,
        ),
        ToolDefinition(
            name="scan_ports",
            description="Scan open ports on a host.",
            category=ToolCategory.NETWORK,
            input_schema=_schema(target=_str_prop("Target IP"), port_range=_str_prop("Port range e.g. 1-1024")),
            output_schema=_RESULT_SCHEMA,
            permission_required="analyst", risk_level=RiskLevel.MEDIUM,
            timeout_seconds=120, audit_required=True, handler=network_tools.scan_ports,
        ),
        ToolDefinition(
            name="discover_devices",
            description="Discover devices on a subnet.",
            category=ToolCategory.NETWORK,
            input_schema=_schema(subnet=_str_prop("Subnet to scan")),
            output_schema=_RESULT_SCHEMA,
            permission_required="analyst", risk_level=RiskLevel.MEDIUM,
            timeout_seconds=120, audit_required=True, handler=network_tools.discover_devices,
        ),
        ToolDefinition(
            name="get_connected_devices", description="List devices currently connected to the network.",
            category=ToolCategory.NETWORK, input_schema=_EMPTY_SCHEMA, output_schema=_RESULT_SCHEMA,
            permission_required="analyst", risk_level=RiskLevel.LOW,
            timeout_seconds=30, audit_required=True, handler=network_tools.get_connected_devices,
        ),
        ToolDefinition(
            name="analyze_network_activity", description="Analyse network I/O statistics.",
            category=ToolCategory.NETWORK, input_schema=_EMPTY_SCHEMA, output_schema=_RESULT_SCHEMA,
            permission_required="analyst", risk_level=RiskLevel.LOW,
            timeout_seconds=30, audit_required=True, handler=network_tools.analyze_network_activity,
        ),

        # ── SECURITY ──────────────────────────────────────────────────
        ToolDefinition(
            name="scan_system", description="Run a full malware and integrity scan.",
            category=ToolCategory.SECURITY, input_schema=_EMPTY_SCHEMA, output_schema=_RESULT_SCHEMA,
            permission_required="analyst", risk_level=RiskLevel.MEDIUM,
            timeout_seconds=300, audit_required=True, handler=security_tools.scan_system,
        ),
        ToolDefinition(
            name="scan_file",
            description="Scan a specific file and compute its hashes.",
            category=ToolCategory.SECURITY,
            input_schema=_schema(file_path=_str_prop("Absolute path to the file")),
            output_schema=_RESULT_SCHEMA,
            permission_required="analyst", risk_level=RiskLevel.MEDIUM,
            timeout_seconds=60, audit_required=True, handler=security_tools.scan_file,
        ),
        ToolDefinition(
            name="analyze_file",
            description="Analyze a file's type, hashes, and metadata.",
            category=ToolCategory.SECURITY,
            input_schema=_schema(file_path=_str_prop("Absolute path to the file")),
            output_schema=_RESULT_SCHEMA,
            permission_required="analyst", risk_level=RiskLevel.MEDIUM,
            timeout_seconds=60, audit_required=True, handler=security_tools.analyze_file,
        ),
        ToolDefinition(
            name="calculate_file_hash",
            description="Compute cryptographic hash of a file.",
            category=ToolCategory.SECURITY,
            input_schema=_schema(file_path=_str_prop("Path to file"),
                                 algorithm=_str_prop("Hash algorithm: sha256, md5, sha1")),
            output_schema=_RESULT_SCHEMA,
            permission_required="analyst", risk_level=RiskLevel.LOW,
            timeout_seconds=30, audit_required=True, handler=security_tools.calculate_file_hash,
        ),
        ToolDefinition(
            name="malware_scan", description="Run YARA-based malware scan.",
            category=ToolCategory.SECURITY, input_schema=_EMPTY_SCHEMA, output_schema=_RESULT_SCHEMA,
            permission_required="analyst", risk_level=RiskLevel.MEDIUM,
            timeout_seconds=300, audit_required=True, handler=security_tools.malware_scan,
        ),
        ToolDefinition(
            name="vulnerability_scan", description="Run vulnerability assessment.",
            category=ToolCategory.SECURITY, input_schema=_EMPTY_SCHEMA, output_schema=_RESULT_SCHEMA,
            permission_required="analyst", risk_level=RiskLevel.MEDIUM,
            timeout_seconds=300, audit_required=True, handler=security_tools.vulnerability_scan,
        ),
        ToolDefinition(
            name="get_vulnerabilities", description="Retrieve known vulnerabilities from DB.",
            category=ToolCategory.SECURITY,
            input_schema=_schema(limit=_int_prop("Max results", 50)),
            output_schema=_RESULT_SCHEMA,
            permission_required="viewer", risk_level=RiskLevel.LOW,
            timeout_seconds=30, audit_required=True, handler=security_tools.get_vulnerabilities,
        ),
        ToolDefinition(
            name="get_security_events", description="Retrieve recent security events.",
            category=ToolCategory.SECURITY,
            input_schema=_schema(limit=_int_prop("Max results", 50)),
            output_schema=_RESULT_SCHEMA,
            permission_required="viewer", risk_level=RiskLevel.LOW,
            timeout_seconds=30, audit_required=True, handler=security_tools.get_security_events,
        ),
        ToolDefinition(
            name="get_alerts", description="Retrieve active security alerts.",
            category=ToolCategory.SECURITY,
            input_schema=_schema(limit=_int_prop("Max results", 50)),
            output_schema=_RESULT_SCHEMA,
            permission_required="viewer", risk_level=RiskLevel.LOW,
            timeout_seconds=30, audit_required=True, handler=security_tools.get_alerts,
        ),
        ToolDefinition(
            name="investigate_alert",
            description="Fetch full details for a specific alert.",
            category=ToolCategory.SECURITY,
            input_schema=_schema(alert_id=_str_prop("Alert/threat ID")),
            output_schema=_RESULT_SCHEMA,
            permission_required="analyst", risk_level=RiskLevel.LOW,
            timeout_seconds=30, audit_required=True, handler=security_tools.investigate_alert,
        ),
        ToolDefinition(
            name="analyze_threat",
            description="Analyze a specific threat by ID.",
            category=ToolCategory.SECURITY,
            input_schema=_schema(threat_id=_str_prop("Threat ID")),
            output_schema=_RESULT_SCHEMA,
            permission_required="analyst", risk_level=RiskLevel.LOW,
            timeout_seconds=30, audit_required=True, handler=security_tools.analyze_threat,
        ),
        ToolDefinition(
            name="query_audit_logs", description="Query the agent audit log.",
            category=ToolCategory.SECURITY,
            input_schema=_schema(limit=_int_prop("Max results", 50)),
            output_schema=_RESULT_SCHEMA,
            permission_required="analyst", risk_level=RiskLevel.LOW,
            timeout_seconds=30, audit_required=True, handler=security_tools.query_audit_logs,
        ),

        # ── THREAT INTELLIGENCE ───────────────────────────────────────
        ToolDefinition(
            name="lookup_ioc",
            description="Look up an IOC (IP, hash, domain) via VirusTotal.",
            category=ToolCategory.THREAT_INTELLIGENCE,
            input_schema=_schema(ioc=_str_prop("IP, hash, or domain"), ioc_type=_str_prop("auto|ip|hash|domain")),
            output_schema=_RESULT_SCHEMA,
            permission_required="analyst", risk_level=RiskLevel.LOW,
            timeout_seconds=60, audit_required=True, handler=threat_intel_tools.lookup_ioc,
        ),
        ToolDefinition(
            name="check_ip_reputation",
            description="Check IP address reputation via VirusTotal.",
            category=ToolCategory.THREAT_INTELLIGENCE,
            input_schema=_schema(ip=_str_prop("IP address")),
            output_schema=_RESULT_SCHEMA,
            permission_required="analyst", risk_level=RiskLevel.LOW,
            timeout_seconds=60, audit_required=True, handler=threat_intel_tools.check_ip_reputation,
        ),
        ToolDefinition(
            name="check_domain_reputation",
            description="Check domain reputation via VirusTotal.",
            category=ToolCategory.THREAT_INTELLIGENCE,
            input_schema=_schema(domain=_str_prop("Domain name")),
            output_schema=_RESULT_SCHEMA,
            permission_required="analyst", risk_level=RiskLevel.LOW,
            timeout_seconds=60, audit_required=True, handler=threat_intel_tools.check_domain_reputation,
        ),
        ToolDefinition(
            name="check_hash_reputation",
            description="Check file hash reputation via VirusTotal.",
            category=ToolCategory.THREAT_INTELLIGENCE,
            input_schema=_schema(file_hash=_str_prop("MD5, SHA1, or SHA256 hash")),
            output_schema=_RESULT_SCHEMA,
            permission_required="analyst", risk_level=RiskLevel.LOW,
            timeout_seconds=60, audit_required=True, handler=threat_intel_tools.check_hash_reputation,
        ),
        ToolDefinition(
            name="map_to_mitre_attack",
            description="Map techniques or findings to MITRE ATT&CK framework.",
            category=ToolCategory.THREAT_INTELLIGENCE,
            input_schema=_schema(techniques={"type": "array", "items": {"type": "string"},
                                              "description": "List of technique IDs or names"}),
            output_schema=_RESULT_SCHEMA,
            permission_required="analyst", risk_level=RiskLevel.LOW,
            timeout_seconds=60, audit_required=True, handler=threat_intel_tools.map_to_mitre_attack,
        ),

        # ── DEVICES ───────────────────────────────────────────────────
        ToolDefinition(
            name="get_devices", description="List all registered devices/users.",
            category=ToolCategory.DEVICES, input_schema=_EMPTY_SCHEMA, output_schema=_RESULT_SCHEMA,
            permission_required="analyst", risk_level=RiskLevel.LOW,
            timeout_seconds=30, audit_required=True, handler=device_tools.get_devices,
        ),
        ToolDefinition(
            name="get_device_status",
            description="Get status of a specific device.",
            category=ToolCategory.DEVICES,
            input_schema=_schema(device_id=_str_prop("Device/user ID")),
            output_schema=_RESULT_SCHEMA,
            permission_required="analyst", risk_level=RiskLevel.LOW,
            timeout_seconds=15, audit_required=True, handler=device_tools.get_device_status,
        ),
        ToolDefinition(
            name="authorize_device",
            description="Authorize (activate) a device. HIGH risk — requires approval.",
            category=ToolCategory.DEVICES,
            input_schema=_schema(device_id=_str_prop("Device/user ID to authorize")),
            output_schema=_RESULT_SCHEMA,
            permission_required="admin", risk_level=RiskLevel.HIGH,
            timeout_seconds=30, audit_required=True, handler=device_tools.authorize_device,
        ),
        ToolDefinition(
            name="revoke_device",
            description="Revoke (deactivate) a device. HIGH risk — requires approval.",
            category=ToolCategory.DEVICES,
            input_schema=_schema(device_id=_str_prop("Device/user ID to revoke")),
            output_schema=_RESULT_SCHEMA,
            permission_required="admin", risk_level=RiskLevel.HIGH,
            timeout_seconds=30, audit_required=True, handler=device_tools.revoke_device,
        ),
        ToolDefinition(
            name="connect_device",
            description="Connect a device to the platform.",
            category=ToolCategory.DEVICES,
            input_schema=_schema(device_id=_str_prop("Device ID")),
            output_schema=_RESULT_SCHEMA,
            permission_required="admin", risk_level=RiskLevel.HIGH,
            timeout_seconds=30, audit_required=True, handler=device_tools.connect_device,
        ),
        ToolDefinition(
            name="disconnect_device",
            description="Disconnect a device from the platform.",
            category=ToolCategory.DEVICES,
            input_schema=_schema(device_id=_str_prop("Device ID")),
            output_schema=_RESULT_SCHEMA,
            permission_required="admin", risk_level=RiskLevel.HIGH,
            timeout_seconds=30, audit_required=True, handler=device_tools.disconnect_device,
        ),

        # ── REPORTING ─────────────────────────────────────────────────
        ToolDefinition(
            name="generate_security_report", description="Generate a weekly security report PDF.",
            category=ToolCategory.REPORTING, input_schema=_EMPTY_SCHEMA, output_schema=_RESULT_SCHEMA,
            permission_required="analyst", risk_level=RiskLevel.LOW,
            timeout_seconds=300, audit_required=True, handler=reporting_tools.generate_security_report,
        ),
        ToolDefinition(
            name="generate_pdf_report",
            description="Retrieve a PDF report by ID.",
            category=ToolCategory.REPORTING,
            input_schema=_schema(report_id=_str_prop("Report UUID")),
            output_schema=_RESULT_SCHEMA,
            permission_required="analyst", risk_level=RiskLevel.LOW,
            timeout_seconds=30, audit_required=True, handler=reporting_tools.generate_pdf_report,
        ),
        ToolDefinition(
            name="export_audit_log", description="Export audit log entries.",
            category=ToolCategory.REPORTING,
            input_schema=_schema(limit=_int_prop("Max entries", 100)),
            output_schema=_RESULT_SCHEMA,
            permission_required="analyst", risk_level=RiskLevel.LOW,
            timeout_seconds=30, audit_required=True, handler=reporting_tools.export_audit_log,
        ),
        ToolDefinition(
            name="export_findings", description="Export security findings.",
            category=ToolCategory.REPORTING,
            input_schema=_schema(limit=_int_prop("Max entries", 100)),
            output_schema=_RESULT_SCHEMA,
            permission_required="analyst", risk_level=RiskLevel.LOW,
            timeout_seconds=30, audit_required=True, handler=reporting_tools.export_findings,
        ),

        # ── MONITORING ────────────────────────────────────────────────
        ToolDefinition(
            name="start_monitoring", description="Start real-time security monitoring.",
            category=ToolCategory.MONITORING, input_schema=_EMPTY_SCHEMA, output_schema=_RESULT_SCHEMA,
            permission_required="analyst", risk_level=RiskLevel.LOW,
            timeout_seconds=15, audit_required=True, handler=monitoring_tools.start_monitoring,
        ),
        ToolDefinition(
            name="stop_monitoring", description="Stop real-time security monitoring.",
            category=ToolCategory.MONITORING, input_schema=_EMPTY_SCHEMA, output_schema=_RESULT_SCHEMA,
            permission_required="analyst", risk_level=RiskLevel.LOW,
            timeout_seconds=15, audit_required=True, handler=monitoring_tools.stop_monitoring,
        ),
        ToolDefinition(
            name="get_monitoring_status", description="Check current monitoring status.",
            category=ToolCategory.MONITORING, input_schema=_EMPTY_SCHEMA, output_schema=_RESULT_SCHEMA,
            permission_required="viewer", risk_level=RiskLevel.LOW,
            timeout_seconds=10, audit_required=False, handler=monitoring_tools.get_monitoring_status,
        ),
        ToolDefinition(
            name="get_recent_events", description="Retrieve recent security and system events.",
            category=ToolCategory.MONITORING,
            input_schema=_schema(limit=_int_prop("Max events", 50)),
            output_schema=_RESULT_SCHEMA,
            permission_required="viewer", risk_level=RiskLevel.LOW,
            timeout_seconds=30, audit_required=True, handler=monitoring_tools.get_recent_events,
        ),

        # ── AUTOMATION ────────────────────────────────────────────────
        ToolDefinition(
            name="create_task",
            description="Create a new agent task.",
            category=ToolCategory.AUTOMATION,
            input_schema=_schema(description=_str_prop("Task description")),
            output_schema=_RESULT_SCHEMA,
            permission_required="analyst", risk_level=RiskLevel.LOW,
            timeout_seconds=15, audit_required=True, handler=automation_tools.create_task,
        ),
        ToolDefinition(
            name="schedule_task",
            description="Create a new scheduled recurring task.",
            category=ToolCategory.AUTOMATION,
            input_schema=_schema(name=_str_prop("Task name"),
                                 tool_or_playbook=_str_prop("Tool or playbook name"),
                                 schedule_expression=_str_prop("Cron or interval expression")),
            output_schema=_RESULT_SCHEMA,
            permission_required="analyst", risk_level=RiskLevel.LOW,
            timeout_seconds=15, audit_required=True, handler=automation_tools.schedule_task,
        ),
        ToolDefinition(
            name="cancel_task",
            description="Cancel a running or pending task.",
            category=ToolCategory.AUTOMATION,
            input_schema=_schema(task_id=_str_prop("Task UUID to cancel")),
            output_schema=_RESULT_SCHEMA,
            permission_required="analyst", risk_level=RiskLevel.LOW,
            timeout_seconds=15, audit_required=True, handler=automation_tools.cancel_task,
        ),
        ToolDefinition(
            name="get_scheduled_tasks", description="List all scheduled tasks.",
            category=ToolCategory.AUTOMATION, input_schema=_EMPTY_SCHEMA, output_schema=_RESULT_SCHEMA,
            permission_required="viewer", risk_level=RiskLevel.LOW,
            timeout_seconds=15, audit_required=False, handler=automation_tools.get_scheduled_tasks,
        ),
        ToolDefinition(
            name="run_playbook",
            description="Execute a named security playbook.",
            category=ToolCategory.AUTOMATION,
            input_schema=_schema(playbook_name=_str_prop("Playbook name, e.g. full_security_assessment")),
            output_schema=_RESULT_SCHEMA,
            permission_required="analyst", risk_level=RiskLevel.MEDIUM,
            timeout_seconds=1800, audit_required=True, handler=automation_tools.run_playbook,
        ),
    ]

    for tool in tools:
        registry.register(tool)
