# Requirements Document

## Introduction

This document defines requirements for the **Agentic AI Backend Orchestrator**, a central AI orchestration layer for the AISS (AI Intelligent Security System) cybersecurity platform. The orchestrator acts as an autonomous security agent that sits between the user/frontend and the existing backend security infrastructure. It understands natural-language user requests, plans and executes multi-step security workflows, calls controlled backend tools, manages approvals for sensitive operations, schedules recurring tasks, generates security reports, and maintains a full auditable history of every action it takes.

The orchestrator integrates with the existing FastAPI/SQLAlchemy async backend (Python), the existing JWT-based auth system, and the existing security modules. It communicates with an LLM via OpenRouter (backend-only, key never exposed to the frontend) with the model configurable via the `OPENROUTER_MODEL` environment variable.

---

## Glossary

- **Orchestrator**: The central agentic AI component that plans, coordinates, and executes security workflows on behalf of authenticated users.
- **Tool**: A controlled, registered backend function the Orchestrator may call. Each tool has a defined input/output schema, permission requirement, risk level, and timeout.
- **Tool_Registry**: The centralised catalogue of all available tools the Orchestrator may select from during planning.
- **Permission_Engine**: The subsystem that evaluates whether a requested tool call is authorised for the current user and context.
- **Risk_Level**: A classification (LOW, MEDIUM, HIGH, CRITICAL) indicating the potential impact of a tool execution.
- **Approval**: A user-confirmed authorisation required before the Orchestrator executes HIGH or CRITICAL risk tools.
- **Task**: A discrete unit of work created by the Orchestrator to fulfil a user request, potentially spanning multiple tool calls.
- **Execution**: A single run of a Task, recording start time, steps taken, tool results, and final status.
- **Scheduled_Task**: A Task configured to run automatically on a defined schedule (cron or interval).
- **Agent_Memory**: Persistent and session-scoped context the Orchestrator uses to maintain continuity across requests and investigations.
- **Audit_Event**: An immutable record of every Orchestrator action, logged to the database for compliance.
- **Security_Report**: A structured PDF document summarising security posture, findings, and recommendations for a defined time window.
- **Report_History**: The collection of all past generated Security_Reports with metadata.
- **Playbook**: A named, predefined multi-step workflow template (e.g., "full security assessment").
- **IOC**: Indicator of Compromise — a piece of forensic data (IP, hash, domain) used in threat intelligence lookups.
- **MITRE_ATT&CK**: The MITRE Adversarial Tactics, Techniques, and Common Knowledge framework used to classify threat behaviour.
- **OpenRouter**: The third-party LLM routing service used exclusively from the backend via `OPENROUTER_API_KEY`.
- **AISS_Backend**: The existing Python/FastAPI application that hosts all security modules, database, and API routes.
- **Frontend**: The existing React application that communicates with the AISS_Backend via REST and WebSocket.

---

## Requirements

---

### Requirement 1: Agent Chat Interface

**User Story:** As a security analyst, I want to send natural-language requests to the Orchestrator via a chat interface, so that I can interact with the security platform conversationally without writing queries or scripts.

#### Acceptance Criteria

1. WHEN an authenticated user submits a message to `POST /agent/chat`, THE Orchestrator SHALL accept the message, create a Task, begin planning, and return a response containing the Task ID, initial status, and the Orchestrator's reply within 30 seconds or an acknowledgement that processing is ongoing.
2. WHEN the Orchestrator receives a chat message, THE Orchestrator SHALL classify the user intent and determine whether it maps to a known Playbook, a direct tool call, or a multi-step plan.
3. WHILE a Task is executing, THE Orchestrator SHALL stream intermediate progress updates to the caller via the existing WebSocket manager so the Frontend can display live step-by-step progress.
4. IF the Orchestrator cannot determine a safe, valid plan for a user request, THEN THE Orchestrator SHALL completely refuse execution, respond with a clear explanation of what it cannot do, and SHALL NOT attempt any partial or speculative tool calls.
5. THE Orchestrator SHALL enforce that all chat interactions originate from authenticated users with valid JWT tokens; unauthenticated requests SHALL receive HTTP 401.
6. THE Orchestrator SHALL reject any user message that contains prompt injection patterns (instructions attempting to override system policy, claim elevated permissions, or instruct the Orchestrator to ignore safety rules), log the attempt as an Audit_Event with severity `warning`, and respond with a rejection message.

---

### Requirement 2: Tool Registry

**User Story:** As a platform architect, I want all Orchestrator-callable tools to be defined in a central registry with strict schemas, so that the Orchestrator can never execute arbitrary code and every tool invocation is controlled and validated.

#### Acceptance Criteria

1. THE Tool_Registry SHALL expose a complete catalogue of tools organised into the categories: SYSTEM, NETWORK, SECURITY, THREAT_INTELLIGENCE, DEVICES, REPORTING, MONITORING, and AUTOMATION.
2. THE Tool_Registry SHALL define each tool with: `name`, `description`, `input_schema` (JSON Schema), `output_schema` (JSON Schema), `permission_required`, `risk_level` (LOW | MEDIUM | HIGH | CRITICAL), `timeout_seconds`, and `audit_required` flag.
3. WHEN the Orchestrator selects a tool for execution, THE Tool_Registry SHALL validate the tool's input arguments against the tool's `input_schema` before execution begins.
4. IF a tool's input arguments fail schema validation, THEN THE Tool_Registry SHALL reject the execution, return a structured validation error to the Orchestrator, and log the failure as an Audit_Event.
5. THE Tool_Registry SHALL expose the complete tool catalogue via `GET /agent/tools` for authenticated users, returning name, description, category, risk_level, and input_schema for each tool.
6. THE Orchestrator SHALL never execute shell commands, file system writes, or network operations outside of a registered Tool; any attempt to do so by the AI planning layer SHALL be blocked by the Tool_Registry with an Audit_Event logged.
7. THE Tool_Registry SHALL include the following SYSTEM tools: `get_system_status`, `get_system_information`, `get_cpu_usage`, `get_memory_usage`, `get_disk_usage`, `get_running_processes`, `get_installed_software`, `get_system_services`.
8. THE Tool_Registry SHALL include the following NETWORK tools: `get_network_interfaces`, `get_network_connections`, `scan_network`, `scan_ports`, `discover_devices`, `get_connected_devices`, `analyze_network_activity`.
9. THE Tool_Registry SHALL include the following SECURITY tools: `scan_system`, `scan_file`, `analyze_file`, `calculate_file_hash`, `malware_scan`, `vulnerability_scan`, `get_vulnerabilities`, `get_security_events`, `get_alerts`, `investigate_alert`, `analyze_threat`, `query_audit_logs`.
10. THE Tool_Registry SHALL include the following THREAT_INTELLIGENCE tools: `lookup_ioc`, `check_ip_reputation`, `check_domain_reputation`, `check_hash_reputation`, `map_to_mitre_attack`.
11. THE Tool_Registry SHALL include the following DEVICES tools: `get_devices`, `connect_device`, `disconnect_device`, `authorize_device`, `revoke_device`, `get_device_status`.
12. THE Tool_Registry SHALL include the following REPORTING tools: `generate_security_report`, `generate_pdf_report`, `export_audit_log`, `export_findings`.
13. THE Tool_Registry SHALL include the following MONITORING tools: `start_monitoring`, `stop_monitoring`, `get_monitoring_status`, `get_recent_events`.
14. THE Tool_Registry SHALL include the following AUTOMATION tools: `create_task`, `schedule_task`, `cancel_task`, `get_scheduled_tasks`, `run_playbook`.

---

### Requirement 3: Permission and Risk Engine

**User Story:** As a security administrator, I want every tool execution to be evaluated against user permissions and risk levels before it runs, so that the Orchestrator cannot perform privileged operations without the appropriate authorisation.

#### Acceptance Criteria

1. THE Permission_Engine SHALL classify every tool into exactly one Risk_Level: LOW (read system info, read logs, read devices, read security events, generate reports), MEDIUM (system scan, network scan, vulnerability scan, file analysis), HIGH (quarantine, process termination, network blocking, security configuration changes), or CRITICAL (delete files, destructive operations, irreversible configuration changes).
2. WHEN a tool with Risk_Level LOW or MEDIUM is selected by the Orchestrator, THE Permission_Engine SHALL evaluate the requesting user's role against the tool's `permission_required` field and, if authorised, permit immediate execution without requiring user approval.
3. WHEN a tool with Risk_Level HIGH or CRITICAL is selected by the Orchestrator, THE Permission_Engine SHALL pause execution, create an Approval record, and present the approval request to the Frontend before any execution occurs; this requirement applies to ALL authenticated users regardless of their role, including admin users.
4. IF the Permission_Engine determines the requesting user's role does not meet the tool's `permission_required` level, THEN THE Permission_Engine SHALL deny the execution, return HTTP 403, and log the denial as an Audit_Event.
5. THE Permission_Engine SHALL prevent privilege escalation: an AI-generated plan SHALL never be able to grant itself or the user elevated permissions beyond those assigned at authentication time.
6. THE Permission_Engine SHALL evaluate tool permission checks synchronously and complete the check within 100 milliseconds for LOW and MEDIUM risk tools to avoid blocking the planning pipeline.

---

### Requirement 4: Approval System for High-Risk Operations

**User Story:** As a security analyst, I want to review and explicitly approve or reject any HIGH or CRITICAL risk operations the Orchestrator proposes, so that no destructive or irreversible action is taken without my informed consent.

#### Acceptance Criteria

1. WHEN the Orchestrator plans a HIGH or CRITICAL risk tool execution, THE Orchestrator SHALL create an Approval record containing: what will happen (natural-language description), why it is required, which device or system will be affected, the Risk_Level, what will change, and the estimated impact.
2. THE Orchestrator SHALL expose the pending Approval to the Frontend via `POST /agent/approvals/{id}/approve` and `POST /agent/approvals/{id}/reject`.
3. WHILE an Approval is pending, THE Orchestrator SHALL halt the relevant Task step and wait for the user's decision before proceeding.
4. WHEN a user approves an Approval via `POST /agent/approvals/{id}/approve`, THE Orchestrator SHALL resume the halted Task step, execute the tool, and log the approval action as an Audit_Event with the approving user's identity.
5. WHEN a user rejects an Approval via `POST /agent/approvals/{id}/reject`, THE Orchestrator SHALL cancel the halted Task step, log the rejection as an Audit_Event, and update the Task status to `approval_rejected`.
6. IF an Approval is not acted upon within 3600 seconds (1 hour), THEN THE Orchestrator SHALL automatically expire the Approval, cancel the pending Task step, and log the expiry as an Audit_Event.
7. WHEN an Approval bypass attempt is detected (an AI plan that references a HIGH or CRITICAL tool without creating an Approval record, or a chat message instructing the Orchestrator to skip approval), THE Orchestrator SHALL immediately halt all execution for the associated Task, log an Audit_Event with event_type `approval_bypass_attempt` and severity `critical`, and update the Task status to `failed`.

---

### Requirement 5: Task and Execution Management

**User Story:** As a security analyst, I want to create, monitor, cancel, and review the history of all Orchestrator tasks, so that I can track what the AI agent has done and is currently doing.

#### Acceptance Criteria

1. WHEN an Orchestrator Task is created, THE Orchestrator SHALL persist a Task record with: task ID, user ID, description, status (`pending` | `planning` | `running` | `awaiting_approval` | `completed` | `failed` | `cancelled` | `approval_rejected`), created_at, updated_at, and the AI-generated plan.
2. THE Orchestrator SHALL expose `GET /agent/tasks/{id}` returning the full Task record including all Execution steps and their statuses.
3. WHEN a user calls `POST /agent/tasks/{id}/cancel`, THE Orchestrator SHALL stop any in-progress tool executions for that Task (where safe to do so) and update the Task status to `cancelled`; if audit logging or execution stopping fails, THE Orchestrator SHALL still update the status to `cancelled` and make a best-effort attempt to log the cancellation.
4. THE Orchestrator SHALL expose `GET /agent/executions` returning a paginated list of all Executions for the authenticated user, ordered by created_at descending.
5. THE Orchestrator SHALL expose `GET /agent/executions/{id}` returning a single Execution record including: all tool call steps, arguments (with secrets redacted), results, duration, and any errors.
6. WHEN a tool execution times out (exceeds its registered `timeout_seconds`), THE Orchestrator SHALL first successfully log the timeout as an Audit_Event, then mark the execution step as `timed_out`, and then attempt to continue the Task plan with the remaining steps where the step is not blocking; timeout handling SHALL NOT proceed to mark the step or continue execution if audit logging fails.
7. THE Orchestrator SHALL expose `GET /agent/status` returning the Orchestrator's current operational state: whether it is active, how many Tasks are running, any degraded subsystems, and the LLM model in use.

---

### Requirement 6: Autonomous Multi-Step Security Workflows (Playbooks)

**User Story:** As a security analyst, I want the Orchestrator to execute complex, pre-defined multi-step security assessment workflows automatically, so that I can perform a comprehensive security review with a single request.

#### Acceptance Criteria

1. THE Orchestrator SHALL support a built-in Playbook named `full_security_assessment` that executes steps in this sequence: system health check, process analysis, network analysis, open port analysis, installed software inspection, vulnerability assessment, malware and file analysis, security event analysis, audit log analysis, threat intelligence checks, MITRE ATT&CK mapping, correlation, risk scoring, recommendations, and final report generation.
2. WHEN a Playbook is started, THE Orchestrator SHALL execute each step in sequence, passing relevant outputs from prior steps as context to subsequent steps.
3. WHEN a Playbook step produces findings (threats, vulnerabilities, suspicious processes), THE Orchestrator SHALL persist those findings as Security_Findings records and reference them in the final report.
4. IF a Playbook step fails due to a tool error or timeout, THEN THE Orchestrator SHALL log the failure, record it in the Execution record, and continue with all remaining steps regardless of whether those remaining steps need the failed step's output; gaps in data due to failed steps SHALL be noted in the final report.
5. THE Orchestrator SHALL produce a final AI-generated summary after completing a Playbook, including: overall risk score (0–100), top findings, recommended actions ranked by priority, and any steps that could not complete; IF AI service is unavailable and the summary cannot be generated, THEN THE Orchestrator SHALL still mark the Execution as `completed` and note in the record that AI summary generation failed.
6. THE Orchestrator SHALL allow users to trigger a Playbook by name via the chat interface or via `POST /agent/tasks` with `{ "playbook": "full_security_assessment" }`.

---

### Requirement 7: Agent Memory

**User Story:** As a security analyst, I want the Orchestrator to remember context from previous investigations and sessions, so that it can provide continuity and avoid re-discovering known information.

#### Acceptance Criteria

1. THE Orchestrator SHALL maintain short-term memory scoped to the current Task, storing: the original user request, the AI-generated plan, results of each tool call, and intermediate conclusions.
2. THE Orchestrator SHALL maintain long-term memory in persistent storage containing: authorised devices, previous investigation summaries, past findings, generated reports, active incidents, scheduled tasks, and user-approved policies.
3. THE Orchestrator SHALL never persist secrets, credentials, passwords, API keys, authentication tokens, or any credential material in Agent_Memory; WHEN an investigation tool requires API access, the tool SHALL require re-authentication for each session rather than relying on persisted credentials.
4. WHEN a new Task is created, THE Orchestrator SHALL retrieve relevant long-term memory entries (previous investigations on the same device or IP, known threats, prior findings) and include them in the AI planning context.
5. WHEN an investigation is completed, THE Orchestrator SHALL summarise the key findings and store the summary in long-term memory with: investigation ID, scope, findings summary, risk level, and timestamp.
6. THE Orchestrator SHALL limit short-term memory to the current session only; short-term memory SHALL be discarded immediately when the Task reaches a terminal state (`completed`, `failed`, `cancelled`) with no grace period.

---

### Requirement 8: Audit Logging

**User Story:** As a compliance officer, I want every Orchestrator operation to be recorded in a tamper-evident audit log, so that I can review the full history of AI-driven actions for compliance and forensic purposes.

#### Acceptance Criteria

1. THE Orchestrator SHALL record an Audit_Event for every operation it performs, containing: user identity, original request (truncated at 2048 characters), timestamp (UTC ISO-8601), AI-generated plan summary, tool selected, tool arguments (with all secrets, passwords, API keys, and tokens redacted), authorisation result, execution result summary, Risk_Level, approval status, and final AI conclusion.
2. THE Orchestrator SHALL never log API keys, passwords, tokens, or any credential material in any Audit_Event field; credential fields SHALL be replaced with the string `[REDACTED]`.
3. THE Orchestrator SHALL persist Audit_Events to the `agent_audit_events` database table using the existing SQLAlchemy async session pattern.
4. WHEN a prompt injection attempt is detected, THE Orchestrator SHALL log it as an Audit_Event with event_type `prompt_injection_attempt` and severity `warning`.
5. WHEN an Approval is created, approved, rejected, or expired, THE Orchestrator SHALL log each state transition as a separate Audit_Event using a specific `event_type` value from the set: `approval_created`, `approval_approved`, `approval_rejected`, `approval_expired`.
6. THE Orchestrator SHALL expose audit log data via the existing `query_audit_logs` tool in the Tool_Registry; access to audit log data SHALL be restricted to users with `analyst` or `admin` roles and SHALL be denied for all other roles with HTTP 403.
7. THE Audit_Event records SHALL be immutable once written; the Orchestrator SHALL not provide any endpoint or mechanism to delete or modify individual Audit_Event records.

---

### Requirement 9: Failure Recovery and Resilience

**User Story:** As a platform operator, I want the Orchestrator to handle tool failures, timeouts, and service unavailability gracefully, so that a partial failure never causes misleading output or system instability.

#### Acceptance Criteria

1. WHEN a tool execution fails due to a transient error (network timeout, temporary service unavailability), THE Orchestrator SHALL retry the tool call up to 3 times with exponential back-off (2s, 4s, 8s delays) before marking the step as failed.
2. WHEN the OpenRouter API is unavailable or returns an error, THE Orchestrator SHALL treat it as a critical service failure, update the Task status to `degraded`, notify the user via the chat response, and log the failure as an Audit_Event; partial completion of notification and logging is acceptable if one action fails; THE Orchestrator SHALL NOT fabricate an AI analysis or plan.
3. WHEN a backend security service (scanner, threat engine, network module) is unavailable, THE Orchestrator SHALL log the unavailability, skip the dependent tool call, note the gap in the Execution record, and continue with independent steps.
4. WHEN a database operation fails during Task or Audit_Event persistence, THE Orchestrator SHALL attempt one immediate retry and, if still failing, log to the application logger (structlog) and return an error response; THE Orchestrator SHALL NOT proceed with tool execution if the Audit_Event cannot be persisted.
5. THE Orchestrator SHALL implement a per-Task timeout of 1800 seconds (30 minutes); WHEN a Task exceeds this limit, THE Orchestrator SHALL mark it as `timed_out`, log an Audit_Event, and release all associated resources.
6. THE Orchestrator SHALL never return fabricated, simulated, or placeholder data as real security findings; IF real data is unavailable, THEN THE Orchestrator SHALL respond with a clear message stating that real data is not available for that operation.
7. IF a tool returns a result that fails output schema validation, THEN THE Orchestrator SHALL log the schema violation as an Audit_Event, exclude the invalid result from the AI analysis context, and note the data quality issue in the Task Execution record.

---

### Requirement 10: Weekly Automated Security Report

**User Story:** As a security manager, I want an automated weekly security report generated from real backend data and delivered as a PDF, so that I can review the platform's security posture each week without manual effort.

#### Acceptance Criteria

1. THE Orchestrator SHALL run a Scheduled_Task every 7 days that automatically generates a Security_Report using real data from the AISS_Backend; on-demand generation via `POST /reports/generate` is also permitted; the report SHALL NOT use fabricated or placeholder data in either case.
2. THE Security_Report SHALL be a valid PDF document containing the following sections: Executive Summary, Security Score (0–100), Security Events, Threats Detected, Vulnerabilities, Critical Findings, Network Activity Summary, Device Status, Suspicious Processes, Malware and File Analysis, Authentication and Security Events, Audit Activity, MITRE ATT&CK Mapping, Resolved and Unresolved Incidents, Risk Trends, Recommendations, Actions Taken, Actions Requiring Attention, and Next 7-Day Recommendations.
3. WHEN a Security_Report is generated, THE Orchestrator SHALL persist a Report record containing: report ID (UUID), user/device scope, reporting period start and end dates, generation timestamp (UTC ISO-8601), status (`generating` | `ready` | `failed`), PDF file path (server-side), and a SHA-256 integrity hash of the PDF file.
4. THE Orchestrator SHALL expose `GET /reports` returning a paginated list of all Report records for the authenticated user.
5. THE Orchestrator SHALL expose `GET /reports/latest` returning the most recently generated Security_Report record for the authenticated user.
6. THE Orchestrator SHALL expose `POST /reports/generate` allowing an authenticated user with analyst or admin role to trigger immediate on-demand report generation; this endpoint SHALL return a Task ID so the user can track progress.
7. THE Orchestrator SHALL expose `GET /reports/{id}` returning the full Report record metadata.
8. THE Orchestrator SHALL expose `GET /reports/{id}/pdf` returning the binary PDF file with Content-Type `application/pdf` and Content-Disposition `attachment`; IF the PDF file does not exist on disk, THEN THE Orchestrator SHALL return HTTP 404 with a descriptive error.
9. WHEN a user accesses `GET /reports/{id}/pdf`, THE Orchestrator SHALL verify the PDF file's SHA-256 hash matches the stored integrity hash before serving it; IF the hashes do not match, THEN THE Orchestrator SHALL return HTTP 409 with an integrity violation error and log an Audit_Event.
10. THE Orchestrator SHALL expose `GET /reports/{id}` with deletion support via `DELETE /reports/{id}` for admin users only, logging the deletion as an Audit_Event.

---

### Requirement 11: Report History

**User Story:** As a security analyst, I want to view, download, and manage the history of all past security reports, so that I can track security posture trends over time.

#### Acceptance Criteria

1. THE Orchestrator SHALL maintain a Report_History that includes all past Security_Report records with their metadata (report ID, period, status, generated_at, file size, scope).
2. WHEN a user navigates to the report history view, THE Frontend SHALL retrieve report history via `GET /reports` and display report ID, period dates, status, generated_at, and file size for each entry.
3. THE Orchestrator SHALL support view, download (PDF), export (metadata as JSON), and delete actions on each Report_History entry via the defined API endpoints.
4. WHEN a report generation fails, THE Orchestrator SHALL record the failure in the Report_History with status `failed` and an error_message field, rather than omitting the entry.

---

### Requirement 12: Scheduled Task and Automation Engine

**User Story:** As a security operations engineer, I want to define and manage recurring automated security tasks, so that routine security checks run without manual intervention.

#### Acceptance Criteria

1. THE Orchestrator SHALL expose `POST /scheduled-tasks` accepting: task name, description, tool name or playbook name, arguments, schedule expression (cron or interval in seconds), and enabled flag; authenticated admin or analyst users may create Scheduled_Tasks.
2. THE Orchestrator SHALL expose `GET /scheduled-tasks` returning all Scheduled_Task records for the authenticated user with their next scheduled execution time.
3. THE Orchestrator SHALL expose `DELETE /scheduled-tasks/{id}` allowing authenticated users who are the creator of the task or have the `admin` role to remove a Scheduled_Task; all requests to this endpoint SHALL first be authenticated via JWT before permission checks are evaluated; deletion SHALL log an Audit_Event.
4. WHEN a Scheduled_Task execution time arrives, THE Orchestrator SHALL create a new Task and Execution record, run the task, and record results identically to a user-initiated Task.
5. THE Orchestrator SHALL include the following default Scheduled_Tasks on first startup (if not already present): check critical vulnerabilities every 24 hours, check connected devices every 6 hours, generate weekly security report every 7 days, and investigate suspicious activity on detection events.
6. IF a Scheduled_Task execution fails, THEN THE Orchestrator SHALL record the failure in the Execution record, log an Audit_Event, and continue scheduling future runs without halting the scheduler.
7. THE Orchestrator SHALL limit concurrent Scheduled_Task executions to 5 at any point in time; additional triggered executions SHALL be queued and executed when a slot becomes available.

---

### Requirement 13: Agent Security and Injection Protection

**User Story:** As a security engineer, I want the Orchestrator to defend against prompt injection, tool injection, and privilege escalation attacks, so that a malicious user cannot weaponise the AI agent against the platform.

#### Acceptance Criteria

1. THE Orchestrator SHALL evaluate every incoming chat message against a prompt injection detection filter before passing it to the LLM planning layer; messages containing any prompt injection pattern (including, but not limited to, instruction override strings such as "ignore previous instructions" or "you are now") SHALL be rejected.
2. THE Orchestrator SHALL enforce that the LLM planning output only references tool names that exist in the Tool_Registry; any AI-generated plan referencing a non-existent tool SHALL be rejected with an Audit_Event logged.
3. THE Orchestrator SHALL validate all tool arguments generated by the LLM against the tool's registered `input_schema` before execution; arguments that fail validation SHALL be rejected and not forwarded to the tool implementation.
4. THE Orchestrator SHALL enforce user-scope isolation: a Task created by User A SHALL only be able to access data, devices, and findings scoped to User A; THE Orchestrator SHALL log an Audit_Event with severity `critical` and event_type `cross_user_access_attempt` only when an actual cross-user access attempt is detected, not proactively.
5. THE Orchestrator SHALL enforce that system security policies (Permission_Engine rules, Risk_Level classifications, Approval requirements) always take precedence over any instructions provided in LLM output or user chat messages.
6. THE Orchestrator SHALL rate-limit chat requests to 60 requests per minute per authenticated user; requests exceeding this limit SHALL receive HTTP 429 and be logged as an Audit_Event with event_type `rate_limit_exceeded`.
7. WHEN the Orchestrator detects a tool argument that appears to contain an injection pattern (shell metacharacters, SQL injection strings, path traversal sequences), THE Orchestrator SHALL reject the tool call, log an Audit_Event with event_type `tool_injection_attempt`, and notify the user.

---

### Requirement 14: Database Entities

**User Story:** As a backend developer, I want all Orchestrator data persisted in well-defined database tables using the existing SQLAlchemy async pattern, so that all agent state is durable and queryable.

#### Acceptance Criteria

1. THE AISS_Backend SHALL define and migrate the following new database tables using Alembic: `agent_tasks`, `agent_executions`, `tool_executions`, `scheduled_tasks`, `approvals`, `reports`, `report_history`, `security_findings`, `investigations`, and `agent_audit_events`.
2. THE `agent_tasks` table SHALL include columns: id (UUID PK), user_id (FK to users), status, description, plan_json, created_at, updated_at, completed_at, error_message, playbook_name.
3. THE `agent_executions` table SHALL include columns: id (UUID PK), task_id (FK to agent_tasks), status, steps_json, started_at, completed_at, duration_seconds, error_message.
4. THE `tool_executions` table SHALL include columns: id (UUID PK), execution_id (FK to agent_executions), tool_name, category, risk_level, arguments_json (secrets redacted), result_json, status, started_at, completed_at, duration_seconds, error_message, retry_count.
5. THE `approvals` table SHALL include columns: id (UUID PK), task_id (FK to agent_tasks), tool_name, risk_level, description, reason, affected_resource, status (`pending` | `approved` | `rejected` | `expired`), created_at, decided_at, decided_by.
6. THE `scheduled_tasks` table SHALL include columns: id (UUID PK), user_id (FK to users), name, description, tool_or_playbook, arguments_json, schedule_expression, enabled, last_run_at, next_run_at, created_at.
7. THE `reports` table SHALL include columns: id (UUID PK), user_id (FK to users), period_start, period_end, status, generated_at, file_path, file_size_bytes, sha256_hash, error_message, scope_json.
8. THE `security_findings` table SHALL include columns: id (UUID PK), task_id (FK to agent_tasks), finding_type, severity, title, description, affected_resource, mitre_technique, recommendation, created_at, resolved_at.
9. THE `agent_audit_events` table SHALL include columns: id (UUID PK), user_id (FK to users), event_type, severity, request_summary, plan_summary, tool_name, arguments_redacted_json, auth_result, execution_result_summary, risk_level, approval_status, ai_conclusion, created_at.
10. THE AISS_Backend SHALL register all new models in the existing `init_db()` function so tables are created on startup using the existing `Base.metadata.create_all` pattern.

---

### Requirement 15: OpenRouter LLM Integration

**User Story:** As a platform engineer, I want the Orchestrator to use OpenRouter as its LLM backend, with the API key securely confined to the server, so that the AI planning capability is available without exposing credentials to the frontend.

#### Acceptance Criteria

1. THE Orchestrator SHALL call the OpenRouter API exclusively from the AISS_Backend; the `OPENROUTER_API_KEY` environment variable SHALL never be returned in any API response, logged in any Audit_Event, or transmitted to the Frontend.
2. THE Orchestrator SHALL read the LLM model identifier from the `OPENROUTER_MODEL` environment variable; IF the variable is not set, THEN THE Orchestrator SHALL use a documented default model.
3. WHEN the OpenRouter API returns an authentication error (HTTP 401), THE Orchestrator SHALL log the failure as an Audit_Event with severity `error`, update the Task to status `failed`, and return a user-facing message indicating the LLM service is unavailable; THE Orchestrator SHALL NOT expose the API key or error detail to the user.
4. THE Orchestrator SHALL set a request timeout of 120 seconds for all OpenRouter API calls; WHEN a timeout occurs, THE Orchestrator SHALL treat it as a transient failure and apply the retry policy defined in Requirement 9.
5. THE Orchestrator SHALL construct LLM prompts that include: the available Tool_Registry summary, the user's request, relevant Agent_Memory context, and explicit system-level instructions enforcing the Permission_Engine rules and security policies.
6. THE Orchestrator SHALL parse the LLM's structured plan output and validate it before execution; IF the plan output cannot be parsed into a valid execution plan, THEN THE Orchestrator SHALL always log the parse failure as an Audit_Event regardless of whether a clarification request is subsequently sent to the user, and SHALL respond to the user with a clarification request.

---

### Requirement 16: No Mock or Fabricated Data

**User Story:** As a security analyst, I want all data displayed by the Orchestrator to come from real backend sources, so that I can trust the security assessments and not act on fabricated information.

#### Acceptance Criteria

1. THE Orchestrator SHALL source all security data (threats, vulnerabilities, network activity, device status, audit logs) exclusively from the existing AISS_Backend modules and database; THE Orchestrator SHALL NOT generate or return fabricated security findings, invented threat data, or placeholder results.
2. IF a backend data source is unavailable for a requested tool call, THEN THE Orchestrator SHALL return the message "No real data available for [tool_name]" in the tool result, note the gap in the Execution record, and allow subsequent tool executions to proceed independently; a single tool's backend unavailability SHALL NOT block other tool calls.
3. THE Orchestrator SHALL remove any existing mock data, stub implementations, or `TODO: replace with real data` patterns from the agent implementation before the feature is considered complete.
4. WHEN the Orchestrator generates a Security_Report, THE Orchestrator SHALL include only findings and metrics derived from actual database records and tool execution results within the reporting period.

---

### Requirement 17: API Surface

**User Story:** As a frontend developer, I want a well-defined set of REST API endpoints for all Orchestrator features, so that I can build the frontend interactions predictably.

#### Acceptance Criteria

1. THE AISS_Backend SHALL expose `POST /agent/chat` for submitting chat messages to the Orchestrator.
2. THE AISS_Backend SHALL expose `POST /agent/tasks` for creating a new Task directly (including Playbook invocation).
3. THE AISS_Backend SHALL expose `GET /agent/tasks/{id}` for retrieving a Task with all its Execution steps.
4. THE AISS_Backend SHALL expose `POST /agent/tasks/{id}/cancel` for cancelling a running Task.
5. THE AISS_Backend SHALL expose `GET /agent/executions` for listing all Executions (paginated).
6. THE AISS_Backend SHALL expose `GET /agent/executions/{id}` for retrieving a single Execution record.
7. THE AISS_Backend SHALL expose `POST /agent/approvals/{id}/approve` for approving a pending Approval.
8. THE AISS_Backend SHALL expose `POST /agent/approvals/{id}/reject` for rejecting a pending Approval.
9. THE AISS_Backend SHALL expose `GET /agent/tools` for retrieving the full Tool_Registry catalogue.
10. THE AISS_Backend SHALL expose `GET /agent/status` for retrieving Orchestrator operational status.
11. THE AISS_Backend SHALL expose `GET /reports` for listing all Security_Reports.
12. THE AISS_Backend SHALL expose `GET /reports/latest` for retrieving the latest Security_Report.
13. THE AISS_Backend SHALL expose `POST /reports/generate` for triggering on-demand report generation.
14. THE AISS_Backend SHALL expose `GET /reports/{id}` for retrieving a specific Security_Report's metadata.
15. THE AISS_Backend SHALL expose `GET /reports/{id}/pdf` for downloading a Security_Report as a PDF.
16. THE AISS_Backend SHALL expose `POST /scheduled-tasks` for creating a new Scheduled_Task.
17. THE AISS_Backend SHALL expose `GET /scheduled-tasks` for listing all Scheduled_Tasks.
18. THE AISS_Backend SHALL expose `DELETE /scheduled-tasks/{id}` for deleting a Scheduled_Task.
19. ALL endpoints listed in this requirement SHALL enforce JWT authentication using the existing auth dependency; unauthenticated requests SHALL receive HTTP 401.
20. ALL endpoints listed in this requirement SHALL return JSON responses conforming to consistent schema patterns (data envelope with `status`, `data`, and optionally `error` fields).
