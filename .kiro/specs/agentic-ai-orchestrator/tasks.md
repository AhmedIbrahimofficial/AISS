# Implementation Plan: Agentic AI Orchestrator

## Overview

Implement the Agentic AI Orchestrator as a new autonomous security-agent layer inside the existing
Python/FastAPI backend, plus a React frontend page. The implementation follows the design document
exactly: no mock data, audit-first, approval-gated HIGH/CRITICAL tools, schema-validated execution,
and full user-scope isolation.

All backend files live under `aiss backend/`. All frontend files live under `frontend/src/`.

---

## Tasks

### Phase 1 — Foundation

- [x] 1. Create the `agents/` package and all foundational files
  - [x] 1.1 Create `agents/__init__.py` and `agents/exceptions.py`
    - Create `aiss backend/agents/__init__.py` (empty package marker)
    - Create `aiss backend/agents/exceptions.py` with all custom exception classes:
      `LLMUnavailableError`, `PlanParseError`, `ToolNotFoundError`, `ToolArgValidationError`,
      `PermissionDeniedError`, `PrivilegeEscalationError`, `AuditPersistenceError`,
      `ApprovalTimeoutError`, `ApprovalBypassAttemptError`, `CrossUserAccessError`,
      `RateLimitExceededError`, `OutputSchemaViolationError`
    - Each exception stores a `detail: str` message and optional `audit_event_type: str` class attribute
    - _Requirements: 9.4, 13.4, 4.7, 8.4_

  - [x] 1.2 Create `agents/models.py` — all 9 ORM models
    - Create `aiss backend/agents/models.py`
    - Define `AgentTask`, `AgentExecution`, `ToolExecution`, `Approval`, `ScheduledTask`,
      `Report`, `SecurityFinding`, `AgentAuditEvent` exactly as specified in the design document
    - Use `core.models.Base`, UUID string PKs, `_uuid()` / `_now()` helpers
    - Include all columns, FKs, relationships, and composite indexes from the design
    - _Requirements: 14.1–14.9_

  - [x] 1.3 Create `agents/schemas.py` — all Pydantic request/response schemas
    - Create `aiss backend/agents/schemas.py`
    - Define dataclasses/Pydantic models: `PlanStep`, `ExecutionPlan`, `ToolSummary`,
      `MemoryContext`, `ChatResponse`, `TaskResponse`, `TaskDetailResponse`, `StatusResponse`,
      `ApprovalResponse`, `ToolCatalogueResponse`, `OrchestratorStatusResponse`,
      `PaginatedExecutionsResponse`, `ExecutionDetailResponse`, `PaginatedReportsResponse`,
      `ReportResponse`, `ScheduledTaskResponse`, `ScheduledTasksListResponse`,
      `StepResult`, `ReportData`
    - All JSON responses use the `{"status": "ok"|"error", "data": {...}, "error": null}` envelope
    - _Requirements: 17.20_

  - [x] 1.4 Create Alembic migration for all 9 new tables
    - Create `aiss backend/alembic/versions/XXXX_add_agent_tables.py`
    - Migration creates: `agent_tasks`, `agent_executions`, `tool_executions`, `approvals`,
      `scheduled_tasks`, `reports`, `security_findings`, `agent_audit_events`
    - Include all columns, FK constraints, and indexes from the design
    - `downgrade()` drops all 8 tables in reverse dependency order
    - _Requirements: 14.1_

  - [x] 1.5 Modify `core/database.py` to register agent models in `init_db()`
    - Modify `aiss backend/core/database.py`
    - Inside `init_db()`, add `import agents.models  # noqa: F401` before `Base.metadata.create_all`
    - _Requirements: 14.10_

  - [x] 1.6 Update `.env.example` with new environment variables
    - Modify `aiss backend/.env.example`
    - Add: `OPENROUTER_API_KEY`, `OPENROUTER_MODEL`, `AGENT_REPORTS_DIR`,
      `AGENT_MAX_TASK_TIMEOUT`, `AGENT_APPROVAL_TIMEOUT`
    - _Requirements: 15.1, 15.2_

---

### Phase 2 — Core Agent Layer

- [x] 2. Implement each agent subsystem module
  - [x] 2.1 Implement `agents/audit_logger.py` — `AuditLogger`
    - Create `aiss backend/agents/audit_logger.py`
    - Implement `AuditLogger.log(db, *, user_id, event_type, severity, request_summary, ...)`
      truncating `request_summary` to 2048 chars and calling `_redact_credentials` before any DB write
    - Implement `_redact_credentials(data)` with both key-based and value-based redaction passes
      (patterns: `api_key|apikey|password|passwd|secret|token|credential|auth` keys,
      values matching `sk-[A-Za-z0-9]{20,}`, `Bearer [A-Za-z0-9._-]{20,}`, `ghp_[A-Za-z0-9]{36}`)
    - Raise `AuditPersistenceError` if the DB INSERT fails after one retry; log to structlog
    - Records are INSERT-only — no update/delete methods
    - _Requirements: 8.1–8.7_

  - [x]* 2.2 Write unit tests for `AuditLogger`
    - Create `aiss backend/tests/agents/test_audit_logger.py`
    - Test: password field is redacted; api_key field is redacted; Bearer token value is redacted;
      `sk-` prefix value is redacted; clean dict passes through unchanged;
      DB failure raises `AuditPersistenceError`
    - _Requirements: 8.1, 8.2_

  - [x] 2.3 Implement `agents/security_filter.py` — `SecurityFilter`
    - Create `aiss backend/agents/security_filter.py`
    - Implement `detect_injection(message: str) -> bool` using `INJECTION_PATTERNS` (case-insensitive)
    - Implement `sanitize_args(args: dict) -> tuple[dict, bool]` using `ARG_INJECTION_PATTERNS`
    - Implement `check_rate_limit(user_id, limit=60, window_seconds=60) -> bool`
      using an in-process `collections.defaultdict(deque)` sliding window
    - _Requirements: 1.6, 13.1, 13.3, 13.6_

  - [x]* 2.4 Write unit tests for `SecurityFilter`
    - Create `aiss backend/tests/agents/test_security_filter.py`
    - Test: each injection pattern string is rejected; clean messages pass;
      shell metachar in args is caught; SQL injection string in args is caught;
      rate limit allows 60 req and rejects the 61st within 60s window
    - _Requirements: 1.6, 13.1, 13.6_

  - [x] 2.5 Implement `agents/tool_registry.py` — `ToolRegistry` and `ToolDefinition`
    - Create `aiss backend/agents/tool_registry.py`
    - Define `ToolCategory` enum: `SYSTEM|NETWORK|SECURITY|THREAT_INTELLIGENCE|DEVICES|REPORTING|MONITORING|AUTOMATION`
    - Define `RiskLevel` enum: `LOW|MEDIUM|HIGH|CRITICAL`
    - Define `@dataclass ToolDefinition` with all fields from the design
    - Implement `ToolRegistry` with `register`, `lookup` (raises `ToolNotFoundError`),
      `validate_args` (wraps `jsonschema.validate`, raises `ToolArgValidationError`),
      `get_catalogue() -> list[ToolSummary]`, `get_all() -> list[ToolDefinition]`
    - _Requirements: 2.1–2.6_

  - [x]* 2.6 Write unit tests for `ToolRegistry`
    - Create `aiss backend/tests/agents/test_tool_registry.py`
    - Test: `lookup` raises `ToolNotFoundError` on unknown name;
      `validate_args` raises `ToolArgValidationError` on invalid args;
      `validate_args` passes for valid args; catalogue includes all registered tools
    - _Requirements: 2.3, 2.4_

  - [x] 2.7 Implement `agents/permission_engine.py` — `PermissionEngine`
    - Create `aiss backend/agents/permission_engine.py`
    - Define `ROLE_RANK = {"viewer": 0, "analyst": 1, "admin": 2}`
    - Implement `check(user, tool, task) -> PermissionResult` synchronously
      — LOW/MEDIUM: evaluate role rank; HIGH/CRITICAL: always `requires_approval=True`
    - Implement `validate_plan_scope(plan, user)` — iterates all steps, raises `PrivilegeEscalationError`
      if any tool requires a higher role than the user has
    - All checks complete in < 100 ms (no I/O)
    - _Requirements: 3.1–3.6, 13.5_

  - [x]* 2.8 Write unit tests for `PermissionEngine`
    - Create `aiss backend/tests/agents/test_permission_engine.py`
    - Test: viewer + admin tool → denied; analyst + analyst tool → allowed;
      HIGH tool for any role → `requires_approval=True`;
      CRITICAL tool for admin → `requires_approval=True`;
      plan with escalating tool → `PrivilegeEscalationError`
    - _Requirements: 3.1, 3.2, 3.3_

  - [x] 2.9 Implement `agents/audit_logger.py` property test
    - _(sub-task intentionally under 2.9 so it sits next to the implementation)_
    - Create `aiss backend/tests/agents/property/test_persistence_properties.py`
    - **Property 11: Audit events never contain credential material**
    - `@given(event=any_audit_event())` — scan all string fields of every written `AgentAuditEvent`
      against the credential redaction regex patterns; assert no raw credential found
    - **Validates: Requirements 8.1, 8.2, 7.3**

  - [x] 2.10 Implement `agents/memory_store.py` — `AgentMemoryStore`
    - Create `aiss backend/agents/memory_store.py`
    - Short-term: `dict[task_id, list[StepResult]]` in-process
    - Implement `get_context(user_id, task_id, db) -> MemoryContext`
      — fetches recent `SecurityFinding` and `AgentTask` rows for the user from DB
    - Implement `store_step_result(task_id, step_index, tool_name, result)` (in-memory only)
    - Implement `commit_investigation_summary(task, summary, risk_level, db)` (writes to DB)
    - Implement `discard_short_term(task_id)` — removes from in-process dict immediately
    - Never persist secrets; all string values are passed through `_redact_credentials` before DB writes
    - _Requirements: 7.1–7.6_

  - [x] 2.11 Implement `agents/ai_service.py` — `AIService`
    - Create `aiss backend/agents/ai_service.py`
    - Constructor reads `OPENROUTER_API_KEY` and `OPENROUTER_MODEL` env vars
      (default model: `openai/gpt-4o`); raises `LLMUnavailableError` if key is missing
    - Implement `plan(system_prompt, user_message, tool_catalogue, memory_context) -> ExecutionPlan`
      — calls OpenRouter via `httpx.AsyncClient(timeout=120)`;
      parses response with `pydantic.TypeAdapter(ExecutionPlan)`;
      raises `PlanParseError` on validation failure; raises `LLMUnavailableError` on HTTP 401 (no retry)
    - Implement `_call_openrouter(payload)` with 3-attempt retry loop: delays 2s/4s/8s
      for `TimeoutException` and HTTP 5xx; HTTP 401 raises immediately without retry
    - Implement `summarise(task_results, user_request) -> str`
    - Implement `_build_system_prompt(tool_catalogue, memory_context) -> str`
      — assembles 3 layers: static security policy (hardcoded), dynamic tool catalogue JSON,
      memory context block; the OPENROUTER_API_KEY is never included in the prompt
    - _Requirements: 15.1–15.6_

  - [x]* 2.12 Write property test for `AIService` prompt construction
    - Add to `aiss backend/tests/agents/property/test_llm_properties.py`
    - **Property 14: LLM prompt always contains all required sections**
    - `@given(user_message=text(), memory=any_memory_context())`
    - Assert built prompt contains: tool catalogue JSON block, memory context section,
      and the 5 static policy enforcement rules
    - **Validates: Requirements 15.5**

---

### Phase 3 — Orchestration Engine

- [x] 3. Implement the orchestration core
  - [x] 3.1 Implement `agents/approval_manager.py` — `ApprovalManager`
    - Create `aiss backend/agents/approval_manager.py`
    - Internal `_pending: dict[str, asyncio.Event]`
    - Implement `create_approval(task, tool, description, reason, affected_resource, db) -> Approval`
      — INSERT `Approval` record; broadcast `agent_approval_required` WS event;
      store asyncio.Event keyed by approval_id; log `approval_created` audit event
    - Implement `wait_for_decision(approval_id, timeout=3600) -> ApprovalDecision`
      — `asyncio.wait_for(event.wait(), timeout)`;
      on `TimeoutError`: UPDATE status=`expired`, log `approval_expired`, return `ApprovalDecision.EXPIRED`
    - Implement `approve(approval_id, decided_by, db)` — UPDATE status=`approved`; event.set(); log audit
    - Implement `reject(approval_id, decided_by, db)` — UPDATE status=`rejected`; event.set(); log audit
    - _Requirements: 4.1–4.7_

  - [x]* 3.2 Write unit tests for `ApprovalManager`
    - Create `aiss backend/tests/agents/test_approval_manager.py`
    - Test: `approve` sets event and updates DB status; `reject` cancels and updates DB;
      timeout after 1s mock elapses updates status to `expired` and returns `EXPIRED`
    - _Requirements: 4.4, 4.5, 4.6_

  - [x] 3.3 Implement `agents/tool_implementations/` — all 8 tool handler modules
    - Create `aiss backend/agents/tool_implementations/__init__.py`
    - Create `system_tools.py` — handlers for all 8 SYSTEM tools
      calling existing `core.system_health` / `modules.live_monitor` / psutil
    - Create `network_tools.py` — handlers for all 7 NETWORK tools
      calling existing `modules.network_discovery`, `api.routes.network`
    - Create `security_tools.py` — handlers for all 12 SECURITY tools
      calling existing `core.threat_engine`, `modules.malware_scanner`, `api.routes.scanner`
    - Create `threat_intel_tools.py` — handlers for all 5 THREAT_INTELLIGENCE tools
      calling existing `modules.ioc_extractor`, `modules.threat_intel_feeds`
    - Create `device_tools.py` — handlers for all 6 DEVICES tools
      calling existing `auth.models.AuthUser`/device tables
    - Create `reporting_tools.py` — handlers for all 4 REPORTING tools
      delegating to `ReportGenerator`
    - Create `monitoring_tools.py` — handlers for all 4 MONITORING tools
      calling existing `core.threat_engine`
    - Create `automation_tools.py` — handlers for all 5 AUTOMATION tools
      creating `AgentTask` and `ScheduledTask` records via DB
    - Each handler must: (a) never fabricate data, (b) return `"No real data available for [tool_name]"`
      if the underlying module raises or is unavailable, (c) never accept raw shell commands
    - _Requirements: 2.7–2.14, 16.1–16.3_

  - [x] 3.4 Register all tools in `ToolRegistry` — `agents/tool_registry.py` (continued)
    - Modify `aiss backend/agents/tool_registry.py`
    - Add a `_register_all_tools(registry: ToolRegistry)` function that registers all 40+ tools
      with correct `ToolDefinition` fields (name, description, category, input_schema, output_schema,
      permission_required, risk_level, timeout_seconds, audit_required, handler)
    - Risk-level assignments must match design: LOW for reads, MEDIUM for scans,
      HIGH for quarantine/block/terminate, CRITICAL for delete/irreversible operations
    - Call `_register_all_tools` once at module import time so the singleton is populated
    - _Requirements: 2.1, 2.2, 3.1_

  - [x]* 3.5 Write property tests for `ToolRegistry`
    - Create `aiss backend/tests/agents/property/test_registry_properties.py`
    - **Property 4: Every tool has all required fields and a valid risk level**
    - `@given(tool=sampled_from(registry.get_all()))` — assert all 9 required fields are non-null;
      `risk_level` is one of `LOW|MEDIUM|HIGH|CRITICAL`
    - **Property 5: Invalid tool arguments are always rejected before execution**
    - `@given(tool=sampled_from(registry.get_all()), args=invalid_args_for(tool))`
    - Assert `ToolArgValidationError` raised; handler is never called
    - **Validates: Requirements 2.2, 2.3, 2.4, 3.1**

  - [x] 3.6 Implement `agents/playbooks.py` — Playbook definitions
    - Create `aiss backend/agents/playbooks.py`
    - Define `PLAYBOOK_REGISTRY: dict[str, list[PlanStep]]`
    - Implement `full_security_assessment` playbook with all 15 steps from Requirement 6.1
      in the correct sequence (system health → processes → network → ports → software →
      vulnerability → malware → security events → audit logs → threat intel → MITRE → correlation →
      risk scoring → recommendations → report generation)
    - Each step references the exact registered tool name and a sensible default arguments dict
    - _Requirements: 6.1–6.6_

  - [x] 3.7 Implement `agents/orchestrator.py` — `AgentOrchestrator`
    - Create `aiss backend/agents/orchestrator.py`
    - Constructor takes all 7 dependencies (see design interface)
    - Implement `handle_chat(user, message, session_id, db) -> ChatResponse`:
      1. Create `AgentTask(status="planning")` → DB
      2. `AgentMemoryStore.get_context`
      3. `AIService.plan`
      4. `PermissionEngine.validate_plan_scope`
      5. Update task `status="running"`, store `plan_json`
      6. For each step: lookup → permission check → (approval gate for HIGH/CRITICAL) →
         `validate_args` → `AuditLogger.log_pre` → execute with retry → `AuditLogger.log_post` →
         `AgentMemoryStore.store_step_result` → WS broadcast `agent_step_complete`
      7. Summarise → `AgentTask(status="completed")` → WS broadcast `agent_task_complete`
    - Implement `execute_plan(task, plan, db) -> AgentExecution` (used by scheduler)
    - Implement `cancel_task(task_id, user, db)` — sets `status="cancelled"` regardless of stop result
    - Implement `get_status() -> OrchestratorStatus`
    - Per-task timeout: `asyncio.wait_for(execute_plan(...), timeout=AGENT_MAX_TASK_TIMEOUT)`
    - On `PlanParseError`: log audit, return clarification response, do NOT execute any tool
    - On `LLMUnavailableError`: update task to `degraded`, notify via WS, do NOT fabricate
    - On `AuditPersistenceError`: block tool execution, return HTTP 500
    - On tool backend unavailable: log gap, return "No real data available for [tool]", continue
    - _Requirements: 1.1–1.5, 5.1–5.7, 6.1–6.6, 9.1–9.7_

  - [x]* 3.8 Write unit tests for `AgentOrchestrator`
    - Create `aiss backend/tests/agents/test_orchestrator.py`
    - Test: `cancel_task` returns `status="cancelled"` even when tool stop fails;
      `LLMUnavailableError` → task `status="degraded"`, no tool calls;
      `PlanParseError` → zero tool handler calls, clarification response returned;
      approval bypass attempt detected → task `status="failed"`, critical audit event logged
    - _Requirements: 1.4, 5.3, 9.2_

  - [x]* 3.9 Write property tests for chat and permission
    - Create `aiss backend/tests/agents/property/test_chat_properties.py`
    - **Property 1: Valid chat messages always produce a Task record**
    - `@given(message=valid_chat_message())` — response has UUID `task_id`, status from valid enum
    - **Property 2: Prompt injection patterns are always rejected**
    - `@given(message=injected_message())` — audit event created with `event_type="prompt_injection_attempt"`, no plan executed
    - **Property 3: Invalid plans produce no tool executions**
    - `@given(message=..., llm_response=invalid_plan_json())` — zero tool handler calls
    - Create `aiss backend/tests/agents/property/test_permission_properties.py`
    - **Property 6: HIGH/CRITICAL tools always produce an Approval record**
    - `@given(tool=high_critical_tool(), user=any_user())` — `Approval` record created with `status="pending"`
    - **Property 7: Task halted while approval pending**
    - `@given(task=task_with_pending_approval())` — `task.status == "awaiting_approval"`, no further steps
    - **Validates: Requirements 1.1, 1.6, 1.4, 3.3, 4.1, 4.3, 13.1**

- [x] 4. Checkpoint — Foundation and orchestration core complete
  - Ensure all tests pass. Run `pytest aiss\ backend/tests/agents/ -v`. Ask the user if any questions arise.

---

### Phase 4 — Scheduling and Report Generation

- [x] 5. Implement the scheduler and report generator
  - [x] 5.1 Implement `agents/scheduler.py` — `SchedulerEngine`
    - Create `aiss backend/agents/scheduler.py`
    - Use `AsyncIOScheduler` from `apscheduler>=3.10`
    - Implement `start()` — starts the scheduler; attaches a `asyncio.Semaphore(5)` for concurrency cap
    - Implement `add_job(scheduled_task: ScheduledTask) -> str` — parses `schedule_expression`
      (`"cron:..."` or `"interval:<seconds>"`) and adds to APScheduler
    - Implement `remove_job(job_id: str)`
    - Implement `seed_defaults(db: AsyncSession)` — inserts 4 default `ScheduledTask` rows
      if not already present: check_critical_vulns (24h), check_devices (6h),
      weekly_report (7d), investigate_suspicious (on-detection trigger)
    - Implement `_run_scheduled_task(scheduled_task_id)` — creates `AgentTask` + `AgentExecution`,
      calls `orchestrator.execute_plan`, records results; on failure: log audit, continue scheduling
    - Enforce `Semaphore(5)` — queue additional triggers when all 5 slots are in use
    - _Requirements: 12.1–12.7_

  - [x]* 5.2 Write unit tests for `SchedulerEngine`
    - Create `aiss backend/tests/agents/test_scheduler.py`
    - Test: `seed_defaults` creates exactly 4 tasks on first call and 0 tasks on second call;
      max 5 concurrent enforced (6th call blocks until a slot frees);
      failed scheduled run records failure in `AgentExecution` and does not halt future scheduling
    - _Requirements: 12.5, 12.6, 12.7_

  - [x] 5.3 Create Jinja2 HTML template for PDF reports
    - Create `aiss backend/agents/templates/report/report.html.j2`
    - Include all 20 sections from Requirement 10.2:
      Executive Summary, Security Score (0–100), Security Events, Threats Detected,
      Vulnerabilities, Critical Findings, Network Activity Summary, Device Status,
      Suspicious Processes, Malware and File Analysis, Authentication and Security Events,
      Audit Activity, MITRE ATT&CK Mapping, Resolved/Unresolved Incidents, Risk Trends,
      Recommendations, Actions Taken, Actions Requiring Attention, Next 7-Day Recommendations
    - Create `aiss backend/agents/templates/report/report.css`
      with print-safe styles (WeasyPrint-compatible, no JavaScript, A4 page setup)
    - _Requirements: 10.2_

  - [x] 5.4 Implement `agents/report_generator.py` — `ReportGenerator`
    - Create `aiss backend/agents/report_generator.py`
    - Constructor: `reports_dir = os.environ.get("AGENT_REPORTS_DIR", "data/reports")`
    - Implement `generate(user, period_start, period_end, db) -> Report`:
      1. `_collect_report_data` — queries `agent_audit_events`, `security_findings`,
         threat engine data, scan results, device status for the period and user
      2. Render `report.html.j2` with Jinja2
      3. Convert HTML → PDF via `weasyprint.HTML(string=html).write_pdf()`
      4. Write to `data/reports/{report_id}.pdf`
      5. Compute `hashlib.sha256(file_bytes).hexdigest()`
      6. INSERT `Report(status="ready", file_path, sha256_hash, file_size_bytes, generated_at)`
      7. On any error: UPDATE `Report(status="failed", error_message=...)`
    - Implement `verify_integrity(report) -> bool` — recomputes SHA-256 on disk and compares
    - Source ALL data from real DB records; never use placeholder values
    - Create `data/reports/` directory with `os.makedirs(..., exist_ok=True)` on init
    - _Requirements: 10.1–10.10, 16.4_

  - [x]* 5.5 Write unit tests for `ReportGenerator`
    - Create `aiss backend/tests/agents/test_report_generator.py`
    - Test: generated file exists on disk; `verify_integrity` returns True for untampered file;
      `verify_integrity` returns False after file content is mutated;
      `Report.sha256_hash` stored in DB matches SHA-256 of the file on disk
    - _Requirements: 10.3, 10.9_

  - [x]* 5.6 Write property test for report integrity
    - Create `aiss backend/tests/agents/property/test_report_properties.py`
    - **Property 12: Report PDF integrity verification**
    - `@given(report=generated_report())` — SHA-256 of file at `report.file_path` equals `report.sha256_hash`
    - **Validates: Requirements 10.9**

---

### Phase 5 — API Routes

- [x] 6. Implement all FastAPI routes and wire into main.py
  - [x] 6.1 Implement `api/routes/orchestrator.py` — all agent endpoints
    - Create `aiss backend/api/routes/orchestrator.py`
    - Implement all routes per the design's API Route Definitions section:
      - `POST /agent/chat` — validate JWT; `SecurityFilter.check_rate_limit` (429 if exceeded);
        `SecurityFilter.detect_injection` (400 if hit, log audit); call `orchestrator.handle_chat`
      - `POST /agent/tasks` — create task directly or trigger playbook
      - `GET /agent/tasks/{task_id}` — return full task with executions
      - `POST /agent/tasks/{task_id}/cancel`
      - `GET /agent/executions` — paginated list for current user
      - `GET /agent/executions/{exec_id}` — single execution with redacted args
      - `POST /agent/approvals/{id}/approve` — call `approval_manager.approve`
      - `POST /agent/approvals/{id}/reject` — call `approval_manager.reject`
      - `GET /agent/tools` — return tool catalogue
      - `GET /agent/status`
      - `GET /reports` — paginated
      - `GET /reports/latest`
      - `POST /reports/generate` — analyst|admin only; returns task ID
      - `GET /reports/{report_id}`
      - `GET /reports/{report_id}/pdf` — verify SHA-256 integrity before serving; 409 on mismatch
      - `DELETE /reports/{report_id}` — admin only; log audit
      - `GET /scheduled-tasks`
      - `POST /scheduled-tasks` — analyst|admin only
      - `DELETE /scheduled-tasks/{task_id}` — creator or admin only; authenticate first, then check permission
    - All routes: `Depends(get_current_verified_user)`; unauthenticated → HTTP 401
    - All JSON responses use the standard envelope
    - _Requirements: 17.1–17.20_

  - [x] 6.2 Rename existing `api/routes/agents.py` router prefix to `/remote-agents`
    - Modify `aiss backend/api/routes/agents.py`
    - Change the `router = APIRouter()` declaration to `router = APIRouter(prefix="/remote-agents")`
      OR leave the prefix declaration empty and update `main.py` include to use `/api/remote-agents`
    - This avoids collision between the existing remote-agents routes and the new `/api/agent/*` routes
    - _Requirements: 17.1 (no-collision prerequisite)_

  - [x] 6.3 Add orchestrator and scheduler dependency factories to `core/dependencies.py`
    - Modify `aiss backend/core/dependencies.py`
    - Add `_orchestrator: AgentOrchestrator | None = None` and `_scheduler: SchedulerEngine | None = None` singletons
    - Add `init_agent_services(orchestrator, scheduler)` function
    - Add `get_orchestrator() -> AgentOrchestrator` and `get_scheduler() -> SchedulerEngine` FastAPI dependencies
      (raise 503 if not initialized)
    - _Requirements: 17.19_

  - [x] 6.4 Wire orchestrator and scheduler into `main.py` lifespan
    - Modify `aiss backend/main.py`
    - Import `orchestrator_router` from `api.routes.orchestrator`
    - In `lifespan`, after `init_db()`, construct:
      `AuditLogger`, `SecurityFilter`, `AgentMemoryStore`, `AIService`, `PermissionEngine`,
      `ToolRegistry` (with all tools registered), `ApprovalManager`, `AgentOrchestrator`, `SchedulerEngine`
    - Call `init_agent_services(orchestrator, scheduler)` from `core.dependencies`
    - Call `await scheduler.start()` and `await scheduler.seed_defaults(db)`
    - In the shutdown block, call `await scheduler.shutdown()`
    - Register `orchestrator_router` with `app.include_router(orchestrator_router, prefix="/api")`
    - Update the existing `agents_routes` include prefix from `/api/agents` to `/api/remote-agents`
    - _Requirements: 12.5, 17.1_

- [x] 7. Checkpoint — All backend routes operational
  - Run `pytest aiss\ backend/tests/ -v` and verify all tests pass. Check that `GET /api/agent/tools` returns the tool catalogue when the server starts. Ask the user if any questions arise.

---

### Phase 6 — Frontend

- [x] 8. Implement all frontend agent components
  - [x] 8.1 Create `frontend/src/api/agentApi.ts`
    - Create `frontend/src/api/agentApi.ts`
    - Export `agentApi` object using the existing `apiFetch` helper from `src/lib/api.ts`
    - Implement all methods from the design: `chat`, `getTask`, `cancelTask`, `listExecutions`,
      `getExecution`, `approveAction`, `rejectAction`, `listTools`, `getStatus`,
      `listReports`, `getLatestReport`, `generateReport`, `getReport`, `downloadPdf`,
      `deleteReport`, `listScheduled`, `createScheduled`, `deleteScheduled`
    - For `downloadPdf`: use native `fetch` with `responseType: 'blob'` pattern (not `apiFetch`)
    - Export TypeScript interfaces: `AgentTask`, `AgentExecution`, `ApprovalRequest`,
      `ChatMessage`, `ExecutionStep`, `TaskStatus`, `Report`, `ScheduledTask`, `ToolCatalogueEntry`
    - _Requirements: 17.1–17.19_

  - [x] 8.2 Create `frontend/src/context/AgentContext.tsx`
    - Create `frontend/src/context/AgentContext.tsx`
    - Define `AgentContextValue` interface (tasks map, currentTaskId, pendingApproval,
      chatMessages, dispatch)
    - Define `AgentAction` discriminated union for all state transitions
    - Implement `useReducer`-based context with `AgentProvider` component
    - Implement `useAgentContext()` hook (throws if used outside provider)
    - Wire incoming WebSocket events (`agent_task_created`, `agent_step_complete`,
      `agent_approval_required`, `agent_task_complete`, `agent_task_failed`) to dispatch actions
      using the existing `onWSEvent` from `src/lib/api.ts`
    - _Requirements: 1.3_

  - [x] 8.3 Create `frontend/src/components/agent/ChatPanel.tsx`
    - Create `frontend/src/components/agent/ChatPanel.tsx`
    - Implement `ChatPanelProps` interface: `{ onMessage, messages, isLoading }`
    - Render conversation thread with `role`-based alignment (user right, assistant/system left)
    - Show typing indicator spinner when `isLoading=true`
    - Auto-scroll to bottom on new messages using `useRef` + `useEffect`
    - On submit: call `agentApi.chat(message)`, update context via dispatch
    - Accessibility: textarea has `aria-label`, send button has `aria-label`, list has `role="log"`
    - _Requirements: 1.1, 1.2_

  - [x] 8.4 Create `frontend/src/components/agent/StatusTimeline.tsx`
    - Create `frontend/src/components/agent/StatusTimeline.tsx`
    - Implement `StatusTimelineProps`: `{ taskId, steps, overallStatus }`
    - Render vertical timeline with step index, tool name, status icon, duration, collapsible result
    - Status icons: spinner for `running`, check for `completed`, error X for `failed`, clock for `timed_out`
    - Updates in real-time from WebSocket `agent_step_complete` events via `AgentContext`
    - _Requirements: 1.3, 5.2_

  - [x] 8.5 Create `frontend/src/components/agent/ApprovalModal.tsx`
    - Create `frontend/src/components/agent/ApprovalModal.tsx`
    - Implement `ApprovalModalProps`: `{ approval, onApprove, onReject }`
    - Render modal with: operation description, rationale, affected resource, risk level badge
      (HIGH=orange `border-orange-500`, CRITICAL=red `border-red-600`), estimated impact,
      countdown timer (3600s), "Approve" primary button, "Reject" destructive button
    - Countdown via `useEffect` + `setInterval`; when countdown reaches 0, show "Approval expired"
      toast and auto-close modal
    - `onApprove`: calls `agentApi.approveAction(id)`
    - `onReject`: calls `agentApi.rejectAction(id)`
    - Accessible: `role="dialog"`, `aria-modal="true"`, focus trap on open
    - _Requirements: 4.2, 4.4, 4.5, 4.6_

  - [x] 8.6 Create `frontend/src/components/agent/ReportHistory.tsx`
    - Create `frontend/src/components/agent/ReportHistory.tsx`
    - Fetch `GET /reports` via `agentApi.listReports()` on mount using `useEffect`
    - Display table: Period, Status badge, Generated At, File Size, Actions
    - Actions: "Download PDF" → `agentApi.downloadPdf(id)` → trigger browser download;
      "Delete" (admin only, check `user.role === "admin"`) → `agentApi.deleteReport(id)`
    - "Generate Report" button → `agentApi.generateReport()` → dispatches task to `StatusTimeline`
    - Show skeleton rows while loading; show error state on fetch failure
    - _Requirements: 10.4–10.8, 10.10, 11.1–11.4_

  - [x] 8.7 Create `frontend/src/components/agent/ScheduledTasksPanel.tsx`
    - Create `frontend/src/components/agent/ScheduledTasksPanel.tsx`
    - Fetch `GET /scheduled-tasks` via `agentApi.listScheduled()` on mount
    - Display list: name, schedule expression, last run, next run, enabled toggle
    - "Add Task" button opens inline form modal with fields: name, description, tool_or_playbook,
      arguments_json (JSON textarea), schedule_expression, enabled toggle
    - Form submit: calls `agentApi.createScheduled(body)`
    - "Delete" button: calls `agentApi.deleteScheduled(id)`
    - _Requirements: 12.1–12.3_

  - [x] 8.8 Create `frontend/src/pages/AgentPage.tsx` and register the route
    - Create `frontend/src/pages/AgentPage.tsx`
      — two-column layout: left `ChatPanel` (flex-grow), right column with `StatusTimeline`,
      conditionally-rendered `ApprovalModal`, `ScheduledTasksPanel`, `ReportHistory`
      — wrap content in `AgentProvider`
      — subscribe to WebSocket `agent_*` events and dispatch to context
    - Create `frontend/src/routes/agent.tsx`
      — TanStack Router file-based route that renders `AgentPage`
      — protected: redirect to `/login` if no valid token
    - Add "Agent" navigation link to the existing `AppShell` sidebar
      (modify `frontend/src/components/soc/AppShell.tsx` to add the link)
    - _Requirements: 1.1, 1.3, 4.2_

---

### Phase 7 — Tests

- [x] 9. Write all remaining tests
  - [x] 9.1 Write remaining property-based tests
    - Create `aiss backend/tests/agents/property/test_persistence_properties.py` (if not yet created in 2.9)
    - **Property 8: Task creation persistence round-trip**
    - `@given(message=valid_chat_message())` — `GET /agent/tasks/{id}` returns matching `task_id`,
      `user_id`, `description`, and a valid `status`
    - **Property 9: Task cancellation is always reflected in status**
    - `@given(task=running_task())` — after `cancel_task`: `AgentTask.status == "cancelled"` in DB
    - **Validates: Requirements 5.1, 5.2, 5.3**

  - [x]* 9.2 Write property test for retry policy
    - Create `aiss backend/tests/agents/property/test_retry_properties.py`
    - **Property 13: Transient failures trigger retry with bounded count**
    - `@given(tool=any_tool(), failure_count=integers(0, 3))`
    - Assert `ToolExecution.retry_count <= 3` after terminal state;
      assert delays match the 2s/4s/8s backoff sequence (mock `asyncio.sleep`)
    - **Validates: Requirements 9.1**

  - [x]* 9.3 Write integration tests
    - Create `aiss backend/tests/integration/test_agent_api.py`
    - Full roundtrip: `POST /api/agent/chat` → poll WebSocket for step events →
      `GET /api/agent/tasks/{id}` → assert status `completed` and steps recorded
    - Use test SQLite database and mock `AIService.plan` to return a deterministic plan
    - Create `aiss backend/tests/integration/test_approval_flow.py`
    - HIGH risk tool in plan → assert `Approval` record created with `status="pending"` →
      `POST /api/agent/approvals/{id}/approve` → assert tool execution proceeds →
      assert `Approval.status="approved"` in DB
    - Create `aiss backend/tests/integration/test_scheduler.py`
    - Start app with test lifespan → assert `seed_defaults` creates exactly 4 scheduled tasks →
      manually trigger a scheduled run → assert `AgentExecution` record created
    - Create `aiss backend/tests/integration/test_reports.py`
    - `POST /api/reports/generate` → poll until `status="ready"` →
      `GET /api/reports/{id}/pdf` → assert binary PDF response; assert integrity hash matches
    - _Requirements: 1.1, 4.1, 10.1, 10.9, 12.5_

  - [x] 9.4 Add new Python dependencies to `requirements.txt`
    - Modify `aiss backend/requirements.txt`
    - Add (pinned): `apscheduler==3.10.4`, `weasyprint==62.0`, `jinja2==3.1.4`,
      `httpx==0.27.0`, `jsonschema==4.22.0`
    - Add (test-only): `hypothesis==6.100.0`
    - Verify `pydantic>=2.7.0` is already present (do not add duplicate)
    - _Requirements: design dependencies section_

- [x] 10. Final checkpoint — complete feature validation
  - Run the full test suite: `pytest aiss\ backend/tests/ -v --tb=short`
  - Verify `GET /api/agent/tools` returns 40+ tools
  - Verify `GET /api/agent/status` returns operational state with LLM model name
  - Verify frontend builds without TypeScript errors: `cd frontend && npm run build`
  - Ask the user if any questions arise.

---

## Notes

- Tasks marked with `*` are optional and may be skipped for a faster MVP iteration
- Every sub-task references specific requirements for full traceability
- All tool handlers must return real data or the explicit "No real data available for [tool_name]" message — no mocks
- `AuditPersistenceError` blocks tool execution in ALL cases — the audit-first invariant is non-negotiable
- The `OPENROUTER_API_KEY` must never appear in any log, response, or prompt string
- The existing `api/routes/agents.py` remote-agent routes must remain functional after the prefix rename

## Task Dependency Graph

```json
{
  "waves": [
    { "id": 0, "tasks": ["1.1", "1.6"] },
    { "id": 1, "tasks": ["1.2", "1.3"] },
    { "id": 2, "tasks": ["1.4", "1.5"] },
    { "id": 3, "tasks": ["2.1", "2.3", "2.5", "2.7", "2.10"] },
    { "id": 4, "tasks": ["2.2", "2.4", "2.6", "2.8", "2.9", "2.11"] },
    { "id": 5, "tasks": ["2.12", "3.1", "3.3"] },
    { "id": 6, "tasks": ["3.2", "3.4"] },
    { "id": 7, "tasks": ["3.5", "3.6"] },
    { "id": 8, "tasks": ["3.7", "2.9"] },
    { "id": 9, "tasks": ["3.8", "3.9", "5.1", "5.3"] },
    { "id": 10, "tasks": ["5.2", "5.4"] },
    { "id": 11, "tasks": ["5.5", "5.6", "6.1", "6.2", "6.3"] },
    { "id": 12, "tasks": ["6.4", "8.1"] },
    { "id": 13, "tasks": ["8.2"] },
    { "id": 14, "tasks": ["8.3", "8.4", "8.5", "8.6", "8.7"] },
    { "id": 15, "tasks": ["8.8", "9.4"] },
    { "id": 16, "tasks": ["9.1", "9.2", "9.3"] }
  ]
}
```
