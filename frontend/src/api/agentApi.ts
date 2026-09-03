/**
 * AISS Agent Orchestrator — API Client
 * All calls go to the backend only. No API keys are ever exposed here.
 */
import { getToken } from "../lib/api";

const BASE = (import.meta.env["VITE_AISS_API_URL"] as string | undefined) ?? "http://localhost:8000";

// ── Types ─────────────────────────────────────────────────────────────

export interface AgentTask {
  id: string;
  status: string;
  description: string;
  created_at: string;
  updated_at: string;
  plan_json?: Record<string, unknown>;
  playbook_name?: string;
  error_message?: string;
  executions: ExecutionSummary[];
  approvals: ApprovalSummary[];
}

export interface ExecutionSummary {
  id: string;
  status: string;
  started_at: string;
  completed_at?: string;
  duration_seconds?: number;
}

export interface ApprovalSummary {
  id: string;
  tool_name: string;
  risk_level: string;
  status: string;
  created_at: string;
}

export interface ApprovalRequest {
  id: string;
  task_id: string;
  tool_name: string;
  risk_level: string;
  description: string;
  reason: string;
  affected_resource?: string;
  estimated_impact?: string;
  status: string;
  created_at: string;
  decided_at?: string;
  decided_by?: string;
}

export interface ChatMessage {
  role: "user" | "assistant" | "system";
  content: string;
  task_id?: string;
  created_at: string;
}

export interface ExecutionStep {
  step_index: number;
  tool_name: string;
  status: string;
  duration_ms?: number;
  result_summary?: string;
  error?: string;
}

export type TaskStatus =
  | "pending" | "planning" | "running" | "awaiting_approval"
  | "completed" | "failed" | "cancelled" | "approval_rejected"
  | "timed_out" | "degraded";

export interface Report {
  id: string;
  user_id: string;
  period_start: string;
  period_end: string;
  status: "generating" | "ready" | "failed";
  generated_at?: string;
  file_size_bytes?: number;
  sha256_hash?: string;
  error_message?: string;
  scope_json?: Record<string, unknown>;
}

export interface ScheduledTask {
  id: string;
  name: string;
  description?: string;
  tool_or_playbook: string;
  arguments_json?: Record<string, unknown>;
  schedule_expression: string;
  enabled: boolean;
  last_run_at?: string;
  next_run_at?: string;
  created_at: string;
}

export interface ToolCatalogueEntry {
  name: string;
  description: string;
  category: string;
  risk_level: string;
  input_schema: Record<string, unknown>;
}

export interface AgentStatus {
  is_active: boolean;
  running_tasks: number;
  degraded_subsystems: string[];
  llm_model: string;
}

// ── Core fetch ────────────────────────────────────────────────────────

async function agentFetch<T>(path: string, opts: RequestInit = {}): Promise<T> {
  const token = getToken();
  const headers: Record<string, string> = {
    "Content-Type": "application/json",
    ...(opts.headers as Record<string, string> | undefined),
  };
  if (token) headers["Authorization"] = `Bearer ${token}`;

  const res = await fetch(`${BASE}${path}`, { ...opts, headers });
  if (!res.ok) {
    const err = await res.json().catch(() => ({ error: res.statusText }));
    throw new Error(
      (err as { error?: string; detail?: string }).error ??
      (err as { detail?: string }).detail ??
      `HTTP ${res.status}`
    );
  }
  const body = await res.json() as { status: string; data: T; error?: string };
  if (body.status === "error") throw new Error(body.error ?? "API error");
  return body.data as T;
}

// ── Agent Chat & Tasks ────────────────────────────────────────────────

export const agentApi = {
  /** Send a natural-language message to the AI agent */
  chat: (message: string, sessionId?: string) =>
    agentFetch<{ task_id: string; status: string; reply: string; created_at: string }>(
      "/api/agent/chat",
      { method: "POST", body: JSON.stringify({ message, session_id: sessionId }) }
    ),

  /** Create a task directly or trigger a playbook */
  createTask: (body: { description?: string; playbook?: string }) =>
    agentFetch<{ task_id: string; status: string; reply: string; created_at: string }>(
      "/api/agent/tasks",
      { method: "POST", body: JSON.stringify(body) }
    ),

  /** Get full task details with executions and approvals */
  getTask: (id: string) =>
    agentFetch<AgentTask>(`/api/agent/tasks/${id}`),

  /** Cancel a running task */
  cancelTask: (id: string) =>
    agentFetch<{ task_id: string; status: string }>(
      `/api/agent/tasks/${id}/cancel`,
      { method: "POST" }
    ),

  /** List executions (paginated) */
  listExecutions: (page = 1, pageSize = 20) =>
    agentFetch<{ items: ExecutionSummary[]; total: number; page: number; page_size: number }>(
      `/api/agent/executions?page=${page}&page_size=${pageSize}`
    ),

  /** Get full execution details */
  getExecution: (id: string) =>
    agentFetch<{ id: string; task_id: string; status: string; steps_json: unknown[]; tool_executions: unknown[] }>(
      `/api/agent/executions/${id}`
    ),

  /** Approve a pending HIGH/CRITICAL operation */
  approveAction: (id: string) =>
    agentFetch<{ approval_id: string; status: string }>(
      `/api/agent/approvals/${id}/approve`,
      { method: "POST" }
    ),

  /** Reject a pending operation */
  rejectAction: (id: string) =>
    agentFetch<{ approval_id: string; status: string }>(
      `/api/agent/approvals/${id}/reject`,
      { method: "POST" }
    ),

  /** Get all registered tools */
  listTools: () =>
    agentFetch<{ tools: ToolCatalogueEntry[] }>("/api/agent/tools"),

  /** Get orchestrator status */
  getStatus: () =>
    agentFetch<AgentStatus>("/api/agent/status"),

  // ── Reports ──────────────────────────────────────────────────────

  /** List all reports (paginated) */
  listReports: (page = 1, pageSize = 20) =>
    agentFetch<{ items: Report[]; total: number; page: number; page_size: number }>(
      `/api/reports?page=${page}&page_size=${pageSize}`
    ),

  /** Get the latest report */
  getLatestReport: () =>
    agentFetch<Report>("/api/reports/latest"),

  /** Trigger on-demand report generation */
  generateReport: (periodStart?: string, periodEnd?: string) =>
    agentFetch<{ report_id: string; status: string }>(
      "/api/reports/generate",
      {
        method: "POST",
        body: JSON.stringify({ period_start: periodStart, period_end: periodEnd }),
      }
    ),

  /** Get report metadata */
  getReport: (id: string) =>
    agentFetch<Report>(`/api/reports/${id}`),

  /** Download a report PDF — returns a Blob */
  downloadPdf: async (id: string): Promise<Blob> => {
    const token = getToken();
    const res = await fetch(`${BASE}/api/reports/${id}/pdf`, {
      headers: token ? { Authorization: `Bearer ${token}` } : {},
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({ detail: res.statusText }));
      throw new Error((err as { detail?: string }).detail ?? `HTTP ${res.status}`);
    }
    return res.blob();
  },

  /** Delete a report (admin only) */
  deleteReport: (id: string) =>
    agentFetch<{ report_id: string; status: string }>(
      `/api/reports/${id}`,
      { method: "DELETE" }
    ),

  // ── Scheduled Tasks ───────────────────────────────────────────────

  /** List all scheduled tasks */
  listScheduled: () =>
    agentFetch<{ items: ScheduledTask[] }>("/api/scheduled-tasks"),

  /** Create a scheduled task */
  createScheduled: (body: {
    name: string;
    tool_or_playbook: string;
    schedule_expression: string;
    description?: string;
    arguments_json?: Record<string, unknown>;
    enabled?: boolean;
  }) =>
    agentFetch<ScheduledTask>("/api/scheduled-tasks", {
      method: "POST",
      body: JSON.stringify(body),
    }),

  /** Delete a scheduled task */
  deleteScheduled: (id: string) =>
    agentFetch<{ task_id: string; status: string }>(
      `/api/scheduled-tasks/${id}`,
      { method: "DELETE" }
    ),
};

export default agentApi;
