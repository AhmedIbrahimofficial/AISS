/**
 * Audit Logs — AISS
 * Real backend:
 *  - /api/agent/executions  — agent audit events
 *  - /api/threats/          — threat log
 *  - /api/auth/sessions     — active sessions
 */
import { createFileRoute } from "@tanstack/react-router";
import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { toast } from "sonner";
import { History, Search, Download, RefreshCw, Shield, Activity } from "lucide-react";
import { PageHeader } from "@/components/soc/AppShell";
import { Panel } from "@/components/soc/Panel";
import { Badge, Metric } from "@/components/soc/ui";
import { ActionButton } from "@/components/soc/actions";
import { getThreats, exportThreatsExcel } from "@/lib/api";

const BASE = (import.meta.env["VITE_AISS_API_URL"] as string | undefined) ?? "http://localhost:8000";

async function apiFetch<T>(path: string): Promise<T> {
  const tok = localStorage.getItem("aiss_token") ?? "";
  const r = await fetch(`${BASE}${path}`, {
    headers: { "Content-Type": "application/json", Authorization: `Bearer ${tok}` },
  });
  if (!r.ok) throw new Error(`HTTP ${r.status}`);
  return r.json() as Promise<T>;
}

interface AgentExecution {
  id: string; task_id: string; status: string; started_at: string;
  completed_at?: string; duration_seconds?: number; error_message?: string;
  steps_json?: unknown;
}

interface Session {
  id: string; device_info?: string; created_at: string; last_used_at?: string; revoked: boolean;
}

export const Route = createFileRoute("/audit-logs")({
  head: () => ({
    meta: [
      { title: "Audit Logs — AISS Security Console" },
      { name: "description", content: "Immutable audit trail: threats, agent actions, operator sessions" },
    ],
  }),
  component: AuditLogsPage,
});

type TabId = "threats" | "agent" | "sessions";

function AuditLogsPage() {
  const [tab, setTab]       = useState<TabId>("threats");
  const [search, setSearch] = useState("");
  const [exporting, setExporting] = useState(false);

  const { data: threatsData, isLoading: threatsLoading, refetch: refetchThreats } = useQuery({
    queryKey: ["audit-threats"],
    queryFn: getThreats,
    refetchInterval: 15_000,
  });

  const { data: executionsData, isLoading: execLoading, refetch: refetchExec } = useQuery({
    queryKey: ["audit-executions"],
    queryFn: async () => {
      const resp = await apiFetch<{ status: string; data: { items: AgentExecution[]; total: number } } | { executions: AgentExecution[] }>("/api/agent/executions");
      if ("data" in resp && resp.data && "items" in resp.data) return { executions: resp.data.items };
      return resp as { executions: AgentExecution[] };
    },
    refetchInterval: 15_000,
  });

  const { data: sessionsData, isLoading: sessLoading, refetch: refetchSessions } = useQuery({
    queryKey: ["auth-sessions"],
    queryFn: () => apiFetch<{ sessions: Session[] }>("/api/auth/sessions"),
    refetchInterval: 30_000,
  });

  const threats     = threatsData?.threats ?? [];
  const executions  = executionsData?.executions ?? [];
  const sessions    = sessionsData?.sessions ?? [];

  const filteredThreats = threats.filter(t =>
    !search ||
    t.type.toLowerCase().includes(search.toLowerCase()) ||
    t.source.toLowerCase().includes(search.toLowerCase()) ||
    t.module.toLowerCase().includes(search.toLowerCase())
  );

  const handleExport = async () => {
    setExporting(true);
    try {
      const r = await exportThreatsExcel();
      const blob = await r.blob();
      const url  = URL.createObjectURL(blob);
      const a    = document.createElement("a");
      a.href = url; a.download = "aiss_audit.xlsx"; a.click();
      URL.revokeObjectURL(url);
      toast.success("Audit export downloaded");
    } catch (e) {
      toast.error(String(e));
    } finally {
      setExporting(false);
    }
  };

  const sev = (s: string) =>
    s === "critical" ? "critical" : s === "high" ? "warning" : s === "medium" ? "info" : "success";

  const TABS: { id: TabId; label: string; count: number }[] = [
    { id: "threats",  label: "Threat Log",      count: threats.length },
    { id: "agent",    label: "Agent Actions",    count: executions.length },
    { id: "sessions", label: "Operator Sessions", count: sessions.length },
  ];

  return (
    <div>
      <PageHeader
        title="Audit Logs"
        subtitle="Immutable record of threat detections, AI agent actions, and operator sessions"
        right={
          <div className="flex gap-2">
            <ActionButton label="Refresh" onClick={() => { void refetchThreats(); void refetchExec(); void refetchSessions(); }} />
            <ActionButton label="Export" tone="success" onClick={() => void handleExport()} />
          </div>
        }
      />

      {/* KPIs */}
      <div className="mb-4 grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
        <Metric label="Threat Events"     value={String(threats.length)}      tone="default" sub="all time" />
        <Metric label="Agent Executions"  value={String(executions.length)}   tone="info"    sub="recorded" />
        <Metric label="Active Sessions"   value={String(sessions.filter(s => !s.revoked).length)} tone="success" sub="operator sessions" />
        <Metric label="Resolved Threats"  value={String(threats.filter(t => t.status === "resolved").length)} tone="success" />
      </div>

      {/* Tab bar */}
      <div className="mb-4 flex gap-1 border-b border-[var(--hairline)] pb-2">
        {TABS.map(t => (
          <button
            key={t.id}
            onClick={() => setTab(t.id)}
            className={`flex items-center gap-1.5 rounded-md border px-3 py-1.5 font-mono text-[0.62rem] uppercase transition-colors ${
              tab === t.id ? "border-primary/40 bg-primary/12 text-primary" : "border-transparent text-muted-foreground hover:bg-white/5"
            }`}
          >
            {t.label}
            <span className={`rounded px-1 py-0.5 font-mono text-[0.55rem] ${tab === t.id ? "bg-primary/20" : "bg-white/10"}`}>
              {t.count}
            </span>
          </button>
        ))}

        {tab === "threats" && (
          <div className="ml-auto relative">
            <Search className="absolute left-2 top-1/2 -translate-y-1/2 size-3 text-muted-foreground" />
            <input
              value={search}
              onChange={e => setSearch(e.target.value)}
              placeholder="Filter threats..."
              className="rounded-md border border-[var(--hairline)] bg-white/5 pl-6 pr-2 py-1 text-xs outline-none focus:border-primary/50"
            />
          </div>
        )}
      </div>

      {/* ── Threat log ────────────────────────────────────── */}
      {tab === "threats" && (
        <Panel title="Threat Detection Log">
          {threatsLoading ? (
            <div className="flex h-32 items-center justify-center">
              <div className="size-6 animate-spin rounded-full border-2 border-primary border-t-transparent" />
            </div>
          ) : filteredThreats.length === 0 ? (
            <div className="flex h-24 flex-col items-center justify-center gap-2 text-muted-foreground">
              <Shield className="size-8 opacity-40" />
              <p className="text-sm">No threat events recorded</p>
            </div>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-[var(--hairline)]">
                    {["Time", "Type", "Source", "Module", "Severity", "Status", "Actions"].map(h => (
                      <th key={h} className="label-cap px-2.5 py-2 text-left text-[0.58rem]">{h}</th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {filteredThreats.slice(0, 100).map((t) => (
                    <tr key={t.id} className="border-b border-[var(--hairline)] last:border-0 hover:bg-white/4">
                      <td className="px-2.5 py-1.5 font-mono text-[0.6rem] text-muted-foreground whitespace-nowrap">
                        {new Date(t.detected_at).toLocaleString()}
                      </td>
                      <td className="px-2.5 py-1.5 max-w-[160px] truncate text-xs">{t.type}</td>
                      <td className="px-2.5 py-1.5 font-mono text-[0.65rem] text-muted-foreground">{t.source}</td>
                      <td className="px-2.5 py-1.5 text-[0.65rem] text-muted-foreground">{t.module}</td>
                      <td className="px-2.5 py-1.5"><Badge tone={sev(t.severity)}>{t.severity.toUpperCase()}</Badge></td>
                      <td className="px-2.5 py-1.5">
                        <Badge tone={t.status === "resolved" ? "success" : t.status === "active" ? "critical" : "warning"}>
                          {t.status}
                        </Badge>
                      </td>
                      <td className="px-2.5 py-1.5">
                        <ActionButton label="View" tone="info" className="px-1.5 py-0.5 text-[0.58rem]"
                          to={`/investigate/alert/${t.id}`} />
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
              {filteredThreats.length > 100 && (
                <p className="mt-2 text-center font-mono text-[0.6rem] text-muted-foreground">
                  Showing 100 of {filteredThreats.length} records
                </p>
              )}
            </div>
          )}
        </Panel>
      )}

      {/* ── Agent executions ──────────────────────────────── */}
      {tab === "agent" && (
        <Panel title="AI Agent Execution Log">
          {execLoading ? (
            <div className="flex h-32 items-center justify-center">
              <div className="size-6 animate-spin rounded-full border-2 border-primary border-t-transparent" />
            </div>
          ) : executions.length === 0 ? (
            <div className="flex h-24 flex-col items-center justify-center gap-2 text-muted-foreground">
              <Activity className="size-8 opacity-40" />
              <p className="text-sm">No agent executions yet</p>
              <p className="text-xs opacity-60">Use the AI Security Agent to run security tasks</p>
            </div>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-[var(--hairline)]">
                    {["ID", "Task", "Status", "Started", "Duration", "Details"].map(h => (
                      <th key={h} className="label-cap px-2.5 py-2 text-left text-[0.58rem]">{h}</th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {executions.map((e: AgentExecution) => (
                    <tr key={e.id} className="border-b border-[var(--hairline)] last:border-0 hover:bg-white/4">
                      <td className="px-2.5 py-1.5 font-mono text-[0.6rem] text-muted-foreground">{e.id.slice(0, 8)}</td>
                      <td className="px-2.5 py-1.5 font-mono text-[0.6rem] text-muted-foreground">{e.task_id.slice(0, 8)}</td>
                      <td className="px-2.5 py-1.5">
                        <Badge tone={e.status === "completed" ? "success" : e.status === "failed" ? "critical" : "warning"}>
                          {e.status}
                        </Badge>
                      </td>
                      <td className="px-2.5 py-1.5 font-mono text-[0.6rem] text-muted-foreground whitespace-nowrap">
                        {new Date(e.started_at).toLocaleString()}
                      </td>
                      <td className="px-2.5 py-1.5 font-mono text-xs">
                        {e.duration_seconds != null ? `${e.duration_seconds.toFixed(1)}s` : "—"}
                      </td>
                      <td className="px-2.5 py-1.5 text-xs text-muted-foreground max-w-[200px] truncate">
                        {e.error_message ?? "OK"}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </Panel>
      )}

      {/* ── Sessions ──────────────────────────────────────── */}
      {tab === "sessions" && (
        <Panel title="Operator Sessions">
          {sessLoading ? (
            <div className="flex h-32 items-center justify-center">
              <div className="size-6 animate-spin rounded-full border-2 border-primary border-t-transparent" />
            </div>
          ) : sessions.length === 0 ? (
            <div className="flex h-24 flex-col items-center justify-center gap-2 text-muted-foreground">
              <Shield className="size-8 opacity-40" />
              <p className="text-sm">No session records</p>
            </div>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-[var(--hairline)]">
                    {["Session ID", "Device", "Created", "Last Used", "Status"].map(h => (
                      <th key={h} className="label-cap px-2.5 py-2 text-left text-[0.58rem]">{h}</th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {sessions.map((s: Session) => (
                    <tr key={s.id} className="border-b border-[var(--hairline)] last:border-0 hover:bg-white/4">
                      <td className="px-2.5 py-1.5 font-mono text-[0.6rem] text-muted-foreground">{s.id.slice(0, 12)}</td>
                      <td className="px-2.5 py-1.5 text-xs text-muted-foreground">{s.device_info ?? "Unknown"}</td>
                      <td className="px-2.5 py-1.5 font-mono text-[0.6rem] text-muted-foreground whitespace-nowrap">
                        {new Date(s.created_at).toLocaleString()}
                      </td>
                      <td className="px-2.5 py-1.5 font-mono text-[0.6rem] text-muted-foreground whitespace-nowrap">
                        {s.last_used_at ? new Date(s.last_used_at).toLocaleString() : "—"}
                      </td>
                      <td className="px-2.5 py-1.5">
                        <Badge tone={s.revoked ? "critical" : "success"}>{s.revoked ? "REVOKED" : "ACTIVE"}</Badge>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </Panel>
      )}
    </div>
  );
}
