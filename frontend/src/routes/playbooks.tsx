/**
 * Playbooks — AISS
 * Real backend:
 *  - POST /api/agent/tasks    — execute a playbook via AI agent
 *  - GET  /api/agent/tasks    — task history
 *  - GET  /api/agent/tools    — available tools catalog
 */
import { createFileRoute, Link } from "@tanstack/react-router";
import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { toast } from "sonner";
import { Play, Loader2, CheckCircle, XCircle, Clock, ChevronRight, Shield } from "lucide-react";
import { PageHeader } from "@/components/soc/AppShell";
import { Panel } from "@/components/soc/Panel";
import { Badge, Metric } from "@/components/soc/ui";
import { ActionButton } from "@/components/soc/actions";

const BASE = (import.meta.env["VITE_AISS_API_URL"] as string | undefined) ?? "http://localhost:8000";

async function apiFetch<T>(path: string, opts: RequestInit = {}): Promise<T> {
  const tok = localStorage.getItem("aiss_token") ?? "";
  const r = await fetch(`${BASE}${path}`, {
    ...opts,
    headers: { "Content-Type": "application/json", Authorization: `Bearer ${tok}`, ...(opts.headers ?? {}) },
  });
  if (!r.ok) {
    const err = await r.json().catch(() => ({ detail: r.statusText })) as { detail?: string };
    throw new Error(err.detail ?? `HTTP ${r.status}`);
  }
  return r.json() as Promise<T>;
}

interface AgentTask {
  id: string; status: string; description?: string; playbook_name?: string;
  created_at: string; updated_at?: string; completed_at?: string;
  error_message?: string; plan_json?: unknown;
}

// ── Built-in playbook catalog ─────────────────────────────────────────
const PLAYBOOKS = [
  {
    id: "full_security_assessment",
    name: "Full Security Assessment",
    description: "15-step comprehensive security review: system health, processes, network, vulnerability scan, malware, events, threat intel, risk analysis, report generation.",
    steps: 15,
    duration: "3–5 min",
    risk: "LOW",
    category: "Assessment",
  },
  {
    id: "incident_response",
    name: "Incident Response",
    description: "Automated incident response: collect evidence, analyze threats, isolate if needed, document findings, and generate incident report.",
    steps: 8,
    duration: "1–3 min",
    risk: "MEDIUM",
    category: "Response",
  },
  {
    id: "vulnerability_scan",
    name: "Vulnerability Scan",
    description: "Scan all assets for known vulnerabilities using CVE intelligence, check installed software versions, map MITRE ATT&CK coverage.",
    steps: 6,
    duration: "2–4 min",
    risk: "LOW",
    category: "Vulnerability",
  },
  {
    id: "network_recon",
    name: "Network Reconnaissance",
    description: "Discover all hosts on configured segments, scan open ports, identify risky services, check for C2 beaconing patterns.",
    steps: 7,
    duration: "3–8 min",
    risk: "LOW",
    category: "Network",
  },
  {
    id: "threat_hunting",
    name: "Threat Hunting",
    description: "AI-assisted threat hunting: analyze processes, network, files, and logs for indicators of compromise and lateral movement.",
    steps: 10,
    duration: "2–5 min",
    risk: "LOW",
    category: "Hunting",
  },
  {
    id: "malware_sweep",
    name: "Malware Sweep",
    description: "Full YARA-based malware sweep of running processes and file system, entropy analysis, IOC extraction, quarantine recommendations.",
    steps: 5,
    duration: "1–3 min",
    risk: "LOW",
    category: "Malware",
  },
] as const;

const categoryTone: Record<string, "info" | "warning" | "critical" | "success" | "default"> = {
  Assessment:    "info",
  Response:      "warning",
  Vulnerability: "warning",
  Network:       "info",
  Hunting:       "success",
  Malware:       "critical",
};

const riskTone: Record<string, "success" | "warning" | "critical"> = {
  LOW: "success", MEDIUM: "warning", HIGH: "critical",
};

function PlaybooksPage() {
  const [running, setRunning]     = useState<string | null>(null);
  const [selected, setSelected]   = useState<AgentTask | null>(null);

  const { data: tasksData, isLoading: tasksLoading, refetch } = useQuery({
    queryKey: ["playbook-tasks"],
    queryFn: async () => {
      const resp = await apiFetch<{ status: string; data: { tasks: AgentTask[]; total: number } }>("/api/agent/tasks");
      return { tasks: resp.data?.tasks ?? [] };
    },
    refetchInterval: 5000,
  });

  const tasks = tasksData?.tasks ?? [];

  const runPlaybook = async (playbook: typeof PLAYBOOKS[number]) => {
    setRunning(playbook.id);
    try {
      const resp = await apiFetch<{ status: string; data: { task_id: string; status: string } }>("/api/agent/tasks", {
        method: "POST",
        body: JSON.stringify({ playbook: playbook.id, description: playbook.description }),
      });
      toast.success(`Playbook started: ${playbook.name}`, {
        description: `Task ID: ${resp.data?.task_id?.slice(0, 12) ?? "unknown"}`,
      });
      void refetch();
    } catch (e) {
      toast.error(`Playbook failed: ${String(e)}`);
    } finally {
      setRunning(null);
    }
  };

  const completedCount = tasks.filter(t => t.status === "completed").length;
  const failedCount    = tasks.filter(t => t.status === "failed").length;
  const runningCount   = tasks.filter(t => t.status === "running" || t.status === "pending").length;

  return (
    <div>
      <PageHeader
        title="Playbooks"
        subtitle="Execute automated security response workflows powered by the AI agent"
        right={
          <div className="flex items-center gap-2">
            <Badge tone={runningCount > 0 ? "warning" : "success"}>
              {runningCount > 0 ? `${runningCount} RUNNING` : "READY"}
            </Badge>
            <ActionButton label="Refresh" onClick={() => void refetch()} />
          </div>
        }
      />

      {/* KPIs */}
      <div className="mb-4 grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
        <Metric label="Available Playbooks" value={String(PLAYBOOKS.length)}  tone="info"    sub="automated workflows" />
        <Metric label="Running"             value={String(runningCount)}      tone={runningCount > 0 ? "warning" : "default"} />
        <Metric label="Completed"           value={String(completedCount)}    tone="success" />
        <Metric label="Failed"              value={String(failedCount)}       tone={failedCount > 0 ? "critical" : "default"} />
      </div>

      <div className="grid gap-4 xl:grid-cols-12">
        {/* Playbook catalog */}
        <div className="xl:col-span-7">
          <Panel title="Playbook Catalog">
            <div className="space-y-2">
              {PLAYBOOKS.map(pb => {
                const isRunning = running === pb.id;
                const activeTask = tasks.find(t =>
                  (t.playbook_name === pb.id) &&
                  (t.status === "running" || t.status === "pending")
                );

                return (
                  <div key={pb.id} className="rounded-lg border border-[var(--hairline)] p-4 hover:bg-white/4 transition-colors">
                    <div className="flex items-start gap-3">
                      <div className="flex-1 min-w-0">
                        <div className="flex items-center gap-2 mb-1">
                          <p className="text-sm font-semibold">{pb.name}</p>
                          <Badge tone={categoryTone[pb.category] ?? "default"}>{pb.category}</Badge>
                          <Badge tone={riskTone[pb.risk] ?? "default"}>{pb.risk} RISK</Badge>
                        </div>
                        <p className="text-xs text-muted-foreground leading-relaxed">{pb.description}</p>
                        <div className="flex items-center gap-4 mt-2 font-mono text-[0.6rem] text-muted-foreground">
                          <span>{pb.steps} steps</span>
                          <span>~{pb.duration}</span>
                          {activeTask && (
                            <span className="text-yellow-400 flex items-center gap-1">
                              <Loader2 className="size-2.5 animate-spin" /> Running...
                            </span>
                          )}
                        </div>
                      </div>
                      <button
                        onClick={() => void runPlaybook(pb)}
                        disabled={isRunning || !!activeTask}
                        className="flex shrink-0 items-center gap-1.5 rounded-lg border border-primary/30 bg-primary/8 px-3 py-2 font-mono text-[0.62rem] text-primary transition-colors hover:bg-primary/15 disabled:opacity-50"
                      >
                        {isRunning || activeTask
                          ? <Loader2 className="size-3.5 animate-spin" />
                          : <Play className="size-3.5" />
                        }
                        {isRunning || activeTask ? "Running" : "Run"}
                      </button>
                    </div>
                  </div>
                );
              })}
            </div>

            <div className="mt-4 rounded-lg border border-blue-400/20 bg-blue-400/5 p-3 text-xs text-blue-300">
              <Shield className="size-4 inline mr-1.5" />
              Playbooks require the AI Security Agent (LLM key). If no key is configured, tasks will fail with a 400 error. Configure via Settings → Setup Wizard.
            </div>
          </Panel>
        </div>

        {/* Task history */}
        <div className="xl:col-span-5">
          <Panel
            title="Execution History"
            right={<Badge tone="info">{tasks.length} tasks</Badge>}
          >
            {tasksLoading ? (
              <div className="flex h-32 items-center justify-center">
                <div className="size-6 animate-spin rounded-full border-2 border-primary border-t-transparent" />
              </div>
            ) : tasks.length === 0 ? (
              <div className="flex h-32 flex-col items-center justify-center gap-2 text-muted-foreground">
                <Play className="size-8 opacity-30" />
                <p className="text-sm">No playbooks run yet</p>
                <p className="text-xs opacity-60">Select a playbook and click Run</p>
              </div>
            ) : (
              <div className="space-y-1.5">
                {tasks.slice(0, 20).map((t: AgentTask) => (
                  <div
                    key={t.id}
                    onClick={() => setSelected(selected?.id === t.id ? null : t)}
                    className={`cursor-pointer rounded-lg border px-3 py-2 transition-colors hover:bg-white/4 ${
                      selected?.id === t.id ? "border-primary/40 bg-primary/5" : "border-[var(--hairline)]"
                    }`}
                  >
                    <div className="flex items-center gap-2 mb-0.5">
                      {t.status === "completed" && <CheckCircle className="size-3.5 text-green-400 shrink-0" />}
                      {t.status === "failed"    && <XCircle    className="size-3.5 text-red-400   shrink-0" />}
                      {(t.status === "running" || t.status === "pending") && <Loader2 className="size-3.5 text-blue-400 animate-spin shrink-0" />}
                      <Badge tone={
                        t.status === "completed" ? "success" :
                        t.status === "failed"    ? "critical" :
                        t.status === "running"   ? "info" : "warning"
                      }>{t.status}</Badge>
                      <span className="font-mono text-[0.55rem] text-muted-foreground">{t.id.slice(0, 8)}</span>
                    </div>
                    <p className="text-xs truncate">{t.playbook_name ?? t.description ?? "Unknown task"}</p>
                    <p className="font-mono text-[0.6rem] text-muted-foreground mt-0.5">
                      {new Date(t.created_at).toLocaleString()}
                    </p>
                    {t.error_message && (
                      <p className="font-mono text-[0.6rem] text-red-400 mt-0.5 truncate">{t.error_message}</p>
                    )}
                  </div>
                ))}
              </div>
            )}
          </Panel>

          {/* Task detail */}
          {selected && (
            <Panel
              title="Task Details"
              right={
                <button onClick={() => setSelected(null)} className="font-mono text-[0.6rem] text-muted-foreground hover:text-foreground">✕</button>
              }
              className="mt-4"
            >
              <div className="space-y-2 font-mono text-[0.65rem]">
                {[
                  ["ID",       selected.id],
                  ["Playbook", selected.playbook_name ?? "—"],
                  ["Status",   selected.status],
                  ["Created",  new Date(selected.created_at).toLocaleString()],
                  ["Completed", selected.completed_at ? new Date(selected.completed_at).toLocaleString() : "—"],
                ].map(([k, v]) => (
                  <div key={k} className="flex gap-2">
                    <span className="text-muted-foreground w-20 shrink-0">{k}</span>
                    <span className="truncate">{v}</span>
                  </div>
                ))}
                {selected.error_message && (
                  <div className="rounded-lg border border-red-400/20 bg-red-400/5 p-2 mt-2">
                    <p className="text-[0.6rem] text-red-400 font-semibold mb-0.5">Error</p>
                    <p className="text-[0.62rem] text-red-300">{selected.error_message}</p>
                  </div>
                )}
              </div>
              <div className="mt-3">
                <Link
                  to="/agent"
                  className="text-xs text-primary hover:underline"
                >
                  → View in AI Security Agent for full execution trace
                </Link>
              </div>
            </Panel>
          )}
        </div>
      </div>
    </div>
  );
}

export const Route = createFileRoute("/playbooks")({
  head: () => ({
    meta: [
      { title: "Playbooks — AISS Security Operations" },
      { name: "description", content: "Execute automated security response playbooks via the AI agent" },
    ],
  }),
  component: PlaybooksPage,
});
