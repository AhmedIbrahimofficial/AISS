/**
 * Scan Jobs — AISS
 * Security scan task management with real-time status, lifecycle timeline,
 * finding details, and task cancellation.
 */
import { createFileRoute } from "@tanstack/react-router";
import { useState } from "react";
import { toast } from "sonner";
import {
  PlayCircle, Loader2, CheckCircle, XCircle, Clock,
  ChevronRight, RefreshCw, Search, Shield, AlertTriangle,
  X,
} from "lucide-react";
import { PageHeader } from "@/components/soc/AppShell";
import { Panel } from "@/components/soc/Panel";
import { Badge, Metric } from "@/components/soc/ui";
import { ActionButton } from "@/components/soc/actions";
import {
  useSecurityTasks, useSecurityTask, useCancelSecurityTask,
  useStartSecurityScan, useStartEicarTest, useVerifyPipeline,
} from "@/hooks/useAISS";
import type { SecurityTaskSummary, SecurityTaskDetail } from "@/lib/api";

export const Route = createFileRoute("/jobs")({
  head: () => ({
    meta: [
      { title: "Scan Jobs — AISS Security Console" },
      { name: "description", content: "Security scan job management with lifecycle tracking" },
    ],
  }),
  component: JobsPage,
});

// ── Scan lifecycle phases ──────────────────────────────────────────────
const PHASES = [
  "local_discovery",
  "network_discovery",
  "file_scan",
  "eicar_verification",
  "ioc_enrichment",
  "vulnerability_check",
  "correlation",
] as const;

const PHASE_LABELS: Record<string, string> = {
  local_discovery:     "Local Discovery",
  network_discovery:   "Network Discovery",
  file_scan:           "File Scan",
  eicar_verification:  "EICAR Verify",
  ioc_enrichment:      "IOC Enrichment",
  vulnerability_check: "Vulnerability Check",
  correlation:         "Correlation",
};

function statusIcon(status: string, size = "size-4") {
  switch (status) {
    case "running":   return <Loader2 className={`${size} animate-spin text-primary`} />;
    case "completed": return <CheckCircle className={`${size} text-[var(--success)]`} />;
    case "failed":    return <XCircle className={`${size} text-[var(--critical)]`} />;
    case "cancelled": return <XCircle className={`${size} text-[var(--warning)]`} />;
    default:          return <Clock className={`${size} text-muted-foreground`} />;
  }
}

function statusTone(status: string): string {
  switch (status) {
    case "running":   return "info";
    case "completed": return "success";
    case "failed":    return "critical";
    case "cancelled": return "warning";
    default:          return "muted";
  }
}

function sevTone(s: string): string {
  return s === "critical" ? "critical" : s === "high" ? "warning" : s === "medium" ? "info" : s === "low" ? "success" : "muted";
}

// ── Task detail panel ──────────────────────────────────────────────────
function TaskDetail({
  taskId,
  onClose,
}: {
  taskId: string;
  onClose: () => void;
}) {
  const { data: task, isLoading } = useSecurityTask(taskId);
  const cancel = useCancelSecurityTask();

  if (isLoading) {
    return (
      <Panel title="Task Detail" right={<button onClick={onClose} className="font-mono text-[0.6rem] text-muted-foreground hover:text-foreground">✕ CLOSE</button>}>
        <div className="flex h-32 items-center justify-center">
          <Loader2 className="size-6 animate-spin text-primary" />
        </div>
      </Panel>
    );
  }

  if (!task) {
    return (
      <Panel title="Task Not Found" right={<button onClick={onClose} className="font-mono text-[0.6rem] text-muted-foreground hover:text-foreground">✕ CLOSE</button>}>
        <p className="text-sm text-muted-foreground">Task data unavailable.</p>
      </Panel>
    );
  }

  const canCancel = task.status === "running" || task.status === "pending";

  return (
    <Panel
      title={`Task: ${task.description || task.task_id.slice(0, 8)}`}
      right={<button onClick={onClose} className="font-mono text-[0.6rem] text-muted-foreground hover:text-foreground">✕ CLOSE</button>}
    >
      {/* Status + EICAR */}
      <div className="mb-3 flex items-center gap-2 flex-wrap">
        <Badge tone={statusTone(task.status)}>{task.status.toUpperCase()}</Badge>
        {task.eicar_verified === true && <Badge tone="success">EICAR VERIFIED</Badge>}
        {task.eicar_verified === false && <Badge tone="critical">EICAR FAILED</Badge>}
        <span className="font-mono text-[0.55rem] text-muted-foreground">{task.task_id.slice(0, 12)}</span>
      </div>

      {/* Phase timeline */}
      <div className="mb-4">
        <p className="label-cap text-[0.55rem] mb-1.5">Scan Lifecycle</p>
        <div className="flex items-center gap-0 overflow-x-auto pb-1">
          {PHASES.map((p, i) => {
            const phaseComplete = task.status === "completed";
            const isRunning = task.status === "running";
            return (
              <div key={p} className="flex items-center">
                <div className={`flex flex-col items-center px-2 ${phaseComplete ? "opacity-100" : isRunning ? "opacity-70" : "opacity-40"}`}>
                  <div className={`size-2 rounded-full mb-1 ${
                    phaseComplete ? "bg-[var(--success)]" : isRunning ? "bg-primary animate-pulse" : "bg-gray-700"
                  }`} />
                  <span className="font-mono text-[0.48rem] whitespace-nowrap">{PHASE_LABELS[p]}</span>
                </div>
                {i < PHASES.length - 1 && <ChevronRight className="size-3 text-muted-foreground/30 shrink-0" />}
              </div>
            );
          })}
          <div className="flex items-center">
            <ChevronRight className="size-3 text-muted-foreground/30 shrink-0" />
            <div className="flex flex-col items-center px-2">
              <div className={`size-2 rounded-full mb-1 ${task.status === "completed" ? "bg-[var(--success)]" : "bg-gray-700"}`} />
              <span className="font-mono text-[0.48rem] whitespace-nowrap">Complete</span>
            </div>
          </div>
        </div>
      </div>

      {/* Task info */}
      <div className="mb-3 grid grid-cols-2 gap-2 text-xs">
        <div>
          <p className="label-cap text-[0.55rem] mb-0.5">Created</p>
          <span className="font-mono">{task.created_at ? new Date(task.created_at).toLocaleString() : "—"}</span>
        </div>
        <div>
          <p className="label-cap text-[0.55rem] mb-0.5">Completed</p>
          <span className="font-mono">{task.completed_at ? new Date(task.completed_at).toLocaleString() : "—"}</span>
        </div>
        <div>
          <p className="label-cap text-[0.55rem] mb-0.5">Findings</p>
          <span className="font-mono">{task.findings_count}</span>
        </div>
        <div>
          <p className="label-cap text-[0.55rem] mb-0.5">Duration</p>
          <span className="font-mono">{task.execution?.duration_seconds ? `${task.execution.duration_seconds.toFixed(1)}s` : "—"}</span>
        </div>
      </div>

      {/* Error */}
      {task.error && (
        <div className="mb-3 rounded-lg border border-[var(--critical)]/30 bg-[var(--critical)]/5 p-2.5">
          <p className="label-cap text-[0.55rem] text-[var(--critical)] mb-0.5">ERROR</p>
          <p className="font-mono text-[0.62rem] text-muted-foreground">{task.error}</p>
        </div>
      )}

      {/* Findings */}
      {task.findings.length > 0 && (
        <div className="mb-3">
          <p className="label-cap text-[0.55rem] mb-1.5">Findings ({task.findings.length})</p>
          <div className="max-h-60 overflow-y-auto space-y-1.5 pr-1">
            {task.findings.map((f, i) => (
              <div key={i} className="rounded-md border border-[var(--hairline)] px-2.5 py-2 hover:bg-white/4">
                <div className="flex items-center gap-2 mb-0.5">
                  <Badge tone={sevTone(f.severity)}>{f.severity.toUpperCase()}</Badge>
                  <span className="font-mono text-[0.55rem] text-muted-foreground">{f.type}</span>
                </div>
                <p className="text-xs font-medium truncate">{f.title}</p>
                {f.description && (
                  <p className="font-mono text-[0.58rem] text-muted-foreground mt-0.5 line-clamp-2">{f.description}</p>
                )}
                {f.affected_resource && (
                  <p className="font-mono text-[0.55rem] text-muted-foreground mt-0.5">Resource: {f.affected_resource}</p>
                )}
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Actions */}
      <div className="flex flex-wrap gap-1.5 border-t border-[var(--hairline)] pt-3">
        {canCancel && (
          <ActionButton
            label="Cancel Task"
            tone="critical"
            onClick={() => {
              cancel.mutate(task.task_id);
              onClose();
            }}
          />
        )}
        <ActionButton label="View Threats" tone="info" to="/threats" />
      </div>
    </Panel>
  );
}

// ── Main page ──────────────────────────────────────────────────────────
function JobsPage() {
  const { data: tasks = [], isLoading, refetch } = useSecurityTasks();
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [filter, setFilter] = useState<"all" | "running" | "completed" | "failed">("all");
  const [search, setSearch] = useState("");

  const startScan = useStartSecurityScan();
  const startEicar = useStartEicarTest();
  const verifyPipe = useVerifyPipeline();

  const filtered = tasks.filter((t: SecurityTaskSummary) => {
    if (filter !== "all" && t.status !== filter) return false;
    if (search) {
      const q = search.toLowerCase();
      return (
        t.id.toLowerCase().includes(q) ||
        t.description.toLowerCase().includes(q) ||
        t.status.toLowerCase().includes(q)
      );
    }
    return true;
  });

  const runningCount   = tasks.filter((t: SecurityTaskSummary) => t.status === "running").length;
  const completedCount = tasks.filter((t: SecurityTaskSummary) => t.status === "completed").length;
  const failedCount    = tasks.filter((t: SecurityTaskSummary) => t.status === "failed").length;
  const totalFindings  = tasks.reduce((a: number, t: SecurityTaskSummary) => a + t.findings_count, 0);

  return (
    <div>
      <PageHeader
        title="Scan Jobs"
        subtitle="Security scan task management — lifecycle tracking, findings, and cancellation"
        right={
          <div className="flex gap-2">
            <ActionButton label="Refresh" onClick={() => void refetch()} />
            <ActionButton
              label="Full Scan"
              tone="info"
              onClick={() => startScan.mutate({ description: "Manual full security scan" })}
            />
            <ActionButton
              label="EICAR Test"
              tone="warning"
              onClick={() => startEicar.mutate()}
            />
            <ActionButton
              label="Verify Pipeline"
              tone="success"
              onClick={() => {
                verifyPipe.mutate(undefined, {
                  onSuccess: (res) => {
                    if (res.data.verified) {
                      toast.success("Pipeline verified", { description: "EICAR detection confirmed" });
                    } else {
                      toast.error("Pipeline verification failed", { description: res.data.error ?? "EICAR not detected" });
                    }
                    void refetch();
                  },
                });
              }}
            />
          </div>
        }
      />

      {/* KPIs */}
      <div className="mb-4 grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
        <Metric label="Running"        value={String(runningCount)}   tone={runningCount > 0 ? "info" : "default"} sub="active scans" />
        <Metric label="Completed"      value={String(completedCount)} tone="success" sub="successful scans" />
        <Metric label="Failed"         value={String(failedCount)}    tone={failedCount > 0 ? "critical" : "success"} sub="needs attention" />
        <Metric label="Total Findings" value={String(totalFindings)}  tone={totalFindings > 0 ? "warning" : "success"} sub="across all scans" />
      </div>

      <div className="grid gap-4 xl:grid-cols-12">
        {/* Task list */}
        <div className={selectedId ? "xl:col-span-7" : "xl:col-span-12"}>
          <Panel
            title="Scan Tasks"
            right={
              <div className="flex items-center gap-2">
                <div className="relative">
                  <Search className="absolute left-2 top-1/2 -translate-y-1/2 size-3 text-muted-foreground" />
                  <input
                    value={search}
                    onChange={(e) => setSearch(e.target.value)}
                    placeholder="Search..."
                    className="rounded-md border border-[var(--hairline)] bg-white/5 pl-6 pr-2 py-1 text-xs outline-none focus:border-primary/50 w-32"
                  />
                </div>
                {(["all", "running", "completed", "failed"] as const).map((f) => (
                  <button
                    key={f}
                    onClick={() => setFilter(f)}
                    className={`rounded border px-2 py-1 font-mono text-[0.6rem] uppercase transition-colors ${
                      filter === f
                        ? "border-primary/40 bg-primary/12 text-primary"
                        : "border-transparent text-muted-foreground hover:bg-white/5"
                    }`}
                  >
                    {f}
                  </button>
                ))}
              </div>
            }
          >
            {isLoading ? (
              <div className="flex h-32 items-center justify-center">
                <Loader2 className="size-6 animate-spin text-primary" />
              </div>
            ) : filtered.length === 0 ? (
              <div className="flex h-24 flex-col items-center justify-center gap-2 text-muted-foreground">
                <PlayCircle className="size-8 opacity-40" />
                <p className="text-sm">{filter === "all" ? "No scan jobs yet" : `No ${filter} jobs`}</p>
                <p className="text-xs opacity-60">
                  {filter === "all" ? "Start a scan from the buttons above" : "Try changing the filter"}
                </p>
              </div>
            ) : (
              <div className="space-y-1.5">
                {filtered.map((t: SecurityTaskSummary) => {
                  const isSelected = selectedId === t.id;
                  return (
                    <div
                      key={t.id}
                      onClick={() => setSelectedId(isSelected ? null : t.id)}
                      className={`cursor-pointer rounded-lg border px-3 py-2.5 transition-colors hover:bg-white/4 ${
                        isSelected ? "border-primary/40 bg-primary/5" : "border-[var(--hairline)]"
                      }`}
                    >
                      <div className="flex items-start justify-between gap-3">
                        <div className="flex-1 min-w-0">
                          <div className="flex items-center gap-2 mb-0.5">
                            {statusIcon(t.status, "size-3.5")}
                            <Badge tone={statusTone(t.status)}>{t.status.toUpperCase()}</Badge>
                            <span className="font-mono text-[0.55rem] text-muted-foreground">{t.id.slice(0, 8)}</span>
                          </div>
                          <p className="text-sm font-medium truncate">{t.description || "Security Scan"}</p>
                          <p className="text-xs text-muted-foreground truncate mt-0.5">
                            {t.findings_count > 0 ? `${t.findings_count} finding(s)` : "No findings"}
                            {t.created_at && ` · ${new Date(t.created_at).toLocaleString()}`}
                          </p>
                        </div>
                        <div className="text-right shrink-0">
                          <p className="font-mono text-[0.6rem] text-muted-foreground">
                            {t.completed_at
                              ? new Date(t.completed_at).toLocaleTimeString()
                              : t.status === "running" ? "in progress" : "—"}
                          </p>
                        </div>
                      </div>
                    </div>
                  );
                })}
              </div>
            )}
          </Panel>
        </div>

        {/* Task detail */}
        {selectedId && (
          <div className="xl:col-span-5">
            <TaskDetail taskId={selectedId} onClose={() => setSelectedId(null)} />
          </div>
        )}
      </div>
    </div>
  );
}
