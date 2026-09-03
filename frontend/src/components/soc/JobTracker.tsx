/**
 * JobTracker — dashboard widget showing active scan job progress.
 * Displays the most recent security scan task with real-time phase timeline.
 */
import { useSecurityTasks } from "@/hooks/useAISS";
import { Panel } from "./Panel";
import { Badge } from "./ui";
import { Link } from "@tanstack/react-router";
import { PlayCircle, CheckCircle, XCircle, Loader2, Clock } from "lucide-react";

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
  local_discovery:     "Local Disc.",
  network_discovery:   "Network Disc.",
  file_scan:           "File Scan",
  eicar_verification:  "EICAR Verify",
  ioc_enrichment:      "IOC Enrich",
  vulnerability_check: "Vuln Check",
  correlation:         "Correlation",
};

function statusIcon(status: string) {
  switch (status) {
    case "running":   return <Loader2 className="size-3.5 animate-spin text-primary" />;
    case "completed": return <CheckCircle className="size-3.5 text-[var(--success)]" />;
    case "failed":    return <XCircle className="size-3.5 text-[var(--critical)]" />;
    case "cancelled": return <XCircle className="size-3.5 text-[var(--warning)]" />;
    default:          return <Clock className="size-3.5 text-muted-foreground" />;
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

export function JobTracker() {
  const { data: tasks = [], isLoading } = useSecurityTasks(10);

  const active = tasks.find((t) => t.status === "running" || t.status === "pending");
  const recent = tasks.slice(0, 5);

  return (
    <Panel
      title="Scan Jobs"
      right={
        <Link
          to="/jobs"
          className="font-mono text-[0.6rem] text-primary hover:underline"
        >
          VIEW ALL →
        </Link>
      }
    >
      {isLoading ? (
        <div className="flex h-20 items-center justify-center">
          <Loader2 className="size-5 animate-spin text-primary" />
        </div>
      ) : recent.length === 0 ? (
        <div className="flex h-20 flex-col items-center justify-center gap-1 text-muted-foreground">
          <PlayCircle className="size-6 opacity-30" />
          <p className="text-xs">No scan jobs yet</p>
        </div>
      ) : (
        <div className="space-y-2">
          {/* Active job highlight */}
          {active && (
            <div className="rounded-lg border border-primary/30 bg-primary/5 p-2.5">
              <div className="flex items-center gap-2 mb-1.5">
                {statusIcon(active.status)}
                <span className="flex-1 truncate text-xs font-medium">{active.description || "Security Scan"}</span>
                <Badge tone={statusTone(active.status)}>{active.status.toUpperCase()}</Badge>
              </div>
              {/* Mini phase timeline */}
              <div className="flex items-center gap-0 overflow-x-auto">
                {PHASES.map((p, i) => (
                  <div key={p} className="flex items-center">
                    <div className="flex flex-col items-center px-0.5">
                      <div className="size-1.5 rounded-full bg-gray-600 mb-0.5" />
                      <span className="font-mono text-[0.45rem] text-muted-foreground whitespace-nowrap">
                        {PHASE_LABELS[p]}
                      </span>
                    </div>
                    {i < PHASES.length - 1 && (
                      <div className="h-px w-2 bg-gray-700 shrink-0" />
                    )}
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Recent jobs list */}
          <div className="space-y-1">
            {recent.map((t) => (
              <div
                key={t.id}
                className="flex items-center gap-2 rounded-md border border-[var(--hairline)] px-2 py-1.5 hover:bg-white/4"
              >
                {statusIcon(t.status)}
                <span className="flex-1 truncate font-mono text-[0.58rem] text-muted-foreground">
                  {t.description || t.id.slice(0, 8)}
                </span>
                <span className="font-mono text-[0.55rem] text-muted-foreground shrink-0">
                  {t.findings_count > 0 ? `${t.findings_count} findings` : ""}
                </span>
                <Badge tone={statusTone(t.status)}>{t.status.toUpperCase()}</Badge>
              </div>
            ))}
          </div>
        </div>
      )}
    </Panel>
  );
}
