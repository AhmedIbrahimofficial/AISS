import { createFileRoute, useNavigate } from "@tanstack/react-router";
import { useState } from "react";
import {
  AlertTriangle, CheckCircle2, Clock, Eye, Shield, ChevronDown,
  ChevronRight, Zap, Activity, Network, FileSearch, Cpu,
  XCircle, ArrowRight, Tag,
} from "lucide-react";
import { PageHeader } from "@/components/soc/AppShell";
import { useAllThreats, useResolve, useBackendStatus } from "@/hooks/useAISS";
import type { Threat } from "@/lib/api";
import { toast } from "sonner";

export const Route = createFileRoute("/investigations")({
  head: () => ({
    meta: [{ title: "Investigations — AISS" }],
  }),
  component: InvestigationsPage,
  validateSearch: (s: Record<string, unknown>) => ({
    id: (s["id"] as string | undefined) ?? null,
  }),
});

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────
function relativeTime(iso: string): string {
  try {
    const diff = Date.now() - new Date(iso).getTime();
    const mins = Math.floor(diff / 60_000);
    if (mins < 1) return "just now";
    if (mins < 60) return `${mins}m ago`;
    const hrs = Math.floor(mins / 60);
    if (hrs < 24) return `${hrs}h ago`;
    return `${Math.floor(hrs / 24)}d ago`;
  } catch {
    return "";
  }
}

const SEV_COLOR: Record<string, string> = {
  critical: "var(--critical)",
  high: "#f97316",
  medium: "var(--warning)",
  low: "var(--success)",
};

const SEV_BG: Record<string, string> = {
  critical: "rgba(220,38,38,0.08)",
  high: "rgba(249,115,22,0.08)",
  medium: "rgba(217,119,6,0.06)",
  low: "rgba(34,197,94,0.05)",
};

const SEV_BORDER: Record<string, string> = {
  critical: "rgba(220,38,38,0.25)",
  high: "rgba(249,115,22,0.25)",
  medium: "rgba(217,119,6,0.2)",
  low: "rgba(34,197,94,0.15)",
};

const MODULE_ICON: Record<string, React.ComponentType<{ className?: string }>> = {
  network_monitor: Network,
  process_scanner: Cpu,
  file_monitor: FileSearch,
  auth_monitor: Shield,
};

function moduleIcon(module: string) {
  const Icon = MODULE_ICON[module] ?? Activity;
  return Icon;
}

// ─────────────────────────────────────────────────────────────────────────────
// Investigation Story Card (the key differentiator)
// ─────────────────────────────────────────────────────────────────────────────
function InvestigationCard({
  threat,
  selected,
  onSelect,
  onResolve,
}: {
  threat: Threat;
  selected: boolean;
  onSelect: () => void;
  onResolve: () => void;
}) {
  const [expanded, setExpanded] = useState(selected);
  const Icon = moduleIcon(threat.module ?? "");
  const isActive = threat.status !== "resolved";
  const color = SEV_COLOR[threat.severity] ?? "var(--success)";
  const bg = SEV_BG[threat.severity] ?? "transparent";
  const border = SEV_BORDER[threat.severity] ?? "var(--hairline)";

  // Derive story steps from threat data
  const steps = [
    {
      step: 1,
      label: "THREAT DETECTED",
      detail: `Module: ${(threat.module ?? "unknown").replace(/_/g, " ")}`,
    },
    {
      step: 2,
      label: "SOURCE IDENTIFIED",
      detail: threat.source ? `Origin: ${threat.source}` : "Source: unknown",
    },
    {
      step: 3,
      label: "AI ANALYSIS",
      detail:
        threat.ai_analysis
          ? threat.ai_analysis.slice(0, 80) + "…"
          : `Type: ${threat.type.replace(/_/g, " ")}`,
    },
    ...(isActive
      ? [{ step: 4, label: "ACTION REQUIRED", detail: "Awaiting your decision", highlight: true }]
      : [{ step: 4, label: "RESOLVED", detail: threat.resolution_note ?? "Threat contained", done: true }]),
  ];

  // MITRE technique guesses from type
  const mitreMap: Record<string, string> = {
    malware: "T1059 — Command Execution",
    cryptominer: "T1496 — Resource Hijacking",
    ransomware: "T1486 — Data Encrypted for Impact",
    port_scan: "T1046 — Network Service Scanning",
    brute_force: "T1110 — Brute Force",
    c2_traffic: "T1071 — Application Layer Protocol",
    process_injection: "T1055 — Process Injection",
    credential: "T1003 — OS Credential Dumping",
  };
  const mitre = Object.entries(mitreMap).find(([k]) =>
    threat.type.toLowerCase().includes(k)
  )?.[1];

  return (
    <div
      className="rounded-2xl border overflow-hidden transition-all cursor-pointer"
      style={{
        borderColor: selected || expanded ? border : "var(--hairline)",
        background: selected || expanded ? bg : "var(--panel)",
      }}
      onClick={() => { setExpanded((v) => !v); onSelect(); }}
    >
      {/* Header */}
      <div className="flex items-start gap-3 p-4">
        <div
          className="flex size-9 shrink-0 items-center justify-center rounded-xl border mt-0.5"
          style={{ borderColor: `${color}40`, background: `${color}15` }}
        >
          <Icon className="size-4.5" style={{ color }} />
        </div>

        <div className="min-w-0 flex-1">
          <div className="flex flex-wrap items-center gap-2 mb-1">
            <span
              className="rounded-md border px-2 py-0.5 font-mono text-[0.58rem] font-semibold uppercase tracking-widest"
              style={{ color, borderColor: `${color}40`, background: `${color}12` }}
            >
              {threat.severity}
            </span>
            {isActive ? (
              <span className="rounded-md border border-[var(--warning)]/30 bg-[var(--warning)]/10 px-2 py-0.5 font-mono text-[0.58rem] text-[var(--warning)]">
                ACTIVE
              </span>
            ) : (
              <span className="rounded-md border border-[var(--success)]/30 bg-[var(--success)]/10 px-2 py-0.5 font-mono text-[0.58rem] text-[var(--success)]">
                RESOLVED
              </span>
            )}
            {mitre && (
              <span className="rounded-md border border-[var(--hairline)] px-2 py-0.5 font-mono text-[0.58rem] text-muted-foreground">
                {mitre.split(" — ")[0]}
              </span>
            )}
          </div>
          <p className="text-sm font-semibold leading-tight">
            {threat.type.replace(/_/g, " ").replace(/\b\w/g, (c) => c.toUpperCase())}
          </p>
          <p className="mt-0.5 text-[0.72rem] text-muted-foreground line-clamp-2 leading-relaxed">
            {threat.description}
          </p>
        </div>

        <div className="flex shrink-0 flex-col items-end gap-1">
          <span className="font-mono text-[0.6rem] text-muted-foreground">
            {relativeTime(threat.detected_at)}
          </span>
          <button
            onClick={(e) => { e.stopPropagation(); setExpanded((v) => !v); }}
            className="rounded-md p-1 text-muted-foreground hover:text-foreground transition-colors"
          >
            {expanded ? (
              <ChevronDown className="size-4" />
            ) : (
              <ChevronRight className="size-4" />
            )}
          </button>
        </div>
      </div>

      {/* Expanded: Investigation Story */}
      {expanded && (
        <div className="border-t border-[var(--hairline)] px-4 pb-4 pt-3">
          {/* Attack Story */}
          <p className="label-cap text-[0.6rem] mb-3">Investigation Story</p>
          <div className="relative ml-3">
            {/* Vertical line */}
            <div className="absolute left-3 top-0 bottom-0 w-px bg-[var(--hairline)]" />
            <div className="space-y-3">
              {steps.map((s, i) => (
                <div key={i} className="relative flex gap-3 pl-7">
                  <div
                    className="absolute left-0 flex size-6 items-center justify-center rounded-full border text-[0.55rem] font-mono font-bold"
                    style={
                      (s as { highlight?: boolean; done?: boolean }).done
                        ? { borderColor: "var(--success)", background: "var(--success)", color: "#000" }
                        : (s as { highlight?: boolean }).highlight
                        ? { borderColor: color, background: color + "20", color }
                        : { borderColor: "var(--hairline)", background: "var(--panel)", color: "var(--muted-foreground)" }
                    }
                  >
                    {(s as { done?: boolean }).done ? "✓" : s.step}
                  </div>
                  <div>
                    <p
                      className="font-mono text-[0.65rem] font-semibold tracking-wider"
                      style={(s as { highlight?: boolean }).highlight ? { color } : {}}
                    >
                      {s.step}. {s.label}
                    </p>
                    <p className="text-[0.72rem] text-muted-foreground">{s.detail}</p>
                  </div>
                </div>
              ))}
            </div>
          </div>

          {/* Metadata */}
          <div className="mt-3 flex flex-wrap gap-2">
            {threat.source && (
              <span className="flex items-center gap-1 rounded-md border border-[var(--hairline)] bg-white/3 px-2 py-1 text-[0.65rem] text-muted-foreground">
                <Network className="size-3" /> {threat.source}
              </span>
            )}
            {mitre && (
              <span className="flex items-center gap-1 rounded-md border border-[var(--hairline)] bg-white/3 px-2 py-1 text-[0.65rem] text-muted-foreground">
                <Tag className="size-3" /> {mitre}
              </span>
            )}
          </div>

          {/* Actions */}
          {isActive && (
            <div
              className="mt-4 rounded-xl border p-3"
              style={{ borderColor: `${color}30`, background: `${color}08` }}
            >
              <p
                className="label-cap text-[0.6rem] mb-2.5"
                style={{ color }}
              >
                ⚠ Action Required
              </p>
              <div className="flex flex-wrap gap-2">
                <button
                  onClick={(e) => {
                    e.stopPropagation();
                    onResolve();
                  }}
                  className="flex items-center gap-1.5 rounded-lg border border-[var(--success)]/40 bg-[var(--success)]/12 px-3 py-1.5 text-xs font-semibold text-[var(--success)] transition hover:bg-[var(--success)]/20"
                >
                  <CheckCircle2 className="size-3.5" /> Resolve
                </button>
                <button
                  onClick={(e) => e.stopPropagation()}
                  className="flex items-center gap-1.5 rounded-lg border border-[var(--hairline)] px-3 py-1.5 text-xs text-muted-foreground transition hover:bg-white/4 hover:text-foreground"
                >
                  <Eye className="size-3.5" /> Monitor
                </button>
                {threat.severity === "critical" && (
                  <button
                    onClick={(e) => {
                      e.stopPropagation();
                      toast.warning("Kill process action requires approval");
                    }}
                    className="flex items-center gap-1.5 rounded-lg border border-[var(--critical)]/30 bg-[var(--critical)]/10 px-3 py-1.5 text-xs font-semibold text-[var(--critical)] transition hover:bg-[var(--critical)]/20"
                  >
                    <XCircle className="size-3.5" /> Kill Process
                  </button>
                )}
              </div>
            </div>
          )}

          {!isActive && threat.resolution_note && (
            <div className="mt-3 flex items-start gap-2 rounded-lg border border-[var(--success)]/20 bg-[var(--success)]/5 px-3 py-2.5">
              <CheckCircle2 className="size-4 shrink-0 text-[var(--success)]" />
              <p className="text-[0.72rem] text-muted-foreground">{threat.resolution_note}</p>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// Main Page
// ─────────────────────────────────────────────────────────────────────────────
function InvestigationsPage() {
  const { online } = useBackendStatus();
  const { data: threats, isLoading } = useAllThreats();
  const resolve = useResolve();
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [filter, setFilter] = useState<"all" | "active" | "resolved">("all");
  const [severityFilter, setSeverityFilter] = useState<string>("all");

  const all = threats ?? [];
  const active = all.filter((t) => t.status !== "resolved");
  const resolved = all.filter((t) => t.status === "resolved");

  const filtered = all.filter((t) => {
    const statusOk =
      filter === "all" ? true
      : filter === "active" ? t.status !== "resolved"
      : t.status === "resolved";
    const sevOk =
      severityFilter === "all" ? true : t.severity === severityFilter;
    return statusOk && sevOk;
  });

  return (
    <div className="flex flex-col gap-4 max-w-4xl">
      <PageHeader
        title="Investigations"
        subtitle="Every threat tells a story. AISS writes it."
        right={
          <div className="flex items-center gap-2">
            {active.length > 0 && (
              <span className="flex items-center gap-1.5 rounded-lg border border-[var(--critical)]/30 bg-[var(--critical)]/10 px-3 py-1.5 text-xs font-semibold text-[var(--critical)]">
                <AlertTriangle className="size-3.5" />
                {active.length} active
              </span>
            )}
            <span className="flex items-center gap-1.5 rounded-lg border border-[var(--success)]/20 bg-[var(--success)]/8 px-3 py-1.5 text-xs text-[var(--success)]">
              <CheckCircle2 className="size-3.5" />
              {resolved.length} resolved
            </span>
          </div>
        }
      />

      {/* Filter bar */}
      <div className="flex flex-wrap items-center gap-2">
        <div className="flex gap-1 rounded-xl border border-[var(--hairline)] bg-black/20 p-1">
          {(["all", "active", "resolved"] as const).map((f) => (
            <button
              key={f}
              onClick={() => setFilter(f)}
              className={`rounded-lg px-3 py-1.5 text-xs font-medium capitalize transition-all ${
                filter === f
                  ? "bg-primary/15 text-primary border border-primary/30"
                  : "text-muted-foreground hover:text-foreground"
              }`}
            >
              {f === "all" ? `All (${all.length})` : f === "active" ? `Active (${active.length})` : `Resolved (${resolved.length})`}
            </button>
          ))}
        </div>

        <div className="flex gap-1 rounded-xl border border-[var(--hairline)] bg-black/20 p-1">
          {(["all", "critical", "high", "medium", "low"] as const).map((s) => (
            <button
              key={s}
              onClick={() => setSeverityFilter(s)}
              className={`rounded-lg px-3 py-1.5 text-xs font-medium capitalize transition-all ${
                severityFilter === s
                  ? "bg-primary/15 text-primary border border-primary/30"
                  : "text-muted-foreground hover:text-foreground"
              }`}
            >
              {s}
            </button>
          ))}
        </div>
      </div>

      {/* Investigations list */}
      {!online && (
        <div className="panel flex flex-col items-center gap-3 py-12 text-center">
          <Shield className="size-10 text-muted-foreground opacity-20" />
          <p className="text-sm text-muted-foreground">
            Backend offline. Start the backend to view investigations.
          </p>
        </div>
      )}

      {online && isLoading && (
        <div className="panel flex items-center gap-3 py-8 justify-center text-muted-foreground">
          <div className="size-5 animate-spin rounded-full border-2 border-primary border-t-transparent" />
          Loading investigations…
        </div>
      )}

      {online && !isLoading && filtered.length === 0 && (
        <div className="panel flex flex-col items-center gap-3 py-12 text-center">
          <CheckCircle2 className="size-10 text-[var(--success)] opacity-40" />
          <p className="text-sm font-medium">
            {filter === "active" ? "No active threats — your system is secure." : "No investigations match this filter."}
          </p>
          <p className="text-[0.78rem] text-muted-foreground">
            AISS is continuously monitoring for threats.
          </p>
        </div>
      )}

      {online && !isLoading && filtered.length > 0 && (
        <div className="flex flex-col gap-3">
          {filtered.map((threat) => (
            <InvestigationCard
              key={threat.id}
              threat={threat}
              selected={selectedId === threat.id}
              onSelect={() => setSelectedId(threat.id)}
              onResolve={() =>
                resolve.mutate({ id: threat.id, note: "Resolved from Investigations" })
              }
            />
          ))}
        </div>
      )}
    </div>
  );
}
