/**
 * Incidents — AISS
 * Incidents derived from real threat data with full workflow:
 * Detect → Investigate → Contain → Respond → Recover → Close
 */
import { createFileRoute, Link } from "@tanstack/react-router";
import { useState } from "react";
import { toast } from "sonner";
import {
  Shield, AlertTriangle, Clock, CheckCircle,
  Search, RefreshCw, ChevronRight, FileText,
} from "lucide-react";
import { PageHeader } from "@/components/soc/AppShell";
import { Panel } from "@/components/soc/Panel";
import { Badge, Metric } from "@/components/soc/ui";
import { ActionButton } from "@/components/soc/actions";
import { useThreats, useThreatStats, useResolve } from "@/hooks/useAISS";
import { aiAnalyzeThreat, triggerScan, exportThreatsExcel } from "@/lib/api";
import type { Threat } from "@/lib/api";

export const Route = createFileRoute("/incidents")({
  head: () => ({
    meta: [
      { title: "Incidents — AISS Security Console" },
      { name: "description", content: "Active incident queue derived from real threat detections" },
    ],
  }),
  component: IncidentsPage,
});

// ── Incident lifecycle stages ─────────────────────────────────────────
const STAGES = ["Detected", "Investigating", "Containing", "Responding", "Recovering", "Closed"] as const;
type Stage = typeof STAGES[number];

function stageTone(s: Stage): "critical" | "warning" | "info" | "success" | "default" {
  switch (s) {
    case "Detected":     return "critical";
    case "Investigating": return "warning";
    case "Containing":   return "warning";
    case "Responding":   return "info";
    case "Recovering":   return "info";
    case "Closed":       return "success";
  }
}

function threatToStage(t: Threat): Stage {
  switch (t.status) {
    case "active":     return "Detected";
    case "analyzing":  return "Investigating";
    case "responding": return "Containing";
    case "resolved":   return "Closed";
    default:           return "Detected";
  }
}

function toneFor(sev: string) {
  return sev === "critical" ? "critical" : sev === "high" ? "warning" : sev === "medium" ? "info" : "success";
}

// ── Selected incident detail panel ────────────────────────────────────
function IncidentDetail({
  threat,
  onClose,
  onResolve,
}: {
  threat: Threat;
  onClose: () => void;
  onResolve: (id: string) => void;
}) {
  const [aiResult, setAiResult] = useState<string | null>(null);
  const [loading, setLoading]   = useState(false);
  const stage = threatToStage(threat);

  const handleAI = async () => {
    setLoading(true);
    try {
      const r = await aiAnalyzeThreat(threat.id);
      setAiResult(r.threat_assessment + "\n\nRisk: " + r.risk_level + "\nVector: " + r.attack_vector + "\n\nImmediate actions:\n" + r.immediate_actions.join("\n"));
      toast.success("AI analysis complete");
    } catch (e) {
      toast.error(`AI analysis failed: ${String(e)}`);
    } finally {
      setLoading(false);
    }
  };

  return (
    <Panel
      title={`Incident: ${threat.type}`}
      right={
        <button onClick={onClose} className="font-mono text-[0.6rem] text-muted-foreground hover:text-foreground">
          ✕ CLOSE
        </button>
      }
    >
      {/* Stage progress */}
      <div className="mb-4 flex items-center gap-0 overflow-x-auto pb-1">
        {STAGES.map((s, i) => (
          <div key={s} className="flex items-center">
            <div className={`flex flex-col items-center px-2 ${s === stage ? "opacity-100" : "opacity-40"}`}>
              <div className={`size-2 rounded-full mb-1 ${s === stage ? "bg-primary" : "bg-gray-700"}`} />
              <span className="font-mono text-[0.52rem] whitespace-nowrap">{s}</span>
            </div>
            {i < STAGES.length - 1 && <ChevronRight className="size-3 text-muted-foreground/30 shrink-0" />}
          </div>
        ))}
      </div>

      {/* Details */}
      <div className="space-y-3 mb-4">
        <div className="grid grid-cols-2 gap-3 text-xs">
          <div>
            <p className="label-cap text-[0.55rem] mb-0.5">Severity</p>
            <Badge tone={toneFor(threat.severity)}>{threat.severity.toUpperCase()}</Badge>
          </div>
          <div>
            <p className="label-cap text-[0.55rem] mb-0.5">Stage</p>
            <Badge tone={stageTone(stage)}>{stage}</Badge>
          </div>
          <div>
            <p className="label-cap text-[0.55rem] mb-0.5">Source</p>
            <span className="font-mono">{threat.source}</span>
          </div>
          <div>
            <p className="label-cap text-[0.55rem] mb-0.5">Module</p>
            <span className="font-mono">{threat.module}</span>
          </div>
          <div className="col-span-2">
            <p className="label-cap text-[0.55rem] mb-0.5">Detected</p>
            <span className="font-mono">{new Date(threat.detected_at).toLocaleString()}</span>
          </div>
          <div className="col-span-2">
            <p className="label-cap text-[0.55rem] mb-0.5">Description</p>
            <p className="text-muted-foreground leading-relaxed">{threat.description}</p>
          </div>
        </div>

        {/* Metadata */}
        {threat.metadata && Object.keys(threat.metadata).length > 0 && (
          <div>
            <p className="label-cap text-[0.55rem] mb-1">Context</p>
            <div className="rounded-lg border border-[var(--hairline)] bg-white/3 p-2 font-mono text-[0.62rem] space-y-0.5">
              {Object.entries(threat.metadata).slice(0, 8).map(([k, v]) => (
                <div key={k} className="flex gap-2">
                  <span className="text-muted-foreground shrink-0 w-28">{k}</span>
                  <span className="truncate">{String(v)}</span>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Existing AI analysis */}
        {threat.ai_analysis && (
          <div className="rounded-lg border border-blue-400/20 bg-blue-400/5 p-3">
            <p className="label-cap text-[0.55rem] text-blue-400 mb-1">AI ANALYSIS</p>
            <p className="font-mono text-[0.62rem] text-muted-foreground leading-relaxed">{threat.ai_analysis}</p>
          </div>
        )}

        {/* New AI analysis result */}
        {aiResult && (
          <div className="rounded-lg border border-blue-400/20 bg-blue-400/5 p-3">
            <p className="label-cap text-[0.55rem] text-blue-400 mb-1">FRESH AI ANALYSIS</p>
            <pre className="font-mono text-[0.62rem] text-muted-foreground leading-relaxed whitespace-pre-wrap">{aiResult}</pre>
          </div>
        )}
      </div>

      {/* Actions */}
      <div className="flex flex-wrap gap-1.5 border-t border-[var(--hairline)] pt-3">
        <ActionButton label="Analyze with AI" tone="info"    onClick={() => void handleAI()} />
        <ActionButton label="View IOC" tone="info"
          to={`/threat-intelligence`}
        />
        <ActionButton
          label="Resolve"
          tone="success"
          onClick={() => { onResolve(threat.id); onClose(); }}
        />
        <ActionButton
          label="Full Details"
          tone="default"
          to={`/investigate/alert/${threat.id}`}
        />
      </div>
    </Panel>
  );
}

// ── Main page ─────────────────────────────────────────────────────────
function IncidentsPage() {
  const { data: threats = [], isLoading, refetch } = useThreats();
  const { data: stats }  = useThreatStats();
  const resolve          = useResolve();
  const [selected, setSelected]   = useState<Threat | null>(null);
  const [filter, setFilter]       = useState<"all" | "active" | "resolved">("active");
  const [search, setSearch]       = useState("");
  const [exporting, setExporting] = useState(false);

  const filtered = threats.filter((t: Threat) => {
    if (filter === "active"   && t.status === "resolved") return false;
    if (filter === "resolved" && t.status !== "resolved") return false;
    if (search && !t.type.toLowerCase().includes(search.toLowerCase()) &&
        !t.source.toLowerCase().includes(search.toLowerCase()) &&
        !t.description.toLowerCase().includes(search.toLowerCase())) return false;
    return true;
  });

  const handleExport = async () => {
    setExporting(true);
    try {
      const r = await exportThreatsExcel();
      if (!r.ok) throw new Error("Export failed");
      const blob = await r.blob();
      const url  = URL.createObjectURL(blob);
      const a    = document.createElement("a");
      a.href = url; a.download = "aiss_incidents.xlsx"; a.click();
      URL.revokeObjectURL(url);
      toast.success("Incidents exported");
    } catch (e) { toast.error(String(e)); }
    finally { setExporting(false); }
  };

  const openCount     = threats.filter((t: Threat) => t.status !== "resolved").length;
  const criticalCount = threats.filter((t: Threat) => t.severity === "critical" && t.status !== "resolved").length;
  const avgTime       = "—";  // Could be calculated from timestamps

  return (
    <div>
      <PageHeader
        title="Incidents"
        subtitle="Active security incidents from real threat detections — full lifecycle workflow"
        right={
          <div className="flex gap-2">
            <ActionButton label="Refresh" onClick={() => void refetch()} />
            <ActionButton label="Export" tone="success" onClick={() => void handleExport()} />
            <ActionButton label="Run Scan" tone="info" onClick={async () => {
              try { await triggerScan(); toast.success("System scan started"); }
              catch (e) { toast.error(String(e)); }
            }} />
          </div>
        }
      />

      {/* KPIs */}
      <div className="mb-4 grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
        <Metric label="Open Incidents"    value={String(openCount)}     tone={openCount > 0 ? "critical" : "success"} sub="needs attention" />
        <Metric label="Critical"          value={String(criticalCount)} tone={criticalCount > 0 ? "critical" : "success"} />
        <Metric label="Total Threats"     value={String(stats?.total ?? threats.length)}   tone="default" sub="all time" />
        <Metric label="Auto-Resolved"     value={String(stats?.resolved ?? 0)} tone="success" sub="by AISS AI" />
      </div>

      <div className="grid gap-4 xl:grid-cols-12">
        {/* Incident list */}
        <div className={selected ? "xl:col-span-7" : "xl:col-span-12"}>
          <Panel
            title="Incident Queue"
            right={
              <div className="flex items-center gap-2">
                <div className="relative">
                  <Search className="absolute left-2 top-1/2 -translate-y-1/2 size-3 text-muted-foreground" />
                  <input
                    value={search}
                    onChange={e => setSearch(e.target.value)}
                    placeholder="Search..."
                    className="rounded-md border border-[var(--hairline)] bg-white/5 pl-6 pr-2 py-1 text-xs outline-none focus:border-primary/50 w-32"
                  />
                </div>
                {(["all", "active", "resolved"] as const).map(f => (
                  <button
                    key={f}
                    onClick={() => setFilter(f)}
                    className={`rounded border px-2 py-1 font-mono text-[0.6rem] uppercase transition-colors ${
                      filter === f ? "border-primary/40 bg-primary/12 text-primary" : "border-transparent text-muted-foreground hover:bg-white/5"
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
                <div className="size-6 animate-spin rounded-full border-2 border-primary border-t-transparent" />
              </div>
            ) : filtered.length === 0 ? (
              <div className="flex h-24 flex-col items-center justify-center gap-2 text-muted-foreground">
                <Shield className="size-8 opacity-40" />
                <p className="text-sm">{filter === "active" ? "No open incidents" : "No incidents found"}</p>
                <p className="text-xs opacity-60">{filter === "active" ? "All clear — system is secure" : "Try changing the filter"}</p>
              </div>
            ) : (
              <div className="space-y-1.5">
                {filtered.map((t: Threat) => {
                  const stage = threatToStage(t);
                  const isSelected = selected?.id === t.id;
                  return (
                    <div
                      key={t.id}
                      onClick={() => setSelected(isSelected ? null : t)}
                      className={`cursor-pointer rounded-lg border px-3 py-2.5 transition-colors hover:bg-white/4 ${
                        isSelected ? "border-primary/40 bg-primary/5" : "border-[var(--hairline)]"
                      }`}
                    >
                      <div className="flex items-start justify-between gap-3">
                        <div className="flex-1 min-w-0">
                          <div className="flex items-center gap-2 mb-0.5">
                            <Badge tone={toneFor(t.severity)}>{t.severity.toUpperCase()}</Badge>
                            <Badge tone={stageTone(stage)}>{stage}</Badge>
                            <span className="font-mono text-[0.55rem] text-muted-foreground">{t.id.slice(0, 8)}</span>
                          </div>
                          <p className="text-sm font-medium truncate">{t.type}</p>
                          <p className="text-xs text-muted-foreground truncate mt-0.5">{t.description}</p>
                        </div>
                        <div className="text-right shrink-0">
                          <p className="font-mono text-[0.6rem] text-muted-foreground">{t.source}</p>
                          <p className="font-mono text-[0.55rem] text-muted-foreground mt-0.5">
                            {new Date(t.detected_at).toLocaleTimeString()}
                          </p>
                        </div>
                      </div>
                      {isSelected && (
                        <div className="mt-2 flex gap-1.5">
                          <ActionButton label="Investigate" tone="info" className="px-1.5 py-0.5 text-[0.58rem]" to={`/investigate/alert/${t.id}`} />
                          <ActionButton label="Resolve" tone="success" className="px-1.5 py-0.5 text-[0.58rem]"
                            onClick={() => {
                              resolve.mutate({ id: t.id });
                              toast.success("Incident resolved");
                              setSelected(null);
                            }}
                          />
                        </div>
                      )}
                    </div>
                  );
                })}
              </div>
            )}
          </Panel>
        </div>

        {/* Incident detail */}
        {selected && (
          <div className="xl:col-span-5">
            <IncidentDetail
              threat={selected}
              onClose={() => setSelected(null)}
              onResolve={(id) => {
                resolve.mutate({ id });
                toast.success("Incident resolved");
              }}
            />
          </div>
        )}
      </div>
    </div>
  );
}
