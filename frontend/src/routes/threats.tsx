import { createFileRoute, Link } from "@tanstack/react-router";
import { useState } from "react";
import { toast } from "sonner";
import { RefreshCw, Download, Play, Shield } from "lucide-react";
import { PageHeader } from "@/components/soc/AppShell";
import { Panel } from "@/components/soc/Panel";
import { Badge, DataTable, Metric } from "@/components/soc/ui";
import { ActionButton } from "@/components/soc/actions";
import { useThreats, useThreatStats, useResolve, useTriggerScan } from "@/hooks/useAISS";
import { exportThreatsExcel, exportThreatsChart } from "@/lib/api";
import type { Threat } from "@/lib/api";

export const Route = createFileRoute("/threats")({
  head: () => ({
    meta: [
      { title: "Threat Detections — AISS Security Console" },
      { name: "description", content: "Live threat detections from AISS backend" },
    ],
  }),
  component: ThreatsPage,
});

const toneFor = (sev: string) =>
  sev === "critical" ? "critical" : sev === "high" ? "warning" : sev === "medium" ? "info" : "success";

function ThreatsPage() {
  const [filter, setFilter] = useState("all");
  const { data: threats = [], isLoading, refetch } = useThreats();
  const { data: stats }  = useThreatStats();
  const resolve          = useResolve();
  const triggerScan      = useTriggerScan();

  const visible = filter === "all" ? threats : threats.filter((t: Threat) => t.severity === filter);

  const handleExportExcel = async () => {
    try {
      const r = await exportThreatsExcel();
      if (!r.ok) throw new Error("Export failed");
      const blob = await r.blob();
      const url  = URL.createObjectURL(blob);
      const a    = document.createElement("a");
      a.href = url; a.download = "aiss_threats.xlsx"; a.click();
      URL.revokeObjectURL(url);
      toast.success("Excel export downloaded");
    } catch (e) { toast.error(String(e)); }
  };

  const handleExportChart = async () => {
    try {
      const r = await exportThreatsChart();
      if (!r.ok) throw new Error("Export failed");
      const blob = await r.blob();
      const url  = URL.createObjectURL(blob);
      window.open(url, "_blank");
      toast.success("Chart opened");
    } catch (e) { toast.error(String(e)); }
  };

  return (
    <div>
      <PageHeader
        title="Threat Detections"
        subtitle="Live detection queue from AISS AI engine"
        right={
          <div className="flex items-center gap-2">
            <ActionButton label="Quick Scan"    tone="info"     onClick={() => triggerScan.mutate()} />
            <ActionButton label="Export Excel"  tone="success"  onClick={handleExportExcel} />
            <ActionButton label="Export Chart"  tone="info"     onClick={handleExportChart} />
            <ActionButton label="Refresh"                       onClick={() => void refetch()} />
          </div>
        }
      />

      {/* KPIs — live from backend */}
      <div className="mb-3 grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
        <Metric label="Active Threats"  value={String(stats?.active  ?? threats.length)} tone="critical" sub="live" />
        <Metric label="Critical"        value={String(stats?.critical ?? 0)} tone="critical" />
        <Metric label="High"            value={String(stats?.high     ?? 0)} tone="warning" />
        <Metric label="Resolved (24h)"  value={String(stats?.resolved ?? 0)} tone="success" sub="auto + manual" />
      </div>

      <Panel
        title="Live Detection Queue"
        right={
          <div className="flex gap-1">
            {["all", "critical", "high", "medium", "low"].map((f) => (
              <button
                key={f}
                onClick={() => setFilter(f)}
                className={`rounded border px-2 py-1 font-mono text-[0.6rem] tracking-wider uppercase transition-colors ${
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
            <div className="size-6 animate-spin rounded-full border-2 border-primary border-t-transparent" />
          </div>
        ) : visible.length === 0 ? (
          <div className="flex h-24 flex-col items-center justify-center gap-2 text-muted-foreground">
            <Shield className="size-8 opacity-40" />
            <p className="text-sm">No {filter !== "all" ? filter : "active"} threats detected</p>
            <p className="text-xs opacity-60">
              {filter === "all" ? "AISS is monitoring your system" : `No ${filter} severity threats`}
            </p>
          </div>
        ) : (
          <DataTable
            columns={["ID", "Type", "Source", "Severity", "Module", "Status", "Detected", "Actions"]}
            rows={visible.map((t: Threat) => [
              <span className="font-mono text-xs text-muted-foreground">{t.id.slice(0, 8)}</span>,
              <Link
                to="/investigate/$type/$id"
                params={{ type: "alert", id: t.id }}
                className="text-xs hover:text-primary"
              >
                {t.type}
              </Link>,
              <span className="font-mono text-xs">{t.source}</span>,
              <Badge tone={toneFor(t.severity)}>{t.severity.toUpperCase()}</Badge>,
              <span className="text-xs text-muted-foreground">{t.module}</span>,
              <Badge tone={t.status === "active" ? "warning" : "success"}>{t.status}</Badge>,
              <span className="font-mono text-xs text-muted-foreground">
                {new Date(t.detected_at).toTimeString().slice(0, 8)}
              </span>,
              <div className="flex gap-1">
                <ActionButton
                  label="Resolve"
                  tone="success"
                  className="px-1.5 py-0.5"
                  onClick={() => resolve.mutate({ id: t.id })}
                />
                <ActionButton
                  label="View"
                  tone="info"
                  className="px-1.5 py-0.5"
                  to={`/investigate/alert/${t.id}`}
                />
              </div>,
            ])}
          />
        )}
      </Panel>
    </div>
  );
}
