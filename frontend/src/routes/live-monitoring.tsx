/**
 * Live Monitoring — AISS
 * Shows real system telemetry + WebSocket-based threat feed with actions
 */
import { createFileRoute } from "@tanstack/react-router";
import { useState, useEffect } from "react";
import { useQuery } from "@tanstack/react-query";
import { toast } from "sonner";
import { Radio, Activity, Cpu, HardDrive, Wifi, StopCircle } from "lucide-react";
import { PageHeader } from "@/components/soc/AppShell";
import { Panel } from "@/components/soc/Panel";
import { Badge, Metric } from "@/components/soc/ui";
import { ActionButton } from "@/components/soc/actions";
import { LiveProcessMonitor } from "@/components/soc/LiveProcessMonitor";
import { LiveFileScanner } from "@/components/soc/LiveFileScanner";
import { LiveScannerFeed } from "@/components/soc/LiveScannerFeed";
import { LiveDiskPanel, LiveNetworkIOPanel } from "@/components/soc/LiveSystemOverview";
import { useWebSocket, useSystemHealth, useThreatStats } from "@/hooks/useAISS";
import { getActiveThreats, triggerScan, scoreAnomaly } from "@/lib/api";

export const Route = createFileRoute("/live-monitoring")({
  head: () => ({
    meta: [
      { title: "Live Monitoring — AISS Security Console" },
      { name: "description", content: "Real-time system monitoring: processes, files, network, anomaly detection" },
    ],
  }),
  component: LiveMonitoringPage,
});

function LiveMonitoringPage() {
  const { data: health }        = useSystemHealth();
  const { data: stats }         = useThreatStats();
  const { connected, startMonitoring } = useWebSocket(() => {});
  const [scoring, setScoring]   = useState(false);
  const [anomalyResult, setAnomalyResult] = useState<{ score: number; is_anomaly: boolean } | null>(null);

  const { data: activeThreats } = useQuery({
    queryKey: ["active-threats"],
    queryFn: getActiveThreats,
    refetchInterval: 5000,
    select: d => d.threats,
  });

  const handleAnomalyScore = async () => {
    if (!health) { toast.error("No system data available yet"); return; }
    setScoring(true);
    try {
      const r = await scoreAnomaly({
        cpu:     health.cpu_percent,
        ram:     health.ram_percent,
        disk:    health.disk_percent,
        conns:   health.process_count,
        threats: stats?.active ?? 0,
      });
      setAnomalyResult(r);
      if (r.is_anomaly) {
        toast.error(`Anomaly detected! Score: ${r.score.toFixed(3)}`, {
          description: "System behavior is outside normal baseline",
        });
      } else {
        toast.success(`System normal. Anomaly score: ${r.score.toFixed(3)}`);
      }
    } catch (e) {
      toast.error(`Anomaly scoring failed: ${String(e)}`);
    } finally {
      setScoring(false);
    }
  };

  return (
    <div>
      <PageHeader
        title="Live Monitoring"
        subtitle="Real-time system telemetry: processes, files, network connections and anomaly scoring"
        right={
          <div className="flex items-center gap-2">
            <Badge tone={connected ? "success" : "warning"}>
              WS {connected ? "LIVE" : "RECONNECTING"}
            </Badge>
            <Badge tone={stats && stats.active > 0 ? "critical" : "success"}>
              {stats?.active ?? 0} ACTIVE THREATS
            </Badge>
            <ActionButton label="Score Anomaly" tone="info"   onClick={() => void handleAnomalyScore()} />
            <ActionButton label="Run Scan"      tone="warning" onClick={async () => {
              try { await triggerScan(); toast.success("Scan started"); }
              catch (e) { toast.error(String(e)); }
            }} />
          </div>
        }
      />

      {/* Live KPIs from real backend */}
      <div className="mb-4 grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
        <Metric label="CPU"           value={health ? `${Math.round(health.cpu_percent)}%`  : "—"} tone={health && health.cpu_percent > 80 ? "critical" : health && health.cpu_percent > 60 ? "warning" : "success"} sub="current usage" />
        <Metric label="RAM"           value={health ? `${Math.round(health.ram_percent)}%`  : "—"} tone={health && health.ram_percent > 85 ? "critical" : health && health.ram_percent > 70 ? "warning" : "success"} sub={health ? `${Math.round(health.ram_used_mb / 1024)}/${Math.round(health.ram_total_mb / 1024)} GB` : ""} />
        <Metric label="Active Threats" value={String(stats?.active ?? 0)}                          tone={stats && stats.active > 0 ? "critical" : "success"} sub="detected" />
        <Metric label="Processes"     value={String(health?.process_count ?? "—")}                  tone="info" sub="running" />
      </div>

      {/* Anomaly result */}
      {anomalyResult && (
        <div className={`mb-4 rounded-lg border p-3 flex items-center gap-3 ${
          anomalyResult.is_anomaly ? "border-red-400/30 bg-red-400/5" : "border-green-400/30 bg-green-400/5"
        }`}>
          <Activity className={`size-5 shrink-0 ${anomalyResult.is_anomaly ? "text-red-400" : "text-green-400"}`} />
          <div>
            <p className={`text-sm font-semibold ${anomalyResult.is_anomaly ? "text-red-300" : "text-green-300"}`}>
              {anomalyResult.is_anomaly ? "ANOMALY DETECTED" : "System Behavior Normal"}
            </p>
            <p className="font-mono text-[0.65rem] text-muted-foreground">
              Anomaly score: {anomalyResult.score.toFixed(4)} · ML model: River HalfSpaceTrees + IsolationForest
            </p>
          </div>
          <button className="ml-auto font-mono text-[0.6rem] text-muted-foreground hover:text-foreground"
            onClick={() => setAnomalyResult(null)}>✕</button>
        </div>
      )}

      {/* Real-time panels */}
      <div className="grid items-stretch gap-3 xl:grid-cols-2 mb-3">
        <LiveDiskPanel />
        <LiveNetworkIOPanel />
      </div>

      <LiveProcessMonitor />
      <div className="mt-3">
        <LiveFileScanner />
      </div>
      <div className="mt-3">
        <LiveScannerFeed />
      </div>
    </div>
  );
}
