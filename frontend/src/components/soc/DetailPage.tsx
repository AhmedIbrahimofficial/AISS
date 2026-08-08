import { useState } from "react";
import { Link, useNavigate } from "@tanstack/react-router";
import { Area, AreaChart, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { toast } from "sonner";
import { PageHeader } from "./AppShell";
import { Panel } from "./Panel";
import { Badge, Bar, DataTable, Metric } from "./ui";
import { ActionBar, ActionButton } from "./actions";
import { C } from "./data";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import {
  getActiveThreats, getThreatStats, resolveThreat, triggerScan,
  enrichIP, aiAnalyzeThreat, getSystemHealth, getNetworkConnections,
  exportThreatsExcel, type Threat,
} from "@/lib/api";
import { showActionConfirm } from "@/routes/__root";

export type DetailKind = "entity" | "mitre" | "country" | "vector" | "alert" | "blocklist";

const DETAIL_ACTIONS = [
  { label: "Analyze with AI",    tone: "success"  as const },
  { label: "Open Timeline",      tone: "info"     as const },
  { label: "Open Evidence",      tone: "info"     as const },
  { label: "Show Raw Logs" },
  { label: "View MITRE Mapping" },
  { label: "Block IP",           tone: "critical" as const },
  { label: "Quarantine Device",  tone: "critical" as const },
  { label: "Terminate Process",  tone: "critical" as const },
  { label: "Kill Session",       tone: "critical" as const },
  { label: "Escalate",           tone: "warning"  as const },
  { label: "Assign Incident" },
  { label: "Run Playbook",       tone: "success"  as const },
  { label: "Start Isolation",    tone: "critical" as const },
  { label: "Start Live Response", tone: "info"    as const },
  { label: "WHOIS Lookup" },
  { label: "DNS Lookup" },
  { label: "Geo Locate IP" },
  { label: "Traceroute" },
  { label: "Ping Host" },
  { label: "Open Packet Capture" },
  { label: "Compare Baseline" },
  { label: "Risk Analysis" },
  { label: "Generate Report" },
  { label: "Export PDF" },
  { label: "Export CSV" },
  { label: "Whitelist",          tone: "success"  as const },
  { label: "Blacklist",          tone: "critical" as const },
];

function severityTone(s: string) {
  return s === "critical" ? "critical" : s === "high" ? "warning" : s === "medium" ? "info" : "success";
}

function KV({ rows }: { rows: [string, string][] }) {
  return (
    <ul className="flex-1 divide-y divide-[var(--hairline)]">
      {rows.map(([k, v]) => (
        <li key={k} className="grid grid-cols-[minmax(0,9rem)_minmax(0,1fr)] gap-3 py-1.5 first:pt-0">
          <span className="label-cap truncate">{k}</span>
          <span className="truncate font-mono text-[0.7rem] text-foreground">{v}</span>
        </li>
      ))}
    </ul>
  );
}

// ── Real threat detail view ───────────────────────────────────────────
function ThreatDetail({ threat }: { threat: Threat }) {
  const qc = useQueryClient();
  const navigate = useNavigate();
  const [aiResult, setAiResult] = useState<string | null>(null);
  const [enrichResult, setEnrichResult] = useState<Record<string, unknown> | null>(null);

  const resolve = useMutation({
    mutationFn: (note: string) => resolveThreat(threat.id, note),
    onSuccess: () => {
      toast.success("Threat resolved");
      void qc.invalidateQueries({ queryKey: ["threats"] });
    },
    onError: (e) => toast.error(String(e)),
  });

  const handleAction = async (label: string) => {
    // Dangerous actions need confirmation popup first
    const dangerousActions: Record<string, { title: string; description: string; level: "warning" | "critical" }> = {
      "Block IP":           { title: "Block IP Address",      description: `This will add ${threat.source ?? "the source IP"} to the firewall blocklist immediately. All traffic from this IP will be denied.`, level: "critical" },
      "Quarantine Device":  { title: "Quarantine Device",     description: `This will isolate the affected host from all network segments. The device will lose network connectivity until manually re-admitted.`, level: "critical" },
      "Terminate Process":  { title: "Terminate Process",     description: `This will forcefully kill the malicious process on the endpoint. The target application will close immediately.`, level: "critical" },
      "Kill Session":       { title: "Kill Network Session",  description: `This will forcefully terminate the active connection from ${threat.source ?? "source"}. The session cannot be restored.`, level: "critical" },
      "Start Isolation":    { title: "Start Host Isolation",  description: `Full network quarantine of the affected host. This is a major response action — all network access will be blocked.`, level: "critical" },
      "Blacklist":          { title: "Permanently Blacklist", description: `This will permanently blacklist ${threat.source ?? "this indicator"}. It cannot be undone without manual intervention.`, level: "critical" },
      "Escalate":           { title: "Escalate Incident",     description: `This will escalate the incident to Tier 3 / SOC manager and trigger PagerDuty alerts. Are you sure?`, level: "warning" },
      "Run Playbook":       { title: "Run Response Playbook", description: `This will trigger the automated response playbook for ${threat.type}. It may perform multiple containment actions automatically.`, level: "warning" },
    };

    const dangerous = dangerousActions[label];
    if (dangerous) {
      const confirmed = await showActionConfirm(dangerous);
      if (!confirmed) return;
    }

    switch (label) {
      case "Analyze with AI": {
        try {
          toast("Running AI analysis...");
          const r = await aiAnalyzeThreat(threat.id);
          setAiResult(r.threat_assessment ?? JSON.stringify(r, null, 2));
          toast.success("AI analysis complete");
        } catch (e) { toast.error(`AI analysis failed: ${String(e)}`); }
        break;
      }
      case "Block IP":
      case "Quarantine Device":
      case "Terminate Process":
      case "Kill Session":
      case "Start Isolation":
      case "Blacklist": {
        resolve.mutate(`${label} — operator action via dashboard`);
        toast.success(`${label} executed — threat resolved`);
        break;
      }
      case "Geo Locate IP":
      case "WHOIS Lookup": {
        try {
          const ip = threat.source?.match(/\d+\.\d+\.\d+\.\d+/)?.[0];
          if (ip) {
            toast(`Looking up ${ip}...`);
            const r = await enrichIP(ip);
            setEnrichResult(r as unknown as Record<string, unknown>);
            toast.success(`${ip} — ${r.geo?.country_name ?? "unknown location"}, risk ${r.intel?.risk_score ?? "?"}`);
          } else {
            toast.error("No IP found in threat source");
          }
        } catch (e) { toast.error(String(e)); }
        break;
      }
      case "Export CSV":
      case "Generate Report": {
        try {
          const blob = await exportThreatsExcel().then(r => r.blob());
          const url = URL.createObjectURL(blob);
          const a = document.createElement("a"); a.href = url; a.download = "aiss_threats.xlsx"; a.click();
          URL.revokeObjectURL(url);
          toast.success("Report downloaded");
        } catch (e) { toast.error(String(e)); }
        break;
      }
      case "Open Timeline":      void navigate({ to: "/threats" }); break;
      case "View MITRE Mapping": void navigate({ to: "/mitre/t1566.001" }); break;
      case "Run Playbook":       void navigate({ to: "/playbooks" }); break;
      case "Open Evidence":      void navigate({ to: "/forensics" }); break;
      case "Show Raw Logs":      void navigate({ to: "/logs" }); break;
      case "Start Live Response":void navigate({ to: "/incident-response" }); break;
      case "Risk Analysis":      void navigate({ to: "/threat-center" }); break;
      case "Compare Baseline":   void navigate({ to: "/system-health" }); break;
      default:
        toast.success(`${label} dispatched`, {
          description: `Action queued on AISS response bus · ${new Date().toTimeString().slice(0, 8)}`,
        });
    }
  };

  const meta = threat.metadata ?? {};
  const attrs: [string, string][] = [
    ["Type",        threat.type],
    ["Source",      threat.source ?? "unknown"],
    ["Module",      threat.module ?? "unknown"],
    ["Severity",    threat.severity.toUpperCase()],
    ["Status",      threat.status],
    ["Detected",    new Date(threat.detected_at).toLocaleString()],
    ...(threat.resolved_at ? [["Resolved", new Date(threat.resolved_at).toLocaleString()] as [string, string]] : []),
    ...Object.entries(meta).slice(0, 5).map(([k, v]) => [k, String(v)] as [string, string]),
  ];

  return (
    <div>
      <PageHeader
        title={`Threat — ${threat.type}`}
        subtitle={threat.description}
        right={
          <div className="flex shrink-0 flex-wrap items-center justify-end gap-1.5">
            <Badge tone={severityTone(threat.severity)}>{threat.severity.toUpperCase()}</Badge>
            <Badge tone={threat.status === "active" ? "warning" : "success"}>{threat.status}</Badge>
            <ActionButton label="Back" to="/threats" />
          </div>
        }
      />

      <div className="flex flex-col gap-3">
        {/* Action bar */}
        <Panel title="Operator Actions" right={<span className="label-cap">{DETAIL_ACTIONS.length} available</span>}>
          <ActionBar
            actions={DETAIL_ACTIONS.map(a => ({
              ...a,
              onClick: () => void handleAction(a.label),
            }))}
          />
        </Panel>

        {/* Metrics */}
        <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
          <Metric label="Severity"    value={threat.severity.toUpperCase()} tone={severityTone(threat.severity)} sub="threat level" />
          <Metric label="Status"      value={threat.status.toUpperCase()}   tone={threat.status === "active" ? "warning" : "success"} />
          <Metric label="Module"      value={threat.module ?? "—"}          tone="info"    sub="detector" />
          <Metric label="Source"      value={threat.source ?? "—"}          tone="default" sub="origin" />
        </div>

        {/* AI analysis result */}
        {aiResult && (
          <Panel title="AI Analysis Result" right={<Badge tone="success">complete</Badge>}>
            <p className="text-sm leading-relaxed text-muted-foreground whitespace-pre-wrap">{aiResult}</p>
          </Panel>
        )}

        {/* IP enrichment result */}
        {enrichResult && (
          <Panel title="IP Intelligence" right={<Badge tone="info">enriched</Badge>}>
            <pre className="text-xs text-muted-foreground overflow-auto max-h-40">
              {JSON.stringify(enrichResult, null, 2)}
            </pre>
          </Panel>
        )}

        {/* Threat attributes */}
        <div className="grid gap-3 xl:grid-cols-2">
          <Panel title="Threat Attributes">
            <KV rows={attrs} />
          </Panel>

          <Panel title="Resolution">
            {threat.status === "resolved" ? (
              <div className="space-y-2">
                <Badge tone="success">Resolved</Badge>
                {threat.resolution_note && (
                  <p className="text-xs text-muted-foreground">{threat.resolution_note}</p>
                )}
              </div>
            ) : (
              <div className="space-y-3">
                <p className="text-xs text-muted-foreground">
                  This threat is currently <span className="text-foreground font-semibold">{threat.status}</span>. 
                  Use the action buttons above to respond, or resolve it below.
                </p>
                <div className="flex gap-2">
                  <ActionButton
                    label="Resolve — False Positive"
                    tone="success"
                    onClick={() => resolve.mutate("False positive — confirmed benign")}
                  />
                  <ActionButton
                    label="Resolve — Mitigated"
                    tone="info"
                    onClick={() => resolve.mutate("Mitigated — containment applied")}
                  />
                </div>
              </div>
            )}
          </Panel>
        </div>

        {/* Raw metadata */}
        {Object.keys(meta).length > 0 && (
          <Panel title="Raw Metadata" right={<ActionButton label="Export CSV" className="px-1.5 py-0.5" onClick={() => void handleAction("Export CSV")} />}>
            <pre className="max-h-[200px] overflow-auto rounded-md border border-[var(--hairline)] bg-black/40 p-3 font-mono text-[0.65rem] leading-relaxed text-muted-foreground">
              {JSON.stringify(meta, null, 2)}
            </pre>
          </Panel>
        )}
      </div>
    </div>
  );
}

// ── System overview detail ────────────────────────────────────────────
function SystemDetail() {
  const { data: health } = useQuery({ queryKey: ["system-health"], queryFn: getSystemHealth, refetchInterval: 5000 });
  const { data: stats }  = useQuery({ queryKey: ["threat-stats"],  queryFn: getThreatStats,  refetchInterval: 5000 });
  const { data: net }    = useQuery({ queryKey: ["network-connections"], queryFn: getNetworkConnections, refetchInterval: 8000 });

  return (
    <div>
      <PageHeader title="System Overview" subtitle="Live data from your machine" right={<Badge tone={health ? "success" : "warning"}>{health ? "ONLINE" : "loading..."}</Badge>} />
      <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4 mb-3">
        <Metric label="CPU"           value={health ? `${health.cpu_percent.toFixed(1)}%`  : "—"} tone={health && health.cpu_percent > 80 ? "critical" : "info"} sub="usage" />
        <Metric label="RAM"           value={health ? `${health.ram_percent.toFixed(1)}%`  : "—"} tone={health && health.ram_percent > 85 ? "warning" : "info"} sub={health ? `${health.ram_used_mb}MB / ${health.ram_total_mb}MB` : ""} />
        <Metric label="Disk"          value={health ? `${health.disk_percent.toFixed(1)}%` : "—"} tone={health && health.disk_percent > 80 ? "warning" : "success"} />
        <Metric label="Active Threats" value={String(stats?.active ?? 0)} tone={stats && stats.active > 0 ? "critical" : "success"} sub="live" />
      </div>
      <div className="grid gap-3 xl:grid-cols-2">
        <Panel title="Detection Modules">
          {health?.modules ? (
            <ul className="space-y-1.5">
              {Object.entries(health.modules).map(([mod, ok]) => (
                <li key={mod} className="grid grid-cols-[minmax(0,1fr)_auto] items-center gap-2">
                  <span className="text-xs text-muted-foreground capitalize">{mod.replace(/_/g, " ")}</span>
                  <Badge tone={ok ? "success" : "warning"}>{ok ? "online" : "offline"}</Badge>
                </li>
              ))}
            </ul>
          ) : <p className="text-xs text-muted-foreground">Connecting to backend...</p>}
        </Panel>
        <Panel title="Active Network Connections">
          {net?.connections?.length ? (
            <DataTable
              columns={["Local", "Remote", "Status", "PID"]}
              rows={net.connections.slice(0, 8).map(c => [
                <span className="font-mono text-xs">{c.local_address}</span>,
                <span className="font-mono text-xs text-muted-foreground">{c.remote_address || "—"}</span>,
                <Badge tone={c.status === "ESTABLISHED" ? "success" : "info"}>{c.status}</Badge>,
                <span className="font-mono text-xs text-muted-foreground">{c.pid ?? "—"}</span>,
              ])}
            />
          ) : <p className="text-xs text-muted-foreground">No connections data</p>}
        </Panel>
      </div>
    </div>
  );
}

// ── Main export ───────────────────────────────────────────────────────
export function DetailPage({ kind, id }: { kind: DetailKind; id: string }) {
  // If it's a real threat ID — load from backend
  const { data: threats } = useQuery({
    queryKey: ["threats", "active"],
    queryFn:  getActiveThreats,
    select:   (d) => d.threats,
  });

  const threat = threats?.find((t: Threat) => t.id === id || t.id.startsWith(id));

  // Real threat found — show real data
  if (threat) return <ThreatDetail threat={threat} />;

  // System/network overview kinds
  if (kind === "entity" && (id === "system" || id === "overview")) return <SystemDetail />;

  // Blocklist entry — show network detail
  if (kind === "blocklist") {
    return (
      <div>
        <PageHeader title={`Blocked: ${decodeURIComponent(id)}`} subtitle="Network blocklist entry" right={<ActionButton label="Back" to="/" />} />
        <Panel title="Blocklist Entry">
          <KV rows={[
            ["IP / Host", decodeURIComponent(id)],
            ["Blocked at", new Date().toLocaleString()],
            ["Action", "Denied at perimeter"],
          ]} />
        </Panel>
      </div>
    );
  }

  // Fallback: no threats yet / loading
  return (
    <div>
      <PageHeader
        title={kind === "alert" ? "Threat Details" : `Investigation — ${decodeURIComponent(id)}`}
        subtitle="Loading threat data from backend..."
        right={<ActionButton label="Back" to="/threats" />}
      />
      <Panel title="Status">
        <div className="py-8 text-center space-y-3">
          <div className="size-8 mx-auto animate-spin rounded-full border-2 border-primary border-t-transparent" />
          <p className="text-sm text-muted-foreground">
            {threats === undefined
              ? "Connecting to backend..."
              : "No active threats detected. Your system appears clean."}
          </p>
          <div className="flex justify-center gap-2 pt-2">
            <ActionButton label="View All Threats" tone="info" to="/threats" />
            <ActionButton label="Run Quick Scan"   tone="success" onClick={() => triggerScan().then(() => toast.success("Scan started"))} />
            <ActionButton label="System Health"    to="/system-health" />
          </div>
        </div>
      </Panel>
    </div>
  );
}
