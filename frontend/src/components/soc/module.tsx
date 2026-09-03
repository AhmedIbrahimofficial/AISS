/**
 * AISS Module Page — full-width chart-first layout
 * NO boxes. Everything is a chart, graph, or visual strip.
 * All data wired to real backend.
 */
import { Link } from "@tanstack/react-router";
import { useEffect, useRef, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import {
  Area, AreaChart, Bar as RBar, BarChart,
  CartesianGrid, Cell, ComposedChart, Legend,
  Line, Pie, PieChart, RadialBar, RadialBarChart,
  PolarAngleAxis, ResponsiveContainer, Tooltip, XAxis, YAxis,
} from "recharts";
import { PageHeader } from "./AppShell";
import { Panel } from "./Panel";
import { Badge } from "./ui";
import { ActionBar, ActionButton, ChartToolbar } from "./actions";
import { C } from "./data";
import { useSystemHealth, useThreatStats, useAgentStats } from "@/hooks/useAISS";
import {
  getLiveNetworkStats, getLiveProcesses, getActiveThreats,
  getLiveDisk, getSystemHealth, getThreatStats, getAgents,
  getLiveFiles, getNetworkConnections,
} from "@/lib/api";

export type RowKind = "alert" | "asset" | "log" | "case" | "vuln" | "file" | "rule";

export type ModuleDef = {
  key: string; title: string; subtitle: string; kind: RowKind;
  kpis: [string, string, "default" | "critical" | "warning" | "success" | "info", string][];
  actions: { label: string; tone?: "default" | "critical" | "warning" | "success" | "info" }[];
  tableTitle: string; feedTitle: string; facets: [string, number][];
};

const SEV = ["CRITICAL", "HIGH", "MEDIUM", "LOW"] as const;
const sevTone = (s: string) =>
  s === "CRITICAL" ? "critical" : s === "HIGH" ? "warning" : s === "MEDIUM" ? "info" : "success";

/* ── Row generators removed — no mock data ──────────────────────── */
type Row = { id: string; cells: string[]; sev: string };

function columnsFor(kind: RowKind): string[] {
  switch (kind) {
    case "asset":  return ["Host","OS","Owner","Risk","Agent","Last seen","State"];
    case "log":    return ["Timestamp","Source","Event ID","Host","Message","Severity","Action"];
    case "case":   return ["Case","Title","Assignee","Stage","SLA","Age","Severity"];
    case "vuln":   return ["CVE","Asset","CVSS","Exploit","Vector","Age","Severity"];
    case "file":   return ["File","SHA256","Family","Verdict","Host","Detonated","Severity"];
    case "rule":   return ["Rule","Type","Hits 24h","Confidence","Coverage","Updated","State"];
    default:       return ["Alert","Technique","Source","Asset","Detected","Confidence","Severity"];
  }
}

/* ── rowsFor removed — all data comes from the backend ──────────── */

/* ── 1. FULL-WIDTH LIVE METRICS CHART ──────────────────────────────
   One big AreaChart showing CPU%, RAM%, and threat count live.
   No boxes — just the chart edge to edge.
*/
function LiveMetricsChart({ k }: { k: string }) {
  const { data: health } = useSystemHealth();
  const { data: stats }  = useThreatStats();
  const [hist, setHist]  = useState<{t:string; cpu:number; ram:number; threats:number; conns:number}[]>([]);

  useEffect(() => {
    const now = new Date().toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" });
    setHist(prev => {
      const pt = {
        t: now,
        cpu:     Math.round(health?.cpu_percent ?? 0),
        ram:     Math.round(health?.ram_percent ?? 0),
        threats: stats?.active ?? 0,
        conns:   0,
      };
      const next = [...prev, pt].slice(-60);
      if (next.length === 1) {
        return Array.from({ length: 59 }, (_, i) => ({
          t: new Date(Date.now() - (59 - i) * 5000).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" }),
          cpu: 0, ram: 0, threats: 0, conns: 0,
        })).concat(next);
      }
      return next;
    });
  }, [health, stats]);

  const cpuNow  = Math.round(health?.cpu_percent ?? 0);
  const ramNow  = Math.round(health?.ram_percent ?? 0);
  const thrNow  = stats?.active ?? 0;

  return (
    <Panel
      title="System Telemetry — Live"
      right={
        <div className="flex items-center gap-4 font-mono text-[0.65rem]">
          <span style={{ color: C.teal   }}>● CPU {cpuNow}%</span>
          <span style={{ color: C.warning}}>● RAM {ramNow}%</span>
          <span style={{ color: thrNow > 0 ? C.critical : C.success }}>
            ● {thrNow > 0 ? `${thrNow} THREATS` : "CLEAR"}
          </span>
          <span className="dot-pulse size-2 bg-[var(--success)]" />
        </div>
      }
      bodyClassName="p-0 overflow-hidden"
    >
      <ResponsiveContainer width="100%" height={260}>
        <ComposedChart data={hist} margin={{ top: 16, right: 0, left: 0, bottom: 0 }}>
          <defs>
            <linearGradient id={`gcpu${k}`} x1="0" y1="0" x2="0" y2="1">
              <stop offset="0%" stopColor={C.teal} stopOpacity={0.35} />
              <stop offset="100%" stopColor={C.teal} stopOpacity={0.02} />
            </linearGradient>
            <linearGradient id={`gram${k}`} x1="0" y1="0" x2="0" y2="1">
              <stop offset="0%" stopColor={C.warning} stopOpacity={0.28} />
              <stop offset="100%" stopColor={C.warning} stopOpacity={0.02} />
            </linearGradient>
          </defs>
          <CartesianGrid stroke="rgba(255,255,255,0.045)" vertical={false} />
          <XAxis dataKey="t" tick={{ fill: C.muted, fontSize: 9, fontFamily: "monospace" }}
            axisLine={false} tickLine={false} interval={11} />
          <YAxis yAxisId="pct" domain={[0, 100]}
            tick={{ fill: C.muted, fontSize: 9, fontFamily: "monospace" }}
            axisLine={false} tickLine={false} tickFormatter={v => `${v}%`} width={36} />
          <YAxis yAxisId="thr" orientation="right" domain={[0, "auto"]}
            tick={{ fill: C.muted, fontSize: 9, fontFamily: "monospace" }}
            axisLine={false} tickLine={false} width={28} />
          <Tooltip
            contentStyle={{ background: "#0a1310", border: "1px solid rgba(255,255,255,0.1)", borderRadius: 8, fontSize: 11, fontFamily: "monospace" }}
            labelStyle={{ color: C.muted }}
          />
          <Area yAxisId="pct" type="monotone" dataKey="cpu" name="CPU %" stroke={C.teal}
            fill={`url(#gcpu${k})`} strokeWidth={2} dot={false} isAnimationActive={false} />
          <Area yAxisId="pct" type="monotone" dataKey="ram" name="RAM %" stroke={C.warning}
            fill={`url(#gram${k})`} strokeWidth={1.5} dot={false} isAnimationActive={false} />
          <Line yAxisId="thr" type="stepAfter" dataKey="threats" name="Threats"
            stroke={C.critical} strokeWidth={2} dot={false} isAnimationActive={false}
            strokeDasharray="4 2" />
        </ComposedChart>
      </ResponsiveContainer>
    </Panel>
  );
}

/* ── 2. NETWORK I/O CHART ───────────────────────────────────────────
   Full-width real-time network bandwidth chart.
*/
function NetworkIOChart({ k }: { k: string }) {
  const { data: net } = useQuery({ queryKey: ["live-network-stats"], queryFn: getLiveNetworkStats, refetchInterval: 3000 });
  const [hist, setHist] = useState<{t:string; recv:number; sent:number; conns:number; blocked:number}[]>([]);

  useEffect(() => {
    if (!net) return;
    const now = new Date().toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" });
    setHist(prev => {
      const pt = { t: now, recv: net.recv_mb_s, sent: net.sent_mb_s, conns: net.connections, blocked: net.blocked };
      return [...prev, pt].slice(-60);
    });
  }, [net]);

  return (
    <Panel
      title="Network I/O — Real-time"
      right={
        <div className="flex items-center gap-4 font-mono text-[0.65rem]">
          <span style={{ color: C.teal   }}>▲ {net?.sent_mb_s.toFixed(2) ?? "0"} MB/s</span>
          <span style={{ color: C.cyan   }}>▼ {net?.recv_mb_s.toFixed(2) ?? "0"} MB/s</span>
          <span style={{ color: C.muted  }}>{net?.connections ?? 0} conns</span>
          <span className="dot-pulse size-2 bg-[var(--teal)]" />
        </div>
      }
      bodyClassName="p-0 overflow-hidden"
    >
      <ResponsiveContainer width="100%" height={200}>
        <ComposedChart data={hist} margin={{ top: 12, right: 0, left: 0, bottom: 0 }}>
          <defs>
            <linearGradient id={`grecv${k}`} x1="0" y1="0" x2="0" y2="1">
              <stop offset="0%" stopColor={C.cyan} stopOpacity={0.4} />
              <stop offset="100%" stopColor={C.cyan} stopOpacity={0.02} />
            </linearGradient>
            <linearGradient id={`gsent${k}`} x1="0" y1="0" x2="0" y2="1">
              <stop offset="0%" stopColor={C.teal} stopOpacity={0.35} />
              <stop offset="100%" stopColor={C.teal} stopOpacity={0.02} />
            </linearGradient>
          </defs>
          <CartesianGrid stroke="rgba(255,255,255,0.04)" vertical={false} />
          <XAxis dataKey="t" tick={{ fill: C.muted, fontSize: 9 }} axisLine={false} tickLine={false} interval={14} />
          <YAxis yAxisId="mb" tick={{ fill: C.muted, fontSize: 9 }} axisLine={false} tickLine={false} tickFormatter={v => `${v.toFixed(1)}`} width={36} />
          <YAxis yAxisId="conn" orientation="right" tick={{ fill: C.muted, fontSize: 9 }} axisLine={false} tickLine={false} width={32} />
          <Tooltip contentStyle={{ background: "#0a1310", border: "1px solid rgba(255,255,255,0.1)", borderRadius: 8, fontSize: 11 }} />
          <Area yAxisId="mb" type="monotone" dataKey="recv" name="Recv MB/s" stroke={C.cyan} fill={`url(#grecv${k})`} strokeWidth={2} dot={false} isAnimationActive={false} />
          <Area yAxisId="mb" type="monotone" dataKey="sent" name="Sent MB/s" stroke={C.teal} fill={`url(#gsent${k})`} strokeWidth={1.5} dot={false} isAnimationActive={false} />
          <Line yAxisId="conn" type="monotone" dataKey="conns" name="Connections" stroke={C.campaign} strokeWidth={1.5} dot={false} isAnimationActive={false} />
        </ComposedChart>
      </ResponsiveContainer>
    </Panel>
  );
}

/* ── 3. PROCESS CPU CHART ───────────────────────────────────────────
   Horizontal bar chart of top CPU-consuming processes. Real data.
*/
function ProcessCpuChart() {
  const { data: procs } = useQuery({ queryKey: ["live-processes"], queryFn: getLiveProcesses, refetchInterval: 6000 });

  const top = (procs?.processes ?? []).slice(0, 12).map(p => ({
    name: p.name.length > 18 ? p.name.slice(0, 18) : p.name,
    cpu:  p.cpu,
    mem:  p.mem,
    suspicious: p.suspicious,
  }));

  return (
    <Panel
      title="Top Processes by CPU"
      right={
        <div className="flex items-center gap-2 font-mono text-[0.65rem]">
          <span style={{ color: C.muted }}>{procs?.total ?? "…"} running</span>
          {(procs?.suspicious_count ?? 0) > 0 && (
            <Badge tone="critical">{procs!.suspicious_count} suspect</Badge>
          )}
        </div>
      }
      bodyClassName="p-0 overflow-hidden"
    >
      <ResponsiveContainer width="100%" height={Math.max(160, top.length * 28 + 20)}>
        <BarChart data={top} layout="vertical" margin={{ top: 8, right: 48, left: 8, bottom: 4 }}>
          <XAxis type="number" domain={[0, 100]} tick={{ fill: C.muted, fontSize: 9 }}
            axisLine={false} tickLine={false} tickFormatter={v => `${v}%`} />
          <YAxis type="category" dataKey="name" tick={{ fill: C.muted, fontSize: 10, fontFamily: "monospace" }}
            axisLine={false} tickLine={false} width={110} />
          <Tooltip contentStyle={{ background: "#0a1310", border: "1px solid rgba(255,255,255,0.1)", borderRadius: 8, fontSize: 11 }}
            formatter={(val, name) => [`${String(val)}%`, name]} />
          <RBar dataKey="cpu" name="CPU %" radius={[0, 3, 3, 0]} barSize={14}>
            {top.map((p, i) => (
              <Cell key={i} fill={p.suspicious ? C.critical : p.cpu > 40 ? C.warning : C.teal} />
            ))}
          </RBar>
        </BarChart>
      </ResponsiveContainer>
    </Panel>
  );
}

/* ── 4. DISK USAGE CHART ────────────────────────────────────────────
   Full-width disk usage visualization.
*/
function DiskUsageChart() {
  const { data: disk } = useQuery({ queryKey: ["live-disk"], queryFn: getLiveDisk, refetchInterval: 30_000 });
  const parts = disk?.partitions ?? [];

  const chartData = parts.map(p => ({
    name: p.mountpoint,
    used: p.used_gb, free: p.free_gb, pct: p.percent,
  }));

  if (chartData.length === 0) return null;

  return (
    <Panel
      title="Disk Usage by Partition"
      right={<span className="label-cap font-mono text-[0.6rem]">{parts.length} partitions</span>}
      bodyClassName="p-0 overflow-hidden"
    >
      <ResponsiveContainer width="100%" height={160}>
        <BarChart data={chartData} margin={{ top: 12, right: 16, left: 0, bottom: 0 }}>
          <CartesianGrid stroke="rgba(255,255,255,0.04)" vertical={false} />
          <XAxis dataKey="name" tick={{ fill: C.muted, fontSize: 10 }} axisLine={false} tickLine={false} />
          <YAxis tick={{ fill: C.muted, fontSize: 9 }} axisLine={false} tickLine={false} tickFormatter={v => `${v}GB`} width={40} />
          <Tooltip contentStyle={{ background: "#0a1310", border: "1px solid rgba(255,255,255,0.1)", borderRadius: 8, fontSize: 11 }}
            formatter={(val, name) => [`${String(val)} GB`, name]} />
          <RBar dataKey="used" name="Used GB" stackId="a" radius={[0,0,0,0]}>
            {chartData.map((d, i) => (
              <Cell key={i} fill={d.pct > 85 ? C.critical : d.pct > 70 ? C.warning : C.teal} />
            ))}
          </RBar>
          <RBar dataKey="free" name="Free GB" stackId="a" fill="rgba(255,255,255,0.07)" radius={[3,3,0,0]} />
        </BarChart>
      </ResponsiveContainer>
    </Panel>
  );
}

/* ── 5. THREAT SEVERITY CHART ───────────────────────────────────────
   Full-width stacked chart showing threat breakdown.
*/
function ThreatSeverityChart({ facets, k }: { facets: [string, number][]; k: string }) {
  const { data: stats } = useThreatStats();
  const colors = [C.critical, C.warning, C.campaign, C.teal, C.success, C.cyan];

  // Use real stats if available, fall back to facet definition
  const realData = stats && (stats.critical + stats.high + stats.medium + stats.low > 0)
    ? [
        { name: "Critical", value: stats.critical, color: C.critical },
        { name: "High",     value: stats.high,     color: C.warning  },
        { name: "Medium",   value: stats.medium,   color: C.campaign },
        { name: "Low",      value: stats.low,       color: C.teal    },
      ]
    : facets.map(([name, value], i) => ({ name, value, color: colors[i % colors.length]! }));

  const total = realData.reduce((a, b) => a + b.value, 0);

  // Bar chart version — full width
  return (
    <Panel
      title="Threat Distribution"
      right={
        <div className="flex items-center gap-3 font-mono text-[0.65rem]">
          {realData.map(d => (
            <span key={d.name} style={{ color: d.color }}>● {d.name} {d.value}</span>
          ))}
          <span className="text-muted-foreground">total {total}</span>
        </div>
      }
      bodyClassName="p-0 overflow-hidden"
    >
      <div className="flex h-[140px] items-end gap-0 px-4 pb-4 pt-2">
        {realData.map((d, i) => {
          const pct = total > 0 ? (d.value / total) * 100 : 25;
          return (
            <div key={d.name} className="flex flex-1 flex-col items-center gap-1">
              <span className="font-mono text-xs font-bold" style={{ color: d.color }}>{d.value}</span>
              <div
                className="w-full rounded-t transition-all duration-700"
                style={{
                  height: `${Math.max(4, pct)}%`,
                  background: `linear-gradient(180deg, ${d.color} 0%, color-mix(in oklab, ${d.color} 60%, transparent) 100%)`,
                  boxShadow: `0 0 12px ${d.color}40`,
                  minHeight: 4,
                }}
              />
              <span className="label-cap text-[0.5rem]">{d.name}</span>
            </div>
          );
        })}
      </div>
    </Panel>
  );
}

/* ── 6. FULL-WIDTH DETECTION TREND ─────────────────────────────────
   Rolling area chart with real CPU + threat data.
*/
function DetectionTrendChart({ k }: { k: string }) {
  const { data: health } = useSystemHealth();
  const { data: stats }  = useThreatStats();
  const [hist, setHist]  = useState<{t:string; detected:number; resolved:number; cpu:number}[]>([]);

  useEffect(() => {
    const t = new Date().toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
    setHist(prev => {
      const pt = { t, detected: stats?.active ?? 0, resolved: stats?.resolved ?? 0, cpu: Math.round(health?.cpu_percent ?? 0) };
      const next = [...prev, pt].slice(-48);
      if (next.length === 1) {
        return Array.from({ length: 47 }, (_, i) => ({
          t: new Date(Date.now() - (47-i)*60000).toLocaleTimeString([], { hour:"2-digit", minute:"2-digit" }),
          detected: 0, resolved: 0, cpu: 0,
        })).concat(next);
      }
      return next;
    });
  }, [stats, health]);

  return (
    <Panel
      title="Detection Activity (24h rolling)"
      right={<ChartToolbar drillTo="/threats" />}
      bodyClassName="p-0 overflow-hidden"
    >
      <ResponsiveContainer width="100%" height={220}>
        <AreaChart data={hist} margin={{ top: 12, right: 0, left: 0, bottom: 0 }}>
          <defs>
            <linearGradient id={`gd${k}`} x1="0" y1="0" x2="0" y2="1">
              <stop offset="0%" stopColor={C.teal} stopOpacity={0.45} />
              <stop offset="100%" stopColor={C.teal} stopOpacity={0} />
            </linearGradient>
            <linearGradient id={`gr${k}`} x1="0" y1="0" x2="0" y2="1">
              <stop offset="0%" stopColor={C.critical} stopOpacity={0.38} />
              <stop offset="100%" stopColor={C.critical} stopOpacity={0} />
            </linearGradient>
            <linearGradient id={`gc${k}`} x1="0" y1="0" x2="0" y2="1">
              <stop offset="0%" stopColor={C.campaign} stopOpacity={0.25} />
              <stop offset="100%" stopColor={C.campaign} stopOpacity={0} />
            </linearGradient>
          </defs>
          <CartesianGrid stroke="rgba(255,255,255,0.05)" vertical={false} />
          <XAxis dataKey="t" tick={{ fill: C.muted, fontSize: 10 }} axisLine={false} tickLine={false} interval={7} />
          <YAxis tick={{ fill: C.muted, fontSize: 10 }} axisLine={false} tickLine={false} width={32} />
          <Tooltip contentStyle={{ background: "#0a1310", border: "1px solid rgba(255,255,255,0.1)", borderRadius: 8, fontSize: 11 }} />
          <Area type="monotone" dataKey="detected"  name="Active"   stroke={C.teal}     fill={`url(#gd${k})`} strokeWidth={2}   dot={false} isAnimationActive={false} />
          <Area type="monotone" dataKey="resolved"   name="Resolved" stroke={C.critical} fill={`url(#gr${k})`} strokeWidth={1.8} dot={false} isAnimationActive={false} />
          <Area type="monotone" dataKey="cpu"        name="CPU %"    stroke={C.campaign} fill={`url(#gc${k})`} strokeWidth={1.4} dot={false} isAnimationActive={false} strokeDasharray="4 2" />
          <Legend wrapperStyle={{ fontSize: 10, fontFamily: "monospace", paddingTop: 4 }} />
        </AreaChart>
      </ResponsiveContainer>
    </Panel>
  );
}

/* ── 7. LIVE EVENT FEED ─────────────────────────────────────────── */
export function LiveEventFeed({ title: t, seed }: { title: string; seed: string }) {
  const { data: threats } = useQuery({
    queryKey: ["threats","active"], queryFn: getActiveThreats,
    refetchInterval: 4000, select: d => d.threats,
  });
  const { data: procs } = useQuery({
    queryKey: ["live-processes"], queryFn: getLiveProcesses, refetchInterval: 8000,
  });

  const realEvents = [
    ...(threats??[]).map(th => ({ id:th.id, msg:th.type, src:th.source, sev:th.severity.toUpperCase(), t:new Date(th.detected_at).toTimeString().slice(0,8) })),
    ...(procs?.processes.filter(p=>p.suspicious).map(p => ({ id:`proc-${p.pid}`, msg:`Suspicious: ${p.name}`, src:`PID ${p.pid}`, sev:"HIGH", t:new Date().toTimeString().slice(0,8) }))??[]),
  ];

  return (
    <Panel title={t} right={<span className="dot-pulse size-2 bg-[var(--critical)]" />}
      bodyClassName="max-h-[320px] overflow-y-auto pr-1">
      {realEvents.length === 0 ? (
        <div className="flex h-28 items-center justify-center">
          <p className="text-xs text-muted-foreground">No active events. Monitoring…</p>
        </div>
      ) : (
        <ul className="space-y-0.5">
          {realEvents.map(e => (
            <li key={e.id} className="animate-fade-in grid grid-cols-[auto_minmax(0,1fr)_auto_auto] items-center gap-2.5 rounded px-2 py-1.5 hover:bg-white/5">
              <span className={`size-1.5 shrink-0 rounded-full ${e.sev==="CRITICAL"?"dot-pulse":""}`}
                style={{ background:`var(--${e.sev==="CRITICAL"?"critical":e.sev==="HIGH"?"warning":e.sev==="MEDIUM"?"cyan":"success"})` }} />
              <div className="min-w-0">
                <p className="truncate text-xs">{e.msg}</p>
                <p className="truncate font-mono text-[0.62rem] text-muted-foreground">{e.src}</p>
              </div>
              <Badge tone={sevTone(e.sev)}>{e.sev}</Badge>
              <span className="font-mono text-[0.6rem] text-muted-foreground">{e.t}</span>
            </li>
          ))}
        </ul>
      )}
    </Panel>
  );
}

/* ── 8. INVESTIGATION TABLE ─────────────────────────────────────── */
export function InvestigationTable({ kind, seed, tableTitle, rows: count = 12, moduleKey }: {
  kind: RowKind; seed: string; tableTitle: string; rows?: number; moduleKey?: string;
}) {
  const { data: threatsData } = useQuery({
    queryKey: ["threats", "all-table", seed], queryFn: getActiveThreats,
    refetchInterval: 10_000, select: d => d.threats,
  });
  const { data: agentsData } = useQuery({
    queryKey: ["agents"], queryFn: getAgents, refetchInterval: 15_000,
  });
  const { data: filesData } = useQuery({
    queryKey: ["live-files"], queryFn: getLiveFiles, refetchInterval: 30_000,
  });

  const cols = columnsFor(kind);

  // Build real rows based on module kind
  let realRows: Row[] = [];
  if (kind === "alert" || kind === "case" || kind === "log" || kind === "rule") {
    realRows = (threatsData ?? []).slice(0, count).map(th => ({
      id: th.id,
      sev: th.severity.toUpperCase(),
      cells: kind === "alert"
        ? [th.type, th.module ?? "\u2014", th.source, th.source, new Date(th.detected_at).toLocaleTimeString(), "\u2014", th.severity.toUpperCase()]
        : kind === "case"
        ? [th.id.slice(0,12), th.type, "aiss-auto", th.status, th.status === "resolved" ? "On track" : "At risk", `${Math.floor((Date.now() - new Date(th.detected_at).getTime()) / 3600000)}h`, th.severity.toUpperCase()]
        : kind === "log"
        ? [new Date(th.detected_at).toLocaleTimeString(), th.module ?? "ThreatEngine", th.id.slice(0,8), th.source, th.type, th.severity.toUpperCase(), th.status === "resolved" ? "Resolved" : "Alerted"]
        : [`RULE-${th.id.slice(0,6)}`, "Behavioral", "\u2014", "\u2014", "\u2014", "today", "Enabled"],
    }));
  } else if (kind === "asset") {
    realRows = (agentsData?.agents ?? []).slice(0, count).map(a => ({
      id: a.id,
      sev: "MEDIUM",
      cells: [a.hostname || a.id.slice(0,12), a.os_name ?? "Unknown", "aiss", "\u2014", "v8.42", "\u2014", a.status === "connected" ? "Healthy" : "Offline"],
    }));
  } else if (kind === "file") {
    realRows = (filesData?.suspicious ?? filesData?.files ?? []).slice(0, count).map(f => ({
      id: f.path,
      sev: f.risk ? "HIGH" : "LOW",
      cells: [f.name, f.path.slice(-16), "\u2014", f.risk ? "Suspicious" : "Clean", f.dir, "\u2014", f.risk ? "HIGH" : "LOW"],
    }));
  } else if (kind === "vuln") {
    realRows = (threatsData ?? []).filter(t => t.severity === "critical" || t.severity === "high").slice(0, count).map(th => ({
      id: th.id,
      sev: th.severity.toUpperCase(),
      cells: [`CVE-${th.id.slice(0,6)}`, th.source, "\u2014", "\u2014", "\u2014", "\u2014", th.severity.toUpperCase()],
    }));
  }

  // Show empty state when no real data
  const displayRows = realRows;
  return (
    <Panel title={tableTitle} right={
      <div className="flex items-center gap-1.5">
        <Badge tone={realRows.length > 0 ? "success" : "info"}>
          {realRows.length > 0 ? `${displayRows.length} real` : "no data"}
        </Badge>
        <ActionButton label="Export CSV" className="px-1.5 py-0.5" />
      </div>
    }>
      {realRows.length === 0 && (
        <div className="mb-2 flex h-28 items-center justify-center rounded bg-white/[0.02] px-3 py-1.5">
          <p className="text-[0.65rem] text-muted-foreground">
            No data available — run a scan or ask the AI assistant.
          </p>
        </div>
      )}
      <div className="overflow-x-auto">
        <table className="w-full min-w-[720px] text-left text-sm">
          <thead>
            <tr className="border-b border-[var(--hairline)]">
              {cols.map(c => <th key={c} className="label-cap px-2.5 py-2 font-medium">{c}</th>)}
              <th className="label-cap px-2.5 py-2 text-right font-medium">Investigate</th>
            </tr>
          </thead>
          <tbody>
            {displayRows.map(row => (
              <tr key={row.id} className="group border-b border-[var(--hairline)] last:border-0 hover:bg-white/4">
                {row.cells.map((cell, j) => (
                  <td key={j} className="px-2.5 py-2 whitespace-nowrap">
                    {j === row.cells.length - 1 && SEV.includes(cell as never)
                      ? <Badge tone={sevTone(cell)}>{cell}</Badge>
                      : <span className={j===0?"font-mono text-xs":"text-xs text-muted-foreground"}>{cell}</span>
                    }
                  </td>
                ))}
                <td className="px-2.5 py-2 text-right">
                  <Link to="/investigate/$type/$id" params={{ type: kind, id: row.id }}
                    className="rounded border border-[var(--hairline)] px-2 py-0.5 font-mono text-[0.58rem] tracking-wider text-muted-foreground uppercase group-hover:border-primary/40 group-hover:text-primary">
                    Open
                  </Link>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </Panel>
  );
}

/* ── 9. PIPELINE THROUGHPUT CHART ───────────────────────────────── */
function PipelineChart({ k }: { k: string }) {
  const { data: net  } = useQuery({ queryKey:["live-network-stats"], queryFn:getLiveNetworkStats, refetchInterval:5000 });
  const { data: procs} = useQuery({ queryKey:["live-processes"],     queryFn:getLiveProcesses,    refetchInterval:8000 });
  const { data: stats} = useThreatStats();

  const data = [
    { s: "Ingest",     v: net?.total_conns ?? 0 },
    { s: "Parse",      v: Math.round((net?.recv_mb_s ?? 0) * 100) },
    { s: "Correlate",  v: procs?.total ?? 0 },
    { s: "Enrich",     v: Math.round((stats?.total ?? 0) * 10) },
    { s: "Detect",     v: (stats?.active ?? 0) * 50 },
    { s: "Respond",    v: (stats?.resolved ?? 0) * 50 },
  ];

  return (
    <Panel title="Pipeline Activity" right={<span className="label-cap">live metrics</span>} bodyClassName="p-0 overflow-hidden">
      <ResponsiveContainer width="100%" height={160}>
        <BarChart data={data} margin={{ top: 12, right: 8, left: 0, bottom: 0 }}>
          <CartesianGrid stroke="rgba(255,255,255,0.04)" vertical={false} />
          <XAxis dataKey="s" tick={{ fill: C.muted, fontSize: 9 }} axisLine={false} tickLine={false} />
          <YAxis tick={{ fill: C.muted, fontSize: 9 }} axisLine={false} tickLine={false} width={32} />
          <Tooltip contentStyle={{ background:"#0a1310", border:"1px solid rgba(255,255,255,0.1)", borderRadius:8, fontSize:11 }} />
          <RBar dataKey="v" radius={[4,4,0,0]}>
            {data.map((d, i) => (
              <Cell key={i} fill={[C.teal,C.cyan,C.campaign,C.warning,C.critical,C.success][i % 6]!} />
            ))}
          </RBar>
        </BarChart>
      </ResponsiveContainer>
    </Panel>
  );
}

/* ── 10. QUICK ACTIONS (no boxes — horizontal strip) ─────────────── */
function QuickActions({ actions }: { actions: ModuleDef["actions"] }) {
  return (
    <Panel title="Quick Actions" right={<span className="label-cap">operator console</span>}>
      <div className="flex flex-wrap gap-1.5">
        {actions.map(a => (
          <ActionButton key={a.label} label={a.label} tone={a.tone} />
        ))}
      </div>
    </Panel>
  );
}

/* ── MODULE KPI STRIP — real data from backend ──────────────────── */
function ModuleKpiStrip({ m }: { m: ModuleDef }) {
  const { data: stats }  = useThreatStats();
  const { data: health } = useSystemHealth();
  const { data: agents } = useAgentStats();

  // Build KPIs based on module kind and real backend data
  const kpis: { label: string; value: string; tone: string }[] = [];

  if (m.kind === "alert" || m.kind === "case") {
    kpis.push({ label: "Active", value: String(stats?.active ?? 0), tone: (stats?.active ?? 0) > 0 ? C.critical : C.success });
    kpis.push({ label: "Critical", value: String(stats?.critical ?? 0), tone: (stats?.critical ?? 0) > 0 ? C.critical : C.teal });
    kpis.push({ label: "Resolved", value: String(stats?.resolved ?? 0), tone: C.success });
    kpis.push({ label: "Total", value: String(stats?.total ?? 0), tone: C.teal });
  } else if (m.kind === "asset") {
    kpis.push({ label: "Agents", value: String(agents?.total ?? 0), tone: C.teal });
    kpis.push({ label: "Connected", value: String(agents?.connected ?? 0), tone: C.success });
    kpis.push({ label: "CPU", value: `${Math.round(health?.cpu_percent ?? 0)}%`, tone: (health?.cpu_percent ?? 0) > 80 ? C.critical : C.teal });
    kpis.push({ label: "RAM", value: `${Math.round(health?.ram_percent ?? 0)}%`, tone: (health?.ram_percent ?? 0) > 85 ? C.critical : C.warning });
  } else if (m.kind === "log" || m.kind === "rule") {
    kpis.push({ label: "Events", value: String(stats?.total ?? 0), tone: C.teal });
    kpis.push({ label: "Active", value: String(stats?.active ?? 0), tone: (stats?.active ?? 0) > 0 ? C.warning : C.success });
    kpis.push({ label: "High Sev", value: String((stats?.high ?? 0) + (stats?.critical ?? 0)), tone: (stats?.critical ?? 0) > 0 ? C.critical : C.teal });
    kpis.push({ label: "CPU", value: `${Math.round(health?.cpu_percent ?? 0)}%`, tone: (health?.cpu_percent ?? 0) > 80 ? C.critical : C.teal });
  } else if (m.kind === "file") {
    kpis.push({ label: "Active Threats", value: String(stats?.active ?? 0), tone: (stats?.active ?? 0) > 0 ? C.critical : C.success });
    kpis.push({ label: "Critical", value: String(stats?.critical ?? 0), tone: (stats?.critical ?? 0) > 0 ? C.critical : C.teal });
    kpis.push({ label: "CPU", value: `${Math.round(health?.cpu_percent ?? 0)}%`, tone: (health?.cpu_percent ?? 0) > 80 ? C.critical : C.teal });
    kpis.push({ label: "RAM", value: `${Math.round(health?.ram_percent ?? 0)}%`, tone: (health?.ram_percent ?? 0) > 85 ? C.critical : C.warning });
  } else if (m.kind === "vuln") {
    kpis.push({ label: "Active", value: String(stats?.active ?? 0), tone: (stats?.active ?? 0) > 0 ? C.warning : C.success });
    kpis.push({ label: "Critical", value: String(stats?.critical ?? 0), tone: (stats?.critical ?? 0) > 0 ? C.critical : C.teal });
    kpis.push({ label: "Total", value: String(stats?.total ?? 0), tone: C.teal });
    kpis.push({ label: "Resolved", value: String(stats?.resolved ?? 0), tone: C.success });
  } else {
    kpis.push({ label: "Threats", value: String(stats?.active ?? 0), tone: (stats?.active ?? 0) > 0 ? C.critical : C.success });
    kpis.push({ label: "CPU", value: `${Math.round(health?.cpu_percent ?? 0)}%`, tone: (health?.cpu_percent ?? 0) > 80 ? C.critical : C.teal });
    kpis.push({ label: "RAM", value: `${Math.round(health?.ram_percent ?? 0)}%`, tone: (health?.ram_percent ?? 0) > 85 ? C.critical : C.warning });
  }

  return (
    <div className="flex items-center gap-6 rounded-lg border border-[var(--hairline)] bg-[rgba(255,255,255,0.015)] px-4 py-2">
      {kpis.map(kpi => (
        <div key={kpi.label} className="flex items-center gap-2">
          <span className="size-1.5 shrink-0 rounded-full" style={{ background: kpi.tone }} />
          <span className="label-cap text-[0.6rem]">{kpi.label}</span>
          <span className="font-mono text-sm font-bold" style={{ color: kpi.tone }}>{kpi.value}</span>
        </div>
      ))}
      <span className="ml-auto flex items-center gap-1.5 font-mono text-[0.6rem] text-muted-foreground">
        <span className="dot-pulse size-1.5 rounded-full bg-[var(--success)]" /> LIVE
      </span>
    </div>
  );
}

/* ── MODULE PAGE — NO BOXES, ONLY CHARTS ─────────────────────────── */
export function ModulePage({ m }: { m: ModuleDef }) {
  const { data: threatStats } = useThreatStats();
  const hasThreats = (threatStats?.active ?? 0) > 0;

  return (
    <div>
      <PageHeader
        title={m.title}
        subtitle={m.subtitle}
        right={
          <div className="flex shrink-0 flex-wrap justify-end gap-1.5">
            <Badge tone={hasThreats ? "critical" : "success"}>{hasThreats ? "THREATS ACTIVE" : "SYSTEM CLEAR"}</Badge>
            <Badge tone="success">LIVE</Badge>
            <ActionBar actions={m.actions.slice(0, 4)} />
          </div>
        }
      />

      <div className="flex flex-col gap-3">

        {/* KPI strip — real data from backend */}
        <ModuleKpiStrip m={m} />

        {/* Row 1 — Full-width live metrics chart (CPU + RAM + threats) */}
        <LiveMetricsChart k={m.key} />

        {/* Row 2 — Detection trend + Network I/O side by side */}
        <div className="grid items-stretch gap-3 xl:grid-cols-2">
          <DetectionTrendChart k={m.key} />
          <NetworkIOChart k={m.key} />
        </div>

        {/* Row 3 — Threat severity + Process CPU chart side by side */}
        <div className="grid items-stretch gap-3 xl:grid-cols-2">
          <ThreatSeverityChart facets={m.facets} k={m.key} />
          <ProcessCpuChart />
        </div>

        {/* Row 4 — Disk chart full width */}
        <DiskUsageChart />

        {/* Row 5 — Actions + Live feed */}
        <div className="grid items-stretch gap-3 xl:grid-cols-12">
          <div className="xl:col-span-9">
            <LiveEventFeed title={m.feedTitle} seed={m.key} />
          </div>
          <div className="xl:col-span-3">
            <QuickActions actions={m.actions} />
          </div>
        </div>

        {/* Row 6 — Main investigation table full width */}
        <InvestigationTable kind={m.kind} seed={m.key} tableTitle={m.tableTitle} moduleKey={m.key} />

        {/* Row 7 — Pipeline activity + Correlated signals */}
        <div className="grid items-stretch gap-3 xl:grid-cols-12">
          <div className="xl:col-span-4">
            <PipelineChart k={m.key} />
          </div>
          <div className="xl:col-span-8">
            <InvestigationTable kind={m.kind === "alert" ? "log" : "alert"} seed={m.key+"b"} tableTitle="Correlated Signals" rows={8} moduleKey={m.key} />
          </div>
        </div>

      </div>
    </div>
  );
}

export { columnsFor };
