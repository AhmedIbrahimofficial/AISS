import { useEffect, useState } from "react";
import {
  Bar as RBar,
  BarChart,
  Cell,
  Pie,
  PieChart,
  PolarAngleAxis,
  RadialBar,
  RadialBarChart,
  ResponsiveContainer,
  XAxis,
  YAxis,
} from "recharts";
import { Link } from "@tanstack/react-router";
import { Panel } from "./Panel";
import { Badge, Bar } from "./ui";
import { C, randomIp } from "./data";
import { useThreatStats } from "@/hooks/useAISS";

/* ---------------- Severity distribution donut ---------------- */

export function SeverityDonut() {
  const { data: stats } = useThreatStats();

  const SEV = [
    { name: "Critical", value: stats?.critical ?? 0, color: C.critical },
    { name: "High",     value: stats?.high     ?? 0, color: C.warning },
    { name: "Medium",   value: stats?.medium   ?? 0, color: C.campaign },
    { name: "Low",      value: stats?.low      ?? 0, color: C.teal },
  ];
  const total = SEV.reduce((a, b) => a + b.value, 0);

  return (
    <Panel title="Alert Severity Mix" right={<span className="label-cap">LIVE</span>}>
      <div className="flex flex-1 items-center gap-4">
        <div className="relative size-[118px] shrink-0">
          <ResponsiveContainer width="100%" height="100%">
            <PieChart>
              <Pie data={SEV} dataKey="value" innerRadius={38} outerRadius={56}
                paddingAngle={2} stroke="none" isAnimationActive>
                {SEV.map((s) => <Cell key={s.name} fill={s.color} />)}
              </Pie>
            </PieChart>
          </ResponsiveContainer>
          <div className="pointer-events-none absolute inset-0 grid place-items-center">
            <div className="text-center">
              <p className="font-mono text-xl leading-none font-bold">{total}</p>
              <p className="label-cap mt-1 text-[0.55rem]">alerts</p>
            </div>
          </div>
        </div>
        <ul className="min-w-0 flex-1 space-y-2">
          {SEV.map((s) => (
            <li key={s.name} className="grid grid-cols-[auto_minmax(0,1fr)_auto] items-center gap-2">
              <span className="size-2 shrink-0 rounded-full" style={{ background: s.color }} />
              <span className="truncate text-xs text-muted-foreground">{s.name}</span>
              <span className="font-mono text-xs">{s.value}</span>
            </li>
          ))}
        </ul>
      </div>
    </Panel>
  );
}

/* ---------------- MITRE ATT&CK coverage ---------------- */

const TACTICS = [
  { name: "Initial Access", v: 92 },
  { name: "Execution", v: 88 },
  { name: "Persistence", v: 74 },
  { name: "Priv. Escalation", v: 81 },
  { name: "Defense Evasion", v: 69 },
  { name: "Credential Access", v: 90 },
  { name: "Lateral Movement", v: 77 },
  { name: "Exfiltration", v: 85 },
];

export function MitreCoverage() {
  return (
    <Panel
      title="MITRE ATT&CK Coverage"
      right={<Badge tone="info">82% mapped</Badge>}
      bodyClassName="flex flex-col justify-between gap-2.5"
    >
      {TACTICS.map((t) => (
        <Link
          key={t.name}
          to="/mitre/$tactic"
          params={{ tactic: t.name.toLowerCase().replace(/[^a-z]+/g, "-") }}
          className="grid grid-cols-[minmax(0,1fr)_auto] items-center gap-3 rounded px-1 py-0.5 hover:bg-white/5"
        >
          <div className="min-w-0">
            <p className="mb-1 truncate text-xs text-muted-foreground">{t.name}</p>
            <Bar
              value={t.v}
              tone={t.v > 85 ? "var(--success)" : t.v > 72 ? "var(--teal)" : "var(--warning)"}
            />
          </div>
          <span className="font-mono text-xs tabular-nums">{t.v}%</span>
        </Link>
      ))}
    </Panel>
  );
}

/* ---------------- Top attacker sources ---------------- */

const COUNTRIES = [
  ["Russia", "RU", 412],
  ["China", "CN", 388],
  ["Brazil", "BR", 221],
  ["Netherlands", "NL", 164],
  ["Vietnam", "VN", 132],
  ["United States", "US", 96],
] as const;

export function TopAttackers() {
  const max = COUNTRIES[0][2];
  return (
    <Panel title="Top Attack Origins" right={<span className="label-cap">blocked</span>}>
      <ul className="flex flex-1 flex-col justify-between gap-2.5">
        {COUNTRIES.map(([name, code, n]) => (
          <li key={code}>
            <Link to="/intel/country/$code" params={{ code }} className="grid grid-cols-[2.2rem_minmax(0,1fr)_3rem] items-center gap-3 rounded px-1 py-0.5 hover:bg-white/5">
            <span className="rounded border border-[var(--hairline)] bg-white/4 py-0.5 text-center font-mono text-[0.6rem]">
              {code}
            </span>
            <div className="min-w-0">
              <p className="mb-1 truncate text-xs">{name}</p>
              <Bar value={(n / max) * 100} tone="var(--critical)" />
            </div>
            <span className="text-right font-mono text-xs tabular-nums">{n}</span>
            </Link>
          </li>
        ))}
      </ul>
    </Panel>
  );
}

/* ---------------- SLA / SOC efficiency radial ---------------- */

const SLA = [
  { name: "Triage SLA", value: 96, fill: C.success },
  { name: "Containment", value: 89, fill: C.teal },
  { name: "Closure", value: 78, fill: C.campaign },
];

export function SlaGauges() {
  return (
    <Panel title="SOC SLA Attainment" right={<span className="label-cap">30D</span>}>
      <div className="grid flex-1 grid-cols-3 items-center gap-2">
        {SLA.map((s) => (
          <div key={s.name} className="text-center">
            <div className="mx-auto h-[86px] w-full">
              <ResponsiveContainer width="100%" height="100%">
                <RadialBarChart
                  innerRadius="66%"
                  outerRadius="100%"
                  data={[s]}
                  startAngle={90}
                  endAngle={-270}
                >
                  <PolarAngleAxis type="number" domain={[0, 100]} tick={false} />
                  <RadialBar background={{ fill: "rgba(255,255,255,0.07)" }} dataKey="value" cornerRadius={8} />
                </RadialBarChart>
              </ResponsiveContainer>
            </div>
            <p className="-mt-1 font-mono text-sm font-semibold" style={{ color: s.fill }}>
              {s.value}%
            </p>
            <p className="label-cap mt-0.5 truncate text-[0.55rem]">{s.name}</p>
          </div>
        ))}
      </div>
    </Panel>
  );
}

/* ---------------- Detections by vector (bar chart) ---------------- */

const VECTORS = [
  { k: "Email", v: 148 },
  { k: "Web", v: 122 },
  { k: "Endpoint", v: 97 },
  { k: "Identity", v: 84 },
  { k: "Cloud", v: 61 },
  { k: "OT/IoT", v: 28 },
];

export function VectorBars() {
  return (
    <Panel title="Detections by Vector" right={<span className="label-cap">7D</span>}>
      <ResponsiveContainer width="100%" height={190}>
        <BarChart data={VECTORS} margin={{ top: 4, right: 4, left: -22, bottom: 0 }}>
          <XAxis
            dataKey="k"
            tick={{ fill: C.muted, fontSize: 10 }}
            axisLine={false}
            tickLine={false}
          />
          <YAxis tick={{ fill: C.muted, fontSize: 10 }} axisLine={false} tickLine={false} />
          <RBar dataKey="v" radius={[4, 4, 0, 0]} fill={C.teal} />
        </BarChart>
      </ResponsiveContainer>
      <div className="mt-2 flex flex-wrap gap-1">
        {VECTORS.map((v) => (
          <Link
            key={v.k}
            to="/vector/$name"
            params={{ name: v.k.toLowerCase().replace(/[^a-z]+/g, "-") }}
            className="rounded border border-[var(--hairline)] px-1.5 py-0.5 font-mono text-[0.55rem] text-muted-foreground hover:border-primary/40 hover:text-primary"
          >
            {v.k}
          </Link>
        ))}
      </div>
    </Panel>
  );
}

/* ---------------- Threat intel feeds ---------------- */

const FEEDS = [
  ["AlienVault OTX", "synced", "2m"],
  ["MISP Community", "synced", "5m"],
  ["Abuse.ch URLhaus", "synced", "1m"],
  ["CISA KEV", "synced", "18m"],
  ["Internal Honeypots", "streaming", "live"],
  ["Vendor Sigma Rules", "degraded", "46m"],
] as const;

export function IntelFeeds() {
  return (
    <Panel title="Threat Intel Feeds" right={<Badge tone="success">5 / 6 healthy</Badge>}>
      <ul className="flex flex-1 flex-col justify-between divide-y divide-[var(--hairline)]">
        {FEEDS.map(([name, state, age]) => (
          <li key={name} className="grid grid-cols-[minmax(0,1fr)_auto_auto] items-center gap-3 py-2 first:pt-0 last:pb-0">
            <span className="truncate text-xs">{name}</span>
            <Badge tone={state === "degraded" ? "warning" : state === "streaming" ? "info" : "success"}>
              {state}
            </Badge>
            <span className="w-10 text-right font-mono text-[0.65rem] text-muted-foreground">{age}</span>
          </li>
        ))}
      </ul>
    </Panel>
  );
}

/* ---------------- Live blocklist ticker ---------------- */

import { getNetworkConnections } from "@/lib/api";
import { useQuery } from "@tanstack/react-query";

export function BlocklistTicker() {
  const { data } = useQuery({
    queryKey: ["network-connections"],
    queryFn: getNetworkConnections,
    refetchInterval: 5000,
  });

  const rows = data?.connections?.slice(0, 10) ?? [];

  return (
    <Panel
      title="Network Connections — Live"
      right={<span className="dot-pulse size-2 bg-[var(--critical)] text-[var(--critical)]" />}
      bodyClassName="max-h-[248px] overflow-y-auto pr-1"
    >
      {rows.length === 0 && (
        <p className="text-xs text-muted-foreground py-4 text-center">No active connections</p>
      )}
      <ul className="space-y-1">
        {rows.map((r, i) => (
          <li key={i} className="animate-fade-in rounded-md hover:bg-white/4">
            <div className="grid grid-cols-[minmax(0,1fr)_auto_auto] items-center gap-3 px-2 py-1.5">
              <span className="truncate font-mono text-xs">{r.remote_address || r.local_address}</span>
              <span className="text-[0.65rem] text-muted-foreground">{r.status}</span>
              <span className="font-mono text-[0.6rem] text-muted-foreground">
                {r.pid ? `PID ${r.pid}` : "--"}
              </span>
            </div>
          </li>
        ))}
      </ul>
    </Panel>
  );
}

/* ---------------- On-shift analysts ---------------- */

const SHIFT = [
  ["A. Rahman", "Incident Lead", "success"],
  ["M. Chen", "Tier 2", "success"],
  ["L. Novak", "Triage", "success"],
  ["K. Adeyemi", "Threat Intel", "warning"],
  ["aiss-automation", "Autonomous", "info"],
] as const;

export function ShiftRoster() {
  return (
    <Panel title="On Shift" right={<span className="label-cap">Day · UTC</span>}>
      <ul className="flex flex-1 flex-col justify-between gap-2">
        {SHIFT.map(([name, role, tone]) => (
          <li key={name} className="grid grid-cols-[auto_minmax(0,1fr)_auto] items-center gap-3">
            <span className="grid size-7 shrink-0 place-items-center rounded-full border border-[var(--hairline)] bg-white/4 font-mono text-[0.6rem]">
              {name.slice(0, 2).toUpperCase()}
            </span>
            <div className="min-w-0">
              <p className="truncate text-xs">{name}</p>
              <p className="truncate text-[0.65rem] text-muted-foreground">{role}</p>
            </div>
            <Badge tone={tone}>{tone === "warning" ? "away" : "online"}</Badge>
          </li>
        ))}
      </ul>
    </Panel>
  );
}

/* ---------------- Playbook runs ---------------- */

const PLAYBOOKS = [
  ["PB-014 Ransomware Containment", 100, "success"],
  ["PB-007 Credential Reset", 72, "info"],
  ["PB-021 Phish Sweep", 48, "warning"],
  ["PB-002 Host Isolation", 100, "success"],
] as const;

export function PlaybookRuns() {
  return (
    <Panel title="Automated Playbooks" right={<Badge tone="info">4 running</Badge>}>
      <ul className="flex flex-1 flex-col justify-between gap-3">
        {PLAYBOOKS.map(([name, pct, tone]) => (
          <li key={name}>
            <div className="mb-1 grid grid-cols-[minmax(0,1fr)_auto] items-center gap-2">
              <span className="truncate text-xs">{name}</span>
              <span className="font-mono text-[0.65rem] tabular-nums text-muted-foreground">{pct}%</span>
            </div>
            <Bar
              value={pct}
              tone={tone === "success" ? "var(--success)" : tone === "info" ? "var(--cyan)" : "var(--warning)"}
            />
          </li>
        ))}
      </ul>
    </Panel>
  );
}

/* ---------------- Vulnerability posture ---------------- */

const VULNS = [
  ["Critical", 4, C.critical],
  ["High", 18, C.warning],
  ["Medium", 63, C.campaign],
  ["Low", 129, C.teal],
] as const;

export function VulnPosture() {
  return (
    <Panel title="Vulnerability Posture" right={<span className="label-cap">214 open</span>}>
      <div className="grid flex-1 grid-cols-2 gap-2">
        {VULNS.map(([label, n, color]) => (
          <div
            key={label}
            className="rounded-lg border p-3"
            style={{
              borderColor: `color-mix(in oklab, ${color} 25%, transparent)`,
              background: `color-mix(in oklab, ${color} 7%, transparent)`,
            }}
          >
            <p className="label-cap truncate">{label}</p>
            <p className="mt-1 font-mono text-xl font-bold" style={{ color }}>
              {n}
            </p>
          </div>
        ))}
      </div>
      <p className="mt-3 text-[0.65rem] text-muted-foreground">
        Mean time to patch critical: <span className="font-mono text-foreground">2.1 days</span>
      </p>
    </Panel>
  );
}

/* ---------------- Compliance snapshot ---------------- */

const FRAMEWORKS = [
  ["ISO 27001", 94],
  ["SOC 2 Type II", 91],
  ["NIST CSF 2.0", 88],
  ["GDPR", 97],
  ["PCI DSS 4.0", 83],
] as const;

export function ComplianceSnapshot() {
  return (
    <Panel title="Compliance Readiness" right={<Badge tone="success">audit ready</Badge>}>
      <ul className="flex flex-1 flex-col justify-between gap-2.5">
        {FRAMEWORKS.map(([name, v]) => (
          <li key={name} className="grid grid-cols-[minmax(0,1fr)_auto] items-center gap-3">
            <div className="min-w-0">
              <p className="mb-1 truncate text-xs text-muted-foreground">{name}</p>
              <Bar value={v} tone={v >= 90 ? "var(--success)" : "var(--warning)"} />
            </div>
            <span className="font-mono text-xs tabular-nums">{v}%</span>
          </li>
        ))}
      </ul>
    </Panel>
  );
}
