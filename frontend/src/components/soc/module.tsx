import { Link } from "@tanstack/react-router";
import { useEffect, useState } from "react";
import {
  Area,
  AreaChart,
  Bar as RBar,
  BarChart,
  CartesianGrid,
  Cell,
  Pie,
  PieChart,
  PolarAngleAxis,
  RadialBar,
  RadialBarChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import { PageHeader } from "./AppShell";
import { Panel } from "./Panel";
import { Badge, Bar, Metric } from "./ui";
import { ActionBar, ActionButton, ChartToolbar } from "./actions";
import { C } from "./data";
import { CVES, MALWARE, TECHNIQUES, hash, host, int, ip, pick, seeded, title } from "./sim";

export type RowKind = "alert" | "asset" | "log" | "case" | "vuln" | "file" | "rule";

export type ModuleDef = {
  key: string;
  title: string;
  subtitle: string;
  kind: RowKind;
  kpis: [string, string, "default" | "critical" | "warning" | "success" | "info", string][];
  actions: { label: string; tone?: ("default" | "critical" | "warning" | "success" | "info") | undefined }[];
  tableTitle: string;
  feedTitle: string;
  facets: [string, number][];
};

const SEV = ["CRITICAL", "HIGH", "MEDIUM", "LOW"] as const;
const sevTone = (s: string) =>
  s === "CRITICAL" ? "critical" : s === "HIGH" ? "warning" : s === "MEDIUM" ? "info" : "success";

/* ------------------------------ synthesized rows ------------------------------ */

type Row = { id: string; cells: string[]; sev: string };

function columnsFor(kind: RowKind): string[] {
  switch (kind) {
    case "asset":
      return ["Host", "OS", "Owner", "Risk", "Agent", "Last seen", "State"];
    case "log":
      return ["Timestamp", "Source", "Event ID", "Host", "Message", "Severity", "Action"];
    case "case":
      return ["Case", "Title", "Assignee", "Stage", "SLA", "Age", "Severity"];
    case "vuln":
      return ["CVE", "Asset", "CVSS", "Exploit", "Vector", "Age", "Severity"];
    case "file":
      return ["File", "SHA256", "Family", "Verdict", "Host", "Detonated", "Severity"];
    case "rule":
      return ["Rule", "Type", "Hits 24h", "Confidence", "Coverage", "Updated", "State"];
    default:
      return ["Alert", "Technique", "Source", "Asset", "Detected", "Confidence", "Severity"];
  }
}

function rowsFor(kind: RowKind, key: string, n = 12): Row[] {
  const r = seeded(key + kind);
  return Array.from({ length: n }, (_, i) => {
    const sev = pick(r, SEV);
    const t = pick(r, TECHNIQUES);
    const id = `${key.slice(0, 3).toUpperCase()}-${1000 + i * 7 + int(r, 1, 6)}`;
    const time = `${String(int(r, 0, 23)).padStart(2, "0")}:${String(int(r, 0, 59)).padStart(2, "0")}:${String(int(r, 0, 59)).padStart(2, "0")}`;
    const cells =
      kind === "asset"
        ? [host(r), pick(r, ["Windows 11", "Ubuntu 24.04", "macOS 15", "RHEL 9"]), pick(r, ["Finance", "R&D", "Ops", "Sales"]), String(int(r, 12, 98)), "v8.42", `${int(r, 1, 59)}m ago`, pick(r, ["Healthy", "Isolated", "Degraded"])]
        : kind === "log"
          ? [time, pick(r, ["Sysmon", "Firewall", "AzureAD", "CloudTrail", "Zeek"]), String(int(r, 1000, 5999)), host(r), pick(r, ["Process created", "Auth failure", "Outbound deny", "Policy change", "DNS anomaly"]), sev, pick(r, ["Logged", "Blocked", "Alerted"])]
          : kind === "case"
            ? [id, pick(r, ["Ransomware staging", "Credential theft", "Data exfiltration", "Phishing wave", "C2 beacon"]), pick(r, ["A. Rahman", "M. Chen", "L. Novak", "aiss-auto"]), pick(r, ["Triage", "Investigating", "Containment", "Eradication"]), pick(r, ["On track", "At risk", "Breached"]), `${int(r, 1, 40)}h`, sev]
            : kind === "vuln"
              ? [pick(r, CVES), host(r), (4 + r() * 6).toFixed(1), pick(r, ["Weaponized", "PoC", "None"]), pick(r, ["Network", "Local", "Adjacent"]), `${int(r, 1, 90)}d`, sev]
              : kind === "file"
                ? [`${pick(r, ["invoice", "update", "svchost", "payload"])}_${int(r, 10, 99)}.exe`, hash(r, 16) + "…", pick(r, MALWARE), pick(r, ["Malicious", "Suspicious", "Clean"]), host(r), `${int(r, 1, 50)}m ago`, sev]
                : kind === "rule"
                  ? [`${pick(r, ["SIGMA", "YARA", "ML", "CORR"])}-${int(r, 100, 999)}`, pick(r, ["Sigma", "YARA", "Behavioral", "Correlation"]), String(int(r, 0, 940)), `${int(r, 62, 99)}%`, `${int(r, 40, 100)}%`, `${int(r, 1, 30)}d ago`, pick(r, ["Enabled", "Tuning", "Disabled"])]
                  : [pick(r, ["Suspicious PowerShell", "Beacon callback", "Mass file encryption", "Impossible travel", "Kerberoasting", "Credential dump"]), `${t[0]} ${t[1]}`, ip(r), host(r), `${int(r, 1, 59)}m ago`, `${int(r, 70, 99)}%`, sev];
    return { id, cells, sev };
  });
}

/* ------------------------------ dense sub-widgets ------------------------------ */

function TrendPanel({ k, drillTo }: { k: string; drillTo: string }) {
  const r = seeded(k + "trend");
  const data = Array.from({ length: 24 }, (_, i) => ({
    t: `${String(i).padStart(2, "0")}:00`,
    detected: int(r, 40, 220),
    blocked: int(r, 20, 180),
    anomaly: int(r, 5, 70),
  }));
  return (
    <Panel
      title="Detection Trend"
      right={<ChartToolbar drillTo={drillTo} />}
      bodyClassName="min-h-[236px]"
    >
      <ResponsiveContainer width="100%" height={220}>
        <AreaChart data={data} margin={{ top: 6, right: 6, left: -22, bottom: 0 }}>
          <defs>
            <linearGradient id={`g1${k}`} x1="0" y1="0" x2="0" y2="1">
              <stop offset="0%" stopColor={C.teal} stopOpacity={0.45} />
              <stop offset="100%" stopColor={C.teal} stopOpacity={0} />
            </linearGradient>
            <linearGradient id={`g2${k}`} x1="0" y1="0" x2="0" y2="1">
              <stop offset="0%" stopColor={C.critical} stopOpacity={0.4} />
              <stop offset="100%" stopColor={C.critical} stopOpacity={0} />
            </linearGradient>
          </defs>
          <CartesianGrid stroke="rgba(255,255,255,0.05)" vertical={false} />
          <XAxis dataKey="t" tick={{ fill: C.muted, fontSize: 10 }} axisLine={false} tickLine={false} interval={3} />
          <YAxis tick={{ fill: C.muted, fontSize: 10 }} axisLine={false} tickLine={false} />
          <Tooltip
            contentStyle={{
              background: "#0b1512",
              border: "1px solid rgba(255,255,255,0.1)",
              borderRadius: 8,
              fontSize: 12,
            }}
          />
          <Area type="monotone" dataKey="detected" stroke={C.teal} fill={`url(#g1${k})`} strokeWidth={1.6} />
          <Area type="monotone" dataKey="blocked" stroke={C.critical} fill={`url(#g2${k})`} strokeWidth={1.6} />
          <Area type="monotone" dataKey="anomaly" stroke={C.campaign} fill="transparent" strokeWidth={1.4} strokeDasharray="3 3" />
        </AreaChart>
      </ResponsiveContainer>
    </Panel>
  );
}

function FacetDonut({ facets, k }: { facets: [string, number][]; k: string }) {
  const colors = [C.critical, C.warning, C.campaign, C.teal, C.success, C.cyan];
  const data = facets.map(([name, value], i) => ({ name, value, color: colors[i % colors.length]! }));
  const total = data.reduce((a, b) => a + b.value, 0);
  return (
    <Panel title="Distribution" right={<span className="label-cap">click to drill</span>}>
      <div className="flex flex-1 items-center gap-3">
        <div className="relative size-[116px] shrink-0">
          <ResponsiveContainer width="100%" height="100%">
            <PieChart>
              <Pie data={data} dataKey="value" innerRadius={36} outerRadius={55} paddingAngle={2} stroke="none">
                {data.map((d) => (
                  <Cell key={d.name} fill={d.color} />
                ))}
              </Pie>
            </PieChart>
          </ResponsiveContainer>
          <div className="pointer-events-none absolute inset-0 grid place-items-center text-center">
            <div>
              <p className="font-mono text-lg leading-none font-bold">{total}</p>
              <p className="label-cap mt-1 text-[0.5rem]">total</p>
            </div>
          </div>
        </div>
        <ul className="min-w-0 flex-1 space-y-1.5">
          {data.map((d) => (
            <li key={d.name}>
              <Link
                to="/investigate/$type/$id"
                params={{ type: k, id: d.name.toLowerCase().replace(/\s+/g, "-") }}
                className="grid grid-cols-[auto_minmax(0,1fr)_auto] items-center gap-2 rounded px-1 py-0.5 hover:bg-white/5"
              >
                <span className="size-2 shrink-0 rounded-full" style={{ background: d.color }} />
                <span className="truncate text-xs text-muted-foreground">{d.name}</span>
                <span className="font-mono text-xs">{d.value}</span>
              </Link>
            </li>
          ))}
        </ul>
      </div>
    </Panel>
  );
}

function RiskGauges({ k }: { k: string }) {
  const r = seeded(k + "risk");
  const gauges = [
    { name: "Exposure", value: int(r, 40, 95), fill: C.warning },
    { name: "Coverage", value: int(r, 60, 99), fill: C.teal },
    { name: "Confidence", value: int(r, 70, 99), fill: C.success },
  ];
  return (
    <Panel title="Risk Indicators" right={<span className="dot-pulse size-2 bg-[var(--warning)] text-[var(--warning)]" />}>
      <div className="grid flex-1 grid-cols-3 items-center gap-1 xl:grid-cols-1">
        {gauges.map((g) => (
          <div key={g.name} className="text-center xl:grid xl:grid-cols-[auto_minmax(0,1fr)] xl:items-center xl:gap-2 xl:text-left">
            <div className="mx-auto h-[62px] w-[62px]">
              <ResponsiveContainer width="100%" height="100%">
                <RadialBarChart innerRadius="64%" outerRadius="100%" data={[g]} startAngle={90} endAngle={-270}>
                  <PolarAngleAxis type="number" domain={[0, 100]} tick={false} />
                  <RadialBar background={{ fill: "rgba(255,255,255,0.07)" }} dataKey="value" cornerRadius={6} />
                </RadialBarChart>
              </ResponsiveContainer>
            </div>
            <div>
              <p className="font-mono text-xs font-semibold" style={{ color: g.fill }}>
                {g.value}%
              </p>
              <p className="label-cap truncate text-[0.5rem]">{g.name}</p>
            </div>
          </div>
        ))}
      </div>
    </Panel>
  );
}

export function LiveEventFeed({ title: t, seed }: { title: string; seed: string }) {
  const [rows, setRows] = useState<{ id: number; msg: string; src: string; sev: string; t: string }[]>([]);
  useEffect(() => {
    const r = seeded(seed + "feed");
    let n = 0;
    const MSG = [
      "Process injection blocked",
      "Beacon callback detected",
      "Credential dump attempt",
      "Outbound deny — TI match",
      "Anomalous login geo",
      "Sandbox verdict: malicious",
      "Rule promoted to blocking",
      "Host auto-isolated",
    ];
    const make = () => ({
      id: n++,
      msg: MSG[Math.floor(Math.random() * MSG.length)]!,
      src: Math.random() > 0.5 ? ip(r) : host(r),
      sev: SEV[Math.floor(Math.random() * SEV.length)]!,
      t: new Date().toTimeString().slice(0, 8),
    });
    setRows(Array.from({ length: 10 }, make));
    const iv = setInterval(() => setRows((p) => [make(), ...p].slice(0, 18)), 2600);
    return () => clearInterval(iv);
  }, [seed]);
  return (
    <Panel
      title={t}
      right={<span className="dot-pulse size-2 bg-[var(--critical)] text-[var(--critical)]" />}
      bodyClassName="max-h-[300px] overflow-y-auto pr-1"
    >
      <ul className="space-y-1">
        {rows.length === 0 &&
          Array.from({ length: 6 }, (_, i) => (
            <li key={i} className="h-8 animate-pulse rounded bg-white/5" />
          ))}
        {rows.map((e) => (
          <li key={e.id}>
            <Link
              to="/investigate/$type/$id"
              params={{ type: "event", id: String(e.id) + "-" + seed }}
              className="animate-fade-in grid grid-cols-[auto_minmax(0,1fr)_auto_auto] items-center gap-2.5 rounded-md px-2 py-1.5 hover:bg-white/5"
            >
              <span
                className={`size-2 shrink-0 rounded-full ${e.sev === "CRITICAL" ? "dot-pulse" : ""}`}
                style={{ background: `var(--${e.sev === "CRITICAL" ? "critical" : e.sev === "HIGH" ? "warning" : e.sev === "MEDIUM" ? "cyan" : "success"})` }}
              />
              <div className="min-w-0">
                <p className="truncate text-xs">{e.msg}</p>
                <p className="truncate font-mono text-[0.62rem] text-muted-foreground">{e.src}</p>
              </div>
              <Badge tone={sevTone(e.sev)}>{e.sev}</Badge>
              <span className="font-mono text-[0.6rem] text-muted-foreground">{e.t}</span>
            </Link>
          </li>
        ))}
      </ul>
    </Panel>
  );
}

export function InvestigationTable({
  kind,
  seed,
  tableTitle,
  rows: count = 12,
}: {
  kind: RowKind;
  seed: string;
  tableTitle: string;
  rows?: number;
}) {
  const cols = columnsFor(kind);
  const rows = rowsFor(kind, seed, count);
  return (
    <Panel
      title={tableTitle}
      right={
        <div className="flex items-center gap-1.5">
          <Badge tone="info">{rows.length} rows</Badge>
          <ActionButton label="Export CSV" className="px-1.5 py-0.5" />
          <ActionButton label="Export PDF" className="px-1.5 py-0.5" />
        </div>
      }
    >
      <div className="overflow-x-auto">
        <table className="w-full min-w-[720px] text-left text-sm">
          <thead>
            <tr className="border-b border-[var(--hairline)]">
              {cols.map((c) => (
                <th key={c} className="label-cap px-2.5 py-2 font-medium">
                  {c}
                </th>
              ))}
              <th className="label-cap px-2.5 py-2 text-right font-medium">Investigate</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((row) => (
              <tr
                key={row.id}
                className="group border-b border-[var(--hairline)] last:border-0 transition-colors hover:bg-white/4"
              >
                {row.cells.map((cell, j) => (
                  <td key={j} className="px-2.5 py-2 whitespace-nowrap">
                    {j === row.cells.length - 1 && SEV.includes(cell as never) ? (
                      <Badge tone={sevTone(cell)}>{cell}</Badge>
                    ) : (
                      <span className={j === 0 ? "font-mono text-xs" : "text-xs text-muted-foreground"}>
                        {cell}
                      </span>
                    )}
                  </td>
                ))}
                <td className="px-2.5 py-2 text-right">
                  <Link
                    to="/investigate/$type/$id"
                    params={{ type: kind, id: row.id }}
                    className="rounded border border-[var(--hairline)] px-2 py-0.5 font-mono text-[0.58rem] tracking-wider text-muted-foreground uppercase transition-colors group-hover:border-primary/40 group-hover:text-primary"
                  >
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

function TimelinePanel({ k }: { k: string }) {
  const r = seeded(k + "tl");
  const steps = [
    ["Signal ingested", "Sensor telemetry normalised"],
    ["Correlation matched", "3 rules fired across 2 sources"],
    ["AI triage", "Confidence 96% · malicious"],
    ["Containment", "Host isolated · session killed"],
    ["Evidence captured", "Memory + packet capture stored"],
    ["Case opened", "Assigned to Tier 2"],
  ];
  return (
    <Panel title="Response Timeline" right={<Badge tone="success">autonomous</Badge>}>
      <ol className="flex-1 space-y-3">
        {steps.map(([t, d], i) => (
          <li key={t} className="grid grid-cols-[auto_minmax(0,1fr)_auto] items-start gap-3">
            <span className="mt-1 grid size-5 shrink-0 place-items-center rounded-full border border-[var(--hairline)] bg-white/5 font-mono text-[0.55rem]">
              {i + 1}
            </span>
            <div className="min-w-0">
              <p className="truncate text-xs">{t}</p>
              <p className="truncate text-[0.65rem] text-muted-foreground">{d}</p>
            </div>
            <span className="font-mono text-[0.6rem] text-muted-foreground">
              +{int(r, 1, 240)}s
            </span>
          </li>
        ))}
      </ol>
    </Panel>
  );
}

function QuickActions({ actions }: { actions: ModuleDef["actions"] }) {
  return (
    <Panel title="Quick Actions" right={<span className="label-cap">operator</span>}>
      <div className="grid flex-1 grid-cols-2 content-start gap-1.5">
        {actions.map((a) => (
          <ActionButton key={a.label} label={a.label} tone={a.tone} className="justify-center" />
        ))}
      </div>
    </Panel>
  );
}

function TelemetryBars({ k }: { k: string }) {
  const r = seeded(k + "bars");
  const data = ["Ingest", "Parse", "Correlate", "Enrich", "Detect", "Respond"].map((s) => ({
    s,
    v: int(r, 30, 100),
  }));
  return (
    <Panel title="Pipeline Throughput" right={<span className="label-cap">events/s</span>}>
      <ResponsiveContainer width="100%" height={168}>
        <BarChart data={data} margin={{ top: 4, right: 4, left: -24, bottom: 0 }}>
          <XAxis dataKey="s" tick={{ fill: C.muted, fontSize: 9 }} axisLine={false} tickLine={false} />
          <YAxis tick={{ fill: C.muted, fontSize: 9 }} axisLine={false} tickLine={false} />
          <Tooltip cursor={{ fill: "rgba(255,255,255,0.04)" }} contentStyle={{ background: "#0b1512", border: "1px solid rgba(255,255,255,0.1)", borderRadius: 8, fontSize: 12 }} />
          <RBar dataKey="v" radius={[4, 4, 0, 0]} fill={C.teal} />
        </BarChart>
      </ResponsiveContainer>
    </Panel>
  );
}

function WatchList({ k }: { k: string }) {
  const r = seeded(k + "watch");
  const items = Array.from({ length: 6 }, () => ({
    ioc: r() > 0.5 ? ip(r) : hash(r, 12) + "…",
    kind: pick(r, ["IPv4", "SHA256", "Domain", "URL"]),
    score: int(r, 40, 99),
  }));
  return (
    <Panel title="IOC Watchlist" right={<Badge tone="warning">live match</Badge>}>
      <ul className="flex-1 space-y-2">
        {items.map((i) => (
          <li key={i.ioc} className="grid grid-cols-[minmax(0,1fr)_auto_auto] items-center gap-2">
            <span className="truncate font-mono text-[0.68rem]">{i.ioc}</span>
            <Badge>{i.kind}</Badge>
            <span className="w-8 text-right font-mono text-xs" style={{ color: i.score > 80 ? C.critical : C.warning }}>
              {i.score}
            </span>
          </li>
        ))}
      </ul>
    </Panel>
  );
}

function CoverageStrip({ k }: { k: string }) {
  const r = seeded(k + "cov");
  return (
    <Panel title="Module Coverage" right={<span className="label-cap">by tactic</span>}>
      <ul className="flex flex-1 flex-col justify-between gap-2">
        {TECHNIQUES.slice(0, 5).map(([id, name]) => {
          const v = int(r, 45, 99);
          return (
            <li key={id}>
              <Link to="/mitre/$tactic" params={{ tactic: id.toLowerCase() }} className="block rounded px-1 py-0.5 hover:bg-white/5">
                <div className="mb-1 grid grid-cols-[auto_minmax(0,1fr)_auto] items-center gap-2">
                  <span className="font-mono text-[0.6rem] text-primary">{id}</span>
                  <span className="truncate text-[0.68rem] text-muted-foreground">{name}</span>
                  <span className="font-mono text-[0.65rem]">{v}%</span>
                </div>
                <Bar value={v} tone={v > 80 ? "var(--success)" : "var(--warning)"} />
              </Link>
            </li>
          );
        })}
      </ul>
    </Panel>
  );
}

/* ------------------------------ page ------------------------------ */

export function ModulePage({ m }: { m: ModuleDef }) {
  return (
    <div>
      <PageHeader
        title={m.title}
        subtitle={m.subtitle}
        right={
          <div className="flex shrink-0 flex-wrap justify-end gap-1.5">
            <Badge tone="success">LIVE</Badge>
            <ActionBar actions={m.actions.slice(0, 4)} />
          </div>
        }
      />

      <div className="flex flex-col gap-3">
        <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-6">
          {m.kpis.map(([label, value, tone, sub]) => (
            <Link key={label} to="/investigate/$type/$id" params={{ type: m.key, id: label.toLowerCase().replace(/\s+/g, "-") }} className="transition-transform hover:-translate-y-0.5">
              <Metric label={label} value={value} tone={tone} sub={sub} />
            </Link>
          ))}
        </div>

        <div className="grid items-stretch gap-3 xl:grid-cols-12">
          <div className="xl:col-span-7">
            <TrendPanel k={m.key} drillTo="/threats" />
          </div>
          <div className="xl:col-span-3">
            <FacetDonut facets={m.facets} k={m.key} />
          </div>
          <div className="xl:col-span-2">
            <RiskGauges k={m.key} />
          </div>
        </div>

        <div className="grid items-stretch gap-3 xl:grid-cols-12">
          <div className="xl:col-span-8">
            <InvestigationTable kind={m.kind} seed={m.key} tableTitle={m.tableTitle} />
          </div>
          <div className="xl:col-span-4">
            <LiveEventFeed title={m.feedTitle} seed={m.key} />
          </div>
        </div>

        <div className="grid items-stretch gap-3 lg:grid-cols-2 xl:grid-cols-4">
          <TimelinePanel k={m.key} />
          <CoverageStrip k={m.key} />
          <WatchList k={m.key} />
          <QuickActions actions={m.actions} />
        </div>

        <div className="grid items-stretch gap-3 xl:grid-cols-12">
          <div className="xl:col-span-5">
            <TelemetryBars k={m.key} />
          </div>
          <div className="xl:col-span-7">
            <InvestigationTable kind={m.kind === "alert" ? "log" : "alert"} seed={m.key + "b"} tableTitle="Correlated Signals" rows={8} />
          </div>
        </div>
      </div>
    </div>
  );
}

export { columnsFor, rowsFor, title };
