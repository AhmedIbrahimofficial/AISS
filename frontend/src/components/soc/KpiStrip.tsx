import { useCountUp } from "./useCountUp";
import { C } from "./data";
import { useThreats, useThreatStats, useSystemHealth } from "@/hooks/useAISS";

function Tile({
  label, value, color, sub, trend, children,
}: {
  label: string; value: string; color?: string;
  sub?: string; trend?: string; children?: React.ReactNode;
}) {
  return (
    <section className="panel flex h-[112px] flex-col justify-between p-3.5">
      <div className="grid grid-cols-[minmax(0,1fr)_auto] items-start gap-2">
        <p className="label-cap truncate">{label}</p>
        {trend && <span className="shrink-0 font-mono text-[0.6rem] text-muted-foreground">{trend}</span>}
      </div>
      <div className="grid grid-cols-[minmax(0,1fr)_auto] items-end gap-2">
        <div className="min-w-0">
          <p className="font-mono text-[1.7rem] leading-none font-bold tabular-nums"
            style={{ color: color ?? "var(--foreground)" }}>{value}</p>
          {sub && <p className="mt-1.5 truncate text-[0.65rem] text-muted-foreground">{sub}</p>}
        </div>
        {children}
      </div>
    </section>
  );
}

function Sparkline({ data }: { data: number[] }) {
  const max = Math.max(...data, 1);
  const pts = data.map((v, i) => `${(i / (data.length - 1)) * 76},${28 - (v / max) * 24}`).join(" ");
  return (
    <svg viewBox="0 0 76 30" className="h-8 w-20 shrink-0">
      <polyline points={pts} fill="none" stroke={C.teal} strokeWidth="1.6" strokeLinejoin="round" />
    </svg>
  );
}

function MiniGauge({ value }: { value: number }) {
  const r = 16;
  const circ = 2 * Math.PI * r;
  return (
    <svg viewBox="0 0 40 40" className="size-10 shrink-0 -rotate-90">
      <circle cx="20" cy="20" r={r} fill="none" stroke="rgba(255,255,255,0.08)" strokeWidth="4" />
      <circle cx="20" cy="20" r={r} fill="none" stroke={C.teal} strokeWidth="4"
        strokeLinecap="round"
        strokeDasharray={`${(value / 100) * circ} ${circ}`}
        style={{ transition: "stroke-dasharray .6s" }} />
    </svg>
  );
}

export function KpiStrip() {
  const { data: stats } = useThreatStats();
  const { data: health } = useSystemHealth();

  const active   = stats?.active   ?? 0;
  const critical = stats?.critical ?? 0;
  const resolved = stats?.resolved ?? 0;
  const cpu      = health ? Math.round(health.cpu_percent) : 0;
  const ram      = health ? Math.round(health.ram_percent) : 0;
  const uptime   = health ? Math.round(health.uptime_secs / 3600) : 0;

  const resolvedC = useCountUp(resolved);

  const spark = [cpu, ram, cpu, ram, cpu, ram, cpu, ram, cpu, ram, cpu, ram];

  return (
    <div className="grid grid-cols-2 gap-3 md:grid-cols-3 xl:grid-cols-6">
      <Tile
        label="Active Threats"
        value={String(active)}
        color={active > 0 ? C.critical : C.success}
        sub="sessions under watch"
        trend="live"
      />
      <Tile
        label="Resolved Today"
        value={resolvedC}
        color={C.cyan}
        sub="auto-mitigated"
      />
      <Tile
        label="Critical Alerts"
        value={String(critical)}
        color={C.critical}
        sub="P1 queue"
        trend="SLA 15m"
      />
      <Tile
        label="CPU Usage"
        value={`${cpu}%`}
        color={cpu > 80 ? C.critical : cpu > 60 ? C.warning : C.success}
        sub="this machine"
        trend="live"
      />
      <Tile
        label="RAM Usage"
        value={`${ram}%`}
        color={ram > 85 ? C.critical : ram > 70 ? C.warning : C.teal}
        sub={health ? `${health.ram_used_mb} / ${health.ram_total_mb} MB` : "loading..."}
        trend="live"
      >
        <Sparkline data={spark} />
      </Tile>
      <Tile
        label="Uptime"
        value={`${uptime}h`}
        color={C.teal}
        sub="backend running"
      >
        <MiniGauge value={Math.min(100, uptime)} />
      </Tile>
    </div>
  );
}
