/**
 * KpiStrip — replaced with a full-width real-time sparkline bar.
 * NO number boxes. One continuous multi-line chart spanning the full width.
 * CPU, RAM, active threats, network connections — all live from backend.
 */
import { useEffect, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import {
  Area, AreaChart, CartesianGrid, ComposedChart, Line,
  ResponsiveContainer, Tooltip, XAxis, YAxis,
} from "recharts";
import { Panel } from "./Panel";
import { C } from "./data";
import { useSystemHealth, useThreatStats } from "@/hooks/useAISS";
import { getLiveNetworkStats } from "@/lib/api";

type Point = { t: string; cpu: number; ram: number; threats: number; conns: number };

export function KpiStrip() {
  const { data: health } = useSystemHealth();
  const { data: stats  } = useThreatStats();
  const { data: net    } = useQuery({ queryKey: ["live-network-stats"], queryFn: getLiveNetworkStats, refetchInterval: 4000 });

  const [hist, setHist] = useState<Point[]>([]);

  useEffect(() => {
    const t = new Date().toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" });
    const pt: Point = {
      t,
      cpu:     Math.round(health?.cpu_percent ?? 0),
      ram:     Math.round(health?.ram_percent ?? 0),
      threats: stats?.active ?? 0,
      conns:   net?.connections ?? 0,
    };
    setHist(prev => {
      const next = [...prev, pt].slice(-90);
      if (next.length === 1) {
        return Array.from({ length: 89 }, (_, i) => ({
          t: new Date(Date.now() - (89 - i) * 5000).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" }),
          cpu: 0, ram: 0, threats: 0, conns: 0,
        })).concat(next);
      }
      return next;
    });
  }, [health, stats, net]);

  const cpu  = Math.round(health?.cpu_percent ?? 0);
  const ram  = Math.round(health?.ram_percent ?? 0);
  const thr  = stats?.active ?? 0;
  const conn = net?.connections ?? 0;

  const cpuCol  = cpu  > 80 ? C.critical : cpu  > 60 ? C.warning : C.teal;
  const ramCol  = ram  > 85 ? C.critical : ram  > 70 ? C.warning : "#f59e0b";
  const thrCol  = thr  > 0  ? C.critical : C.success;

  return (
    <div className="rounded-lg border border-[var(--hairline)] bg-[rgba(255,255,255,0.015)] overflow-hidden">
      {/* Live legend strip */}
      <div className="flex items-center gap-6 border-b border-[var(--hairline)] px-4 py-2">
        <span className="font-mono text-[0.65rem]" style={{ color: cpuCol }}>
          ⬛ CPU <strong>{cpu}%</strong>
        </span>
        <span className="font-mono text-[0.65rem]" style={{ color: ramCol }}>
          ⬛ RAM <strong>{ram}%</strong>{health ? ` · ${(health.ram_used_mb / 1024).toFixed(1)} GB` : ""}
        </span>
        <span className="font-mono text-[0.65rem]" style={{ color: thrCol }}>
          ⬛ Threats <strong>{thr}</strong>{stats ? ` · ${stats.critical} critical` : ""}
        </span>
        <span className="font-mono text-[0.65rem]" style={{ color: C.cyan }}>
          ⬛ Connections <strong>{conn}</strong>{net ? ` · ${net.recv_mb_s.toFixed(1)} MB/s` : ""}
        </span>
        <span className="ml-auto flex items-center gap-1.5 font-mono text-[0.6rem] text-muted-foreground">
          <span className="dot-pulse size-1.5 rounded-full bg-[var(--success)]" /> LIVE
        </span>
      </div>

      {/* The chart — full width, no padding */}
      <ResponsiveContainer width="100%" height={120}>
        <ComposedChart data={hist} margin={{ top: 8, right: 0, left: 0, bottom: 0 }}>
          <defs>
            <linearGradient id="gKpiCpu" x1="0" y1="0" x2="0" y2="1">
              <stop offset="0%" stopColor={C.teal} stopOpacity={0.3} />
              <stop offset="100%" stopColor={C.teal} stopOpacity={0} />
            </linearGradient>
            <linearGradient id="gKpiRam" x1="0" y1="0" x2="0" y2="1">
              <stop offset="0%" stopColor="#f59e0b" stopOpacity={0.22} />
              <stop offset="100%" stopColor="#f59e0b" stopOpacity={0} />
            </linearGradient>
          </defs>
          <CartesianGrid stroke="rgba(255,255,255,0.04)" vertical={false} />
          <XAxis dataKey="t" tick={{ fill: C.muted, fontSize: 8, fontFamily: "monospace" }}
            axisLine={false} tickLine={false} interval={17} />
          <YAxis yAxisId="pct" domain={[0, 100]}
            tick={{ fill: C.muted, fontSize: 8 }} axisLine={false} tickLine={false}
            tickFormatter={v => `${v}%`} width={30} />
          <YAxis yAxisId="conn" orientation="right" domain={[0, "auto"]}
            tick={{ fill: C.muted, fontSize: 8 }} axisLine={false} tickLine={false} width={28} />
          <Tooltip
            contentStyle={{ background: "#0a1310", border: "1px solid rgba(255,255,255,0.1)", borderRadius: 6, fontSize: 10, fontFamily: "monospace" }}
            labelStyle={{ color: C.muted }}
          />
          <Area yAxisId="pct" type="monotone" dataKey="cpu" name="CPU %"
            stroke={C.teal} fill="url(#gKpiCpu)" strokeWidth={1.8} dot={false} isAnimationActive={false} />
          <Area yAxisId="pct" type="monotone" dataKey="ram" name="RAM %"
            stroke="#f59e0b" fill="url(#gKpiRam)" strokeWidth={1.4} dot={false} isAnimationActive={false} />
          <Line yAxisId="pct" type="stepAfter" dataKey="threats" name="Threats"
            stroke={C.critical} strokeWidth={2} dot={false} isAnimationActive={false} strokeDasharray="3 2" />
          <Line yAxisId="conn" type="monotone" dataKey="conns" name="Connections"
            stroke={C.cyan} strokeWidth={1.2} dot={false} isAnimationActive={false} opacity={0.6} />
        </ComposedChart>
      </ResponsiveContainer>
    </div>
  );
}
