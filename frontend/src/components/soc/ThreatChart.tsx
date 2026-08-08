import { useEffect, useState } from "react";
import {
  Area, AreaChart, CartesianGrid, ResponsiveContainer,
  Tooltip, XAxis, YAxis,
} from "recharts";
import { Panel } from "./Panel";
import { C } from "./data";
import { useThreatStats, useSystemHealth } from "@/hooks/useAISS";

type Point = { t: string; threats: number; cpu: number };

function TipBox({ active, payload, label }: any) {
  if (!active || !payload?.length) return null;
  return (
    <div className="panel px-3 py-2 font-mono text-xs">
      <p className="label-cap mb-1">{label}</p>
      {payload.map((p: any) => (
        <p key={p.dataKey} style={{ color: p.color }}>
          {p.dataKey === "threats" ? "Threats" : "CPU %"}: {p.value}
        </p>
      ))}
    </div>
  );
}

export function ThreatChart() {
  const { data: stats } = useThreatStats();
  const { data: health } = useSystemHealth();
  const [history, setHistory] = useState<Point[]>([]);

  // Build a rolling 24-point history from live data
  useEffect(() => {
    const now = new Date();
    const t = now.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
    const point: Point = {
      t,
      threats: stats?.active ?? 0,
      cpu: Math.round(health?.cpu_percent ?? 0),
    };
    setHistory((h) => {
      const next = [...h, point].slice(-24);
      // Seed with zeros if first point
      if (next.length === 1) {
        return Array.from({ length: 23 }, (_, i) => ({
          t: new Date(Date.now() - (23 - i) * 60_000)
            .toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" }),
          threats: 0,
          cpu: 0,
        })).concat(next);
      }
      return next;
    });
  }, [stats, health]);

  return (
    <Panel
      title="Threat Activity vs CPU Load"
      right={
        <div className="flex items-center gap-4 font-mono text-[0.65rem]">
          <span className="flex items-center gap-1.5" style={{ color: C.cyan }}>
            <i className="size-2 rounded-full bg-current" /> THREATS
          </span>
          <span className="flex items-center gap-1.5" style={{ color: C.critical }}>
            <i className="size-2 rounded-full bg-current" /> CPU %
          </span>
          <span className="label-cap">LIVE</span>
        </div>
      }
      bodyClassName="chart-draw flex-none"
    >
      <ResponsiveContainer width="100%" height={300}>
        <AreaChart data={history} margin={{ top: 8, right: 8, left: -18, bottom: 0 }}>
          <defs>
            <linearGradient id="gThreats" x1="0" y1="0" x2="0" y2="1">
              <stop offset="0%" stopColor={C.cyan} stopOpacity={0.45} />
              <stop offset="100%" stopColor={C.cyan} stopOpacity={0} />
            </linearGradient>
            <linearGradient id="gCpu" x1="0" y1="0" x2="0" y2="1">
              <stop offset="0%" stopColor={C.critical} stopOpacity={0.4} />
              <stop offset="100%" stopColor={C.critical} stopOpacity={0} />
            </linearGradient>
          </defs>
          <CartesianGrid stroke="rgba(255,255,255,0.06)" vertical={false} />
          <XAxis dataKey="t" tick={{ fill: C.muted, fontSize: 10, fontFamily: "monospace" }}
            axisLine={false} tickLine={false} interval={3} />
          <YAxis tick={{ fill: C.muted, fontSize: 10, fontFamily: "monospace" }}
            axisLine={false} tickLine={false} />
          <Tooltip content={<TipBox />} cursor={{ stroke: "rgba(59,130,246,0.3)" }} />
          <Area type="monotone" dataKey="threats" stroke={C.cyan} strokeWidth={2}
            fill="url(#gThreats)" isAnimationActive />
          <Area type="monotone" dataKey="cpu" stroke={C.critical} strokeWidth={2}
            fill="url(#gCpu)" isAnimationActive />
        </AreaChart>
      </ResponsiveContainer>
    </Panel>
  );
}
