/**
 * Auto-Response Timeline — full-width visual.
 * Shows real resolved threats as a timeline + rolling activity chart.
 * No mock data — shows empty state when no resolved threats exist.
 */
import { useEffect, useState } from "react";
import {
  Area, AreaChart, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis,
} from "recharts";
import { Panel } from "./Panel";
import { Badge } from "./ui";
import { C } from "./data";
import { useAllThreats, useThreatStats } from "@/hooks/useAISS";

type Item = { id: string; label: string; color: string; time: string };
type HistPt = { t: string; resolved: number; active: number; rate: number };

export function AutoResponseTimeline() {
  const { data: threats } = useAllThreats();
  const { data: stats   } = useThreatStats();

  const [hist, setHist] = useState<HistPt[]>([]);

  // Rolling activity history
  useEffect(() => {
    const t = new Date().toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
    setHist(prev => {
      const pt: HistPt = {
        t,
        resolved: stats?.resolved ?? 0,
        active:   stats?.active   ?? 0,
        rate:     stats && stats.total > 0 ? Math.round((stats.resolved / stats.total) * 100) : 0,
      };
      const next = [...prev, pt].slice(-40);
      if (next.length === 1) {
        return Array.from({ length: 39 }, (_, i) => ({
          t: new Date(Date.now() - (39-i)*60000).toLocaleTimeString([], { hour:"2-digit", minute:"2-digit" }),
          resolved: 0, active: 0, rate: 0,
        })).concat(next);
      }
      return next;
    });
  }, [stats]);

  // Use real resolved threats for timeline (no mock fallback)
  const resolved = threats?.filter(t => t.status === "resolved").slice(-8) ?? [];
  const items: Item[] = resolved.map(t => ({
    id: t.id,
    label: `${t.type} — ${t.source}`,
    color: t.severity === "critical" ? C.critical : t.severity === "high" ? C.warning : C.success,
    time: new Date(t.resolved_at ?? t.detected_at).toTimeString().slice(0, 8),
  }));

  const autonomy = stats && stats.total > 0
    ? Math.round((stats.resolved / stats.total) * 100)
    : 0;

  return (
    <Panel
      title="Auto-Response Timeline"
      right={
        <div className="flex items-center gap-2">
          <Badge tone="success">autonomous</Badge>
          <span className="font-mono text-[0.6rem] text-muted-foreground">{autonomy}% auto-resolved</span>
        </div>
      }
      bodyClassName="p-0 overflow-hidden flex flex-col"
    >
      {/* Rolling activity chart — full width */}
      <ResponsiveContainer width="100%" height={110}>
        <AreaChart data={hist} margin={{ top: 8, right: 0, left: 0, bottom: 0 }}>
          <defs>
            <linearGradient id="gResolved" x1="0" y1="0" x2="0" y2="1">
              <stop offset="0%" stopColor={C.success} stopOpacity={0.4} />
              <stop offset="100%" stopColor={C.success} stopOpacity={0} />
            </linearGradient>
            <linearGradient id="gActive" x1="0" y1="0" x2="0" y2="1">
              <stop offset="0%" stopColor={C.critical} stopOpacity={0.35} />
              <stop offset="100%" stopColor={C.critical} stopOpacity={0} />
            </linearGradient>
          </defs>
          <CartesianGrid stroke="rgba(255,255,255,0.04)" vertical={false} />
          <XAxis dataKey="t" tick={{ fill: C.muted, fontSize: 8 }} axisLine={false} tickLine={false} interval={9} />
          <YAxis tick={{ fill: C.muted, fontSize: 8 }} axisLine={false} tickLine={false} width={24} />
          <Tooltip contentStyle={{ background:"#0a1310", border:"1px solid rgba(255,255,255,0.1)", borderRadius:6, fontSize:10 }} />
          <Area type="monotone" dataKey="resolved" name="Resolved" stroke={C.success} fill="url(#gResolved)" strokeWidth={2} dot={false} isAnimationActive={false} />
          <Area type="monotone" dataKey="active"   name="Active"   stroke={C.critical} fill="url(#gActive)" strokeWidth={1.5} dot={false} isAnimationActive={false} />
        </AreaChart>
      </ResponsiveContainer>

      {/* Horizontal event timeline */}
      <div className="relative overflow-x-auto border-t border-[var(--hairline)] px-4 pb-3 pt-5">
        {items.length === 0 ? (
          <div className="flex h-16 items-center justify-center">
            <p className="text-xs text-muted-foreground">No automated responses yet</p>
          </div>
        ) : (
          <>
            {/* Timeline line */}
            <div className="absolute left-4 right-4 top-7 h-px bg-gradient-to-r from-transparent via-[rgba(59,130,246,0.5)] to-transparent" />

            <div className="flex gap-4 min-w-max">
              {items.map(item => (
                <div key={item.id} className="flex flex-col items-center gap-1 w-28">
                  <span
                    className="size-2.5 rounded-full shrink-0 z-10"
                    style={{ backgroundColor: item.color, boxShadow: `0 0 8px ${item.color}` }}
                  />
                  <p className="font-mono text-[0.55rem] text-muted-foreground mt-1">{item.time}</p>
                  <p className="text-center text-[0.6rem] leading-snug text-foreground" title={item.label}>
                    {item.label.length > 28 ? item.label.slice(0, 28) + "…" : item.label}
                  </p>
                </div>
              ))}
            </div>
          </>
        )}
      </div>
    </Panel>
  );
}
