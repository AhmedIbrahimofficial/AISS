/**
 * ResponseBoard — threat status as a full-width stacked area + bar chart combo.
 * No boxes. Real data from /api/threats/stats.
 */
import { useEffect, useState } from "react";
import {
  Bar, BarChart, CartesianGrid, Cell,
  ResponsiveContainer, Tooltip, XAxis, YAxis,
} from "recharts";
import { Panel } from "./Panel";
import { C } from "./data";
import { useThreatStats } from "@/hooks/useAISS";
import { Badge } from "./ui";

export function ResponseBoard() {
  const { data: stats } = useThreatStats();

  // Rolling history of threat counts for animated chart
  const [hist, setHist] = useState<{ t: string; active: number; critical: number; high: number; resolved: number }[]>([]);

  useEffect(() => {
    const t = new Date().toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
    setHist(prev => {
      const pt = {
        t,
        active:   stats?.active   ?? 0,
        critical: stats?.critical ?? 0,
        high:     stats?.high     ?? 0,
        resolved: stats?.resolved ?? 0,
      };
      const next = [...prev, pt].slice(-30);
      if (next.length === 1) {
        return Array.from({ length: 29 }, (_, i) => ({
          t: new Date(Date.now() - (29 - i) * 30000).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" }),
          active: 0, critical: 0, high: 0, resolved: 0,
        })).concat(next);
      }
      return next;
    });
  }, [stats]);

  // Current snapshot bar chart
  const snapshot = [
    { name: "Active",   value: stats?.active   ?? 0, color: C.critical },
    { name: "Critical", value: stats?.critical ?? 0, color: "#ff4444"  },
    { name: "High",     value: stats?.high     ?? 0, color: C.warning  },
    { name: "Medium",   value: stats?.medium   ?? 0, color: C.campaign },
    { name: "Low",      value: stats?.low      ?? 0, color: C.teal     },
    { name: "Resolved", value: stats?.resolved ?? 0, color: C.success  },
  ];

  const total    = stats?.total    ?? 0;
  const resolved = stats?.resolved ?? 0;
  const active   = stats?.active   ?? 0;
  const pctGood  = total > 0 ? Math.round((resolved / total) * 100) : 100;

  return (
    <Panel
      title="Threat Status"
      right={
        <div className="flex items-center gap-2">
          <Badge tone={active > 0 ? "critical" : "success"}>
            {active > 0 ? `${active} ACTIVE` : "CLEAR"}
          </Badge>
          <span className="font-mono text-[0.6rem] text-muted-foreground">{pctGood}% resolved</span>
        </div>
      }
      bodyClassName="p-0 overflow-hidden flex flex-col"
    >
      {/* Top: current snapshot bars */}
      <ResponsiveContainer width="100%" height={130}>
        <BarChart data={snapshot} margin={{ top: 12, right: 8, left: 0, bottom: 4 }}>
          <CartesianGrid stroke="rgba(255,255,255,0.04)" vertical={false} />
          <XAxis dataKey="name" tick={{ fill: C.muted, fontSize: 9 }} axisLine={false} tickLine={false} />
          <YAxis tick={{ fill: C.muted, fontSize: 9 }} axisLine={false} tickLine={false} width={24} />
          <Tooltip
            contentStyle={{ background: "#0a1310", border: "1px solid rgba(255,255,255,0.1)", borderRadius: 6, fontSize: 10 }}
            cursor={{ fill: "rgba(255,255,255,0.04)" }}
          />
          <Bar dataKey="value" radius={[4, 4, 0, 0]} maxBarSize={40}>
            {snapshot.map((s, i) => (
              <Cell key={i} fill={s.color}
                style={{ filter: s.value > 0 ? `drop-shadow(0 0 6px ${s.color}80)` : "none" }} />
            ))}
          </Bar>
        </BarChart>
      </ResponsiveContainer>

      {/* Bottom: rolling history area */}
      <div className="border-t border-[var(--hairline)]">
        <ResponsiveContainer width="100%" height={80}>
          <BarChart data={hist} margin={{ top: 4, right: 0, left: 0, bottom: 0 }} barCategoryGap="10%">
            <XAxis dataKey="t" tick={{ fill: C.muted, fontSize: 7 }} axisLine={false} tickLine={false} interval={9} />
            <Tooltip
              contentStyle={{ background: "#0a1310", border: "1px solid rgba(255,255,255,0.1)", borderRadius: 6, fontSize: 9 }}
              cursor={{ fill: "rgba(255,255,255,0.03)" }}
            />
            <Bar dataKey="resolved" name="Resolved" stackId="a" fill={C.success} opacity={0.7} isAnimationActive={false} />
            <Bar dataKey="active"   name="Active"   stackId="a" fill={C.critical} opacity={0.85} isAnimationActive={false} radius={[2,2,0,0]} />
          </BarChart>
        </ResponsiveContainer>
      </div>
    </Panel>
  );
}
