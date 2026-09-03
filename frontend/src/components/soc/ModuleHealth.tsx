/**
 * ModuleHealth — full-width visual chart, NO boxes.
 * Shows CPU/RAM as overlapping area charts + module status as horizontal bar chart.
 */
import { useEffect, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import {
  Area, AreaChart, Bar, BarChart, CartesianGrid, Cell,
  ResponsiveContainer, Tooltip, XAxis, YAxis,
} from "recharts";
import { Panel } from "./Panel";
import { C } from "./data";
import { useSystemHealth } from "@/hooks/useAISS";
import { getLiveDisk } from "@/lib/api";
import { Badge } from "./ui";

type HealthPoint = { t: string; cpu: number; ram: number; disk: number };

export function ModuleHealth() {
  const { data: health, isLoading } = useSystemHealth();
  const { data: disk } = useQuery({ queryKey: ["live-disk"], queryFn: getLiveDisk, refetchInterval: 20_000 });

  const [hist, setHist] = useState<HealthPoint[]>([]);

  useEffect(() => {
    if (!health) return;
    const t = new Date().toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" });
    setHist(prev => {
      const pt: HealthPoint = {
        t,
        cpu:  Math.round(health.cpu_percent),
        ram:  Math.round(health.ram_percent),
        disk: Math.round(health.disk_percent),
      };
      const next = [...prev, pt].slice(-60);
      if (next.length === 1) {
        return Array.from({ length: 59 }, (_, i) => ({
          t: new Date(Date.now() - (59 - i) * 5000).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" }),
          cpu: 0, ram: 0, disk: 0,
        })).concat(next);
      }
      return next;
    });
  }, [health]);

  // Build module data for bar chart
  const modules = health?.modules
    ? Object.entries(health.modules).map(([name, active]) => ({
        name: name.replace(/_/g, " ").replace(/\b\w/g, c => c.toUpperCase()).slice(0, 16),
        value: active ? 100 : 0,
        active: active as boolean,
      }))
    : [];

  // Disk partitions
  const parts = disk?.partitions ?? [];

  const cpuNow  = Math.round(health?.cpu_percent  ?? 0);
  const ramNow  = Math.round(health?.ram_percent   ?? 0);
  const diskNow = Math.round(health?.disk_percent  ?? 0);
  const online  = !!health;

  return (
    <Panel
      title="System Health"
      right={
        <div className="flex items-center gap-2">
          <Badge tone={online ? "success" : "warning"}>{online ? "ONLINE" : isLoading ? "connecting…" : "OFFLINE"}</Badge>
          {online && (
            <span className="font-mono text-[0.6rem] text-muted-foreground">
              CPU {cpuNow}% · RAM {ramNow}% · Disk {diskNow}%
            </span>
          )}
        </div>
      }
      bodyClassName="p-0 overflow-hidden flex flex-col gap-0"
    >
      {/* Resource history chart */}
      <ResponsiveContainer width="100%" height={140}>
        <AreaChart data={hist} margin={{ top: 8, right: 0, left: 0, bottom: 0 }}>
          <defs>
            <linearGradient id="gMhCpu" x1="0" y1="0" x2="0" y2="1">
              <stop offset="0%" stopColor={C.teal}    stopOpacity={0.35} />
              <stop offset="100%" stopColor={C.teal}  stopOpacity={0} />
            </linearGradient>
            <linearGradient id="gMhRam" x1="0" y1="0" x2="0" y2="1">
              <stop offset="0%" stopColor="#f59e0b"   stopOpacity={0.28} />
              <stop offset="100%" stopColor="#f59e0b" stopOpacity={0} />
            </linearGradient>
            <linearGradient id="gMhDisk" x1="0" y1="0" x2="0" y2="1">
              <stop offset="0%" stopColor={C.campaign} stopOpacity={0.2} />
              <stop offset="100%" stopColor={C.campaign} stopOpacity={0} />
            </linearGradient>
          </defs>
          <CartesianGrid stroke="rgba(255,255,255,0.04)" vertical={false} />
          <XAxis dataKey="t" tick={{ fill: C.muted, fontSize: 8 }} axisLine={false} tickLine={false} interval={14} />
          <YAxis domain={[0, 100]} tick={{ fill: C.muted, fontSize: 8 }} axisLine={false} tickLine={false}
            tickFormatter={v => `${v}%`} width={30} />
          <Tooltip contentStyle={{ background: "#0a1310", border: "1px solid rgba(255,255,255,0.1)", borderRadius: 6, fontSize: 10 }} />
          <Area type="monotone" dataKey="cpu"  name="CPU %"  stroke={C.teal}     fill="url(#gMhCpu)"  strokeWidth={2}   dot={false} isAnimationActive={false} />
          <Area type="monotone" dataKey="ram"  name="RAM %"  stroke="#f59e0b"    fill="url(#gMhRam)"  strokeWidth={1.6} dot={false} isAnimationActive={false} />
          <Area type="monotone" dataKey="disk" name="Disk %" stroke={C.campaign} fill="url(#gMhDisk)" strokeWidth={1.2} dot={false} isAnimationActive={false} />
        </AreaChart>
      </ResponsiveContainer>

      {/* Module status bar chart */}
      {modules.length > 0 && (
        <div className="border-t border-[var(--hairline)]">
          <ResponsiveContainer width="100%" height={Math.max(60, modules.length * 22 + 12)}>
            <BarChart data={modules} layout="vertical" margin={{ top: 6, right: 48, left: 8, bottom: 4 }}>
              <XAxis type="number" domain={[0, 100]} tick={false} axisLine={false} tickLine={false} />
              <YAxis type="category" dataKey="name"
                tick={{ fill: C.muted, fontSize: 9, fontFamily: "monospace" }}
                axisLine={false} tickLine={false} width={100} />
              <Tooltip contentStyle={{ background: "#0a1310", border: "1px solid rgba(255,255,255,0.1)", borderRadius: 6, fontSize: 10 }}
                formatter={(val, _name, props) => [props.payload.active ? "ACTIVE" : "OFFLINE", ""]} />
              <Bar dataKey="value" radius={[0, 4, 4, 0]} barSize={10} background={{ fill: "rgba(255,255,255,0.04)", radius: 4 }}>
                {modules.map((m, i) => (
                  <Cell key={i} fill={m.active ? C.success : "rgba(255,255,255,0.12)"}
                    style={{ filter: m.active ? `drop-shadow(0 0 4px ${C.success}60)` : "none" }} />
                ))}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        </div>
      )}

      {/* Disk partitions strip */}
      {parts.length > 0 && (
        <div className="border-t border-[var(--hairline)] px-4 py-2">
          <div className="flex items-center gap-3">
            {parts.map(p => {
              const color = p.percent > 85 ? C.critical : p.percent > 70 ? C.warning : C.teal;
              return (
                <div key={p.mountpoint} className="flex-1 min-w-0">
                  <div className="flex items-center justify-between mb-1">
                    <span className="font-mono text-[0.58rem] text-muted-foreground truncate">{p.mountpoint}</span>
                    <span className="font-mono text-[0.6rem] ml-1 shrink-0" style={{ color }}>{p.percent}%</span>
                  </div>
                  <div className="h-1.5 rounded-full bg-white/5 overflow-hidden">
                    <div className="h-full rounded-full transition-all duration-700"
                      style={{ width: `${p.percent}%`, background: color }} />
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      )}
    </Panel>
  );
}
