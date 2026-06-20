"use client";
import { useEffect, useState, useRef, useCallback } from "react";
import {
  AreaChart, Area, BarChart, Bar, PieChart, Pie, Cell,
  XAxis, YAxis, Tooltip, ResponsiveContainer, LineChart, Line,
} from "recharts";
import {
  Shield, Activity, AlertTriangle, CheckCircle, Cpu, HardDrive,
  Wifi, Zap, Eye, Lock, Terminal, RefreshCw,
} from "lucide-react";

const API = "http://localhost:8000";
const WS  = "ws://localhost:8000/ws";

// ── Types ─────────────────────────────────────────────────────────────
interface Stats   { total: number; active: number; resolved: number; critical: number; high: number; medium: number; low: number; }
interface Health  { uptime_secs: number; cpu_percent: number; ram_percent: number; ram_used_mb: number; ram_total_mb: number; disk_percent: number; net_sent_mb: number; net_recv_mb: number; process_count: number; modules: Record<string, boolean>; }
interface Threat  { id: string; type: string; severity: string; source: string; module: string; status: string; detected_at: string; description: string; }
interface KillStage { id: string; label: string; icon: string; color: string; total: number; active: number; compromised: boolean; }

const SEV_COLOR: Record<string, string> = { critical: "#ff4444", high: "#ff9900", medium: "#ffd166", low: "#00ff88" };
const PIE_COLORS = ["#ff4444", "#ff9900", "#ffd166", "#00ff88", "#00ccff", "#c77dff"];

// ── Helpers ───────────────────────────────────────────────────────────
function uptime(secs: number) {
  const h = Math.floor(secs / 3600), m = Math.floor((secs % 3600) / 60), s = secs % 60;
  return `${String(h).padStart(2,"0")}:${String(m).padStart(2,"0")}:${String(s).padStart(2,"0")}`;
}
function ago(iso: string) {
  const diff = Math.floor((Date.now() - new Date(iso).getTime()) / 1000);
  if (diff < 60) return `${diff}s ago`;
  if (diff < 3600) return `${Math.floor(diff/60)}m ago`;
  return `${Math.floor(diff/3600)}h ago`;
}

// ── Stat Card ─────────────────────────────────────────────────────────
function StatCard({ icon: Icon, label, value, color = "#00ff88", sub }: {
  icon: React.ElementType; label: string; value: string | number; color?: string; sub?: string;
}) {
  return (
    <div className="cyber-card p-4 flex items-center gap-3">
      <div className="w-10 h-10 rounded-xl flex items-center justify-center flex-shrink-0"
           style={{ background: `${color}15`, border: `1px solid ${color}30` }}>
        <Icon size={18} style={{ color }} />
      </div>
      <div className="min-w-0">
        <p className="text-white/40 text-xs uppercase tracking-widest truncate">{label}</p>
        <p className="text-white font-bold text-xl leading-tight" style={{ color }}>{value}</p>
        {sub && <p className="text-white/30 text-xs">{sub}</p>}
      </div>
    </div>
  );
}

// ── Gauge Bar ─────────────────────────────────────────────────────────
function GaugeBar({ label, value, color }: { label: string; value: number; color: string }) {
  return (
    <div>
      <div className="flex justify-between mb-1">
        <span className="text-white/50 text-xs">{label}</span>
        <span className="text-xs font-bold" style={{ color }}>{value.toFixed(1)}%</span>
      </div>
      <div className="h-2 rounded-full bg-white/5 overflow-hidden">
        <div className="h-full rounded-full transition-all duration-700"
             style={{ width: `${Math.min(value, 100)}%`, background: color }} />
      </div>
    </div>
  );
}

// ── Main Dashboard ────────────────────────────────────────────────────
export default function MonitorPage() {
  const [stats,        setStats]       = useState<Stats | null>(null);
  const [health,       setHealth]      = useState<Health | null>(null);
  const [threats,      setThreats]     = useState<Threat[]>([]);
  const [killChain,    setKillChain]   = useState<KillStage[]>([]);
  const [threatHistory,setThreatHistory] = useState<{ t: string; active: number; total: number }[]>([]);
  const [cpuHistory,   setCpuHistory]  = useState<{ t: string; cpu: number; ram: number }[]>([]);
  const [online,       setOnline]      = useState(false);
  const [lastUpdate,   setLastUpdate]  = useState("");
  const wsRef = useRef<WebSocket | null>(null);
  const tickRef = useRef(0);

  // ── Fetch all data ──────────────────────────────────────────────────
  const fetchAll = useCallback(async () => {
    try {
      const [sRes, hRes, tRes, kRes] = await Promise.all([
        fetch(`${API}/api/threats/stats`,  { signal: AbortSignal.timeout(4000) }),
        fetch(`${API}/api/system/health`,  { signal: AbortSignal.timeout(4000) }),
        fetch(`${API}/api/threats/active`, { signal: AbortSignal.timeout(4000) }),
        fetch(`${API}/api/kill-chain`,     { signal: AbortSignal.timeout(4000) }),
      ]);
      const [s, h, t, k] = await Promise.all([sRes.json(), hRes.json(), tRes.json(), kRes.json()]);

      setStats(s);
      setHealth(h);
      setThreats((t.threats || []).slice(0, 50));
      setKillChain(k.stages || []);
      setOnline(true);

      const now = new Date().toLocaleTimeString("en-US", { hour12: false });
      setLastUpdate(now);
      tickRef.current++;

      setThreatHistory(prev => [...prev.slice(-29), { t: now, active: s.active ?? 0, total: s.total ?? 0 }]);
      setCpuHistory(prev   => [...prev.slice(-29), { t: now, cpu: h.cpu_percent ?? 0, ram: h.ram_percent ?? 0 }]);

    } catch {
      setOnline(false);
    }
  }, []);

  // ── WebSocket for instant threat events ────────────────────────────
  useEffect(() => {
    function connect() {
      try {
        const ws = new WebSocket(WS);
        wsRef.current = ws;
        ws.onmessage = () => fetchAll();
        ws.onclose   = () => setTimeout(connect, 3000);
      } catch { /* retry */ }
    }
    connect();
    return () => wsRef.current?.close();
  }, [fetchAll]);

  // ── Poll every 5 seconds ────────────────────────────────────────────
  useEffect(() => {
    fetchAll();
    const id = setInterval(fetchAll, 5000);
    return () => clearInterval(id);
  }, [fetchAll]);

  // ── Severity distribution for pie chart ────────────────────────────
  const sevDist = stats ? [
    { name: "Critical", value: stats.critical, color: "#ff4444" },
    { name: "High",     value: stats.high,     color: "#ff9900" },
    { name: "Medium",   value: stats.medium,   color: "#ffd166" },
    { name: "Low",      value: stats.low,      color: "#00ff88" },
  ].filter(d => d.value > 0) : [];

  // ── Module list from health ─────────────────────────────────────────
  const modules = health ? Object.entries(health.modules) : [];

  return (
    <main className="bg-black min-h-screen pt-20 pb-10 px-4 overflow-x-hidden">

      {/* ── Header ─────────────────────────────────────────────── */}
      <div className="max-w-[1600px] mx-auto mb-6 flex items-center justify-between">
        <div>
          <p className="section-label">Live Monitor</p>
          <h1 className="text-2xl font-bold text-white">
            AISS <span className="text-neon">Security Operations Center</span>
          </h1>
        </div>
        <div className="flex items-center gap-3">
          <div className={`flex items-center gap-2 px-3 py-1.5 rounded-full text-xs font-bold border ${
            online ? "border-neon/30 text-neon bg-neon/5" : "border-red-500/30 text-red-400 bg-red-500/5"
          }`}>
            <span className={`w-2 h-2 rounded-full ${online ? "bg-neon animate-pulse" : "bg-red-400"}`} />
            {online ? "BACKEND ONLINE" : "BACKEND OFFLINE"}
          </div>
          <div className="text-white/30 text-xs font-mono">{lastUpdate || "—"}</div>
          <button onClick={fetchAll} className="p-2 rounded-lg bg-white/5 hover:bg-white/10 transition-colors">
            <RefreshCw size={14} className="text-white/50" />
          </button>
        </div>
      </div>

      <div className="max-w-[1600px] mx-auto space-y-4">

        {/* ── Row 1: Stat Cards ─────────────────────────────────── */}
        <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-8 gap-3">
          <StatCard icon={Shield}        label="Total"    value={stats?.total    ?? "—"} color="#00ff88" />
          <StatCard icon={AlertTriangle} label="Active"   value={stats?.active   ?? "—"} color="#ff4444" />
          <StatCard icon={CheckCircle}   label="Resolved" value={stats?.resolved ?? "—"} color="#00ccff" />
          <StatCard icon={Zap}           label="Critical" value={stats?.critical ?? "—"} color="#ff4444" />
          <StatCard icon={Cpu}           label="CPU"      value={health ? `${health.cpu_percent.toFixed(0)}%` : "—"} color="#ffd166" />
          <StatCard icon={Activity}      label="RAM"      value={health ? `${health.ram_percent.toFixed(0)}%` : "—"} color="#c77dff" />
          <StatCard icon={HardDrive}     label="Disk"     value={health ? `${health.disk_percent.toFixed(0)}%` : "—"} color="#00d4ff" />
          <StatCard icon={Terminal}      label="Uptime"   value={health ? uptime(health.uptime_secs) : "—:—:—"} color="#00ff88" sub="hh:mm:ss" />
        </div>

        {/* ── Row 2: Charts ────────────────────────────────────── */}
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">

          {/* Threat Activity Chart */}
          <div className="lg:col-span-2 cyber-card p-4">
            <p className="text-white/40 text-xs uppercase tracking-widest mb-3">Live Threat Activity</p>
            <ResponsiveContainer width="100%" height={160}>
              <AreaChart data={threatHistory}>
                <defs>
                  <linearGradient id="ga" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%"  stopColor="#ff4444" stopOpacity={0.3} />
                    <stop offset="95%" stopColor="#ff4444" stopOpacity={0} />
                  </linearGradient>
                  <linearGradient id="gt" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%"  stopColor="#00ff88" stopOpacity={0.2} />
                    <stop offset="95%" stopColor="#00ff88" stopOpacity={0} />
                  </linearGradient>
                </defs>
                <XAxis dataKey="t" tick={{ fill: "#555", fontSize: 10 }} tickLine={false} axisLine={false} />
                <YAxis tick={{ fill: "#555", fontSize: 10 }} tickLine={false} axisLine={false} />
                <Tooltip contentStyle={{ background: "#0a0a0f", border: "1px solid #00ff8820", borderRadius: 8, fontSize: 11 }}
                         labelStyle={{ color: "#666" }} />
                <Area type="monotone" dataKey="active" stroke="#ff4444" strokeWidth={2} fill="url(#ga)" name="Active" />
                <Area type="monotone" dataKey="total"  stroke="#00ff88" strokeWidth={1.5} fill="url(#gt)" name="Total" strokeDasharray="4 2" />
              </AreaChart>
            </ResponsiveContainer>
          </div>

          {/* Severity Donut */}
          <div className="cyber-card p-4">
            <p className="text-white/40 text-xs uppercase tracking-widest mb-3">Severity Distribution</p>
            {sevDist.length > 0 ? (
              <div className="flex items-center gap-4">
                <ResponsiveContainer width={120} height={120}>
                  <PieChart>
                    <Pie data={sevDist} cx={55} cy={55} innerRadius={35} outerRadius={55} dataKey="value" strokeWidth={0}>
                      {sevDist.map((d, i) => <Cell key={i} fill={d.color} />)}
                    </Pie>
                  </PieChart>
                </ResponsiveContainer>
                <div className="space-y-2 flex-1">
                  {sevDist.map(d => (
                    <div key={d.name} className="flex items-center justify-between">
                      <div className="flex items-center gap-2">
                        <span className="w-2 h-2 rounded-full" style={{ background: d.color }} />
                        <span className="text-white/50 text-xs">{d.name}</span>
                      </div>
                      <span className="text-white text-xs font-bold">{d.value}</span>
                    </div>
                  ))}
                </div>
              </div>
            ) : (
              <div className="flex items-center justify-center h-28 text-white/20 text-sm">No threats</div>
            )}
          </div>
        </div>

        {/* ── Row 3: CPU/RAM + Kill Chain ──────────────────────── */}
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">

          {/* CPU & RAM Chart */}
          <div className="cyber-card p-4">
            <p className="text-white/40 text-xs uppercase tracking-widest mb-3">CPU & RAM History</p>
            <ResponsiveContainer width="100%" height={140}>
              <LineChart data={cpuHistory}>
                <XAxis dataKey="t" tick={{ fill: "#555", fontSize: 9 }} tickLine={false} axisLine={false} />
                <YAxis domain={[0,100]} tick={{ fill: "#555", fontSize: 9 }} tickLine={false} axisLine={false} />
                <Tooltip contentStyle={{ background: "#0a0a0f", border: "1px solid #00ff8820", borderRadius: 8, fontSize: 11 }}
                         labelStyle={{ color: "#666" }} />
                <Line type="monotone" dataKey="cpu" stroke="#ffd166" strokeWidth={2} dot={false} name="CPU %" />
                <Line type="monotone" dataKey="ram" stroke="#c77dff" strokeWidth={2} dot={false} name="RAM %" />
              </LineChart>
            </ResponsiveContainer>
            <div className="mt-3 space-y-2">
              {health && <>
                <GaugeBar label="CPU" value={health.cpu_percent} color="#ffd166" />
                <GaugeBar label="RAM" value={health.ram_percent} color="#c77dff" />
                <GaugeBar label="Disk" value={health.disk_percent} color="#00d4ff" />
              </>}
            </div>
          </div>

          {/* Kill Chain Stages */}
          <div className="lg:col-span-2 cyber-card p-4">
            <p className="text-white/40 text-xs uppercase tracking-widest mb-3">Cyber Kill Chain — Live</p>
            <div className="grid grid-cols-4 md:grid-cols-8 gap-2">
              {killChain.map((stage) => (
                <div key={stage.id} className={`rounded-xl p-2 text-center border transition-all ${
                  stage.compromised
                    ? "border-red-500/40 bg-red-500/5"
                    : "border-white/5 bg-white/2"
                }`}>
                  <div className="text-lg mb-1">{stage.icon}</div>
                  <p className="text-white/40 text-[9px] leading-tight mb-1">{stage.label}</p>
                  <p className={`text-xs font-bold ${stage.compromised ? "text-red-400" : "text-white/20"}`}>
                    {stage.total > 0 ? stage.total : "—"}
                  </p>
                  {stage.active > 0 && (
                    <span className="text-[8px] text-red-400 font-bold">{stage.active} active</span>
                  )}
                </div>
              ))}
            </div>
            {/* Kill chain bar */}
            {killChain.length > 0 && (
              <div className="mt-3">
                <div className="flex gap-0.5 h-2 rounded-full overflow-hidden">
                  {killChain.map((s, i) => (
                    <div key={i} className="flex-1 transition-all duration-700"
                         style={{ background: s.compromised ? "#ff4444" : "#ffffff10" }} />
                  ))}
                </div>
                <p className="text-white/30 text-xs mt-1">
                  {killChain.filter(s => s.compromised).length} / {killChain.length} stages compromised
                </p>
              </div>
            )}
          </div>
        </div>

        {/* ── Row 4: Live Threat Feed + Modules ───────────────── */}
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">

          {/* Live Threat Feed */}
          <div className="lg:col-span-2 cyber-card p-4">
            <div className="flex items-center justify-between mb-3">
              <p className="text-white/40 text-xs uppercase tracking-widest">Live Threat Feed</p>
              <span className="text-xs text-white/30">{threats.length} active</span>
            </div>
            <div className="space-y-1.5 max-h-72 overflow-y-auto pr-1">
              {threats.length === 0 ? (
                <div className="flex items-center justify-center h-20 text-neon/40 text-sm">
                  ✓ No active threats
                </div>
              ) : threats.map((t) => (
                <div key={t.id} className="flex items-start gap-3 p-2.5 rounded-lg bg-white/2 border border-white/5 hover:border-white/10 transition-colors">
                  <div className="w-1.5 h-1.5 rounded-full mt-1.5 flex-shrink-0 animate-pulse"
                       style={{ background: SEV_COLOR[t.severity] || "#fff" }} />
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2 mb-0.5">
                      <span className="text-xs font-bold" style={{ color: SEV_COLOR[t.severity] || "#fff" }}>
                        {t.severity?.toUpperCase()}
                      </span>
                      <span className="text-white text-xs font-medium truncate">{t.type}</span>
                      <span className="text-white/30 text-[10px] ml-auto flex-shrink-0">{ago(t.detected_at)}</span>
                    </div>
                    <p className="text-white/40 text-[11px] truncate">{t.description}</p>
                    <div className="flex items-center gap-2 mt-0.5">
                      <span className="text-white/25 text-[10px]">src: {t.source}</span>
                      <span className="text-white/20 text-[10px]">• {t.module}</span>
                    </div>
                  </div>
                </div>
              ))}
            </div>
          </div>

          {/* Module Status */}
          <div className="cyber-card p-4">
            <p className="text-white/40 text-xs uppercase tracking-widest mb-3">Detection Modules</p>
            <div className="space-y-2">
              {modules.map(([name, active]) => (
                <div key={name} className="flex items-center justify-between py-1.5 border-b border-white/5 last:border-0">
                  <div className="flex items-center gap-2">
                    <span className={`w-1.5 h-1.5 rounded-full ${active ? "bg-neon" : "bg-red-500"}`} />
                    <span className="text-white/60 text-xs capitalize">{name.replace(/_/g, " ")}</span>
                  </div>
                  <span className={`text-[10px] font-bold ${active ? "text-neon" : "text-red-400"}`}>
                    {active ? "ACTIVE" : "DOWN"}
                  </span>
                </div>
              ))}
            </div>

            {/* Network IO */}
            {health && (
              <div className="mt-4 pt-3 border-t border-white/5 space-y-1">
                <p className="text-white/30 text-[10px] uppercase tracking-widest mb-2">Network I/O</p>
                <div className="flex justify-between text-xs">
                  <span className="text-white/40">↑ Sent</span>
                  <span className="text-neon font-mono">{health.net_sent_mb.toFixed(1)} MB</span>
                </div>
                <div className="flex justify-between text-xs">
                  <span className="text-white/40">↓ Recv</span>
                  <span className="text-blue-400 font-mono">{health.net_recv_mb.toFixed(1)} MB</span>
                </div>
                <div className="flex justify-between text-xs">
                  <span className="text-white/40">Processes</span>
                  <span className="text-white/60 font-mono">{health.process_count}</span>
                </div>
              </div>
            )}
          </div>
        </div>

        {/* ── Row 5: Threat Type Bar Chart ────────────────────── */}
        <div className="cyber-card p-4">
          <p className="text-white/40 text-xs uppercase tracking-widest mb-3">Threats by Type</p>
          <ResponsiveContainer width="100%" height={120}>
            <BarChart data={(() => {
              const counts: Record<string, number> = {};
              threats.forEach(t => { counts[t.type] = (counts[t.type] || 0) + 1; });
              return Object.entries(counts)
                .sort((a,b) => b[1]-a[1])
                .slice(0, 12)
                .map(([type, count]) => ({ type: type.length > 14 ? type.slice(0,12)+"…" : type, count }));
            })()}>
              <XAxis dataKey="type" tick={{ fill: "#555", fontSize: 9 }} tickLine={false} axisLine={false} />
              <YAxis tick={{ fill: "#555", fontSize: 9 }} tickLine={false} axisLine={false} />
              <Tooltip contentStyle={{ background: "#0a0a0f", border: "1px solid #00ff8820", borderRadius: 8, fontSize: 11 }}
                       labelStyle={{ color: "#aaa" }} />
              <Bar dataKey="count" name="Count" radius={[4,4,0,0]}>
                {threats.map((_, i) => <Cell key={i} fill={PIE_COLORS[i % PIE_COLORS.length]} />)}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        </div>

      </div>
    </main>
  );
}
