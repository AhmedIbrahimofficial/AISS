"use client";
import { useEffect, useState } from "react";
import { useUser } from "@clerk/nextjs";
import { Shield, Activity, AlertTriangle, CheckCircle, Zap } from "lucide-react";

interface Stats {
  total: number;
  active: number;
  resolved: number;
  critical: number;
}

export default function DashboardPage() {
  const { user, isLoaded } = useUser();
  const [stats, setStats] = useState<Stats | null>(null);
  const [statsLoading, setStatsLoading] = useState(true);

  useEffect(() => {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 5000);
    fetch("http://localhost:8000/api/threats/stats", { signal: controller.signal })
      .then(r => r.json())
      .then(data => setStats(data))
      .catch(() => setStats({ total: 0, active: 0, resolved: 0, critical: 0 }))
      .finally(() => { clearTimeout(timeout); setStatsLoading(false); });
  }, []);

  if (!isLoaded || statsLoading) {
    return (
      <main className="bg-black min-h-screen flex items-center justify-center pt-16">
        <div className="text-center">
          <div className="w-10 h-10 border-2 border-neon/30 border-t-neon rounded-full animate-spin mx-auto mb-4" />
          <p className="text-white/40 text-sm">Loading dashboard...</p>
        </div>
      </main>
    );
  }

  const displayName = user?.firstName || user?.username || user?.emailAddresses[0]?.emailAddress || "Analyst";

  return (
    <main className="bg-black min-h-screen pt-24 pb-16 px-6">
      <div className="max-w-5xl mx-auto">

        {/* Header */}
        <div className="mb-10">
          <p className="section-label">Dashboard</p>
          <h1 className="text-3xl font-bold text-white">
            Welcome back, <span className="text-neon">{displayName}</span>
          </h1>
          <p className="text-white/40 text-sm mt-1">Real-time AISS monitoring</p>
        </div>

        {/* Stats */}
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-10">
          {[
            { icon: Activity,      label: "Total Threats",  value: stats?.total    ?? 0, color: "#fff"    },
            { icon: AlertTriangle, label: "Active Threats", value: stats?.active   ?? 0, color: "#ff4444" },
            { icon: CheckCircle,   label: "Resolved",       value: stats?.resolved ?? 0, color: "#00ff88" },
            { icon: Zap,           label: "Critical",       value: stats?.critical ?? 0, color: "#ff9900" },
          ].map((s, i) => (
            <div key={i} className="cyber-card p-5 text-center">
              <s.icon size={20} className="mx-auto mb-3" style={{ color: s.color }} />
              <p className="text-3xl font-bold text-white mb-1">{s.value}</p>
              <p className="text-white/40 text-xs">{s.label}</p>
            </div>
          ))}
        </div>

        {/* Quick actions */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          {[
            { label: "View All Threats", href: "http://localhost:8000/api/threats/",  icon: Shield   },
            { label: "API Docs",         href: "http://localhost:8000/docs",           icon: Activity },
            { label: "Run Simulation",   href: "/docs",                               icon: Zap      },
          ].map((a, i) => (
            <a key={i} href={a.href} target={a.href.startsWith("http") ? "_blank" : undefined}
              className="cyber-card p-5 flex items-center gap-4 group">
              <div className="w-10 h-10 rounded-xl bg-neon/10 border border-neon/20 flex items-center justify-center group-hover:bg-neon/20 transition-colors">
                <a.icon size={18} className="text-neon" />
              </div>
              <span className="text-white font-medium text-sm">{a.label}</span>
            </a>
          ))}
        </div>

      </div>
    </main>
  );
}
