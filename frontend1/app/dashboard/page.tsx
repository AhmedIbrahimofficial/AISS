"use client";
import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { Shield, Activity, AlertTriangle, CheckCircle, LogOut, Zap } from "lucide-react";
import { authFetch, logout as doLogout, isLoggedIn } from "../lib/auth";

interface UserProfile {
  username: string;
  email: string;
  role: string;
  is_verified: boolean;
}

interface Stats {
  total: number;
  active: number;
  resolved: number;
  critical: number;
}

export default function DashboardPage() {
  const router = useRouter();
  const [user, setUser]   = useState<UserProfile | null>(null);
  const [stats, setStats] = useState<Stats | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    if (!isLoggedIn()) {
      router.push("/login");
      return;
    }

    // Use authFetch — auto-refreshes token if expired
    Promise.all([
      authFetch("http://localhost:8000/api/auth/me").then(r => r.json()),
      authFetch("http://localhost:8000/api/threats/stats").then(r => r.json()),
    ]).then(([userData, statsData]) => {
      if (userData.error || userData.detail) {
        router.push("/login");
        return;
      }
      setUser(userData);
      setStats(statsData);
    }).catch(() => {
      router.push("/login");
    }).finally(() => setLoading(false));
  }, [router]);

  function logout() {
    doLogout();
  }

  if (loading) {
    return (
      <main className="bg-black min-h-screen flex items-center justify-center pt-16">
        <div className="text-center">
          <div className="w-10 h-10 border-2 border-neon/30 border-t-neon rounded-full animate-spin mx-auto mb-4" />
          <p className="text-white/40 text-sm">Loading dashboard...</p>
        </div>
      </main>
    );
  }

  return (
    <main className="bg-black min-h-screen pt-24 pb-16 px-6">
      <div className="max-w-5xl mx-auto">

        {/* Header */}
        <div className="flex items-center justify-between mb-10">
          <div>
            <p className="section-label">Dashboard</p>
            <h1 className="text-3xl font-bold text-white">
              Welcome back, <span className="text-neon">{user?.username}</span>
            </h1>
            <p className="text-white/40 text-sm mt-1">{user?.email}</p>
          </div>
          <div className="flex items-center gap-3">
            <span className="text-xs px-3 py-1 rounded-full border"
              style={{
                color: user?.role === "admin" ? "#00ff88" : "#999",
                borderColor: user?.role === "admin" ? "rgba(0,255,136,0.3)" : "rgba(255,255,255,0.1)",
                background: user?.role === "admin" ? "rgba(0,255,136,0.05)" : "transparent",
              }}>
              {user?.role?.toUpperCase()}
            </span>
            <button onClick={logout}
              className="flex items-center gap-2 text-white/40 hover:text-red-400 transition-colors text-sm border border-white/10 hover:border-red-500/30 rounded-lg px-4 py-2">
              <LogOut size={15} />
              Logout
            </button>
          </div>
        </div>

        {/* Email not verified warning */}
        {user && !user.is_verified && (
          <div className="cyber-card p-4 mb-8 border-yellow-500/20 bg-yellow-500/5 flex items-center gap-3">
            <AlertTriangle size={16} className="text-yellow-400 shrink-0" />
            <p className="text-yellow-400 text-sm">
              Your email is not verified. Check your inbox for a verification link.
            </p>
          </div>
        )}

        {/* Stats */}
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-10">
          {[
            { icon: Activity,      label: "Total Threats",    value: stats?.total    ?? 0, color: "#fff" },
            { icon: AlertTriangle, label: "Active Threats",   value: stats?.active   ?? 0, color: "#ff4444" },
            { icon: CheckCircle,   label: "Resolved",         value: stats?.resolved ?? 0, color: "#00ff88" },
            { icon: Zap,           label: "Critical",         value: stats?.critical ?? 0, color: "#ff9900" },
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
            { label: "View All Threats", href: "/api/threats/",          icon: Shield },
            { label: "API Docs",         href: "http://localhost:8000/docs", icon: Activity },
            { label: "Run Simulation",   href: "/docs",                  icon: Zap },
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
