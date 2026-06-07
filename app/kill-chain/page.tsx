"use client";
import { useEffect, useState } from "react";
import { motion } from "framer-motion";
import { AlertTriangle, CheckCircle, Shield, RefreshCw } from "lucide-react";

interface Stage {
  id:          string;
  label:       string;
  description: string;
  icon:        string;
  color:       string;
  threats:     Threat[];
  total:       number;
  active:      number;
  critical:    number;
  compromised: boolean;
}

interface Threat {
  id:          string;
  type:        string;
  severity:    string;
  description: string;
  status:      string;
  detected_at: string;
}

interface KillChainData {
  stages:             Stage[];
  total_threats:      number;
  stages_compromised: number;
  attack_progress:    number;
}

const SEVERITY_COLOR: Record<string, string> = {
  critical: "#ff4444",
  high:     "#ff9900",
  medium:   "#ffd166",
  low:      "#00ff88",
};

export default function KillChainPage() {
  const [data,     setData]     = useState<KillChainData | null>(null);
  const [loading,  setLoading]  = useState(true);
  const [selected, setSelected] = useState<Stage | null>(null);
  const [error,    setError]    = useState("");

  async function load() {
    setLoading(true);
    setError("");
    try {
      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), 5000);
      const res = await fetch("http://localhost:8000/api/kill-chain", {
        signal: controller.signal,
      });
      clearTimeout(timeout);
      if (!res.ok) throw new Error(`Server returned ${res.status}`);
      setData(await res.json());
    } catch (e: unknown) {
      const msg = e instanceof Error ? e.message : "";
      if (msg.includes("aborted") || msg.includes("fetch") || msg.includes("Failed")) {
        setError("backend_offline");
      } else {
        setError(msg || "backend_offline");
      }
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => { load(); }, []);

  return (
    <main className="bg-black min-h-screen pt-24 pb-20 px-6">
      <div className="max-w-6xl mx-auto">

        {/* Header */}
        <div className="flex items-start justify-between mb-10">
          <div>
            <p className="section-label">Attack Intelligence</p>
            <h1 className="text-4xl md:text-5xl font-bold text-white mb-2">
              Cyber Kill Chain
            </h1>
            <p className="text-white/40 text-sm">
              Real-time attack stage visualization based on detected threats
            </p>
          </div>
          <button
            onClick={load}
            className="btn-neon flex items-center gap-2 text-sm mt-2"
          >
            <RefreshCw size={14} className={loading ? "animate-spin" : ""} />
            Refresh
          </button>
        </div>

        {error && (
          <div className="cyber-card p-8 mb-8 text-center">
            <div className="w-14 h-14 rounded-full bg-yellow-500/10 border border-yellow-500/20 flex items-center justify-center mx-auto mb-4">
              <Shield size={26} className="text-yellow-400" />
            </div>
            <h2 className="text-white font-bold text-lg mb-2">Backend Offline</h2>
            <p className="text-white/40 text-sm mb-6">
              The cybersecurity backend is not running.<br />
              Start it with <code className="text-neon bg-neon/10 px-2 py-0.5 rounded">python main.py</code> then refresh.
            </p>
            <button
              onClick={load}
              className="btn-neon-solid flex items-center gap-2 text-sm mx-auto px-6 py-2"
            >
              <RefreshCw size={14} className={loading ? "animate-spin" : ""} />
              Retry Connection
            </button>
          </div>
        )}

        {/* Progress bar */}
        {data && (
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            className="cyber-card p-6 mb-10"
          >
            <div className="flex items-center justify-between mb-3">
              <div className="flex items-center gap-3">
                <Shield size={18} className="text-neon" />
                <span className="text-white font-semibold">Attack Progress</span>
              </div>
              <span className="text-neon font-bold text-lg">
                {data.attack_progress}%
              </span>
            </div>

            <div className="w-full h-3 bg-white/5 rounded-full overflow-hidden mb-4">
              <motion.div
                initial={{ width: 0 }}
                animate={{ width: `${data.attack_progress}%` }}
                transition={{ duration: 1, ease: "easeOut" }}
                className="h-full rounded-full"
                style={{
                  background: data.attack_progress > 60
                    ? "linear-gradient(90deg, #ff9900, #ff4444)"
                    : "linear-gradient(90deg, #00ff88, #ffd166)",
                }}
              />
            </div>

            <div className="grid grid-cols-3 gap-4 text-center">
              {[
                { label: "Total Threats",      value: data.total_threats,      color: "#fff"     },
                { label: "Stages Compromised", value: data.stages_compromised, color: "#ff9900"  },
                { label: "Attack Progress",    value: `${data.attack_progress}%`, color: "#ff4444" },
              ].map((s, i) => (
                <div key={i}>
                  <p className="text-2xl font-bold" style={{ color: s.color }}>{s.value}</p>
                  <p className="text-white/40 text-xs mt-1">{s.label}</p>
                </div>
              ))}
            </div>
          </motion.div>
        )}

        {/* Kill Chain stages */}
        {loading && !data && (
          <div className="text-center py-20">
            <div className="w-10 h-10 border-2 border-neon/30 border-t-neon rounded-full animate-spin mx-auto mb-4" />
            <p className="text-white/40">Loading kill chain...</p>
          </div>
        )}

        {data && (
          <div className="space-y-4">
            {data.stages.map((stage, i) => (
              <motion.div
                key={stage.id}
                initial={{ opacity: 0, x: -30 }}
                animate={{ opacity: 1, x: 0 }}
                transition={{ duration: 0.4, delay: i * 0.07 }}
              >
                {/* Stage row */}
                <button
                  onClick={() => setSelected(selected?.id === stage.id ? null : stage)}
                  className="w-full text-left"
                >
                  <div
                    className="rounded-2xl p-5 flex items-center gap-5 transition-all duration-200 group"
                    style={{
                      background: stage.compromised
                        ? `rgba(${hexToRgb(stage.color)}, 0.08)`
                        : "rgba(255,255,255,0.02)",
                      border: `1px solid ${stage.compromised
                        ? `rgba(${hexToRgb(stage.color)}, 0.3)`
                        : "rgba(255,255,255,0.08)"}`,
                    }}
                  >
                    {/* Stage number */}
                    <div
                      className="w-10 h-10 rounded-xl flex items-center justify-center text-xl shrink-0 font-bold"
                      style={{
                        background: stage.compromised
                          ? `rgba(${hexToRgb(stage.color)}, 0.15)`
                          : "rgba(255,255,255,0.05)",
                        border: `1px solid ${stage.compromised
                          ? `rgba(${hexToRgb(stage.color)}, 0.4)`
                          : "rgba(255,255,255,0.1)"}`,
                      }}
                    >
                      {stage.icon}
                    </div>

                    {/* Stage info */}
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-3 mb-1">
                        <span className="text-white font-bold">{stage.label}</span>
                        {stage.compromised && (
                          <span
                            className="text-xs px-2 py-0.5 rounded-full font-bold"
                            style={{
                              background: `rgba(${hexToRgb(stage.color)}, 0.15)`,
                              color: stage.color,
                              border: `1px solid rgba(${hexToRgb(stage.color)}, 0.3)`,
                            }}
                          >
                            COMPROMISED
                          </span>
                        )}
                        {!stage.compromised && (
                          <span className="text-xs px-2 py-0.5 rounded-full font-bold text-neon/70"
                            style={{ background: "rgba(0,255,136,0.05)", border: "1px solid rgba(0,255,136,0.15)" }}>
                            CLEAR
                          </span>
                        )}
                      </div>
                      <p className="text-white/40 text-xs">{stage.description}</p>
                    </div>

                    {/* Stats */}
                    <div className="flex items-center gap-4 shrink-0">
                      {stage.total > 0 && (
                        <>
                          <div className="text-center">
                            <p className="text-white font-bold">{stage.total}</p>
                            <p className="text-white/30 text-xs">threats</p>
                          </div>
                          {stage.critical > 0 && (
                            <div className="text-center">
                              <p className="font-bold" style={{ color: "#ff4444" }}>{stage.critical}</p>
                              <p className="text-white/30 text-xs">critical</p>
                            </div>
                          )}
                        </>
                      )}

                      {stage.compromised
                        ? <AlertTriangle size={18} style={{ color: stage.color }} />
                        : <CheckCircle  size={18} className="text-neon/40" />
                      }
                    </div>
                  </div>
                </button>

                {/* Expanded threats */}
                {selected?.id === stage.id && stage.threats.length > 0 && (
                  <motion.div
                    initial={{ opacity: 0, height: 0 }}
                    animate={{ opacity: 1, height: "auto" }}
                    className="mt-2 ml-4 space-y-2"
                  >
                    {stage.threats.map((t) => (
                      <div
                        key={t.id}
                        className="rounded-xl p-4 flex items-start gap-4"
                        style={{
                          background: "rgba(0,0,0,0.5)",
                          border: `1px solid ${SEVERITY_COLOR[t.severity] ?? "#ffffff22"}33`,
                        }}
                      >
                        <div
                          className="w-2 h-2 rounded-full mt-1.5 shrink-0"
                          style={{ background: SEVERITY_COLOR[t.severity] ?? "#fff" }}
                        />
                        <div className="flex-1 min-w-0">
                          <div className="flex items-center gap-3 mb-1 flex-wrap">
                            <span className="text-white text-sm font-medium">{t.type}</span>
                            <span
                              className="text-xs px-2 py-0.5 rounded-full font-bold uppercase"
                              style={{
                                color: SEVERITY_COLOR[t.severity],
                                background: `${SEVERITY_COLOR[t.severity]}15`,
                                border: `1px solid ${SEVERITY_COLOR[t.severity]}40`,
                              }}
                            >
                              {t.severity}
                            </span>
                            <span className={`text-xs px-2 py-0.5 rounded-full ${
                              t.status === "active" ? "text-red-400 bg-red-500/10" : "text-neon/60 bg-neon/5"
                            }`}>
                              {t.status}
                            </span>
                          </div>
                          <p className="text-white/50 text-xs leading-relaxed">{t.description}</p>
                          <p className="text-white/20 text-xs mt-1">
                            {new Date(t.detected_at).toLocaleString()}
                          </p>
                        </div>
                      </div>
                    ))}
                  </motion.div>
                )}

                {selected?.id === stage.id && stage.threats.length === 0 && (
                  <motion.div
                    initial={{ opacity: 0 }}
                    animate={{ opacity: 1 }}
                    className="mt-2 ml-4 rounded-xl p-4 text-center text-white/30 text-sm"
                    style={{ background: "rgba(0,255,136,0.02)", border: "1px solid rgba(0,255,136,0.08)" }}
                  >
                    ✅ No threats detected at this stage
                  </motion.div>
                )}
              </motion.div>
            ))}
          </div>
        )}

      </div>
    </main>
  );
}

function hexToRgb(hex: string): string {
  const r = parseInt(hex.slice(1, 3), 16);
  const g = parseInt(hex.slice(3, 5), 16);
  const b = parseInt(hex.slice(5, 7), 16);
  return `${r},${g},${b}`;
}
