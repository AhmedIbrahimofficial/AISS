"use client";
import { useRef } from "react";
import { motion, useInView } from "framer-motion";
import { Shield, Zap, Database, Lock, Activity, Brain } from "lucide-react";

const FEATURES = [
  { icon: Shield,   title: "Threat Detection",     desc: "Real-time monitoring of network, auth, file & process activity across Windows and Linux." },
  { icon: Zap,      title: "Auto Response",         desc: "Automatically blocks IPs, kills malicious processes, quarantines files — zero human intervention needed." },
  { icon: Brain,    title: "AI Analysis",            desc: "Claude AI provides MITRE ATT&CK mapping, IOC extraction, and step-by-step response plans per threat." },
  { icon: Database, title: "PostgreSQL Storage",     desc: "All threats persist across restarts with SQLAlchemy ORM — users, threats, blocked IPs, scan results." },
  { icon: Lock,     title: "JWT Authentication",     desc: "Secure bcrypt passwords, role-based access (admin/analyst/viewer), account lockout protection." },
  { icon: Activity, title: "WebSocket Feed",         desc: "Real-time threat notifications pushed to all connected clients instantly via secure WebSocket." },
];

const STATS = [
  { value: "25+",  label: "Threat Types Detected" },
  { value: "6",    label: "Detection Modules" },
  { value: "31",   label: "API Endpoints" },
  { value: "100%", label: "Cross-Platform" },
];

export default function ProjectSection() {
  const ref = useRef(null);
  const inView = useInView(ref, { once: true, margin: "-80px" });

  return (
    <section className="cyber-grid bg-black py-28 px-6 overflow-hidden" ref={ref}>
      <div className="max-w-6xl mx-auto">

        {/* Header */}
        <motion.div
          initial={{ opacity: 0, y: 30 }}
          animate={inView ? { opacity: 1, y: 0 } : {}}
          transition={{ duration: 0.7 }}
          className="text-center mb-16"
        >
          <p className="section-label">The Platform</p>
          <h2 className="text-4xl md:text-5xl lg:text-6xl font-bold text-white mb-4 leading-tight">
            AI-Powered <span className="text-neon">AISS</span><br />
            Detection & Response
          </h2>
          <p className="text-white/50 text-lg max-w-2xl mx-auto">
            A production-grade backend that monitors your system 24/7, detects threats in real-time,
            and automatically neutralizes them — built with FastAPI, PostgreSQL & Claude AI.
          </p>
        </motion.div>

        {/* Stats */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={inView ? { opacity: 1, y: 0 } : {}}
          transition={{ duration: 0.6, delay: 0.15 }}
          className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-16"
        >
          {STATS.map((s, i) => (
            <div key={i} className="cyber-card p-6 text-center">
              <p className="text-3xl md:text-4xl font-bold text-neon mb-1">{s.value}</p>
              <p className="text-white/50 text-sm">{s.label}</p>
            </div>
          ))}
        </motion.div>

        {/* Feature grid */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
          {FEATURES.map((f, i) => (
            <motion.div
              key={i}
              initial={{ opacity: 0, y: 40 }}
              animate={inView ? { opacity: 1, y: 0 } : {}}
              transition={{ duration: 0.6, delay: 0.1 + i * 0.08 }}
              className="cyber-card p-6 group"
            >
              <div className="w-10 h-10 rounded-lg bg-neon/10 border border-neon/20 flex items-center justify-center mb-4 group-hover:bg-neon/20 transition-colors">
                <f.icon size={20} className="text-neon" />
              </div>
              <h3 className="text-white font-semibold text-lg mb-2">{f.title}</h3>
              <p className="text-white/50 text-sm leading-relaxed">{f.desc}</p>
            </motion.div>
          ))}
        </div>

      </div>
    </section>
  );
}
