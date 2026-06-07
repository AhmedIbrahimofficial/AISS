"use client";
import { motion } from "framer-motion";
import {
  Shield, Network, Lock, FileSearch, Cpu, Zap, Brain, Eye,
  Terminal, Database, Globe, Usb, AlertTriangle, Bot, Activity,
  ArrowUpRight, CheckCircle,
} from "lucide-react";

// ── All AISS modules & capabilities ───────────────────────────────────
const MODULES = [
  {
    icon: Network,
    tag: "Network Monitor",
    color: "#00d4ff",
    title: "Network Intrusion Detection",
    desc: "Detects port scans, DDoS attacks, MITM, ARP spoofing, C2 traffic, DNS hijacking, DNS tunneling, lateral movement, and data exfiltration — in real-time across Windows and Linux.",
    bullets: ["Port scan detection (SYN, stealth, full connect)", "C2 beacon & callback traffic analysis", "ARP spoofing & MITM detection", "DNS hijacking via baseline comparison", "Data exfiltration volume monitoring"],
  },
  {
    icon: Lock,
    tag: "Auth Monitor",
    color: "#ff6b6b",
    title: "Authentication Attack Detection",
    desc: "Monitors Windows Event Logs and Linux auth files for every type of authentication-based attack pattern including impossible travel detection.",
    bullets: ["Brute force & credential stuffing", "Password spray detection", "Privilege escalation alerts", "Impossible travel (same user, 2 IPs < 5 min)", "Session anomaly & unusual-hour login detection"],
  },
  {
    icon: FileSearch,
    tag: "File Monitor",
    color: "#c77dff",
    title: "File System & Ransomware Detection",
    desc: "Watches temp directories, downloads, and system folders for malicious scripts, ransomware extension patterns, and file hash matching against known threat intel.",
    bullets: ["Ransomware extension pattern matching", "Malicious script detection (.ps1, .vbs, .bat)", "SHA-256 hash comparison against threat intel", "Mass file modification rate monitoring", "Suspicious file creation alerts"],
  },
  {
    icon: Cpu,
    tag: "Malware Scanner",
    color: "#ffd166",
    title: "Malware & Process Analysis",
    desc: "Scans running processes and memory for 25+ malware types including cryptominers, keyloggers, rootkits, trojans, botnets, and fileless malware.",
    bullets: ["XMRig & cryptominer process detection", "Keylogger behavioral signatures", "Rootkit & hidden process scanning", "Botnet C2 communication patterns", "Fileless malware via memory inspection"],
  },
  {
    icon: Brain,
    tag: "AI Analyst",
    color: "#00ff88",
    title: "Claude AI Threat Analysis",
    desc: "Every detected threat is analyzed by Claude AI which provides MITRE ATT&CK mapping, IOC extraction, step-by-step response plans, and severity assessment automatically.",
    bullets: ["MITRE ATT&CK tactic & technique mapping", "IOC (Indicator of Compromise) extraction", "Expert response plan generation", "False positive reasoning", "Threat correlation across events"],
  },
  {
    icon: Zap,
    tag: "Response Engine",
    color: "#ff9f1c",
    title: "Automated Threat Response",
    desc: "When a threat is confirmed, AISS acts immediately — no human required. Blocks, kills, quarantines, and flushes DNS across Windows and Linux.",
    bullets: ["IP blocking via Windows Firewall / iptables", "Malicious process termination (taskkill / kill)", "File quarantine to isolated directory", "DNS cache flushing", "Admin alert broadcast via WebSocket"],
  },
  {
    icon: Eye,
    tag: "Deception Tech",
    color: "#00ccff",
    title: "Honeypot & Deception Layer",
    desc: "Deploys fake credentials, API keys, and admin panels as traps. Any access to these honeypots instantly triggers a CRITICAL alert with the attacker's IP and behaviour.",
    bullets: ["Fake admin panel at /admin route", "Rotating honeypot credentials & API keys", "Fake AWS/Stripe keys as bait", "Instant CRITICAL alert on any access", "Attacker IP + behaviour logging"],
  },
  {
    icon: Usb,
    tag: "USB Monitor",
    color: "#ff4488",
    title: "USB & Removable Media Monitoring",
    desc: "Detects when USB drives and removable media are connected. Scans them automatically for malware, suspicious scripts, and autorun threats.",
    bullets: ["Real-time USB insertion detection", "Auto-scan on connect", "Malicious autorun.inf detection", "Removable media malware scanning", "Cross-platform Windows & Linux support"],
  },
  {
    icon: Terminal,
    tag: "Kill Chain",
    color: "#88ff00",
    title: "MITRE Kill Chain Mapping",
    desc: "Maps every detected threat to the Lockheed Martin Cyber Kill Chain and MITRE ATT&CK framework, showing exactly which stage of an attack is in progress.",
    bullets: ["7-stage kill chain visualization", "MITRE ATT&CK tactic mapping", "Real-time stage progression tracking", "Per-threat kill chain breakdown", "Attack pattern correlation"],
  },
  {
    icon: Bot,
    tag: "SOC Assistant",
    color: "#00ffcc",
    title: "AI SOC Chat Assistant",
    desc: "An always-available AI security analyst you can ask anything — CVE lookups, mitigation strategies, threat explanations, and incident response guidance.",
    bullets: ["Natural language threat Q&A", "CVE lookup & explanation", "Mitigation step recommendations", "False positive analysis", "Incident response guidance"],
  },
  {
    icon: Activity,
    tag: "Self Learner",
    color: "#ff88cc",
    title: "Keyword & Pattern Self-Learning",
    desc: "AISS learns new threat patterns from cybersecurity video transcripts and research, continuously expanding its detection vocabulary without retraining.",
    bullets: ["Video transcript analysis for new threats", "Dynamic keyword threat vocabulary", "Auto-expanding malware name database", "Suspicious port pattern learning", "Zero-config continuous improvement"],
  },
  {
    icon: Database,
    tag: "Infrastructure",
    color: "#aaaaff",
    title: "Production-Grade Backend",
    desc: "Built with FastAPI, SQLAlchemy async ORM, JWT authentication, rate limiting, WebSocket real-time feed, and SQLite/PostgreSQL support — ready for production.",
    bullets: ["FastAPI + SQLAlchemy async ORM", "JWT access + refresh tokens", "Role-based access (admin / analyst / viewer)", "WebSocket real-time threat broadcast", "SQLite (dev) or PostgreSQL (prod)"],
  },
];

const STATS = [
  { value: "25+",  label: "Threat Types" },
  { value: "12",   label: "Detection Modules" },
  { value: "< 1s", label: "Detection Speed" },
  { value: "100%", label: "Cross-Platform" },
];

export default function FeaturesPage() {
  return (
    <main className="bg-black min-h-screen pt-28 pb-24 px-6">
      <div className="max-w-6xl mx-auto">

        {/* Header */}
        <motion.div
          initial={{ opacity: 0, y: 30 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.7 }}
          className="mb-16 text-center"
        >
          <p className="section-label">All Features</p>
          <h1 className="text-5xl md:text-7xl font-bold text-white leading-tight mb-6">
            Everything AISS<br />
            <span className="text-neon">does for you.</span>
          </h1>
          <p className="text-white/50 text-lg md:text-xl max-w-2xl mx-auto leading-relaxed">
            12 detection and response modules working in parallel — 24/7, fully autonomous,
            zero configuration required after setup.
          </p>
        </motion.div>

        {/* Stats bar */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.6, delay: 0.15 }}
          className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-20"
        >
          {STATS.map((s, i) => (
            <div key={i} className="cyber-card p-6 text-center">
              <p className="text-3xl md:text-4xl font-bold text-neon mb-1">{s.value}</p>
              <p className="text-white/50 text-sm">{s.label}</p>
            </div>
          ))}
        </motion.div>

        {/* Modules grid */}
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
          {MODULES.map((mod, i) => (
            <motion.div
              key={i}
              initial={{ opacity: 0, y: 40 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.6, delay: 0.05 * i }}
              className="cyber-card p-6 group"
            >
              {/* Top row */}
              <div className="flex items-start justify-between mb-4">
                <div className="flex items-center gap-3">
                  <div
                    className="w-10 h-10 rounded-xl flex items-center justify-center flex-shrink-0"
                    style={{ background: `${mod.color}15`, border: `1px solid ${mod.color}30` }}
                  >
                    <mod.icon size={20} style={{ color: mod.color }} />
                  </div>
                  <span
                    className="text-xs font-bold tracking-widest uppercase"
                    style={{ color: mod.color }}
                  >
                    {mod.tag}
                  </span>
                </div>
                <ArrowUpRight size={16} className="text-white/20 group-hover:text-neon transition-colors mt-1" />
              </div>

              {/* Title + desc */}
              <h3 className="text-white font-bold text-lg mb-2 tracking-tight">{mod.title}</h3>
              <p className="text-white/50 text-sm leading-relaxed mb-4">{mod.desc}</p>

              {/* Bullets */}
              <ul className="space-y-1.5 pt-4 border-t border-white/5">
                {mod.bullets.map((b, j) => (
                  <li key={j} className="flex items-start gap-2 text-xs text-white/40">
                    <CheckCircle size={12} className="mt-0.5 flex-shrink-0" style={{ color: mod.color }} />
                    {b}
                  </li>
                ))}
              </ul>
            </motion.div>
          ))}
        </div>

        {/* CTA */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.6, delay: 0.6 }}
          className="mt-20 cyber-card p-10 text-center"
        >
          <Globe size={32} className="text-neon mx-auto mb-4" />
          <h2 className="text-3xl font-bold text-white mb-3">Ready to deploy AISS?</h2>
          <p className="text-white/50 mb-8 max-w-xl mx-auto">
            One command. All 12 modules active. Works on Windows and Linux.
          </p>
          <div className="flex gap-4 justify-center flex-wrap">
            <a href="/docs" className="btn-neon-solid flex items-center gap-2">
              <Zap size={16} />
              Get Started
            </a>
            <a href="/about" className="btn-neon flex items-center gap-2">
              <Shield size={16} />
              Learn More
            </a>
          </div>
        </motion.div>

      </div>
    </main>
  );
}
