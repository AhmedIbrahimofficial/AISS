"use client";
import { motion } from "framer-motion";
import { Shield, Target, Cpu, Globe } from "lucide-react";

const MILESTONES = [
  { year: "2024", title: "Concept & Research",   desc: "Identified the gap in affordable, AI-powered security tools for small and mid-size teams." },
  { year: "2025", title: "Core Engine Built",     desc: "Network, auth, file, and malware detection modules developed and tested on Windows & Linux." },
  { year: "2026", title: "AI Integration",        desc: "Claude AI integrated for deep threat analysis, MITRE ATT&CK mapping and auto-response plans." },
  { year: "Now",  title: "Production Ready",      desc: "PostgreSQL persistence, JWT auth, WebSocket real-time feed, rate limiting — fully production-hardened." },
];

const VALUES = [
  { icon: Shield, title: "Security First",   desc: "Every design decision prioritizes the safety and integrity of protected systems." },
  { icon: Target, title: "Precision",        desc: "Low false positives, high detection accuracy — tuned per platform and threat type." },
  { icon: Cpu,    title: "Automation",       desc: "Remove the human bottleneck. Detect, analyze, and respond in milliseconds." },
  { icon: Globe,  title: "Cross-Platform",   desc: "Works natively on Windows and Linux with zero configuration changes needed." },
];

const fade = (delay = 0) => ({
  initial: { opacity: 0, y: 30 },
  animate: { opacity: 1, y: 0 },
  transition: { duration: 0.7, delay },
});

export default function AboutPage() {
  return (
    <main className="bg-black min-h-screen pt-28 pb-20 px-6">
      <div className="max-w-5xl mx-auto">

        {/* Hero */}
        <motion.div {...fade(0)} className="mb-20">
          <p className="section-label">About</p>
          <h1 className="text-5xl md:text-7xl font-bold text-white leading-tight mb-6">
            Built by developers,<br />
            <span className="text-neon">for defenders.</span>
          </h1>
          <p className="text-white/50 text-xl max-w-2xl leading-relaxed">
            CyberSec is an AI-powered threat detection and response platform designed to give
            security teams an autonomous, always-on guardian for their infrastructure.
          </p>
        </motion.div>

        {/* Mission */}
        <motion.div {...fade(0.1)} className="cyber-card p-8 md:p-12 mb-20">
          <p className="section-label">Our Mission</p>
          <p className="text-3xl md:text-4xl text-white font-light leading-snug">
            "Make enterprise-grade threat detection accessible to every team —
            <span className="text-neon font-normal"> without needing a full SOC."</span>
          </p>
        </motion.div>

        {/* Timeline */}
        <motion.div {...fade(0.2)} className="mb-20">
          <p className="section-label">Journey</p>
          <h2 className="text-3xl font-bold text-white mb-10">How we got here</h2>
          <div className="relative border-l border-neon/20 pl-8 space-y-10">
            {MILESTONES.map((m, i) => (
              <motion.div
                key={i}
                initial={{ opacity: 0, x: -20 }}
                animate={{ opacity: 1, x: 0 }}
                transition={{ duration: 0.5, delay: 0.3 + i * 0.1 }}
              >
                <div className="absolute -left-2 w-4 h-4 rounded-full bg-neon border-2 border-black" />
                <span className="text-neon text-xs font-bold tracking-widest uppercase">{m.year}</span>
                <h3 className="text-white font-semibold text-lg mt-1 mb-1">{m.title}</h3>
                <p className="text-white/50 text-sm leading-relaxed">{m.desc}</p>
              </motion.div>
            ))}
          </div>
        </motion.div>

        {/* Values */}
        <motion.div {...fade(0.3)}>
          <p className="section-label">Our Values</p>
          <h2 className="text-3xl font-bold text-white mb-10">What drives us</h2>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            {VALUES.map((v, i) => (
              <div key={i} className="cyber-card p-6 flex gap-4">
                <div className="w-10 h-10 rounded-lg bg-neon/10 border border-neon/20 flex items-center justify-center flex-shrink-0">
                  <v.icon size={20} className="text-neon" />
                </div>
                <div>
                  <h3 className="text-white font-semibold mb-1">{v.title}</h3>
                  <p className="text-white/50 text-sm leading-relaxed">{v.desc}</p>
                </div>
              </div>
            ))}
          </div>
        </motion.div>

      </div>
    </main>
  );
}
