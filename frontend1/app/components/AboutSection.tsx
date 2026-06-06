"use client";
import { useRef } from "react";
import { motion, useInView } from "framer-motion";
import { Shield, Eye, Zap, Brain } from "lucide-react";

const PILLARS = [
  { icon: Eye,    title: "Always Watching",    desc: "Continuous 24/7 monitoring of network traffic, auth events, file system, and running processes." },
  { icon: Zap,    title: "Instant Response",   desc: "Threats are neutralized automatically — IPs blocked, processes killed, files quarantined in milliseconds." },
  { icon: Brain,  title: "AI Intelligence",    desc: "Claude AI provides MITRE ATT&CK analysis, IOC extraction, and response plans for every detected threat." },
  { icon: Shield, title: "Zero Blind Spots",   desc: "From ransomware to rootkits, brute force to DNS hijacking — 25+ threat types across all attack surfaces." },
];

export default function AboutSection() {
  const ref = useRef(null);
  const inView = useInView(ref, { once: true, margin: "-80px" });

  return (
    <section ref={ref} className="bg-black py-28 md:py-36 px-6 overflow-hidden">
      <div className="max-w-6xl mx-auto">

        {/* Label */}
        <motion.p
          initial={{ opacity: 0, y: 20 }}
          animate={inView ? { opacity: 1, y: 0 } : {}}
          transition={{ duration: 0.6 }}
          className="section-label"
        >
          The Platform
        </motion.p>

        {/* Heading */}
        <motion.h2
          initial={{ opacity: 0, y: 40 }}
          animate={inView ? { opacity: 1, y: 0 } : {}}
          transition={{ duration: 0.8, delay: 0.1 }}
          className="text-4xl md:text-6xl lg:text-7xl font-bold text-white leading-tight tracking-tight mb-6"
        >
          Built to stop threats{" "}
          <span className="text-neon">before they spread.</span>
        </motion.h2>

        <motion.p
          initial={{ opacity: 0, y: 20 }}
          animate={inView ? { opacity: 1, y: 0 } : {}}
          transition={{ duration: 0.7, delay: 0.2 }}
          className="text-white/50 text-lg max-w-2xl mb-16 leading-relaxed"
        >
          CyberSec is a production-grade autonomous security platform powered by AI.
          It monitors, detects, analyzes, and responds — without waiting for a human.
        </motion.p>

        {/* Pillars grid */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-5">
          {PILLARS.map((p, i) => (
            <motion.div
              key={i}
              initial={{ opacity: 0, y: 40 }}
              animate={inView ? { opacity: 1, y: 0 } : {}}
              transition={{ duration: 0.6, delay: 0.15 + i * 0.1 }}
              className="cyber-card p-6 group"
            >
              <div className="w-10 h-10 rounded-xl bg-neon/10 border border-neon/20 flex items-center justify-center mb-4 group-hover:bg-neon/20 transition-colors">
                <p.icon size={20} className="text-neon" />
              </div>
              <h3 className="text-white font-semibold text-base mb-2">{p.title}</h3>
              <p className="text-white/40 text-sm leading-relaxed">{p.desc}</p>
            </motion.div>
          ))}
        </div>

      </div>
    </section>
  );
}
