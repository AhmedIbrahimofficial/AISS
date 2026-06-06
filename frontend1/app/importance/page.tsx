"use client";
import { motion } from "framer-motion";
import { AlertTriangle, TrendingUp, DollarSign, Clock, Lock, Users } from "lucide-react";

const THREATS = [
  { stat: "$9.5T",  label: "Global cybercrime cost in 2024",        icon: DollarSign },
  { stat: "2,200+", label: "Cyberattacks happen every single day",   icon: AlertTriangle },
  { stat: "197",    label: "Average days to identify a breach",      icon: Clock },
  { stat: "95%",    label: "Breaches caused by human error",         icon: Users },
];

const REASONS = [
  {
    icon: TrendingUp,
    title: "Attacks are growing exponentially",
    desc: "Ransomware, phishing, and supply chain attacks have increased by over 300% since 2020. No organization is too small to be targeted.",
  },
  {
    icon: Clock,
    title: "Speed is everything",
    desc: "The average attacker moves laterally within 1 hour 58 minutes of initial access. Manual detection simply cannot keep up.",
  },
  {
    icon: DollarSign,
    title: "The cost of inaction is catastrophic",
    desc: "The average cost of a data breach reached $4.88 million in 2024. Early detection reduces this by up to 80%.",
  },
  {
    icon: Lock,
    title: "Compliance is non-negotiable",
    desc: "GDPR, HIPAA, SOC 2, and ISO 27001 all require active threat monitoring. Non-compliance fines can exceed millions.",
  },
  {
    icon: AlertTriangle,
    title: "Insider threats are rising",
    desc: "34% of breaches involve internal actors. Monitoring privilege escalation and unusual access patterns is critical.",
  },
  {
    icon: Users,
    title: "Remote work expanded the attack surface",
    desc: "With distributed teams, endpoints are everywhere. Brute force and credential stuffing attacks have surged 30x.",
  },
];

export default function ImportancePage() {
  return (
    <main className="bg-black min-h-screen pt-28 pb-20 px-6">
      <div className="max-w-5xl mx-auto">

        {/* Hero */}
        <motion.div initial={{ opacity: 0, y: 30 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.7 }} className="mb-20">
          <p className="section-label">Why It Matters</p>
          <h1 className="text-5xl md:text-7xl font-bold text-white leading-tight mb-6">
            Cybersecurity is not<br />
            <span className="text-neon">optional anymore.</span>
          </h1>
          <p className="text-white/50 text-xl max-w-2xl leading-relaxed">
            The threat landscape has changed forever. Here is what the data says —
            and why automated, AI-driven defense is the only viable path forward.
          </p>
        </motion.div>

        {/* Stats */}
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-20">
          {THREATS.map((t, i) => (
            <motion.div
              key={i}
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.5, delay: i * 0.1 }}
              className="cyber-card p-6 text-center"
            >
              <t.icon size={20} className="text-neon mx-auto mb-3" />
              <p className="text-3xl font-bold text-white mb-1">{t.stat}</p>
              <p className="text-white/40 text-xs leading-snug">{t.label}</p>
            </motion.div>
          ))}
        </div>

        {/* Why CyberSec */}
        <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} transition={{ duration: 0.6, delay: 0.3 }} className="mb-16">
          <p className="section-label">6 Reasons</p>
          <h2 className="text-3xl font-bold text-white mb-10">
            Why every team needs active threat monitoring
          </h2>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            {REASONS.map((r, i) => (
              <motion.div
                key={i}
                initial={{ opacity: 0, y: 30 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ duration: 0.5, delay: 0.4 + i * 0.08 }}
                className="cyber-card p-6 flex gap-4"
              >
                <div className="w-10 h-10 rounded-lg bg-neon/10 border border-neon/20 flex items-center justify-center flex-shrink-0 mt-1">
                  <r.icon size={18} className="text-neon" />
                </div>
                <div>
                  <h3 className="text-white font-semibold mb-2">{r.title}</h3>
                  <p className="text-white/50 text-sm leading-relaxed">{r.desc}</p>
                </div>
              </motion.div>
            ))}
          </div>
        </motion.div>

        {/* CTA */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.6, delay: 0.8 }}
          className="cyber-card p-10 text-center"
        >
          <h2 className="text-3xl font-bold text-white mb-3">Ready to protect your infrastructure?</h2>
          <p className="text-white/50 mb-6">Deploy CyberSec in minutes. No SOC team required.</p>
          <div className="flex gap-4 justify-center flex-wrap">
            <a href="/docs" className="btn-neon-solid">Read the Docs</a>
            <a href="/contact" className="btn-neon">Talk to Us</a>
          </div>
        </motion.div>

      </div>
    </main>
  );
}
