"use client";
import { motion } from "framer-motion";
import { ExternalLink, Globe, Link2 } from "lucide-react";

const TEAM = [
  {
    name: "Ahmed Ibrahim",
    role: "Founder & Lead Developer",
    bio: "Full-stack engineer specializing in cybersecurity systems, FastAPI, and AI integrations. Built the core threat engine and all detection modules.",
    initials: "AI",
    color: "#00ff88",
    links: { github: "https://github.com/AhmedIbrahimofficial" },
  },
  {
    name: "Core Engine",
    role: "Threat Detection System",
    bio: "AI-powered autonomous agent that monitors, analyzes, and responds to threats 24/7. Powered by Claude AI with MITRE ATT&CK framework support.",
    initials: "CE",
    color: "#00ccff",
    links: {},
  },
  {
    name: "Auth Guard",
    role: "Authentication Monitor",
    bio: "Detects brute force attacks, credential stuffing, and privilege escalation in real-time across Windows Event Logs and Linux auth files.",
    initials: "AG",
    color: "#ff6b6b",
    links: {},
  },
  {
    name: "Network Sentinel",
    role: "Network Monitor",
    bio: "Tracks port scans, C2 traffic, DNS hijacking and ARP spoofing. Cross-platform support using native OS tools.",
    initials: "NS",
    color: "#ffd166",
    links: {},
  },
  {
    name: "File Inspector",
    role: "File & Malware Scanner",
    bio: "Scans temp directories for malicious scripts, computes SHA256 hashes against threat intel, and monitors for ransomware extension patterns.",
    initials: "FI",
    color: "#c77dff",
    links: {},
  },
  {
    name: "Response Engine",
    role: "Auto-Response System",
    bio: "Automatically blocks IPs via firewall rules, terminates malicious processes, quarantines files, and flushes DNS — on Windows and Linux.",
    initials: "RE",
    color: "#ff9f1c",
    links: {},
  },
];

export default function TeamPage() {
  return (
    <main className="bg-black min-h-screen pt-28 pb-20 px-6">
      <div className="max-w-6xl mx-auto">

        {/* Header */}
        <motion.div
          initial={{ opacity: 0, y: 30 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.7 }}
          className="mb-16"
        >
          <p className="section-label">Our Team</p>
          <h1 className="text-5xl md:text-6xl font-bold text-white leading-tight mb-4">
            The people &<br />
            <span className="text-neon">systems behind CyberSec</span>
          </h1>
          <p className="text-white/50 text-lg max-w-xl">
            A lean team of developers, detection modules, and an AI analyst working
            together to keep your infrastructure safe around the clock.
          </p>
        </motion.div>

        {/* Team grid */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
          {TEAM.map((member, i) => (
            <motion.div
              key={i}
              initial={{ opacity: 0, y: 40 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.6, delay: i * 0.1 }}
              className="cyber-card p-6 group"
            >
              {/* Avatar */}
              <div
                className="w-14 h-14 rounded-2xl flex items-center justify-center text-black font-bold text-xl mb-4"
                style={{ background: member.color }}
              >
                {member.initials}
              </div>

              <h3 className="text-white font-bold text-lg mb-1">{member.name}</h3>
              <p className="text-sm mb-3" style={{ color: member.color }}>
                {member.role}
              </p>
              <p className="text-white/50 text-sm leading-relaxed mb-4">{member.bio}</p>

              {/* Links */}
              {Object.keys(member.links).length > 0 && (
                <div className="flex gap-3 pt-3 border-t border-white/10">
                  {member.links.github && (
                    <a href={member.links.github} target="_blank" rel="noopener noreferrer"
                       className="text-white/40 hover:text-neon transition-colors">
                      <ExternalLink size={16} />
                    </a>
                  )}
                </div>
              )}
            </motion.div>
          ))}
        </div>

        {/* Hiring note */}
        <motion.div
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          transition={{ duration: 0.6, delay: 0.8 }}
          className="mt-16 cyber-card p-8 text-center"
        >
          <h2 className="text-2xl font-bold text-white mb-2">Want to contribute?</h2>
          <p className="text-white/50 mb-6">
            CyberSec is open source. We welcome contributions to detection modules,
            response engine, and frontend.
          </p>
          <a
            href="https://github.com/AhmedIbrahimofficial/cybersecurity-backend"
            target="_blank"
            rel="noopener noreferrer"
            className="btn-neon inline-flex items-center gap-2"
          >
            <ExternalLink size={16} />
            View on GitHub
          </a>
        </motion.div>

      </div>
    </main>
  );
}
