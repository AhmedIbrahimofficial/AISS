"use client";
import { useRef } from "react";
import { motion, useInView } from "framer-motion";
import { ArrowUpRight } from "lucide-react";

const CARDS = [
  {
    videoUrl:
      "https://d8j0ntlcm91z4.cloudfront.net/user_38xzZboKViGWJOttwIXH07lWA1P/hf_20260314_131748_f2ca2a28-fed7-44c8-b9a9-bd9acdd5ec31.mp4",
    tag:   "Network & Auth",
    title: "Intrusion Detection",
    desc:  "Port scans, C2 traffic, DNS hijacking, ARP spoofing, brute force attacks — detected and blocked automatically across Windows and Linux.",
  },
  {
    videoUrl:
      "https://d8j0ntlcm91z4.cloudfront.net/user_38xzZboKViGWJOttwIXH07lWA1P/hf_20260324_151826_c7218672-6e92-402c-9e45-f1e0f454bdc4.mp4",
    tag:   "Malware & Files",
    title: "Malware Elimination",
    desc:  "Cryptominers, ransomware, trojans, rootkits, keyloggers — identified by process signatures, file hashes, and behavioral patterns. Quarantined instantly.",
  },
];

export default function ServicesSection() {
  const ref = useRef(null);
  const inView = useInView(ref, { once: true, margin: "-80px" });

  return (
    <section className="bg-black py-28 md:py-40 px-6 overflow-hidden">
      <div
        className="absolute inset-0 pointer-events-none"
        style={{
          background:
            "radial-gradient(ellipse at center, rgba(0,255,136,0.02) 0%, transparent 60%)",
        }}
      />

      <div className="max-w-6xl mx-auto relative" ref={ref}>

        {/* Header */}
        <motion.div
          initial={{ opacity: 0, y: 30 }}
          animate={inView ? { opacity: 1, y: 0 } : {}}
          transition={{ duration: 0.7 }}
          className="flex items-end justify-between mb-12 md:mb-16"
        >
          <div>
            <p className="section-label">Capabilities</p>
            <h2 className="text-3xl md:text-5xl font-bold text-white tracking-tight">
              What CyberSec defends against
            </h2>
          </div>
          <span className="text-white/30 text-sm hidden md:block">Our modules</span>
        </motion.div>

        {/* Cards */}
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6 md:gap-8">
          {CARDS.map((card, i) => (
            <motion.div
              key={i}
              initial={{ opacity: 0, y: 50 }}
              animate={inView ? { opacity: 1, y: 0 } : {}}
              transition={{ duration: 0.8, delay: i * 0.15 }}
              className="group rounded-3xl overflow-hidden"
              style={{
                background: "rgba(0,255,136,0.02)",
                border: "1px solid rgba(0,255,136,0.12)",
              }}
            >
              {/* Video */}
              <div className="aspect-video relative overflow-hidden">
                <video
                  src={card.videoUrl}
                  muted autoPlay loop playsInline preload="auto"
                  className="w-full h-full object-cover transition-transform duration-700 group-hover:scale-105"
                />
                <div className="absolute inset-0 bg-gradient-to-t from-black/60 to-transparent" />

                {/* Neon scan lines */}
                <div
                  className="absolute inset-0 pointer-events-none opacity-20"
                  style={{
                    background:
                      "repeating-linear-gradient(0deg, transparent, transparent 2px, rgba(0,255,136,0.05) 2px, rgba(0,255,136,0.05) 4px)",
                  }}
                />
              </div>

              {/* Body */}
              <div className="p-6 md:p-8">
                <div className="flex items-center justify-between mb-4">
                  <span className="text-neon text-xs font-bold tracking-widest uppercase">
                    {card.tag}
                  </span>
                  <div
                    className="rounded-full p-2"
                    style={{
                      background: "rgba(0,255,136,0.08)",
                      border: "1px solid rgba(0,255,136,0.2)",
                    }}
                  >
                    <ArrowUpRight size={14} className="text-neon" />
                  </div>
                </div>
                <h3 className="text-white text-xl md:text-2xl font-bold mb-3 tracking-tight">
                  {card.title}
                </h3>
                <p className="text-white/40 text-sm leading-relaxed">{card.desc}</p>
              </div>
            </motion.div>
          ))}
        </div>

        {/* Bottom CTA */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={inView ? { opacity: 1, y: 0 } : {}}
          transition={{ duration: 0.6, delay: 0.4 }}
          className="mt-12 text-center"
        >
          <a href="/importance" className="btn-neon inline-flex items-center gap-2">
            Why Cybersecurity Matters
            <ArrowUpRight size={16} />
          </a>
        </motion.div>

      </div>
    </section>
  );
}
