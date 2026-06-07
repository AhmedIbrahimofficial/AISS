"use client";
import { useRef } from "react";
import { motion, useInView } from "framer-motion";
import { Activity, AlertTriangle, CheckCircle } from "lucide-react";

const VIDEO_URL =
  "https://d8j0ntlcm91z4.cloudfront.net/user_38xzZboKViGWJOttwIXH07lWA1P/hf_20260402_054547_9875cfc5-155a-4229-8ec8-b7ba7125cbf8.mp4";

const THREAT_FEED = [
  { type: "CRITICAL", msg: "Ransomware activity detected — 23 files encrypted",  time: "0.3s ago",  color: "#ff4444" },
  { type: "HIGH",     msg: "Brute force on root — 142 attempts from 45.33.32.156", time: "1.1s ago", color: "#ff9900" },
  { type: "HIGH",     msg: "XMRig cryptominer process detected (PID 4821)",        time: "2.4s ago", color: "#ff9900" },
  { type: "RESOLVED", msg: "IP 45.33.32.156 blocked via firewall",                time: "2.5s ago", color: "#00ff88" },
  { type: "CRITICAL", msg: "C2 traffic to 185.220.101.34:8443 detected",          time: "3.9s ago", color: "#ff4444" },
];

export default function FeaturedVideoSection() {
  const ref = useRef(null);
  const inView = useInView(ref, { once: true, margin: "-80px" });

  return (
    <section className="bg-black pt-6 pb-20 md:pb-32 px-6 overflow-hidden">
      <div className="max-w-6xl mx-auto" ref={ref}>

        <motion.p
          initial={{ opacity: 0, y: 20 }}
          animate={inView ? { opacity: 1, y: 0 } : {}}
          transition={{ duration: 0.6 }}
          className="section-label mb-4"
        >
          Live Demo
        </motion.p>

        <motion.h2
          initial={{ opacity: 0, y: 30 }}
          animate={inView ? { opacity: 1, y: 0 } : {}}
          transition={{ duration: 0.7, delay: 0.1 }}
          className="text-3xl md:text-5xl font-bold text-white mb-10 tracking-tight"
        >
          Real-time threat feed —{" "}
          <span className="text-neon">every second matters.</span>
        </motion.h2>

        <motion.div
          initial={{ opacity: 0, y: 60 }}
          animate={inView ? { opacity: 1, y: 0 } : {}}
          transition={{ duration: 0.9, delay: 0.15 }}
          className="rounded-3xl overflow-hidden relative"
          style={{ border: "1px solid rgba(0,255,136,0.15)" }}
        >
          {/* Video */}
          <div className="aspect-video relative">
            <video
              src={VIDEO_URL}
              muted autoPlay loop playsInline preload="auto"
              className="w-full h-full object-cover"
            />
            {/* Gradient overlay */}
            <div className="absolute inset-0 bg-gradient-to-t from-black/80 via-black/20 to-transparent" />

            {/* Live badge */}
            <div className="absolute top-4 left-4 flex items-center gap-2 bg-black/60 border border-red-500/30 rounded-full px-3 py-1.5">
              <span className="w-2 h-2 rounded-full bg-red-500 animate-pulse" />
              <span className="text-red-400 text-xs font-bold tracking-widest">LIVE</span>
            </div>

            {/* Threat feed overlay */}
            <div className="absolute bottom-0 left-0 right-0 p-6 md:p-8">
              <div className="flex flex-col md:flex-row gap-6 items-end">

                {/* Left — threat log */}
                <div className="cyber-card p-4 md:p-5 flex-1 max-w-lg"
                     style={{ background: "rgba(0,0,0,0.7)" }}>
                  <div className="flex items-center gap-2 mb-3">
                    <Activity size={14} className="text-neon" />
                    <span className="text-neon text-xs font-bold tracking-widest uppercase">Threat Log</span>
                  </div>
                  <div className="space-y-2">
                    {THREAT_FEED.map((t, i) => (
                      <div key={i} className="flex items-start gap-3 text-xs">
                        <span
                          className="font-bold shrink-0 mt-0.5"
                          style={{ color: t.color, minWidth: 56 }}
                        >
                          {t.type}
                        </span>
                        <span className="text-white/60 leading-relaxed flex-1">{t.msg}</span>
                        <span className="text-white/30 shrink-0">{t.time}</span>
                      </div>
                    ))}
                  </div>
                </div>

                {/* Right — action button */}
                <motion.a
                  href="/docs"
                  whileHover={{ scale: 1.05 }}
                  whileTap={{ scale: 0.95 }}
                  className="btn-neon-solid flex items-center gap-2 shrink-0"
                >
                  <CheckCircle size={16} />
                  Deploy Now
                </motion.a>

              </div>
            </div>
          </div>
        </motion.div>

      </div>
    </section>
  );
}
