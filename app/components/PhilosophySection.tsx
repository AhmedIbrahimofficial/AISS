"use client";
import { useRef } from "react";
import { motion, useInView } from "framer-motion";

const VIDEO_URL =
  "https://d8j0ntlcm91z4.cloudfront.net/user_38xzZboKViGWJOttwIXH07lWA1P/hf_20260307_083826_e938b29f-a43a-41ec-a153-3d4730578ab8.mp4";

const MODULES = [
  {
    label: "Detection",
    title: "6 modules. Zero blind spots.",
    desc: "Network Monitor, Auth Guard, File Inspector, Malware Scanner, AI Analyst, and Response Engine work in parallel — scanning every attack surface every 5 seconds.",
  },
  {
    label: "Response",
    title: "Automated, not manual.",
    desc: "When a threat is confirmed, the Response Engine acts immediately — blocking IPs via Windows Firewall or iptables, killing malicious processes, quarantining files, flushing DNS.",
  },
];

export default function PhilosophySection() {
  const ref = useRef(null);
  const inView = useInView(ref, { once: true, margin: "-80px" });

  return (
    <section className="bg-black py-28 md:py-40 px-6 overflow-hidden">
      <div className="max-w-6xl mx-auto" ref={ref}>

        {/* Heading */}
        <motion.div
          initial={{ opacity: 0, y: 40 }}
          animate={inView ? { opacity: 1, y: 0 } : {}}
          transition={{ duration: 0.8 }}
          className="mb-16 md:mb-20"
        >
          <p className="section-label">Architecture</p>
          <h2 className="text-5xl md:text-7xl lg:text-8xl font-bold text-white tracking-tight">
            Detect <span className="text-neon">×</span> Respond
          </h2>
        </motion.div>

        {/* Two-col */}
        <div className="grid grid-cols-1 md:grid-cols-2 gap-8 md:gap-12">

          {/* Left — video */}
          <motion.div
            initial={{ opacity: 0, x: -40 }}
            animate={inView ? { opacity: 1, x: 0 } : {}}
            transition={{ duration: 0.8, delay: 0.2 }}
            className="rounded-3xl overflow-hidden aspect-[4/3] relative"
            style={{ border: "1px solid rgba(0,255,136,0.15)" }}
          >
            <video
              src={VIDEO_URL}
              muted autoPlay loop playsInline preload="auto"
              className="w-full h-full object-cover"
            />
            {/* Neon scan line effect */}
            <div
              className="absolute inset-0 pointer-events-none"
              style={{
                background: "linear-gradient(transparent 50%, rgba(0,255,136,0.02) 50%)",
                backgroundSize: "100% 4px",
              }}
            />
          </motion.div>

          {/* Right — text blocks */}
          <motion.div
            initial={{ opacity: 0, x: 40 }}
            animate={inView ? { opacity: 1, x: 0 } : {}}
            transition={{ duration: 0.8, delay: 0.3 }}
            className="flex flex-col justify-center gap-8"
          >
            {MODULES.map((m, i) => (
              <div key={i}>
                <p className="section-label text-[10px] mb-3">{m.label}</p>
                <h3 className="text-white font-bold text-xl md:text-2xl mb-3 tracking-tight">
                  {m.title}
                </h3>
                <p className="text-white/50 text-base leading-relaxed">{m.desc}</p>
                {i < MODULES.length - 1 && (
                  <div className="w-full h-px bg-white/10 mt-8" />
                )}
              </div>
            ))}
          </motion.div>

        </div>
      </div>
    </section>
  );
}
