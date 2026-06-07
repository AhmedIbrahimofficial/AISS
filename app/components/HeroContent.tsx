"use client";
import { useRef, useState } from "react";
import { Shield, ArrowRight, Zap, Lock } from "lucide-react";
import Link from "next/link";

export default function HeroContent() {
  const [email, setEmail] = useState("");

  return (
    <div className="relative z-10 flex-1 flex flex-col items-center justify-center px-6 py-12 text-center">

      {/* Badge */}
      <div className="inline-flex items-center gap-2 liquid-glass border border-[#00ff88]/20 rounded-full px-4 py-2 mb-8">
        <span className="w-2 h-2 rounded-full bg-[#00ff88] animate-pulse" />
        <span className="text-[#00ff88] text-xs font-semibold tracking-widest uppercase">
          AI-Powered Threat Detection — Active
        </span>
      </div>

      {/* Main heading */}
      <h1 className="text-5xl md:text-7xl lg:text-8xl font-bold text-white tracking-tight leading-tight mb-6 max-w-4xl">
        Detect. Analyze.{" "}
        <span className="text-[#00ff88]" style={{ textShadow: "0 0 40px rgba(0,255,136,0.4)" }}>
          Neutralize.
        </span>
      </h1>

      {/* Subheading */}
      <p className="text-white/50 text-lg md:text-xl max-w-2xl mb-10 leading-relaxed">
        An AI-powered security platform that monitors your infrastructure
        24/7 — detecting threats in real-time and responding automatically.
      </p>

      {/* CTA buttons */}
      <div className="flex flex-wrap items-center justify-center gap-4 mb-12">
        <Link href="/docs" className="btn-neon-solid flex items-center gap-2 text-base px-8 py-3">
          <Zap size={18} />
          Get Started Free
        </Link>
        <Link href="/about" className="btn-neon flex items-center gap-2 text-base px-8 py-3">
          <Shield size={18} />
          Learn More
        </Link>
      </div>

      {/* Stats row */}
      <div className="flex flex-wrap items-center justify-center gap-8 text-center">
        {[
          { value: "25+",  label: "Threat Types" },
          { value: "< 1s", label: "Detection Time" },
          { value: "100%", label: "Cross-Platform" },
        ].map((s, i) => (
          <div key={i}>
            <p className="text-2xl font-bold text-[#00ff88]">{s.value}</p>
            <p className="text-white/40 text-xs uppercase tracking-widest mt-1">{s.label}</p>
          </div>
        ))}
      </div>

    </div>
  );
}
