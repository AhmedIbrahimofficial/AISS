"use client";
import { Globe, X, Link, ExternalLink } from "lucide-react";

const SOCIALS = [
  { icon: ExternalLink, label: "GitHub",  href: "https://github.com/AhmedIbrahimofficial/cybersecurity-backend" },
  { icon: X,            label: "Twitter", href: "#" },
  { icon: Globe,        label: "Website", href: "#" },
];

export default function HeroSocials() {
  return (
    <div className="relative z-10 flex justify-center gap-3 pb-10">
      {SOCIALS.map((s) => (
        <a
          key={s.label}
          href={s.href}
          target="_blank"
          rel="noopener noreferrer"
          title={s.label}
          className="liquid-glass rounded-full p-3 text-white/50 hover:text-[#00ff88] border border-white/10 hover:border-[#00ff88]/30 transition-all duration-200"
        >
          <s.icon size={18} />
        </a>
      ))}
    </div>
  );
}
