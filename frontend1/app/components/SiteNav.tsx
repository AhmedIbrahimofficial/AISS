"use client";
import { useState } from "react";
import Link from "next/link";
import { Shield, Menu, X, Lock } from "lucide-react";

const LINKS = [
  { label: "Home",       href: "/",           protected: false },
  { label: "About",      href: "/about",      protected: false },
  { label: "Kill Chain", href: "/kill-chain", protected: false },
  { label: "Importance", href: "/importance", protected: true  },
  { label: "Docs",       href: "/docs",       protected: true  },
  { label: "Our Team",   href: "/team",       protected: true  },
  { label: "Contact",    href: "/contact",    protected: false },
];

export default function SiteNav() {
  const [open, setOpen] = useState(false);

  return (
    <header className="fixed top-0 left-0 right-0 z-50 px-6 py-4">
      <nav className="liquid-glass rounded-2xl max-w-6xl mx-auto px-6 py-3 flex items-center justify-between">
        {/* Logo */}
        <Link href="/" className="flex items-center gap-2 group">
          <Shield size={22} className="text-neon" />
          <span className="font-bold text-white text-lg tracking-tight">
            Cyber<span className="text-neon">Sec</span>
          </span>
        </Link>

        {/* Desktop links */}
        <div className="hidden md:flex items-center gap-8">
          {LINKS.map((l) => (
            <Link
              key={l.href}
              href={l.href}
              className="text-sm text-white/70 hover:text-neon transition-colors duration-200 font-medium flex items-center gap-1"
            >
              {l.label}
              {l.protected && (
                <Lock size={10} className="text-neon/40" />
              )}
            </Link>
          ))}
        </div>

        {/* CTA */}
        <div className="hidden md:flex items-center gap-3">
          <Link href="/login" className="text-white/60 hover:text-white text-sm font-medium transition-colors">
            Sign In
          </Link>
          <Link href="/register" className="btn-neon-solid text-sm px-5 py-2">
            Get Started
          </Link>
        </div>

        {/* Mobile toggle */}
        <button
          className="md:hidden text-white/70 hover:text-white"
          onClick={() => setOpen(!open)}
        >
          {open ? <X size={22} /> : <Menu size={22} />}
        </button>
      </nav>

      {/* Mobile menu */}
      {open && (
        <div className="md:hidden liquid-glass rounded-2xl max-w-6xl mx-auto mt-2 px-6 py-4 flex flex-col gap-4">
          {LINKS.map((l) => (
            <Link
              key={l.href}
              href={l.href}
              onClick={() => setOpen(false)}
              className="text-sm text-white/70 hover:text-neon transition-colors font-medium py-1 flex items-center gap-2"
            >
              {l.label}
              {l.protected && <Lock size={10} className="text-neon/40" />}
            </Link>
          ))}
          <Link href="/docs" className="btn-neon text-sm text-center mt-2">
            Get Started
          </Link>
          <Link href="/login" className="text-center text-neon text-sm font-medium py-1">
            Sign In
          </Link>
          <Link href="/register" className="btn-neon-solid text-sm text-center">
            Register
          </Link>
        </div>
      )}
    </header>
  );
}
