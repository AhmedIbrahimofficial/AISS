"use client";
import { useState } from "react";
import Link from "next/link";
import { Shield, Menu, X } from "lucide-react";
import { SignInButton, SignUpButton, UserButton, useAuth } from "@clerk/nextjs";

const LINKS = [
  { label: "Home",       href: "/"           },
  { label: "Features",   href: "/features"   },
  { label: "About",      href: "/about"      },
  { label: "Kill Chain", href: "/kill-chain" },
  { label: "Importance", href: "/importance" },
  { label: "Docs",       href: "/docs"       },
  { label: "Our Team",   href: "/team"       },
  { label: "Contact",    href: "/contact"    },
];

export default function SiteNav() {
  const [open, setOpen] = useState(false);
  const { isSignedIn, isLoaded } = useAuth();

  return (
    <header className="fixed top-0 left-0 right-0 z-50 px-6 py-4">
      <nav className="liquid-glass rounded-2xl max-w-6xl mx-auto px-6 py-3 flex items-center justify-between">
        {/* Logo */}
        <Link href="/" className="flex items-center gap-2 group">
          <Shield size={22} className="text-neon" />
          <span className="font-bold text-white text-lg tracking-tight">
            AI<span className="text-neon">SS</span>
          </span>
        </Link>

        {/* Desktop links */}
        <div className="hidden md:flex items-center gap-8">
          {LINKS.map((l) => (
            <Link
              key={l.href}
              href={l.href}
              className="text-sm text-white/70 hover:text-neon transition-colors duration-200 font-medium"
            >
              {l.label}
            </Link>
          ))}
        </div>

        {/* CTA — desktop */}
        <div className="hidden md:flex items-center gap-3">
          {isLoaded && !isSignedIn && (
            <>
              <SignInButton mode="modal">
                <button className="text-white/60 hover:text-white text-sm font-medium transition-colors">
                  Sign In
                </button>
              </SignInButton>
              <SignUpButton mode="modal">
                <button className="btn-neon-solid text-sm px-5 py-2">
                  Get Started
                </button>
              </SignUpButton>
            </>
          )}

          {isLoaded && isSignedIn && (
            <>
              <Link href="/dashboard" className="text-white/70 hover:text-neon text-sm font-medium transition-colors">
                Dashboard
              </Link>
              <UserButton
                appearance={{
                  elements: { avatarBox: "w-8 h-8" },
                }}
              />
            </>
          )}
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
              className="text-sm text-white/70 hover:text-neon transition-colors font-medium py-1"
            >
              {l.label}
            </Link>
          ))}

          {isLoaded && !isSignedIn && (
            <>
              <SignUpButton mode="modal">
                <button className="btn-neon-solid text-sm text-center mt-2 w-full py-2">
                  Get Started
                </button>
              </SignUpButton>
              <SignInButton mode="modal">
                <button className="text-center text-neon text-sm font-medium py-1 w-full">
                  Sign In
                </button>
              </SignInButton>
            </>
          )}

          {isLoaded && isSignedIn && (
            <>
              <Link href="/dashboard" onClick={() => setOpen(false)}
                className="btn-neon text-sm text-center mt-2">
                Dashboard
              </Link>
              <div className="flex justify-center">
                <UserButton />
              </div>
            </>
          )}
        </div>
      )}
    </header>
  );
}
