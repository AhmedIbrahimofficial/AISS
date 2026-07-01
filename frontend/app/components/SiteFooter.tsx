import Link from "next/link";
import { Shield } from "lucide-react";

export default function SiteFooter() {
  return (
    <footer className="border-t border-white/10 py-10 px-6 mt-20">
      <div className="max-w-6xl mx-auto flex flex-col md:flex-row items-center justify-between gap-4">
        <div className="flex items-center gap-2">
          <Shield size={20} className="text-neon" />
          <span className="font-bold text-white text-lg">
            AI<span className="text-neon">SS</span>
          </span>
        </div>
        <p className="text-white/30 text-sm">
          © 2026 AISS Platform. All rights reserved.
        </p>
        <div className="flex gap-6 text-sm text-white/40">
          <Link href="/monitor"    className="hover:text-neon transition-colors">Monitor</Link>
          <Link href="/features"   className="hover:text-neon transition-colors">Features</Link>
          <Link href="/docs"       className="hover:text-neon transition-colors">Docs</Link>
          <Link href="/contact"    className="hover:text-neon transition-colors">Contact</Link>
          <Link href="/about"      className="hover:text-neon transition-colors">About</Link>
          <Link href="/importance" className="hover:text-neon transition-colors">Importance</Link>
          <Link href="/team"       className="hover:text-neon transition-colors">Team</Link>
        </div>
      </div>
    </footer>
  );
}
