"use client";
import { Globe } from "lucide-react";

export default function Navbar() {
  return (
    <div className="relative z-20 px-6 py-6">
      <div className="liquid-glass rounded-full max-w-5xl mx-auto px-6 py-3 flex items-center justify-between">
        {/* Left: Logo */}
        <div className="flex items-center gap-2">
          <Globe size={24} className="text-white" />
          <span className="text-white font-semibold text-lg">Asme</span>
          {/* Nav links hidden on mobile */}
          <nav className="hidden md:flex items-center gap-8 ml-8">
            {["Features", "Pricing", "About"].map((item) => (
              <a
                key={item}
                href="#"
                className="text-white/80 hover:text-white text-sm font-medium transition-colors duration-200"
              >
                {item}
              </a>
            ))}
          </nav>
        </div>

        {/* Right: Auth buttons */}
        <div className="flex items-center gap-4">
          <button className="text-white text-sm font-medium hover:text-white/80 transition-colors cursor-pointer">
            Sign Up
          </button>
          <button className="liquid-glass rounded-full px-6 py-2 text-white text-sm font-medium hover:bg-white/5 transition-colors cursor-pointer">
            Login
          </button>
        </div>
      </div>
    </div>
  );
}
