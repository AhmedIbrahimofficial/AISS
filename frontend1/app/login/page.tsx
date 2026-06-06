"use client";
import { useState } from "react";
import Link from "next/link";
import { Shield, Mail, Lock, Eye, EyeOff, AlertCircle } from "lucide-react";
import { parseApiError } from "../lib/apiError";
import { saveTokens, fetchProfile } from "../lib/auth";

export default function LoginPage() {
  const [form, setForm]       = useState({ email: "", password: "" });
  const [showPass, setShowPass] = useState(false);
  const [loading, setLoading]  = useState(false);
  const [error, setError]      = useState("");

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setError("");
    setLoading(true);

    try {
      const res = await fetch("http://localhost:8000/api/auth/login", {
        method:  "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body:    new URLSearchParams({
          username: form.email,   // backend uses username field
          password: form.password,
        }),
      });

      const data = await res.json();

      if (!res.ok) {
        setError(parseApiError(data, "Login failed"));
        return;
      }

      // Fetch profile to get is_verified
      const profile = await fetchProfile(data.access_token);

      // Save tokens — 7 day cookies, permanent localStorage
      saveTokens(data.access_token, data.refresh_token, profile?.is_verified as boolean ?? false);

      // Redirect — honour ?next= param
      const params  = new URLSearchParams(window.location.search);
      const nextUrl = params.get("next") || "/dashboard";
      window.location.href = profile?.is_verified ? nextUrl : "/verify-pending";

    } catch {
      setError("Cannot connect to server. Make sure the backend is running.");
    } finally {
      setLoading(false);
    }
  }

  return (
    <main className="bg-black min-h-screen flex items-center justify-center px-4 pt-16">

      {/* Background grid */}
      <div className="fixed inset-0 pointer-events-none"
        style={{
          backgroundImage: `linear-gradient(rgba(0,255,136,0.03) 1px, transparent 1px),
                            linear-gradient(90deg, rgba(0,255,136,0.03) 1px, transparent 1px)`,
          backgroundSize: "40px 40px",
        }}
      />

      <div className="relative w-full max-w-md">

        {/* Logo */}
        <div className="text-center mb-8">
          <div className="inline-flex items-center gap-3 mb-4">
            <div className="w-10 h-10 rounded-xl bg-neon/10 border border-neon/30 flex items-center justify-center">
              <Shield size={20} className="text-neon" />
            </div>
            <span className="text-white font-bold text-2xl">
              Cyber<span className="text-neon">Sec</span>
            </span>
          </div>
          <h1 className="text-3xl font-bold text-white mb-2">Welcome back</h1>
          <p className="text-white/40 text-sm">Sign in to your account</p>
        </div>

        {/* Card */}
        <div className="cyber-card p-8">

          {/* Error */}
          {error && (
            <div className="flex items-center gap-3 bg-red-500/10 border border-red-500/20 rounded-xl px-4 py-3 mb-6">
              <AlertCircle size={16} className="text-red-400 shrink-0" />
              <p className="text-red-400 text-sm">{error}</p>
            </div>
          )}

          <form onSubmit={handleSubmit} className="space-y-5">

            {/* Email */}
            <div>
              <label className="text-white/50 text-xs uppercase tracking-widest block mb-2">
                Email
              </label>
              <div className="relative">
                <Mail size={16} className="absolute left-4 top-1/2 -translate-y-1/2 text-white/30" />
                <input
                  type="email"
                  required
                  placeholder="you@example.com"
                  value={form.email}
                  onChange={e => setForm({ ...form, email: e.target.value })}
                  className="w-full bg-white/5 border border-white/10 rounded-xl pl-11 pr-4 py-3 text-white text-sm placeholder:text-white/20 outline-none focus:border-neon/50 transition-colors"
                />
              </div>
            </div>

            {/* Password */}
            <div>
              <label className="text-white/50 text-xs uppercase tracking-widest block mb-2">
                Password
              </label>
              <div className="relative">
                <Lock size={16} className="absolute left-4 top-1/2 -translate-y-1/2 text-white/30" />
                <input
                  type={showPass ? "text" : "password"}
                  required
                  placeholder="••••••••••••"
                  value={form.password}
                  onChange={e => setForm({ ...form, password: e.target.value })}
                  className="w-full bg-white/5 border border-white/10 rounded-xl pl-11 pr-12 py-3 text-white text-sm placeholder:text-white/20 outline-none focus:border-neon/50 transition-colors"
                />
                <button
                  type="button"
                  onClick={() => setShowPass(!showPass)}
                  className="absolute right-4 top-1/2 -translate-y-1/2 text-white/30 hover:text-white/60 transition-colors"
                >
                  {showPass ? <EyeOff size={16} /> : <Eye size={16} />}
                </button>
              </div>
            </div>

            {/* Forgot password */}
            <div className="flex justify-end">
              <Link href="/forgot-password" className="text-neon text-xs hover:underline">
                Forgot password?
              </Link>
            </div>

            {/* Submit */}
            <button
              type="submit"
              disabled={loading}
              className="btn-neon-solid w-full py-3 text-base font-semibold flex items-center justify-center gap-2 disabled:opacity-50"
            >
              {loading ? (
                <>
                  <span className="w-4 h-4 border-2 border-black/30 border-t-black rounded-full animate-spin" />
                  Signing in...
                </>
              ) : (
                "Sign In"
              )}
            </button>

          </form>

          {/* Divider */}
          <div className="flex items-center gap-4 my-6">
            <div className="flex-1 h-px bg-white/10" />
            <span className="text-white/20 text-xs">or</span>
            <div className="flex-1 h-px bg-white/10" />
          </div>

          {/* Register link */}
          <p className="text-center text-white/40 text-sm">
            Don&apos;t have an account?{" "}
            <Link href="/register" className="text-neon hover:underline font-medium">
              Create one
            </Link>
          </p>

        </div>

        {/* Back to home */}
        <p className="text-center mt-6">
          <Link href="/" className="text-white/30 text-sm hover:text-white/60 transition-colors">
            ← Back to home
          </Link>
        </p>

      </div>
    </main>
  );
}
