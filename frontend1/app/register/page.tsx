"use client";
import { useState } from "react";
import Link from "next/link";
import { Shield, Mail, Lock, User, Eye, EyeOff, AlertCircle, CheckCircle } from "lucide-react";
import { parseApiError } from "../lib/apiError";

const PASSWORD_RULES = [
  { test: (p: string) => p.length >= 12,          label: "At least 12 characters" },
  { test: (p: string) => /[A-Z]/.test(p),         label: "One uppercase letter" },
  { test: (p: string) => /[a-z]/.test(p),         label: "One lowercase letter" },
  { test: (p: string) => /\d/.test(p),            label: "One number" },
  { test: (p: string) => /[!@#$%^&*(),.?]/.test(p), label: "One special character" },
];

export default function RegisterPage() {
  const [form, setForm]       = useState({ username: "", email: "", password: "", confirm: "" });
  const [showPass, setShowPass] = useState(false);
  const [loading, setLoading]  = useState(false);
  const [error, setError]      = useState("");
  const [success, setSuccess]  = useState(false);

  const passwordStrength = PASSWORD_RULES.filter(r => r.test(form.password)).length;

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setError("");

    if (form.password !== form.confirm) {
      setError("Passwords do not match");
      return;
    }
    if (passwordStrength < PASSWORD_RULES.length) {
      setError("Password does not meet requirements");
      return;
    }

    setLoading(true);
    try {
      const res = await fetch("http://localhost:8000/api/auth/register", {
        method:  "POST",
        headers: { "Content-Type": "application/json" },
        body:    JSON.stringify({
          username: form.username,
          email:    form.email,
          password: form.password,
        }),
      });

      const data = await res.json();

      if (!res.ok) {
        setError(parseApiError(data, "Registration failed"));
        return;
      }

      setSuccess(true);

    } catch {
      setError("Cannot connect to server. Make sure the backend is running.");
    } finally {
      setLoading(false);
    }
  }

  if (success) {
    return (
      <main className="bg-black min-h-screen flex items-center justify-center px-4 pt-16">
        <div className="w-full max-w-md text-center">
          <div className="cyber-card p-10">
            <div className="w-16 h-16 rounded-full bg-neon/10 border border-neon/30 flex items-center justify-center mx-auto mb-6">
              <CheckCircle size={32} className="text-neon" />
            </div>
            <h2 className="text-2xl font-bold text-white mb-3">Account created!</h2>
            <p className="text-white/50 text-sm mb-6">
              We sent a verification link to{" "}
              <span className="text-neon">{form.email}</span>.
              Please check your inbox and verify your email before logging in.
            </p>
            <Link href="/login" className="btn-neon-solid inline-block px-8 py-3">
              Go to Login
            </Link>
          </div>
        </div>
      </main>
    );
  }

  return (
    <main className="bg-black min-h-screen flex items-center justify-center px-4 py-20">

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
          <h1 className="text-3xl font-bold text-white mb-2">Create account</h1>
          <p className="text-white/40 text-sm">Join the CyberSec platform</p>
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

            {/* Username */}
            <div>
              <label className="text-white/50 text-xs uppercase tracking-widest block mb-2">Username</label>
              <div className="relative">
                <User size={16} className="absolute left-4 top-1/2 -translate-y-1/2 text-white/30" />
                <input
                  type="text"
                  required
                  minLength={3}
                  maxLength={32}
                  placeholder="your_username"
                  value={form.username}
                  onChange={e => setForm({ ...form, username: e.target.value })}
                  className="w-full bg-white/5 border border-white/10 rounded-xl pl-11 pr-4 py-3 text-white text-sm placeholder:text-white/20 outline-none focus:border-neon/50 transition-colors"
                />
              </div>
            </div>

            {/* Email */}
            <div>
              <label className="text-white/50 text-xs uppercase tracking-widest block mb-2">Email</label>
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
              <label className="text-white/50 text-xs uppercase tracking-widest block mb-2">Password</label>
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
                <button type="button" onClick={() => setShowPass(!showPass)}
                  className="absolute right-4 top-1/2 -translate-y-1/2 text-white/30 hover:text-white/60">
                  {showPass ? <EyeOff size={16} /> : <Eye size={16} />}
                </button>
              </div>

              {/* Strength bar */}
              {form.password && (
                <div className="mt-2">
                  <div className="flex gap-1 mb-2">
                    {PASSWORD_RULES.map((_, i) => (
                      <div key={i} className="flex-1 h-1 rounded-full transition-colors"
                        style={{ background: i < passwordStrength ? "#00ff88" : "rgba(255,255,255,0.1)" }}
                      />
                    ))}
                  </div>
                  <div className="space-y-1">
                    {PASSWORD_RULES.map((rule, i) => (
                      <div key={i} className="flex items-center gap-2 text-xs">
                        <div className={`w-3 h-3 rounded-full border flex items-center justify-center
                          ${rule.test(form.password) ? "bg-neon border-neon" : "border-white/20"}`}>
                          {rule.test(form.password) && (
                            <svg width="8" height="6" viewBox="0 0 8 6">
                              <path d="M1 3l2 2 4-4" stroke="#000" strokeWidth="1.5" fill="none" strokeLinecap="round"/>
                            </svg>
                          )}
                        </div>
                        <span className={rule.test(form.password) ? "text-white/60" : "text-white/30"}>
                          {rule.label}
                        </span>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>

            {/* Confirm password */}
            <div>
              <label className="text-white/50 text-xs uppercase tracking-widest block mb-2">Confirm Password</label>
              <div className="relative">
                <Lock size={16} className="absolute left-4 top-1/2 -translate-y-1/2 text-white/30" />
                <input
                  type="password"
                  required
                  placeholder="••••••••••••"
                  value={form.confirm}
                  onChange={e => setForm({ ...form, confirm: e.target.value })}
                  className={`w-full bg-white/5 border rounded-xl pl-11 pr-4 py-3 text-white text-sm placeholder:text-white/20 outline-none transition-colors
                    ${form.confirm && form.confirm !== form.password
                      ? "border-red-500/50 focus:border-red-500"
                      : "border-white/10 focus:border-neon/50"}`}
                />
              </div>
              {form.confirm && form.confirm !== form.password && (
                <p className="text-red-400 text-xs mt-1">Passwords do not match</p>
              )}
            </div>

            {/* Submit */}
            <button
              type="submit"
              disabled={loading || passwordStrength < PASSWORD_RULES.length}
              className="btn-neon-solid w-full py-3 text-base font-semibold flex items-center justify-center gap-2 disabled:opacity-50"
            >
              {loading ? (
                <>
                  <span className="w-4 h-4 border-2 border-black/30 border-t-black rounded-full animate-spin" />
                  Creating account...
                </>
              ) : (
                "Create Account"
              )}
            </button>

          </form>

          <div className="flex items-center gap-4 my-6">
            <div className="flex-1 h-px bg-white/10" />
            <span className="text-white/20 text-xs">or</span>
            <div className="flex-1 h-px bg-white/10" />
          </div>

          <p className="text-center text-white/40 text-sm">
            Already have an account?{" "}
            <Link href="/login" className="text-neon hover:underline font-medium">Sign in</Link>
          </p>

        </div>

        <p className="text-center mt-6">
          <Link href="/" className="text-white/30 text-sm hover:text-white/60 transition-colors">
            ← Back to home
          </Link>
        </p>

      </div>
    </main>
  );
}
