"use client";

import { FormEvent, useEffect, useState } from "react";
import { useRouter } from "next/navigation";

export default function LoginPage() {
  const router = useRouter();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    fetch("/api/auth/me")
      .then((r) => r.json())
      .then((d) => {
        if (!d.setupComplete) router.replace("/setup");
        else if (d.user) router.replace("/dashboard");
      })
      .catch(() => undefined);
  }, [router]);

  async function onSubmit(e: FormEvent) {
    e.preventDefault();
    setLoading(true);
    setError("");
    const res = await fetch("/api/auth/login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email, password }),
    });
    const data = await res.json();
    if (!res.ok) {
      setError(data.error || "Login failed");
      setLoading(false);
      if (data.setupRequired) router.replace("/setup");
      return;
    }
    router.replace("/dashboard");
  }

  return (
    <main className="grid-noise flex min-h-screen items-center justify-center px-6">
      <form onSubmit={onSubmit} className="panel animate-rise w-full max-w-md space-y-5 p-8">
        <div>
          <p className="mono text-xs tracking-[0.25em] text-[var(--accent)]">AISS</p>
          <h1 className="mt-2 text-3xl font-bold">Sign in</h1>
          <p className="mt-1 text-sm text-[var(--muted)]">Access the security control plane</p>
        </div>
        <label className="block">
          <span className="mono text-xs text-[var(--muted)]">Email</span>
          <input
            type="email"
            className="mt-2 w-full rounded-xl border border-[var(--line)] bg-black/20 px-4 py-3 outline-none focus:border-[var(--accent)]"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            required
          />
        </label>
        <label className="block">
          <span className="mono text-xs text-[var(--muted)]">Password</span>
          <input
            type="password"
            className="mt-2 w-full rounded-xl border border-[var(--line)] bg-black/20 px-4 py-3 outline-none focus:border-[var(--accent)]"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            required
          />
        </label>
        {error && <p className="text-sm text-[var(--danger)]">{error}</p>}
        <button
          type="submit"
          disabled={loading}
          className="w-full rounded-xl bg-[var(--accent)] px-4 py-3 font-semibold text-[#04201c] hover:brightness-110 disabled:opacity-60"
        >
          {loading ? "Signing in…" : "Enter dashboard"}
        </button>
      </form>
    </main>
  );
}
