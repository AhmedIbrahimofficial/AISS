"use client";

import { FormEvent, useEffect, useState } from "react";
import { useRouter } from "next/navigation";

export default function SetupPage() {
  const router = useRouter();
  const [org, setOrg] = useState("AISS Security Ops");
  const [email, setEmail] = useState("admin@aiss.local");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);
  const [groq, setGroq] = useState(false);

  useEffect(() => {
    fetch("/api/setup")
      .then((r) => r.json())
      .then((d) => {
        setGroq(Boolean(d.groqConfigured));
        if (d.setupComplete) router.replace("/login");
      })
      .catch(() => undefined);
  }, [router]);

  async function onSubmit(e: FormEvent) {
    e.preventDefault();
    setLoading(true);
    setError("");
    try {
      const res = await fetch("/api/setup", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          organizationName: org,
          adminEmail: email,
          adminPassword: password,
          autoRemediateLowMedium: true,
          requireApprovalHighCritical: true,
        }),
      });
      const data = await res.json();
      if (!res.ok) {
        setError(typeof data.error === "string" ? data.error : "Setup failed");
        setLoading(false);
        return;
      }
      router.replace("/dashboard");
    } catch {
      setError("Network error");
      setLoading(false);
    }
  }

  return (
    <main className="grid-noise relative min-h-screen px-6 py-16">
      <div className="mx-auto max-w-xl animate-rise">
        <p className="mono text-xs tracking-[0.25em] text-[var(--accent)]">ONE-TIME SETUP</p>
        <h1 className="mt-3 text-5xl font-extrabold tracking-tight">AISS</h1>
        <p className="mt-3 max-w-md text-[var(--muted)]">
          Configure your autonomous security control plane once. After this, the Security Gate and
          incident pipeline start protecting automatically.
        </p>

        <form onSubmit={onSubmit} className="panel mt-10 space-y-5 p-7">
          <label className="block">
            <span className="mono text-xs text-[var(--muted)]">Organization</span>
            <input
              className="mt-2 w-full rounded-xl border border-[var(--line)] bg-black/20 px-4 py-3 outline-none focus:border-[var(--accent)]"
              value={org}
              onChange={(e) => setOrg(e.target.value)}
              required
            />
          </label>
          <label className="block">
            <span className="mono text-xs text-[var(--muted)]">Admin email</span>
            <input
              type="email"
              className="mt-2 w-full rounded-xl border border-[var(--line)] bg-black/20 px-4 py-3 outline-none focus:border-[var(--accent)]"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              required
            />
          </label>
          <label className="block">
            <span className="mono text-xs text-[var(--muted)]">Admin password (min 8)</span>
            <input
              type="password"
              className="mt-2 w-full rounded-xl border border-[var(--line)] bg-black/20 px-4 py-3 outline-none focus:border-[var(--accent)]"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              minLength={8}
              required
            />
          </label>

          <div className="rounded-xl border border-[var(--line)] bg-black/15 px-4 py-3 text-sm text-[var(--muted)]">
            Groq AI:{" "}
            <span className={groq ? "text-[var(--ok)]" : "text-[var(--warn)]"}>
              {groq ? "configured" : "set GROQ_API_KEY in env / Vercel"}
            </span>
            <div className="mt-1 text-xs">
              Gate + pipeline work without Groq. AI reasoning tools need the key.
            </div>
          </div>

          {error && <p className="text-sm text-[var(--danger)]">{error}</p>}

          <button
            type="submit"
            disabled={loading}
            className="w-full rounded-xl bg-[var(--accent)] px-4 py-3 font-semibold text-[#04201c] transition hover:brightness-110 disabled:opacity-60"
          >
            {loading ? "Starting AISS…" : "Complete setup & launch"}
          </button>
        </form>
      </div>
    </main>
  );
}
