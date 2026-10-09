import { createFileRoute, useNavigate, Link } from "@tanstack/react-router";
import { useEffect, useState } from "react";
import {
  Shield, Eye, EyeOff, Lock, Mail, User, Loader2, Wifi, WifiOff,
} from "lucide-react";
import { toast } from "sonner";
import { register, login } from "@/lib/api";

export const Route = createFileRoute("/signup")({
  head: () => ({ meta: [{ title: "Sign Up — AISS" }] }),
  component: SignupPage,
});

const BASE_URL =
  (import.meta.env["VITE_AISS_API_URL"] as string | undefined) ??
  "http://localhost:8000";

function SignupPage() {
  const navigate = useNavigate();

  const [username,     setUsername]     = useState("");
  const [email,        setEmail]        = useState("");
  const [password,     setPassword]     = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [showPw,       setShowPw]       = useState(false);
  const [loading,      setLoading]      = useState(false);
  const [error,        setError]        = useState("");
  const [backendUp,    setBackendUp]    = useState<boolean | null>(null);

  // ── Poll backend health every 3 s ──────────────────────────────────
  useEffect(() => {
    let alive = true;
    const check = async () => {
      try {
        const r = await fetch(`${BASE_URL}/api/health`, {
          signal: AbortSignal.timeout(2500),
        });
        if (alive) setBackendUp(r.ok);
      } catch {
        if (alive) setBackendUp(false);
      }
    };
    void check();
    const iv = setInterval(() => void check(), 3000);
    return () => { alive = false; clearInterval(iv); };
  }, []);

  // ── Manual sign-up ─────────────────────────────────────────────────
  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!backendUp) {
      setError("Backend is not ready yet — please wait.");
      return;
    }
    if (password !== confirmPassword) {
      setError("Passwords do not match.");
      return;
    }
    if (password.length < 8) {
      setError("Password must be at least 8 characters.");
      return;
    }

    setError("");
    setLoading(true);
    try {
      await register(username, email, password);
      toast.success("Account created — logging you in…");
      // Auto-login after successful registration
      const result = await login(email, password);
      if (result.must_change_password) {
        toast.info("Please change your password to continue");
        void navigate({ to: "/change-password" });
      } else {
        toast.success("Welcome to AISS");
        void navigate({ to: "/" });
      }
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      setError(msg.toLowerCase().includes("fetch") || msg.toLowerCase().includes("network")
        ? "Cannot reach backend. Is it running?"
        : msg);
    } finally {
      setLoading(false);
    }
  };

  // ── Backend status ──────────────────────────────────────────────────
  const StatusPill = () => {
    if (backendUp === null)
      return (
        <span className="flex items-center gap-1.5 font-mono text-[0.65rem] text-muted-foreground">
          <Loader2 className="size-3 animate-spin" /> Connecting…
        </span>
      );
    if (!backendUp)
      return (
        <span className="flex items-center gap-1.5 font-mono text-[0.65rem] text-[var(--critical)]">
          <WifiOff className="size-3" /> Backend starting…
        </span>
      );
    return (
      <span className="flex items-center gap-1.5 font-mono text-[0.65rem] text-[var(--success)]">
        <Wifi className="size-3" /> Backend online
      </span>
    );
  };

  return (
    <div className="min-h-screen bg-[#070d0b] flex items-center justify-center p-4">
      <div className="pointer-events-none fixed inset-0 bg-[linear-gradient(rgba(16,185,129,0.025)_1px,transparent_1px),linear-gradient(90deg,rgba(16,185,129,0.025)_1px,transparent_1px)] bg-[size:40px_40px]" />
      <div className="pointer-events-none fixed inset-x-0 top-0 h-px bg-gradient-to-r from-transparent via-primary/40 to-transparent animate-pulse" />

      <div className="relative w-full max-w-sm">

        {/* Logo */}
        <div className="mb-8 text-center">
          <div className="relative mx-auto mb-4 flex size-16 items-center justify-center rounded-2xl border border-primary/30 bg-primary/10">
            <Shield className="size-8 text-primary" />
            <span className="absolute inset-0 animate-ping rounded-2xl border border-primary/20"
                  style={{ animationDuration: "2s" }} />
          </div>
          <h1 className="font-serif text-3xl font-bold tracking-tight">AISS</h1>
          <p className="mt-1 text-xs text-muted-foreground">AI Integrated Security System</p>
          <div className="mt-3 flex items-center justify-center">
            <StatusPill />
          </div>
        </div>

        <div className="rounded-2xl border border-[var(--hairline)] bg-[#0c1812]/90 p-7 shadow-2xl backdrop-blur-sm">

          <h2 className="mb-0.5 text-base font-semibold">Operator Sign Up</h2>
          <p className="mb-5 text-[0.7rem] text-muted-foreground">
            Create an account to access the Security Operations Console
          </p>

          {/* Backend still starting — waiting message */}
          {backendUp === false && (
            <div className="mb-4 flex items-center gap-3 rounded-lg border border-primary/20 bg-primary/5 px-4 py-3">
              <Loader2 className="size-4 animate-spin text-primary shrink-0" />
              <div>
                <p className="text-sm font-medium text-primary">Starting up…</p>
                <p className="text-[0.65rem] text-muted-foreground">
                  Backend is initializing — this takes ~30s on first start
                </p>
              </div>
            </div>
          )}

          <form onSubmit={(e) => void handleSubmit(e)} className="space-y-3.5">
            <div>
              <label className="mb-1 block text-[0.7rem] text-muted-foreground">Username</label>
              <div className="relative">
                <User className="absolute left-3 top-1/2 size-3.5 -translate-y-1/2 text-muted-foreground" />
                <input
                  type="text" value={username}
                  onChange={(e) => setUsername(e.target.value)}
                  required placeholder="operator_name" autoComplete="username"
                  minLength={3} maxLength={32}
                  className="w-full rounded-lg border border-[var(--hairline)] bg-white/4 py-2.5 pl-9 pr-4 text-sm outline-none transition placeholder:text-muted-foreground/50 focus:border-primary/50 focus:bg-white/6"
                />
              </div>
            </div>

            <div>
              <label className="mb-1 block text-[0.7rem] text-muted-foreground">Email</label>
              <div className="relative">
                <Mail className="absolute left-3 top-1/2 size-3.5 -translate-y-1/2 text-muted-foreground" />
                <input
                  type="email" value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  required placeholder="your@email.com" autoComplete="email"
                  className="w-full rounded-lg border border-[var(--hairline)] bg-white/4 py-2.5 pl-9 pr-4 text-sm outline-none transition placeholder:text-muted-foreground/50 focus:border-primary/50 focus:bg-white/6"
                />
              </div>
            </div>

            <div>
              <label className="mb-1 block text-[0.7rem] text-muted-foreground">Password</label>
              <div className="relative">
                <Lock className="absolute left-3 top-1/2 size-3.5 -translate-y-1/2 text-muted-foreground" />
                <input
                  type={showPw ? "text" : "password"} value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  required placeholder="••••••••" autoComplete="new-password"
                  minLength={8}
                  className="w-full rounded-lg border border-[var(--hairline)] bg-white/4 py-2.5 pl-9 pr-10 text-sm outline-none transition placeholder:text-muted-foreground/50 focus:border-primary/50 focus:bg-white/6"
                />
                <button type="button" onClick={() => setShowPw(v => !v)}
                  aria-label={showPw ? "Hide password" : "Show password"}
                  className="absolute right-3 top-1/2 -translate-y-1/2 text-muted-foreground hover:text-foreground">
                  {showPw ? <EyeOff className="size-3.5" /> : <Eye className="size-3.5" />}
                </button>
              </div>
            </div>

            <div>
              <label className="mb-1 block text-[0.7rem] text-muted-foreground">Confirm Password</label>
              <div className="relative">
                <Lock className="absolute left-3 top-1/2 size-3.5 -translate-y-1/2 text-muted-foreground" />
                <input
                  type={showPw ? "text" : "password"} value={confirmPassword}
                  onChange={(e) => setConfirmPassword(e.target.value)}
                  required placeholder="••••••••" autoComplete="new-password"
                  minLength={8}
                  className="w-full rounded-lg border border-[var(--hairline)] bg-white/4 py-2.5 pl-9 pr-4 text-sm outline-none transition placeholder:text-muted-foreground/50 focus:border-primary/50 focus:bg-white/6"
                />
              </div>
            </div>

            {error && (
              <div className="flex items-start gap-2 rounded-lg border border-[var(--critical)]/25 bg-[var(--critical)]/8 px-3 py-2.5 text-[0.72rem] text-[var(--critical)]">
                <span className="mt-px shrink-0">⚠</span>
                <span>{error}</span>
              </div>
            )}

            <button type="submit" disabled={loading || backendUp === false}
              className="mt-1 flex w-full items-center justify-center gap-2 rounded-lg border border-primary/40 bg-primary/15 px-4 py-2.5 text-sm font-semibold text-primary transition hover:bg-primary/25 disabled:opacity-40">
              {loading ? <Loader2 className="size-4 animate-spin" /> : <Shield className="size-4" />}
              {loading ? "Creating account…" : backendUp === false ? "Waiting for backend…" : "Create Account"}
            </button>
          </form>

          <div className="mt-5 text-center text-[0.7rem] text-muted-foreground">
            Already have an account?{" "}
            <Link to="/login" className="text-primary hover:underline">
              Log in
            </Link>
          </div>

        </div>

        <p className="mt-5 text-center font-mono text-[0.55rem] text-muted-foreground/50">
          AISS v2.0 · All access is logged and monitored
        </p>
      </div>
    </div>
  );
}
