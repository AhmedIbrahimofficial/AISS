import { createFileRoute, useNavigate, Link } from "@tanstack/react-router";
import { useEffect, useState } from "react";
import {
  Shield, Eye, EyeOff, Lock, Mail, Loader2, Wifi, WifiOff,
} from "lucide-react";
import { toast } from "sonner";
import { login, setToken, silentRefresh, getMe } from "@/lib/api";

export const Route = createFileRoute("/login")({
  head: () => ({ meta: [{ title: "Login — AISS" }] }),
  component: LoginPage,
});

const BASE_URL =
  (import.meta.env["VITE_AISS_API_URL"] as string | undefined) ??
  "http://localhost:8000";

// ── Google OAuth icon ─────────────────────────────────────────────────
function GoogleIcon() {
  return (
    <svg className="size-4 shrink-0" viewBox="0 0 24 24" aria-hidden>
      <path fill="#4285F4" d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z" />
      <path fill="#34A853" d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z" />
      <path fill="#FBBC05" d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.07H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.93l3.66-2.84z" />
      <path fill="#EA4335" d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.07l3.66 2.84c.87-2.6 3.3-4.53 6.16-4.53z" />
    </svg>
  );
}

function LoginPage() {
  const navigate = useNavigate();

  const [email,          setEmail]          = useState("");
  const [password,       setPassword]       = useState("");
  const [showPw,         setShowPw]         = useState(false);
  const [loading,        setLoading]        = useState(false);
  const [error,          setError]          = useState("");
  const [backendUp,      setBackendUp]      = useState<boolean | null>(null);
  const [oauthProviders, setOAuthProviders] = useState<string[]>([]);
  // When user has a stored session and backend is starting, show waiting state
  const [waitingForBackend, setWaitingForBackend] = useState(false);

  const hasStoredSession = typeof window !== "undefined" && !!(
    localStorage.getItem("aiss_token") ||
    localStorage.getItem("aiss_refresh_token")
  );

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

  // ── When backend comes online and we have a stored session, auto-restore ──
  // This is the "stay logged in" flow — user logged in once (Google or password),
  // refresh token is in localStorage, backend was just starting up.
  useEffect(() => {
    if (!backendUp || !hasStoredSession) return;

    setWaitingForBackend(true);
    silentRefresh()
      .then(async (ok) => {
        if (ok) {
          // Check if user must change password
          try {
            const me = await getMe();
            if (me.must_change_password) {
              toast.info("Please change your password to continue");
              void navigate({ to: "/change-password" });
              return;
            }
          } catch { /* ignore — proceed to dashboard */ }
          toast.success("Session restored — welcome back");
          void navigate({ to: "/" });
        } else {
          setWaitingForBackend(false);
        }
      })
      .catch(() => setWaitingForBackend(false));
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [backendUp]);

  // ── Fetch OAuth providers once backend is up ────────────────────────
  useEffect(() => {
    if (!backendUp) return;
    fetch(`${BASE_URL}/api/auth/oauth/providers`)
      .then((r) => r.json() as Promise<{ providers: string[] }>)
      .then((d) => setOAuthProviders(d.providers ?? []))
      .catch(() => {});
  }, [backendUp]);

  // ── Manual login ───────────────────────────────────────────────────
  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!backendUp) {
      setError("Backend is not ready yet — please wait.");
      return;
    }
    setError("");
    setLoading(true);
    try {
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
        : "Invalid email or password.");
    } finally {
      setLoading(false);
    }
  };

  // ── Google OAuth ────────────────────────────────────────────────────
  const handleGoogleLogin = () => {
    window.location.href = `${BASE_URL}/api/auth/oauth/google`;
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

  // ── Waiting for backend to restore session ──────────────────────────
  if (waitingForBackend) {
    return (
      <div className="min-h-screen bg-[#070d0b] flex items-center justify-center p-4">
        <div className="text-center">
          <div className="relative mx-auto mb-6 flex size-20 items-center justify-center rounded-2xl border border-primary/30 bg-primary/10">
            <Shield className="size-10 text-primary animate-pulse" />
          </div>
          <h1 className="font-serif text-2xl font-bold mb-2">AISS</h1>
          <div className="flex items-center justify-center gap-2 text-muted-foreground mb-2">
            <Loader2 className="size-4 animate-spin text-primary" />
            <span className="text-sm">Restoring your session…</span>
          </div>
          <p className="text-xs text-muted-foreground">Backend is ready — logging you in automatically</p>
        </div>
      </div>
    );
  }

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

          <h2 className="mb-0.5 text-base font-semibold">Operator Login</h2>
          <p className="mb-5 text-[0.7rem] text-muted-foreground">
            Authenticate to access the Security Operations Console
          </p>

          {/* Google OAuth — first time setup */}
          {oauthProviders.includes("google") && (
            <div className="mb-4">
              <button
                type="button"
                onClick={handleGoogleLogin}
                disabled={!backendUp}
                className="flex w-full items-center justify-center gap-2.5 rounded-lg border border-[var(--hairline)] bg-white/4 px-4 py-2.5 text-sm font-medium text-foreground transition hover:bg-white/8 disabled:opacity-40"
              >
                <GoogleIcon />
                Continue with Google
              </button>
              <div className="my-4 flex items-center gap-3">
                <div className="flex-1 h-px bg-[var(--hairline)]" />
                <span className="text-[0.65rem] text-muted-foreground uppercase tracking-widest">or</span>
                <div className="flex-1 h-px bg-[var(--hairline)]" />
              </div>
            </div>
          )}

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
              <label className="mb-1 block text-[0.7rem] text-muted-foreground">Email</label>
              <div className="relative">
                <Mail className="absolute left-3 top-1/2 size-3.5 -translate-y-1/2 text-muted-foreground" />
                <input
                  type="email" value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  required placeholder="your@email.com" autoComplete="username"
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
                  required placeholder="••••••••" autoComplete="current-password"
                  className="w-full rounded-lg border border-[var(--hairline)] bg-white/4 py-2.5 pl-9 pr-10 text-sm outline-none transition placeholder:text-muted-foreground/50 focus:border-primary/50 focus:bg-white/6"
                />
                <button type="button" onClick={() => setShowPw(v => !v)}
                  aria-label={showPw ? "Hide password" : "Show password"}
                  className="absolute right-3 top-1/2 -translate-y-1/2 text-muted-foreground hover:text-foreground">
                  {showPw ? <EyeOff className="size-3.5" /> : <Eye className="size-3.5" />}
                </button>
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
              {loading ? "Authenticating…" : backendUp === false ? "Waiting for backend…" : "Login to AISS"}
            </button>
          </form>

          <div className="mt-5 text-center text-[0.7rem] text-muted-foreground">
            New operator?{" "}
            <Link to="/signup" className="text-primary hover:underline">
              Create an account
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
