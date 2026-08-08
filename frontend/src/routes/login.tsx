import { createFileRoute, useNavigate } from "@tanstack/react-router";
import { useState } from "react";
import { Shield, Eye, EyeOff, Lock, Mail, Loader2, Chrome } from "lucide-react";
import { toast } from "sonner";
import { login, setToken } from "@/lib/api";

export const Route = createFileRoute("/login")({
  head: () => ({ meta: [{ title: "Login — AISS Security System" }] }),
  component: LoginPage,
});

function LoginPage() {
  const navigate  = useNavigate();
  const [email, setEmail]       = useState("admin@aiss.local");
  const [password, setPassword] = useState("Admin123!");
  const [showPw, setShowPw]     = useState(false);
  const [loading, setLoading]   = useState(false);
  const [error, setError]       = useState("");

  const handleLogin = async (e: React.FormEvent) => {
    e.preventDefault();
    setError("");
    setLoading(true);
    try {
      await login(email, password);
      toast.success("Welcome to AISS");
      void navigate({ to: "/" });
    } catch (err) {
      setError(String(err).replace("Error: ", ""));
      toast.error("Login failed");
    } finally {
      setLoading(false);
    }
  };

  const handleGoogleOAuth = () => {
    const BASE = (import.meta.env.VITE_AISS_API_URL as string) ?? "http://localhost:8000";
    window.location.href = `${BASE}/api/auth/oauth/google`;
  };

  const handleGuestMode = () => {
    // Allow viewing dashboard without auth (read-only)
    toast("Guest mode — read-only access", { description: "Login for full operator access" });
    void navigate({ to: "/" });
  };

  return (
    <div className="min-h-screen bg-[#070d0b] flex items-center justify-center p-4">
      {/* Background grid */}
      <div className="pointer-events-none fixed inset-0 bg-[linear-gradient(rgba(16,185,129,0.03)_1px,transparent_1px),linear-gradient(90deg,rgba(16,185,129,0.03)_1px,transparent_1px)] bg-[size:40px_40px]" />

      <div className="w-full max-w-md">
        {/* Logo */}
        <div className="mb-8 text-center">
          <div className="mx-auto mb-4 flex size-16 items-center justify-center rounded-2xl border border-primary/30 bg-primary/10">
            <Shield className="size-8 text-primary" />
          </div>
          <h1 className="font-serif text-3xl font-bold text-foreground">AISS</h1>
          <p className="mt-1 text-sm text-muted-foreground">AI Integrated Security System</p>
          <div className="mt-2 flex items-center justify-center gap-2">
            <span className="size-2 rounded-full bg-primary animate-pulse" />
            <span className="font-mono text-xs text-primary">THREAT MONITORING ACTIVE</span>
          </div>
        </div>

        {/* Login card */}
        <div className="rounded-xl border border-[var(--hairline)] bg-[#0d1a15]/80 p-8 shadow-2xl backdrop-blur">
          <h2 className="mb-1 text-lg font-semibold">Operator Login</h2>
          <p className="mb-6 text-xs text-muted-foreground">
            Authenticate to access the Security Operations Console
          </p>

          {/* Google OAuth */}
          <button
            type="button"
            onClick={handleGoogleOAuth}
            className="mb-4 flex w-full items-center justify-center gap-3 rounded-lg border border-[var(--hairline)] bg-white/4 px-4 py-2.5 text-sm font-medium transition-colors hover:bg-white/8"
          >
            <Chrome className="size-4" />
            Continue with Google
          </button>

          <div className="relative mb-4 flex items-center gap-3">
            <div className="flex-1 h-px bg-[var(--hairline)]" />
            <span className="text-xs text-muted-foreground">or</span>
            <div className="flex-1 h-px bg-[var(--hairline)]" />
          </div>

          {/* Email/password form */}
          <form onSubmit={(e) => void handleLogin(e)} className="space-y-4">
            <div>
              <label className="mb-1.5 block text-xs text-muted-foreground">Email</label>
              <div className="relative">
                <Mail className="absolute left-3 top-1/2 size-4 -translate-y-1/2 text-muted-foreground" />
                <input
                  type="email"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  required
                  className="w-full rounded-lg border border-[var(--hairline)] bg-white/5 py-2.5 pl-10 pr-4 text-sm outline-none placeholder:text-muted-foreground focus:border-primary/50 focus:bg-white/8"
                  placeholder="admin@aiss.local"
                />
              </div>
            </div>

            <div>
              <label className="mb-1.5 block text-xs text-muted-foreground">Password</label>
              <div className="relative">
                <Lock className="absolute left-3 top-1/2 size-4 -translate-y-1/2 text-muted-foreground" />
                <input
                  type={showPw ? "text" : "password"}
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  required
                  className="w-full rounded-lg border border-[var(--hairline)] bg-white/5 py-2.5 pl-10 pr-10 text-sm outline-none placeholder:text-muted-foreground focus:border-primary/50 focus:bg-white/8"
                  placeholder="••••••••"
                />
                <button type="button" onClick={() => setShowPw(v => !v)}
                  className="absolute right-3 top-1/2 -translate-y-1/2 text-muted-foreground hover:text-foreground">
                  {showPw ? <EyeOff className="size-4" /> : <Eye className="size-4" />}
                </button>
              </div>
            </div>

            {error && (
              <div className="rounded-lg border border-[var(--critical)]/30 bg-[var(--critical)]/10 px-3 py-2 text-xs text-[var(--critical)]">
                {error}
              </div>
            )}

            <button
              type="submit"
              disabled={loading}
              className="flex w-full items-center justify-center gap-2 rounded-lg bg-primary/20 border border-primary/40 px-4 py-2.5 text-sm font-semibold text-primary transition-colors hover:bg-primary/30 disabled:opacity-50"
            >
              {loading ? <Loader2 className="size-4 animate-spin" /> : <Shield className="size-4" />}
              {loading ? "Authenticating..." : "Login to AISS"}
            </button>
          </form>

          {/* Default credentials hint */}
          <div className="mt-4 rounded-lg border border-[var(--hairline)] bg-white/3 px-3 py-2">
            <p className="text-[0.65rem] text-muted-foreground">
              <span className="text-foreground font-medium">Default credentials:</span>{" "}
              admin@aiss.local / Admin123!
              <br />
              <span className="text-[var(--warning)]">Change password after first login.</span>
            </p>
          </div>

          {/* Guest mode */}
          <button
            type="button"
            onClick={handleGuestMode}
            className="mt-3 w-full text-center text-xs text-muted-foreground hover:text-foreground transition-colors"
          >
            Continue as Guest (read-only)
          </button>
        </div>

        {/* Footer */}
        <p className="mt-6 text-center font-mono text-[0.6rem] text-muted-foreground">
          AISS v2.0 · All access is logged and monitored
        </p>
      </div>
    </div>
  );
}
