import { createFileRoute, useNavigate } from "@tanstack/react-router";
import { useState } from "react";
import { Shield, Eye, EyeOff, Lock, Loader2 } from "lucide-react";
import { toast } from "sonner";
import { changePassword, getMe } from "@/lib/api";

export const Route = createFileRoute("/change-password")({
  head: () => ({ meta: [{ title: "Change Password — AISS" }] }),
  component: ChangePasswordPage,
});

function ChangePasswordPage() {
  const navigate = useNavigate();

  const [currentPw, setCurrentPw] = useState("");
  const [newPw,     setNewPw]     = useState("");
  const [confirmPw, setConfirmPw] = useState("");
  const [showCur,   setShowCur]   = useState(false);
  const [showNew,   setShowNew]   = useState(false);
  const [loading,   setLoading]   = useState(false);
  const [error,     setError]     = useState("");

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError("");

    if (newPw !== confirmPw) {
      setError("New passwords do not match.");
      return;
    }
    if (newPw === currentPw) {
      setError("New password must be different from the current password.");
      return;
    }

    setLoading(true);
    try {
      await changePassword(currentPw, newPw);
      toast.success("Password changed successfully");
      // Refresh profile so must_change_password is cleared in cached state
      await getMe().catch(() => {});
      void navigate({ to: "/ai-console" });
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      setError(msg);
    } finally {
      setLoading(false);
    }
  };

  // Password strength indicator
  const strengthChecks = [
    { label: "12+ characters",   ok: newPw.length >= 12 },
    { label: "Uppercase letter", ok: /[A-Z]/.test(newPw) },
    { label: "Lowercase letter", ok: /[a-z]/.test(newPw) },
    { label: "Digit",            ok: /\d/.test(newPw) },
    { label: "Special character", ok: /[!@#$%^&*(),.?":{}|<>_\-]/.test(newPw) },
  ];
  const strengthScore = strengthChecks.filter((c) => c.ok).length;

  return (
    <div className="min-h-screen bg-[#070d0b] flex items-center justify-center p-4">
      <div className="pointer-events-none fixed inset-0 bg-[linear-gradient(rgba(16,185,129,0.025)_1px,transparent_1px),linear-gradient(90deg,rgba(16,185,129,0.025)_1px,transparent_1px)] bg-[size:40px_40px]" />

      <div className="relative w-full max-w-sm">
        {/* Logo */}
        <div className="mb-8 text-center">
          <div className="relative mx-auto mb-4 flex size-16 items-center justify-center rounded-2xl border border-primary/30 bg-primary/10">
            <Lock className="size-8 text-primary" />
          </div>
          <h1 className="font-serif text-2xl font-bold tracking-tight">Change Password</h1>
          <p className="mt-1 text-xs text-muted-foreground">
            You must set a new password before continuing
          </p>
        </div>

        <div className="rounded-2xl border border-[var(--hairline)] bg-[#0c1812]/90 p-7 shadow-2xl backdrop-blur-sm">
          <form onSubmit={(e) => void handleSubmit(e)} className="space-y-3.5">
            {/* Current password */}
            <div>
              <label className="mb-1 block text-[0.7rem] text-muted-foreground">Current Password</label>
              <div className="relative">
                <Lock className="absolute left-3 top-1/2 size-3.5 -translate-y-1/2 text-muted-foreground" />
                <input
                  type={showCur ? "text" : "password"}
                  value={currentPw}
                  onChange={(e) => setCurrentPw(e.target.value)}
                  required
                  placeholder="Current password"
                  autoComplete="current-password"
                  className="w-full rounded-lg border border-[var(--hairline)] bg-white/4 py-2.5 pl-9 pr-10 text-sm outline-none transition placeholder:text-muted-foreground/50 focus:border-primary/50 focus:bg-white/6"
                />
                <button type="button" onClick={() => setShowCur((v) => !v)}
                  aria-label={showCur ? "Hide password" : "Show password"}
                  className="absolute right-3 top-1/2 -translate-y-1/2 text-muted-foreground hover:text-foreground">
                  {showCur ? <EyeOff className="size-3.5" /> : <Eye className="size-3.5" />}
                </button>
              </div>
            </div>

            {/* New password */}
            <div>
              <label className="mb-1 block text-[0.7rem] text-muted-foreground">New Password</label>
              <div className="relative">
                <Lock className="absolute left-3 top-1/2 size-3.5 -translate-y-1/2 text-muted-foreground" />
                <input
                  type={showNew ? "text" : "password"}
                  value={newPw}
                  onChange={(e) => setNewPw(e.target.value)}
                  required
                  placeholder="New password"
                  autoComplete="new-password"
                  className="w-full rounded-lg border border-[var(--hairline)] bg-white/4 py-2.5 pl-9 pr-10 text-sm outline-none transition placeholder:text-muted-foreground/50 focus:border-primary/50 focus:bg-white/6"
                />
                <button type="button" onClick={() => setShowNew((v) => !v)}
                  aria-label={showNew ? "Hide password" : "Show password"}
                  className="absolute right-3 top-1/2 -translate-y-1/2 text-muted-foreground hover:text-foreground">
                  {showNew ? <EyeOff className="size-3.5" /> : <Eye className="size-3.5" />}
                </button>
              </div>
            </div>

            {/* Confirm new password */}
            <div>
              <label className="mb-1 block text-[0.7rem] text-muted-foreground">Confirm New Password</label>
              <div className="relative">
                <Lock className="absolute left-3 top-1/2 size-3.5 -translate-y-1/2 text-muted-foreground" />
                <input
                  type="password"
                  value={confirmPw}
                  onChange={(e) => setConfirmPw(e.target.value)}
                  required
                  placeholder="Confirm new password"
                  autoComplete="new-password"
                  className="w-full rounded-lg border border-[var(--hairline)] bg-white/4 py-2.5 pl-9 pr-4 text-sm outline-none transition placeholder:text-muted-foreground/50 focus:border-primary/50 focus:bg-white/6"
                />
              </div>
            </div>

            {/* Password strength indicator */}
            {newPw.length > 0 && (
              <div className="space-y-1.5">
                <div className="flex gap-1">
                  {[1, 2, 3, 4, 5].map((i) => (
                    <div
                      key={i}
                      className="h-1 flex-1 rounded-full transition-colors"
                      style={{
                        backgroundColor:
                          i <= strengthScore
                            ? strengthScore <= 2
                              ? "var(--critical)"
                              : strengthScore <= 4
                                ? "#f59e0b"
                                : "var(--success)"
                            : "rgba(255,255,255,0.1)",
                      }}
                    />
                  ))}
                </div>
                <ul className="space-y-0.5">
                  {strengthChecks.map((c) => (
                    <li
                      key={c.label}
                      className="flex items-center gap-1.5 text-[0.65rem]"
                      style={{ color: c.ok ? "var(--success)" : "var(--muted-foreground)" }}
                    >
                      <span>{c.ok ? "✓" : "○"}</span>
                      <span>{c.label}</span>
                    </li>
                  ))}
                </ul>
              </div>
            )}

            {error && (
              <div className="flex items-start gap-2 rounded-lg border border-[var(--critical)]/25 bg-[var(--critical)]/8 px-3 py-2.5 text-[0.72rem] text-[var(--critical)]">
                <span className="mt-px shrink-0">⚠</span>
                <span>{error}</span>
              </div>
            )}

            <button
              type="submit"
              disabled={loading || !currentPw || !newPw || !confirmPw}
              className="mt-1 flex w-full items-center justify-center gap-2 rounded-lg border border-primary/40 bg-primary/15 px-4 py-2.5 text-sm font-semibold text-primary transition hover:bg-primary/25 disabled:opacity-40"
            >
              {loading ? <Loader2 className="size-4 animate-spin" /> : <Shield className="size-4" />}
              {loading ? "Changing password…" : "Change Password"}
            </button>
          </form>
        </div>

        <p className="mt-5 text-center font-mono text-[0.55rem] text-muted-foreground/50">
          AISS v2.0 · Password change required for security
        </p>
      </div>
    </div>
  );
}
