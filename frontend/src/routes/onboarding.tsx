import { createFileRoute, useNavigate } from "@tanstack/react-router";
import { useState, useEffect } from "react";
import { Shield, Chrome, Mail, Lock, Eye, EyeOff,
         BarChart3, Monitor, Wifi, ArrowRight, Check,
         Loader2, ChevronRight, Globe, Cpu, Bell } from "lucide-react";
import { toast } from "sonner";
import { login, setToken } from "@/lib/api";

export const Route = createFileRoute("/onboarding")({
  head: () => ({ meta: [{ title: "Welcome to AISS" }] }),
  component: OnboardingPage,
});

// ── Onboarding steps ──────────────────────────────────────────────────
type Step = "auth" | "reports" | "connect" | "welcome";

function OnboardingPage() {
  const navigate  = useNavigate();
  const [step, setStep] = useState<Step>("auth");

  // User preferences collected during onboarding
  const [prefs, setPrefs] = useState({
    wantsMonthlyReport: true,
    wantsAlerts:        true,
    wantsMultiPC:       false,
    userName:           "",
  });

  const goNext = (s: Step) => setStep(s);

  return (
    <div className="min-h-screen bg-[#040a07] flex flex-col">
      {/* Animated background */}
      <div className="pointer-events-none fixed inset-0 overflow-hidden">
        <div className="absolute -top-40 -right-40 size-96 rounded-full bg-primary/5 blur-3xl" />
        <div className="absolute -bottom-40 -left-40 size-96 rounded-full bg-primary/3 blur-3xl" />
        <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 size-[600px] rounded-full bg-primary/2 blur-3xl" />
        {/* Grid */}
        <div className="absolute inset-0 bg-[linear-gradient(rgba(16,185,129,0.03)_1px,transparent_1px),linear-gradient(90deg,rgba(16,185,129,0.03)_1px,transparent_1px)] bg-[size:50px_50px]" />
      </div>

      <div className="relative z-10 flex flex-1 items-center justify-center p-4">
        {step === "auth"     && <AuthStep    prefs={prefs} setPrefs={setPrefs} onNext={() => goNext("reports")} />}
        {step === "reports"  && <ReportsStep prefs={prefs} setPrefs={setPrefs} onNext={() => goNext("connect")} />}
        {step === "connect"  && <ConnectStep prefs={prefs} setPrefs={setPrefs} onNext={() => goNext("welcome")} />}
        {step === "welcome"  && <WelcomeStep prefs={prefs} navigate={navigate} />}
      </div>
    </div>
  );
}

// ══════════════════════════════════════════════════════════════════════
// STEP 1 — AUTH (Google + Email)
// ══════════════════════════════════════════════════════════════════════
function AuthStep({ prefs, setPrefs, onNext }: any) {
  const [mode, setMode]       = useState<"signin" | "signup">("signup");
  const [email, setEmail]     = useState("");
  const [password, setPassword] = useState("");
  const [name, setName]       = useState("");
  const [showPw, setShowPw]   = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError]     = useState("");

  const BASE = (import.meta.env["VITE_AISS_API_URL"] as string) ?? "http://localhost:8000";

  const handleGoogleAuth = () => {
    window.location.href = `${BASE}/api/auth/oauth/google?redirect_uri=${encodeURIComponent(window.location.origin + "/onboarding?step=reports")}`;
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError("");
    setLoading(true);
    try {
      if (mode === "signup") {
        // Register first
        const r = await fetch(`${BASE}/api/auth/register`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ username: name || email.split("@")[0], email, password }),
        });
        if (!r.ok) {
          const d = await r.json() as { detail?: string };
          throw new Error(d.detail ?? "Registration failed");
        }
      }
      // Login
      await login(email, password);
      setPrefs((p: any) => ({ ...p, userName: name || email.split("@")[0] }));
      toast.success(mode === "signup" ? "Account created!" : "Welcome back!");
      onNext();
    } catch (err) {
      setError(String(err).replace("Error: ", ""));
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="w-full max-w-md">
      {/* Logo */}
      <div className="mb-8 text-center">
        <div className="mx-auto mb-4 flex size-20 items-center justify-center rounded-2xl border border-primary/20 bg-primary/8 shadow-lg shadow-primary/10">
          <Shield className="size-10 text-primary" />
        </div>
        <h1 className="font-serif text-4xl font-bold text-white">AISS</h1>
        <p className="mt-1 text-sm text-[#7c8c85]">AI Integrated Security System</p>
      </div>

      {/* Card */}
      <div className="rounded-2xl border border-[#1a2e25] bg-[#0d1a15]/90 p-8 shadow-2xl backdrop-blur">
        {/* Tab switcher */}
        <div className="mb-6 flex rounded-xl border border-[#1a2e25] bg-[#0a1410] p-1">
          {(["signup", "signin"] as const).map((m) => (
            <button key={m} onClick={() => setMode(m)}
              className={`flex-1 rounded-lg py-2 text-sm font-medium transition-all ${
                mode === m ? "bg-primary/20 text-primary shadow-sm" : "text-[#7c8c85] hover:text-white"
              }`}>
              {m === "signup" ? "Create Account" : "Sign In"}
            </button>
          ))}
        </div>

        {/* Google */}
        <button onClick={handleGoogleAuth}
          className="mb-4 flex w-full items-center justify-center gap-3 rounded-xl border border-[#1a2e25] bg-white/4 px-4 py-3 text-sm font-medium text-white transition-colors hover:bg-white/8">
          <Chrome className="size-5" />
          Continue with Google
        </button>

        <div className="relative my-4 flex items-center gap-3">
          <div className="flex-1 h-px bg-[#1a2e25]" />
          <span className="text-xs text-[#7c8c85]">or with email</span>
          <div className="flex-1 h-px bg-[#1a2e25]" />
        </div>

        {/* Form */}
        <form onSubmit={(e) => void handleSubmit(e)} className="space-y-3">
          {mode === "signup" && (
            <div className="relative">
              <input value={name} onChange={(e) => setName(e.target.value)}
                placeholder="Your name"
                className="w-full rounded-xl border border-[#1a2e25] bg-[#0a1410] px-4 py-3 text-sm text-white outline-none placeholder:text-[#4a6055] focus:border-primary/50" />
            </div>
          )}
          <div className="relative">
            <Mail className="absolute left-3.5 top-1/2 size-4 -translate-y-1/2 text-[#4a6055]" />
            <input type="email" value={email} onChange={(e) => setEmail(e.target.value)}
              required placeholder="Email address"
              className="w-full rounded-xl border border-[#1a2e25] bg-[#0a1410] py-3 pl-10 pr-4 text-sm text-white outline-none placeholder:text-[#4a6055] focus:border-primary/50" />
          </div>
          <div className="relative">
            <Lock className="absolute left-3.5 top-1/2 size-4 -translate-y-1/2 text-[#4a6055]" />
            <input type={showPw ? "text" : "password"} value={password}
              onChange={(e) => setPassword(e.target.value)} required
              placeholder="Password (min 8 chars)"
              className="w-full rounded-xl border border-[#1a2e25] bg-[#0a1410] py-3 pl-10 pr-10 text-sm text-white outline-none placeholder:text-[#4a6055] focus:border-primary/50" />
            <button type="button" onClick={() => setShowPw(v => !v)}
              className="absolute right-3.5 top-1/2 -translate-y-1/2 text-[#4a6055] hover:text-white">
              {showPw ? <EyeOff className="size-4" /> : <Eye className="size-4" />}
            </button>
          </div>

          {error && (
            <p className="rounded-lg border border-red-500/20 bg-red-500/10 px-3 py-2 text-xs text-red-400">{error}</p>
          )}

          <button type="submit" disabled={loading}
            className="flex w-full items-center justify-center gap-2 rounded-xl bg-primary/20 border border-primary/40 py-3 text-sm font-bold text-primary transition-colors hover:bg-primary/30 disabled:opacity-50">
            {loading ? <Loader2 className="size-4 animate-spin" /> : <Shield className="size-4" />}
            {loading ? "Please wait..." : mode === "signup" ? "Create Account & Continue" : "Sign In & Continue"}
          </button>
        </form>

        {/* Skip for testing */}
        <button onClick={() => { setToken(localStorage.getItem("aiss_token") ?? "skip"); onNext(); }}
          className="mt-4 w-full text-center text-xs text-[#4a6055] hover:text-[#7c8c85] transition-colors">
          Skip for now →
        </button>
      </div>
    </div>
  );
}

// ══════════════════════════════════════════════════════════════════════
// STEP 2 — REPORTS & ALERTS POPUP
// ══════════════════════════════════════════════════════════════════════
function ReportsStep({ prefs, setPrefs, onNext }: any) {
  const [selected, setSelected] = useState({ monthly: true, weekly: false, realtime: true, email: true });

  const toggle = (k: keyof typeof selected) =>
    setSelected(s => ({ ...s, [k]: !s[k] }));

  const options = [
    {
      key: "monthly" as const,
      icon: <BarChart3 className="size-6" />,
      title: "Monthly Security Report",
      desc: "Get a detailed PDF report every month — total attacks, threats blocked, top attack sources, AI analysis summary.",
      badge: "Recommended",
      badgeColor: "bg-primary/20 text-primary",
    },
    {
      key: "weekly" as const,
      icon: <BarChart3 className="size-5" />,
      title: "Weekly Summary",
      desc: "Quick weekly digest — what happened on your network, threats detected and resolved.",
      badge: null,
      badgeColor: "",
    },
    {
      key: "realtime" as const,
      icon: <Bell className="size-6" />,
      title: "Real-time Critical Alerts",
      desc: "Instant popup + sound when a critical threat is detected on your PC. Never miss a serious attack.",
      badge: "Important",
      badgeColor: "bg-red-500/20 text-red-400",
    },
    {
      key: "email" as const,
      icon: <Mail className="size-5" />,
      title: "Email Alerts for High Threats",
      desc: "Receive email notifications when high or critical severity threats are detected.",
      badge: null,
      badgeColor: "",
    },
  ];

  return (
    <div className="w-full max-w-lg">
      {/* Progress */}
      <StepProgress current={2} total={4} />

      <div className="rounded-2xl border border-[#1a2e25] bg-[#0d1a15]/90 p-8 shadow-2xl backdrop-blur">
        <div className="mb-6 text-center">
          <div className="mx-auto mb-3 flex size-14 items-center justify-center rounded-xl border border-primary/20 bg-primary/8">
            <BarChart3 className="size-7 text-primary" />
          </div>
          <h2 className="text-xl font-bold text-white">How do you want to stay informed?</h2>
          <p className="mt-1 text-sm text-[#7c8c85]">AISS will monitor your system. Choose how you want to receive reports and alerts.</p>
        </div>

        <div className="space-y-3">
          {options.map(({ key, icon, title, desc, badge, badgeColor }) => (
            <button key={key} onClick={() => toggle(key)}
              className={`w-full rounded-xl border p-4 text-left transition-all ${
                selected[key]
                  ? "border-primary/40 bg-primary/8 shadow-sm shadow-primary/10"
                  : "border-[#1a2e25] bg-[#0a1410] hover:border-[#2a3e2f]"
              }`}>
              <div className="flex items-start gap-3">
                <div className={`mt-0.5 rounded-lg p-2 ${selected[key] ? "bg-primary/20 text-primary" : "bg-white/5 text-[#7c8c85]"}`}>
                  {icon}
                </div>
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2">
                    <span className="text-sm font-semibold text-white">{title}</span>
                    {badge && <span className={`rounded-full px-2 py-0.5 text-[0.6rem] font-bold ${badgeColor}`}>{badge}</span>}
                  </div>
                  <p className="mt-0.5 text-xs text-[#7c8c85] leading-relaxed">{desc}</p>
                </div>
                <div className={`mt-1 size-5 shrink-0 rounded-full border-2 flex items-center justify-center transition-all ${
                  selected[key] ? "border-primary bg-primary" : "border-[#2a3e2f]"
                }`}>
                  {selected[key] && <Check className="size-3 text-white" />}
                </div>
              </div>
            </button>
          ))}
        </div>

        <button onClick={() => { setPrefs((p: any) => ({ ...p, wantsMonthlyReport: selected.monthly, wantsAlerts: selected.realtime })); onNext(); }}
          className="mt-6 flex w-full items-center justify-center gap-2 rounded-xl bg-primary/20 border border-primary/40 py-3 text-sm font-bold text-primary hover:bg-primary/30 transition-colors">
          Save Preferences <ArrowRight className="size-4" />
        </button>
      </div>
    </div>
  );
}

// ══════════════════════════════════════════════════════════════════════
// STEP 3 — CONNECT OTHER PCs
// ══════════════════════════════════════════════════════════════════════
function ConnectStep({ prefs, setPrefs, onNext }: any) {
  const [choice, setChoice] = useState<"yes" | "no" | null>(null);

  return (
    <div className="w-full max-w-lg">
      <StepProgress current={3} total={4} />

      <div className="rounded-2xl border border-[#1a2e25] bg-[#0d1a15]/90 p-8 shadow-2xl backdrop-blur">
        <div className="mb-6 text-center">
          <div className="mx-auto mb-3 flex size-14 items-center justify-center rounded-xl border border-primary/20 bg-primary/8">
            <Wifi className="size-7 text-primary" />
          </div>
          <h2 className="text-xl font-bold text-white">Monitor multiple computers?</h2>
          <p className="mt-1 text-sm text-[#7c8c85]">
            AISS can monitor unlimited PCs, laptops, and servers on your network — all from this one dashboard.
          </p>
        </div>

        {/* Visual: multiple PCs */}
        <div className="mb-6 flex items-center justify-center gap-3">
          {[
            { label: "This PC",    color: "border-primary/40 bg-primary/8",   icon: "🖥️" },
            { label: "+ Laptop",   color: "border-[#1a2e25] bg-[#0a1410]",    icon: "💻" },
            { label: "+ Server",   color: "border-[#1a2e25] bg-[#0a1410]",    icon: "🖧"  },
            { label: "+ Any PC",   color: "border-[#1a2e25] bg-[#0a1410]",    icon: "🖥️" },
          ].map((item) => (
            <div key={item.label} className={`flex flex-col items-center rounded-xl border p-3 ${item.color}`}>
              <span className="text-2xl">{item.icon}</span>
              <span className="mt-1 text-[0.65rem] text-[#7c8c85]">{item.label}</span>
            </div>
          ))}
        </div>

        <div className="mb-2 text-xs font-semibold uppercase tracking-widest text-[#7c8c85]">How it works:</div>
        <div className="mb-6 space-y-2">
          {[
            "Install AISS on any PC on your network",
            "Generate a token from this dashboard",
            "Paste the token on the other PC — connected instantly",
            "See all PCs, threats, and health in one place",
          ].map((txt, i) => (
            <div key={i} className="flex items-center gap-3">
              <span className="flex size-5 shrink-0 items-center justify-center rounded-full bg-primary/20 text-[0.65rem] font-bold text-primary">{i + 1}</span>
              <span className="text-sm text-[#b0c0ba]">{txt}</span>
            </div>
          ))}
        </div>

        {/* Choice */}
        <div className="grid grid-cols-2 gap-3">
          <button onClick={() => setChoice("yes")}
            className={`rounded-xl border p-4 text-center transition-all ${
              choice === "yes" ? "border-primary/40 bg-primary/10" : "border-[#1a2e25] bg-[#0a1410] hover:border-[#2a3e2f]"
            }`}>
            <Wifi className={`mx-auto mb-2 size-6 ${choice === "yes" ? "text-primary" : "text-[#7c8c85]"}`} />
            <p className="text-sm font-semibold text-white">Yes, connect more PCs</p>
            <p className="mt-0.5 text-xs text-[#7c8c85]">I'll set it up later</p>
          </button>
          <button onClick={() => setChoice("no")}
            className={`rounded-xl border p-4 text-center transition-all ${
              choice === "no" ? "border-[#2a3e2f] bg-white/3" : "border-[#1a2e25] bg-[#0a1410] hover:border-[#2a3e2f]"
            }`}>
            <Monitor className={`mx-auto mb-2 size-6 ${choice === "no" ? "text-white" : "text-[#7c8c85]"}`} />
            <p className="text-sm font-semibold text-white">Just this PC for now</p>
            <p className="mt-0.5 text-xs text-[#7c8c85]">Can add more anytime</p>
          </button>
        </div>

        <button
          onClick={() => { setPrefs((p: any) => ({ ...p, wantsMultiPC: choice === "yes" })); onNext(); }}
          disabled={choice === null}
          className="mt-5 flex w-full items-center justify-center gap-2 rounded-xl bg-primary/20 border border-primary/40 py-3 text-sm font-bold text-primary hover:bg-primary/30 transition-colors disabled:opacity-40 disabled:cursor-not-allowed">
          Continue <ArrowRight className="size-4" />
        </button>
      </div>
    </div>
  );
}

// ══════════════════════════════════════════════════════════════════════
// STEP 4 — BEAUTIFUL WELCOME PAGE
// ══════════════════════════════════════════════════════════════════════
function WelcomeStep({ prefs, navigate }: { prefs: any; navigate: any }) {
  const [counting, setCounting] = useState(false);
  const [count, setCount]       = useState(0);
  const [ready, setReady]       = useState(false);

  useEffect(() => {
    // Skip fake animation — go straight to ready
    setCount(100);
    setReady(true);
  }, []);

  const handleStart = async () => {
    // Persist onboarding completion to the BACKEND database — not just localStorage
    try {
      const { completeOnboarding } = await import("@/lib/api");
      await completeOnboarding(["welcome", "reports", "connect"]);
    } catch {
      // fallback — still let user in even if API call fails
    }
    localStorage.setItem("aiss_onboarding_done", "1");
    localStorage.setItem("aiss_prefs", JSON.stringify(prefs));
    toast.success("AISS is now protecting your system!", { duration: 4000 });
    void navigate({ to: "/" });
  };

  return (
    <div className="w-full max-w-xl text-center">
      <StepProgress current={4} total={4} />

      {/* Giant shield animation */}
      <div className="relative mb-8 flex items-center justify-center">
        <div className="absolute size-48 rounded-full bg-primary/5 blur-2xl animate-pulse" />
        <div className="absolute size-32 rounded-full bg-primary/8 blur-xl" />
        <div className="relative flex size-28 items-center justify-center rounded-3xl border-2 border-primary/30 bg-primary/10 shadow-2xl shadow-primary/20">
          <Shield className="size-14 text-primary" />
          {ready && (
            <div className="absolute -top-2 -right-2 flex size-7 items-center justify-center rounded-full bg-primary shadow-lg">
              <Check className="size-4 text-white" />
            </div>
          )}
        </div>
      </div>

      {/* Greeting */}
      <h1 className="font-serif text-4xl font-bold text-white leading-tight">
        {prefs.userName ? `Welcome, ${prefs.userName}!` : "Welcome to AISS!"}
      </h1>
      <p className="mt-3 text-lg text-[#7c8c85]">Your AI Security System is ready.</p>

      {/* System scan animation */}
      {!ready ? (
        <div className="mt-8 rounded-2xl border border-[#1a2e25] bg-[#0d1a15] p-6">
          <p className="mb-3 text-sm text-[#7c8c85]">Scanning your system...</p>
          <div className="h-2 w-full overflow-hidden rounded-full bg-[#0a1410]">
            <div className="h-full rounded-full bg-primary transition-all duration-100"
              style={{ width: `${count}%` }} />
          </div>
          <p className="mt-2 font-mono text-xs text-primary">{count}% — initializing modules</p>
        </div>
      ) : (
        <>
          {/* Features summary */}
          <div className="mt-8 grid grid-cols-3 gap-3">
            {[
              { icon: <Shield className="size-5" />,  label: "Threat Detection",  val: "Active",   color: "text-primary" },
              { icon: <Cpu className="size-5" />,     label: "AI Engine",         val: "Online",   color: "text-primary" },
              { icon: <Globe className="size-5" />,   label: "Network Monitor",   val: "Running",  color: "text-primary" },
              { icon: <Bell className="size-5" />,
                label: "Alerts",
                val: prefs.wantsAlerts ? "Enabled" : "Off",
                color: prefs.wantsAlerts ? "text-primary" : "text-[#7c8c85]" },
              { icon: <BarChart3 className="size-5" />,
                label: "Reports",
                val: prefs.wantsMonthlyReport ? "Monthly" : "Off",
                color: prefs.wantsMonthlyReport ? "text-primary" : "text-[#7c8c85]" },
              { icon: <Wifi className="size-5" />,
                label: "Multi-PC",
                val: prefs.wantsMultiPC ? "Enabled" : "Single",
                color: prefs.wantsMultiPC ? "text-primary" : "text-[#7c8c85]" },
            ].map(({ icon, label, val, color }) => (
              <div key={label} className="rounded-xl border border-[#1a2e25] bg-[#0d1a15] p-3 text-center">
                <div className={`mx-auto mb-1 ${color}`}>{icon}</div>
                <p className="text-[0.65rem] text-[#4a6055] uppercase tracking-wider">{label}</p>
                <p className={`text-xs font-bold ${color}`}>{val}</p>
              </div>
            ))}
          </div>

          {/* BIG START BUTTON */}
          <div className="mt-8">
            <button onClick={handleStart}
              className="group relative inline-flex items-center gap-3 overflow-hidden rounded-2xl bg-primary px-10 py-5 text-lg font-bold text-white shadow-2xl shadow-primary/30 transition-all hover:bg-primary/90 hover:shadow-primary/50 hover:scale-105 active:scale-95">
              {/* Shimmer effect */}
              <div className="absolute inset-0 -translate-x-full bg-gradient-to-r from-transparent via-white/10 to-transparent transition-transform duration-700 group-hover:translate-x-full" />
              <Shield className="relative size-6" />
              <span className="relative">Start Tracking — Give Access</span>
              <ChevronRight className="relative size-5 transition-transform group-hover:translate-x-1" />
            </button>
            <p className="mt-3 text-xs text-[#4a6055]">
              AISS will begin monitoring your PC immediately after clicking
            </p>
          </div>

          {/* What happens next */}
          <div className="mt-6 rounded-xl border border-[#1a2e25] bg-[#0a1410] p-4 text-left">
            <p className="mb-2 text-xs font-semibold uppercase tracking-widest text-[#7c8c85]">What happens when you click Start:</p>
            <div className="space-y-1.5">
              {[
                "Network traffic monitoring starts immediately",
                "File system and process scanner activates",
                "AI threat detection engine goes live",
                "Your SOC dashboard opens — see everything in real-time",
              ].map((txt, i) => (
                <div key={i} className="flex items-center gap-2">
                  <Check className="size-3.5 shrink-0 text-primary" />
                  <span className="text-xs text-[#7c8c85]">{txt}</span>
                </div>
              ))}
            </div>
          </div>
        </>
      )}
    </div>
  );
}

// ── Step progress indicator ────────────────────────────────────────────
function StepProgress({ current, total }: { current: number; total: number }) {
  const labels = ["Account", "Reports", "Connect PCs", "Welcome"];
  return (
    <div className="mb-6 flex items-center justify-center gap-0">
      {Array.from({ length: total }, (_, i) => i + 1).map((n) => (
        <div key={n} className="flex items-center">
          <div className={`flex size-7 items-center justify-center rounded-full text-xs font-bold transition-all ${
            n < current  ? "bg-primary text-white" :
            n === current ? "border-2 border-primary text-primary bg-primary/10" :
                            "border border-[#2a3e2f] text-[#4a6055]"
          }`}>
            {n < current ? <Check className="size-3.5" /> : n}
          </div>
          <span className={`ml-1 mr-3 text-[0.65rem] font-medium ${n === current ? "text-primary" : "text-[#4a6055]"}`}>
            {labels[n - 1]}
          </span>
          {n < total && <div className={`mr-3 h-px w-6 ${n < current ? "bg-primary/40" : "bg-[#1a2e25]"}`} />}
        </div>
      ))}
    </div>
  );
}
