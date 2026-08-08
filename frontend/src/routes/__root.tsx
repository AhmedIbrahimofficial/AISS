import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import {
  Outlet, Link, createRootRouteWithContext,
  useRouter, HeadContent, Scripts, useNavigate, useLocation,
} from "@tanstack/react-router";
import { useEffect, useState, useCallback, type ReactNode } from "react";
import { toast } from "sonner";

import appCss from "../styles.css?url";
import { reportLovableError } from "../lib/lovable-error-reporting";
import { AppShell } from "../components/soc/AppShell";
import { Toaster } from "@/components/ui/sonner";
import { SetupWizard, PopupQuestion } from "@/components/soc/SetupWizard";
import { useWebSocket, useBackendStatus } from "@/hooks/useAISS";
import { connectWS, getToken, login, setToken, type WizardQuestion } from "@/lib/api";
import { Shield, X, AlertTriangle, Info, CheckCircle, Lock } from "lucide-react";

// ── 404 ───────────────────────────────────────────────────────────────
function NotFoundComponent() {
  return (
    <div className="flex min-h-screen items-center justify-center bg-[#070d0b] px-4">
      <div className="max-w-md text-center">
        <Shield className="mx-auto mb-4 size-16 text-muted-foreground opacity-30" />
        <h1 className="font-mono text-7xl font-bold text-primary">404</h1>
        <h2 className="mt-4 text-xl font-semibold">Page not found</h2>
        <p className="mt-2 text-sm text-muted-foreground">This route doesn't exist in the AISS console.</p>
        <div className="mt-6">
          <Link to="/" className="inline-flex items-center gap-2 rounded-lg border border-primary/40 bg-primary/10 px-4 py-2 text-sm text-primary hover:bg-primary/20">
            <Shield className="size-4" /> Back to Dashboard
          </Link>
        </div>
      </div>
    </div>
  );
}

// ── Error boundary ────────────────────────────────────────────────────
function ErrorComponent({ error, reset }: { error: Error; reset: () => void }) {
  const router = useRouter();
  useEffect(() => { reportLovableError(error, { boundary: "tanstack_root_error_component" }); }, [error]);
  return (
    <div className="flex min-h-screen items-center justify-center bg-[#070d0b] px-4">
      <div className="max-w-md rounded-xl border border-[var(--critical)]/30 bg-[var(--critical)]/5 p-8 text-center">
        <AlertTriangle className="mx-auto mb-4 size-12 text-[var(--critical)]" />
        <h1 className="text-xl font-semibold">Something went wrong</h1>
        <p className="mt-2 text-sm text-muted-foreground font-mono">{error.message}</p>
        <div className="mt-6 flex flex-wrap justify-center gap-2">
          <button onClick={() => { router.invalidate(); reset(); }}
            className="rounded-lg border border-primary/40 bg-primary/10 px-4 py-2 text-sm text-primary hover:bg-primary/20">
            Try again
          </button>
          <a href="/" className="rounded-lg border border-[var(--hairline)] px-4 py-2 text-sm text-muted-foreground hover:text-foreground">
            Go home
          </a>
        </div>
      </div>
    </div>
  );
}

// ── Permission Toast / Action Popup ──────────────────────────────────
type PermissionLevel = "info" | "warning" | "critical" | "success";

interface ActionConfirm {
  title:       string;
  description: string;
  level:       PermissionLevel;
  onConfirm:   () => void;
  onCancel:    () => void;
}

function ActionConfirmModal({ confirm }: { confirm: ActionConfirm }) {
  const icons = {
    info:     <Info     className="size-5 text-[var(--cyan)]" />,
    warning:  <AlertTriangle className="size-5 text-[var(--warning)]" />,
    critical: <Lock     className="size-5 text-[var(--critical)]" />,
    success:  <CheckCircle className="size-5 text-[var(--success)]" />,
  };
  const colors = {
    info:     "border-[var(--cyan)]/30 bg-[var(--cyan)]/5",
    warning:  "border-[var(--warning)]/30 bg-[var(--warning)]/5",
    critical: "border-[var(--critical)]/30 bg-[var(--critical)]/5",
    success:  "border-[var(--success)]/30 bg-[var(--success)]/5",
  };
  const btnColors = {
    info:     "border-[var(--cyan)]/40 bg-[var(--cyan)]/10 text-[var(--cyan)] hover:bg-[var(--cyan)]/20",
    warning:  "border-[var(--warning)]/40 bg-[var(--warning)]/10 text-[var(--warning)] hover:bg-[var(--warning)]/20",
    critical: "border-[var(--critical)]/40 bg-[var(--critical)]/10 text-[var(--critical)] hover:bg-[var(--critical)]/20",
    success:  "border-[var(--success)]/40 bg-[var(--success)]/10 text-[var(--success)] hover:bg-[var(--success)]/20",
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4">
      {/* Backdrop */}
      <div className="absolute inset-0 bg-black/60 backdrop-blur-sm" onClick={confirm.onCancel} />

      <div className={`relative w-full max-w-sm rounded-xl border p-6 shadow-2xl ${colors[confirm.level]} bg-[#0d1a15]`}>
        <button onClick={confirm.onCancel}
          className="absolute right-3 top-3 rounded-md p-1 text-muted-foreground hover:text-foreground">
          <X className="size-4" />
        </button>

        <div className="mb-4 flex items-center gap-3">
          {icons[confirm.level]}
          <div>
            <p className="font-semibold text-sm">{confirm.title}</p>
            <p className="text-[0.65rem] font-mono text-muted-foreground tracking-widest uppercase">
              {confirm.level === "critical" ? "⚠ REQUIRES CONFIRMATION" : "ACTION REQUIRED"}
            </p>
          </div>
        </div>

        <p className="text-sm text-muted-foreground leading-relaxed mb-5">
          {confirm.description}
        </p>

        <div className="flex gap-2">
          <button
            onClick={confirm.onConfirm}
            className={`flex-1 rounded-lg border px-4 py-2 text-sm font-semibold transition-colors ${btnColors[confirm.level]}`}
          >
            Confirm & Execute
          </button>
          <button
            onClick={confirm.onCancel}
            className="rounded-lg border border-[var(--hairline)] px-4 py-2 text-sm text-muted-foreground hover:text-foreground transition-colors"
          >
            Cancel
          </button>
        </div>

        <p className="mt-3 text-center font-mono text-[0.55rem] text-muted-foreground">
          This action will be logged in the AISS audit trail
        </p>
      </div>
    </div>
  );
}

// Export for use in other components
export let showActionConfirm: (opts: Omit<ActionConfirm, "onConfirm" | "onCancel">) => Promise<boolean>;

// ── Route definition ──────────────────────────────────────────────────
export const Route = createRootRouteWithContext<{ queryClient: QueryClient }>()({
  head: () => ({
    meta: [
      { charSet: "utf-8" },
      { name: "viewport", content: "width=device-width, initial-scale=1" },
      { title: "AISS — AI Integrated Security System" },
      { name: "description", content: "Real-time SOC with AI-powered threat auto-response." },
    ],
    links: [
      { rel: "stylesheet", href: appCss },
      { rel: "preconnect", href: "https://fonts.googleapis.com" },
      { rel: "preconnect", href: "https://fonts.gstatic.com", crossOrigin: "anonymous" },
      { rel: "stylesheet", href: "https://fonts.googleapis.com/css2?family=Libre+Baskerville:wght@400;700&family=IBM+Plex+Sans:wght@400;500;600&family=IBM+Plex+Mono:wght@400;500;600&display=swap" },
      { rel: "icon", href: "/favicon.ico", type: "image/x-icon" },
    ],
  }),
  shellComponent: RootShell,
  component: RootComponent,
  notFoundComponent: NotFoundComponent,
  errorComponent: ErrorComponent,
});

function RootShell({ children }: { children: ReactNode }) {
  return (
    <html lang="en">
      <head><HeadContent /></head>
      <body>{children}<Scripts /></body>
    </html>
  );
}

// ── App with auth + WS + permission popups ────────────────────────────
function AppWithWS() {
  const navigate   = useNavigate();
  const location   = useLocation();
  const [showWizard,      setShowWizard]      = useState(false);
  const [pendingPopup,    setPendingPopup]     = useState<WizardQuestion | null>(null);
  const [wizardDismissed, setWizardDismissed]  = useState(false);
  const [actionConfirm,   setActionConfirm]    = useState<ActionConfirm | null>(null);
  const [authChecked,     setAuthChecked]      = useState(false);

  const { online } = useBackendStatus();
  const { connected, startMonitoring, answerPopup, dismissPopup } = useWebSocket(
    (q) => { if (!wizardDismissed) setPendingPopup(q); }
  );

  // Register global confirm handler
  useEffect(() => {
    showActionConfirm = (opts) => new Promise<boolean>((resolve) => {
      setActionConfirm({
        ...opts,
        onConfirm: () => { setActionConfirm(null); resolve(true);  },
        onCancel:  () => { setActionConfirm(null); resolve(false); },
      });
    });
  }, []);

  // Auth check + auto-login on startup
  useEffect(() => {
    if (authChecked) return;
    setAuthChecked(true);

    const isLoginPage = location.pathname === "/login";
    if (isLoginPage) return;

    const existing = getToken();
    if (existing) {
      connectWS();
      return;
    }

    // Try silent auto-login with default credentials
    const BASE = (import.meta.env.VITE_AISS_API_URL as string | undefined) ?? "http://localhost:8000";
    const tryLogin = async (email: string, pass: string) => {
      try {
        const r = await fetch(`${BASE}/api/auth/login`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ email, password: pass }),
        });
        if (r.ok) {
          const d = await r.json() as { access_token: string; refresh_token?: string };
          localStorage.setItem("aiss_token", d.access_token);
          if (d.refresh_token) localStorage.setItem("aiss_refresh_token", d.refresh_token);
          connectWS();
          return true;
        }
      } catch { /* offline */ }
      return false;
    };

    tryLogin("admin@aiss.local", "Admin123!")
      .then((ok) => {
        if (!ok) {
          // Backend up but no default user — redirect to login
          void navigate({ to: "/login" });
        }
      })
      .catch(() => {});
  }, [authChecked, location.pathname, navigate]);

  // Re-connect WS when backend comes online
  useEffect(() => {
    if (online && getToken()) connectWS();
  }, [online]);

  // Start monitoring once WS authenticated
  useEffect(() => {
    if (connected) setTimeout(() => startMonitoring(), 800);
  }, [connected, startMonitoring]);

  const isLoginPage = location.pathname === "/login";

  if (isLoginPage) return <Outlet />;

  return (
    <>
      <AppShell
        backendOnline={online}
        wsConnected={connected}
        onOpenWizard={() => setShowWizard(true)}
        onLogout={() => {
          localStorage.removeItem("aiss_token");
          localStorage.removeItem("aiss_refresh_token");
          void navigate({ to: "/login" });
        }}
      >
        <Outlet />
      </AppShell>

      {showWizard && <SetupWizard onClose={() => setShowWizard(false)} />}

      {pendingPopup && !showWizard && (
        <PopupQuestion
          question={pendingPopup}
          onAnswer={(value) => { answerPopup(pendingPopup.id, value); setPendingPopup(null); }}
          onDismiss={() => { dismissPopup(pendingPopup.id); setPendingPopup(null); setWizardDismissed(true); }}
        />
      )}

      {actionConfirm && <ActionConfirmModal confirm={actionConfirm} />}
    </>
  );
}

// ── Root component ────────────────────────────────────────────────────
function RootComponent() {
  const { queryClient } = Route.useRouteContext();
  return (
    <QueryClientProvider client={queryClient}>
      <AppWithWS />
      <Toaster position="bottom-right" />
    </QueryClientProvider>
  );
}
