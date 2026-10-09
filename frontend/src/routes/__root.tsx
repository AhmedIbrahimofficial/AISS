import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import {
  Outlet, Link, createRootRouteWithContext,
  useRouter, HeadContent, Scripts, useNavigate, useLocation,
} from "@tanstack/react-router";
import { useEffect, useState, useCallback, useRef, type ReactNode } from "react";
import { toast } from "sonner";
import { ApprovalModal } from "@/components/agent/ApprovalModal";
import agentApi, { type ApprovalRequest } from "@/api/agentApi";
import { onWSEvent } from "@/lib/api";

import appCss from "../styles.css?url";
import { reportLovableError } from "../lib/lovable-error-reporting";
import { AppShell } from "../components/soc/AppShell";
import { Toaster } from "@/components/ui/sonner";
import { SetupWizard, PopupQuestion } from "@/components/soc/SetupWizard";
import { useWebSocket, useBackendStatus } from "@/hooks/useAISS";
import {
  connectWS, disconnectWS, getToken, setToken, silentRefresh, type WizardQuestion,
} from "@/lib/api";
import { trySSO } from "@/lib/sso";
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

// ── Action confirm modal ──────────────────────────────────────────────
type PermissionLevel = "info" | "warning" | "critical" | "success";
interface ActionConfirm {
  title: string; description: string; level: PermissionLevel;
  onConfirm: () => void; onCancel: () => void;
}

function ActionConfirmModal({ confirm }: { confirm: ActionConfirm }) {
  const icons = {
    info:     <Info className="size-5 text-[var(--cyan)]" />,
    warning:  <AlertTriangle className="size-5 text-[var(--warning)]" />,
    critical: <Lock className="size-5 text-[var(--critical)]" />,
    success:  <CheckCircle className="size-5 text-[var(--success)]" />,
  };
  const colors = {
    info: "border-[var(--cyan)]/30 bg-[var(--cyan)]/5",
    warning: "border-[var(--warning)]/30 bg-[var(--warning)]/5",
    critical: "border-[var(--critical)]/30 bg-[var(--critical)]/5",
    success: "border-[var(--success)]/30 bg-[var(--success)]/5",
  };
  const btnColors = {
    info: "border-[var(--cyan)]/40 bg-[var(--cyan)]/10 text-[var(--cyan)] hover:bg-[var(--cyan)]/20",
    warning: "border-[var(--warning)]/40 bg-[var(--warning)]/10 text-[var(--warning)] hover:bg-[var(--warning)]/20",
    critical: "border-[var(--critical)]/40 bg-[var(--critical)]/10 text-[var(--critical)] hover:bg-[var(--critical)]/20",
    success: "border-[var(--success)]/40 bg-[var(--success)]/10 text-[var(--success)] hover:bg-[var(--success)]/20",
  };
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4">
      <div className="absolute inset-0 bg-black/60 backdrop-blur-sm" onClick={confirm.onCancel} />
      <div className={`relative w-full max-w-sm rounded-xl border p-6 shadow-2xl ${colors[confirm.level]} bg-[#0d1a15]`}>
        <button onClick={confirm.onCancel} className="absolute right-3 top-3 rounded-md p-1 text-muted-foreground hover:text-foreground">
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
        <p className="text-sm text-muted-foreground leading-relaxed mb-5">{confirm.description}</p>
        <div className="flex gap-2">
          <button onClick={confirm.onConfirm}
            className={`flex-1 rounded-lg border px-4 py-2 text-sm font-semibold transition-colors ${btnColors[confirm.level]}`}>
            Confirm & Execute
          </button>
          <button onClick={confirm.onCancel}
            className="rounded-lg border border-[var(--hairline)] px-4 py-2 text-sm text-muted-foreground hover:text-foreground transition-colors">
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

// ── CORE AUTH LOGIC ───────────────────────────────────────────────────
const BASE_URL = (() => {
  if (typeof window === "undefined") return "http://localhost:8000";
  return (import.meta.env["VITE_AISS_API_URL"] as string | undefined) ?? "http://localhost:8000";
})();

/**
 * Auto-login is REMOVED.
 * The launcher injects VITE_DISABLE_AUTO_LOGIN=true, and even without
 * that flag this function no longer exists. Users must log in explicitly
 * via the /login page or Google OAuth.
 */

async function validateToken(tok: string): Promise<boolean> {
  try {
    const r = await fetch(`${BASE_URL}/api/auth/me`, {
      headers: { Authorization: `Bearer ${tok}` },
      signal: AbortSignal.timeout(3000),
    });
    return r.ok;
  } catch {
    return false;
  }
}

// ── App shell with auth ───────────────────────────────────────────────
function AppWithWS() {
  const navigate = useNavigate();
  const location = useLocation();
  const [showWizard, setShowWizard] = useState(false);
  const [pendingPopup, setPendingPopup] = useState<WizardQuestion | null>(null);
  const [wizardDismissed, setWizardDismissed] = useState(false);
  const [actionConfirm, setActionConfirm] = useState<ActionConfirm | null>(null);
  const [authed, setAuthed] = useState(false);
  const [agentApproval, setAgentApproval] = useState<ApprovalRequest | null>(null);
  const authRunning = useRef(false);

  const { online } = useBackendStatus();
  const { connected, startMonitoring, answerPopup, dismissPopup } = useWebSocket(
    (q) => { if (!wizardDismissed) setPendingPopup(q); }
  );

  // Register global confirm handler
  useEffect(() => {
    showActionConfirm = (opts) => new Promise<boolean>((resolve) => {
      setActionConfirm({
        ...opts,
        onConfirm: () => { setActionConfirm(null); resolve(true); },
        onCancel: () => { setActionConfirm(null); resolve(false); },
      });
    });
  }, []);

  // Listen for agent_approval_required events from WebSocket
  useEffect(() => {
    const off = onWSEvent((evt) => {
      if (evt.event === "agent_approval_required" && evt.approval) {
        setAgentApproval(evt.approval as ApprovalRequest);
        toast.warning("Action requires your approval", {
          description: `${(evt.approval as ApprovalRequest).tool_name?.replace(/_/g, " ")} — ${(evt.approval as ApprovalRequest).risk_level}`,
          duration: 10000,
        });
      }
    });
    return off;
  }, []);

  // ── Auth on mount — always ensure a valid token ───────────────────
  useEffect(() => {
    const isPublic = location.pathname === "/login"
      || location.pathname === "/signup"
      || location.pathname === "/onboarding"
      || location.pathname === "/oauth-callback";
    if (isPublic || authRunning.current) return;
    authRunning.current = true;

    const run = async () => {
      // Version-bump: clear stale tokens from old wrong email
      const storedVersion = localStorage.getItem("aiss_auth_v");
      if (storedVersion !== "v3") {
        setToken(null);
        localStorage.removeItem("aiss_refresh_token");
        localStorage.setItem("aiss_auth_v", "v3");
      }

      // ── 0. SSO handoff — check for ?sso= from the website ────────
      const ssoResult = await trySSO();
      if (ssoResult.success) {
        setAuthed(true);
        disconnectWS();
        setTimeout(() => connectWS(), 50);
        return;
      }

      const existing = getToken();
      const storedRefresh = localStorage.getItem("aiss_refresh_token");

      // ── If we have stored credentials, wait for backend to be ready
      // instead of immediately sending user to login page.
      // This handles the case where backend is still starting up (25-30s).
      if (existing || storedRefresh) {
        // Wait up to 60s for backend to come online
        let backendReady = false;
        for (let attempt = 0; attempt < 20; attempt++) {
          try {
            const r = await fetch(`${BASE_URL}/api/health`, {
              signal: AbortSignal.timeout(3000),
            });
            if (r.ok) { backendReady = true; break; }
          } catch { /* still starting */ }
          await new Promise(res => setTimeout(res, 3000));
        }

        if (!backendReady) {
          // Backend never came up — send to login to show error
          void navigate({ to: "/login" });
          return;
        }
      }

      // 1. Existing access token — validate it
      if (existing) {
        const valid = await validateToken(existing);
        if (valid) {
          setAuthed(true);
          disconnectWS();
          setTimeout(() => connectWS(), 50);
          await checkOnboardingState();
          return;
        }
        setToken(null);
      }

      // 2. Silent refresh from stored refresh token (30-day expiry)
      // This is the key path for "stay logged in" — user logged in once
      // with Google, refresh token is stored, never asked again for 30 days.
      const refreshed = await silentRefresh();
      if (refreshed) {
        setAuthed(true);
        disconnectWS();
        setTimeout(() => connectWS(), 50);
        await checkOnboardingState();
        return;
      }

      // 3. No valid session — send to login page
      void navigate({ to: "/login" });
    };

    const checkOnboardingState = async () => {
      const localDone = localStorage.getItem("aiss_onboarding_done");
      if (localDone) return; // already done locally, skip API call
      try {
        const { getOnboardingStatus } = await import("@/lib/api");
        const ob = await getOnboardingStatus();
        if (!ob.is_completed) {
          void navigate({ to: "/onboarding" });
        } else {
          localStorage.setItem("aiss_onboarding_done", "1");
        }
      } catch { /* backend route may not exist yet */ }
    };

    void run();
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // Re-connect WS when backend comes back online
  useEffect(() => {
    if (online && getToken()) connectWS();
  }, [online]);

  // Start monitoring once WS authenticated
  useEffect(() => {
    if (connected) setTimeout(() => startMonitoring(), 800);
  }, [connected, startMonitoring]);

  const isPublicPage = location.pathname === "/login"
    || location.pathname === "/signup"
    || location.pathname === "/onboarding"
    || location.pathname === "/oauth-callback";
  if (isPublicPage) return <Outlet />;

  return (
    <>
      <AppShell
        backendOnline={online}
        wsConnected={connected}
        onOpenWizard={() => setShowWizard(true)}
        onLogout={() => {
          setToken(null);
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
      {agentApproval && (
        <ApprovalModal
          approval={agentApproval}
          onApprove={async (id) => {
            try { await agentApi.approveAction(id); } catch { /* ignore */ }
            setAgentApproval(null);
          }}
          onReject={async (id) => {
            try { await agentApi.rejectAction(id); } catch { /* ignore */ }
            setAgentApproval(null);
          }}
        />
      )}
    </>
  );
}

function RootComponent() {
  const { queryClient } = Route.useRouteContext();
  return (
    <QueryClientProvider client={queryClient}>
      <AppWithWS />
      <Toaster position="bottom-right" />
    </QueryClientProvider>
  );
}
