/**
 * OAuth Callback Page
 *
 * SECURITY FIX: The backend no longer puts tokens in the URL fragment.
 * Instead the backend redirects to /oauth-callback?code=<one-time-code>
 * and this page exchanges that code for real tokens via a POST request
 * to /api/auth/oauth/exchange. Tokens are received in the JSON body —
 * never in URLs, fragments, or browser history.
 */
import { createFileRoute, useNavigate } from "@tanstack/react-router";
import { useEffect, useState } from "react";
import { Shield, Loader2, CheckCircle, AlertTriangle } from "lucide-react";
import { setToken } from "@/lib/api";

export const Route = createFileRoute("/oauth-callback")({
  head: () => ({ meta: [{ title: "Connecting — AISS" }] }),
  component: OAuthCallbackPage,
});

const BASE_URL =
  (import.meta.env["VITE_AISS_API_URL"] as string | undefined) ??
  "http://localhost:8000";

function OAuthCallbackPage() {
  const navigate = useNavigate();
  const [status, setStatus] = useState<"loading" | "ok" | "error">("loading");
  const [message, setMessage] = useState("Completing authentication…");

  useEffect(() => {
    const run = async () => {
      // ── Read the one-time exchange code from the query string ──────
      const params = new URLSearchParams(window.location.search);
      const code = params.get("code");
      const errorParam = params.get("error");

      if (errorParam) {
        setStatus("error");
        setMessage(decodeURIComponent(errorParam));
        return;
      }

      if (!code) {
        setStatus("error");
        setMessage(
          "OAuth callback is missing the exchange code. Please try again."
        );
        return;
      }

      // ── Exchange the one-time code for real tokens (POST, not URL) ──
      try {
        const res = await fetch(`${BASE_URL}/api/auth/oauth/exchange`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ code }),
        });

        if (!res.ok) {
          const err = await res
            .json()
            .catch(() => ({ detail: res.statusText })) as { detail?: string };
          setStatus("error");
          setMessage(err.detail ?? "Token exchange failed. Please try again.");
          return;
        }

        const data = await res.json() as {
          access_token: string;
          refresh_token: string;
          onboarding_done: boolean;
          token_type: string;
        };

        // Store tokens in localStorage (same as email/password login)
        setToken(data.access_token);
        localStorage.setItem("aiss_refresh_token", data.refresh_token);

        // Clean the URL — remove the one-time code from browser history
        window.history.replaceState(null, "", window.location.pathname);

        setStatus("ok");
        setMessage("Authentication successful!");

        // Navigate based on onboarding state
        const isFirstRun = !data.onboarding_done;
        setTimeout(() => {
          if (isFirstRun) {
            void navigate({ to: "/onboarding" });
          } else {
            localStorage.setItem("aiss_onboarding_done", "1");
            void navigate({ to: "/" });
          }
        }, 900);
      } catch (err) {
        setStatus("error");
        setMessage(
          err instanceof Error
            ? err.message
            : "An unexpected error occurred. Please try again."
        );
      }
    };

    void run();
  }, [navigate]);

  return (
    <div className="flex min-h-screen items-center justify-center bg-[#070d0b]">
      <div className="text-center">
        <div className="mx-auto mb-6 flex size-20 items-center justify-center rounded-2xl border border-primary/20 bg-primary/8">
          {status === "loading" && (
            <Shield className="size-10 text-primary animate-pulse" />
          )}
          {status === "ok" && (
            <CheckCircle className="size-10 text-[var(--success)]" />
          )}
          {status === "error" && (
            <AlertTriangle className="size-10 text-[var(--critical)]" />
          )}
        </div>

        {status === "loading" && (
          <div className="flex items-center justify-center gap-2 text-muted-foreground">
            <Loader2 className="size-4 animate-spin" />
            <span className="text-sm">{message}</span>
          </div>
        )}

        {status === "ok" && (
          <>
            <p className="text-sm font-medium text-[var(--success)]">
              {message}
            </p>
            <p className="mt-1 text-xs text-muted-foreground">
              Redirecting to dashboard…
            </p>
          </>
        )}

        {status === "error" && (
          <>
            <p className="text-sm font-medium text-[var(--critical)]">
              Authentication failed
            </p>
            <p className="mt-1 max-w-xs text-xs text-muted-foreground">
              {message}
            </p>
            <button
              onClick={() => void navigate({ to: "/login" })}
              className="mt-4 rounded-lg border border-[var(--hairline)] px-4 py-2 text-xs text-muted-foreground hover:text-foreground transition-colors"
            >
              Back to login
            </button>
          </>
        )}
      </div>
    </div>
  );
}
