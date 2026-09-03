/**
 * AISS — SSO (Single Sign-On) Desktop Handoff
 *
 * When the AISS website has authenticated a user, it issues a one-time
 * SSO token and opens the dashboard with ?sso=<token> in the URL.
 *
 * This module detects that token on startup, redeems it server-side
 * for real JWT + refresh tokens, and sets them so the user never has
 * to log in again.
 *
 * Security notes:
 *  - The SSO token is single-use and expires in 60 s.
 *  - The actual JWT is returned in a POST response body — never in a URL.
 *  - After redemption the sso param is removed from the URL + history.
 */

import { setToken } from "./api";

const BASE_URL =
  (import.meta.env["VITE_AISS_API_URL"] as string | undefined) ??
  "http://localhost:8000";

export interface SSOResult {
  success: boolean;
  error?: string;
}

/**
 * Check for an SSO token in the current URL query string.
 * If found, redeem it for real AISS tokens.
 * Call this once near app startup BEFORE the normal auth flow.
 */
export async function trySSO(): Promise<SSOResult> {
  const params = new URLSearchParams(window.location.search);
  const ssoToken = params.get("sso");

  if (!ssoToken) {
    return { success: false };   // no SSO param — normal auth flow
  }

  // Remove the SSO token from the URL immediately so it doesn't linger
  // in browser history, logs, or bookmarks.
  params.delete("sso");
  const newSearch = params.toString();
  const newUrl =
    window.location.pathname + (newSearch ? `?${newSearch}` : "");
  window.history.replaceState(null, "", newUrl);

  try {
    const res = await fetch(`${BASE_URL}/api/sso/redeem`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ sso_token: ssoToken }),
      signal: AbortSignal.timeout(10_000),
    });

    if (!res.ok) {
      const err = (await res.json().catch(() => ({ detail: res.statusText }))) as {
        detail?: string;
      };
      return {
        success: false,
        error: err.detail ?? `SSO redemption failed (HTTP ${res.status})`,
      };
    }

    const data = (await res.json()) as {
      access_token: string;
      refresh_token: string;
    };

    if (!data.access_token || !data.refresh_token) {
      return { success: false, error: "SSO response missing tokens" };
    }

    setToken(data.access_token);
    localStorage.setItem("aiss_refresh_token", data.refresh_token);
    localStorage.setItem("aiss_onboarding_done", "1");

    return { success: true };
  } catch (err) {
    return {
      success: false,
      error: err instanceof Error ? err.message : "SSO network error",
    };
  }
}
