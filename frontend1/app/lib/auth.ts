/**
 * Auth helpers — token storage + auto-refresh
 * Tokens stored in localStorage (long-lived) AND cookies (for middleware).
 */

const API = "http://localhost:8000/api";

// ── Storage ───────────────────────────────────────────────────────────

export function saveTokens(accessToken: string, refreshToken: string, isVerified: boolean) {
  if (typeof window === "undefined") return;

  localStorage.setItem("access_token",  accessToken);
  localStorage.setItem("refresh_token", refreshToken);
  localStorage.setItem("is_verified",   String(isVerified));

  // Cookies for middleware — 7 days
  const expires = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toUTCString();
  document.cookie = `access_token=${accessToken}; path=/; expires=${expires}; SameSite=Lax`;
  document.cookie = `is_verified=${isVerified}; path=/; expires=${expires}; SameSite=Lax`;
}

export function clearTokens() {
  if (typeof window === "undefined") return;
  localStorage.removeItem("access_token");
  localStorage.removeItem("refresh_token");
  localStorage.removeItem("is_verified");
  document.cookie = "access_token=; path=/; max-age=0";
  document.cookie = "is_verified=; path=/; max-age=0";
}

export function getAccessToken(): string {
  if (typeof window === "undefined") return "";
  return localStorage.getItem("access_token") || "";
}

export function getRefreshToken(): string {
  if (typeof window === "undefined") return "";
  return localStorage.getItem("refresh_token") || "";
}

export function isLoggedIn(): boolean {
  return !!getAccessToken();
}

// ── Auto refresh ──────────────────────────────────────────────────────

/**
 * Try to refresh the access token silently.
 * Returns new access token on success, null on failure (session expired).
 */
export async function refreshAccessToken(): Promise<string | null> {
  const refreshToken = getRefreshToken();
  if (!refreshToken) return null;

  try {
    const res = await fetch(`${API}/auth/refresh`, {
      method:  "POST",
      headers: { "Content-Type": "application/json" },
      body:    JSON.stringify({ refresh_token: refreshToken }),
    });

    if (!res.ok) {
      clearTokens();
      return null;
    }

    const data = await res.json();
    // Fetch updated profile to get is_verified
    const profile = await fetchProfile(data.access_token);
    saveTokens(data.access_token, data.refresh_token, profile?.is_verified ?? false);
    return data.access_token;
  } catch {
    return null;
  }
}

// ── Fetch with auto-refresh ───────────────────────────────────────────

/**
 * Authenticated fetch — automatically refreshes token on 401.
 * Use this instead of raw fetch() on all protected API calls.
 */
export async function authFetch(
  url: string,
  options: RequestInit = {}
): Promise<Response> {
  let token = getAccessToken();

  const makeRequest = (t: string) =>
    fetch(url, {
      ...options,
      headers: {
        "Content-Type": "application/json",
        ...options.headers,
        Authorization: `Bearer ${t}`,
      },
    });

  let res = await makeRequest(token);

  // Token expired → try refresh once
  if (res.status === 401) {
    const newToken = await refreshAccessToken();
    if (!newToken) {
      clearTokens();
      window.location.href = "/login";
      return res;
    }
    res = await makeRequest(newToken);
  }

  return res;
}

// ── Profile ───────────────────────────────────────────────────────────

export async function fetchProfile(token?: string): Promise<Record<string, unknown> | null> {
  const t = token || getAccessToken();
  if (!t) return null;
  try {
    const res = await fetch(`${API}/auth/me`, {
      headers: { Authorization: `Bearer ${t}` },
    });
    return res.ok ? res.json() : null;
  } catch {
    return null;
  }
}

// ── Logout ────────────────────────────────────────────────────────────

export async function logout() {
  const refreshToken = getRefreshToken();
  if (refreshToken) {
    fetch(`${API}/auth/logout`, {
      method:  "POST",
      headers: { "Content-Type": "application/json" },
      body:    JSON.stringify({ refresh_token: refreshToken }),
    }).catch(() => {});
  }
  clearTokens();
  window.location.href = "/login";
}
