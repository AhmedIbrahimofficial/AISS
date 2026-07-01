/**
 * Simple API helper — no authentication required.
 */

export const API = "http://localhost:8000/api";

/**
 * Fetch wrapper for API calls.
 * Use this instead of raw fetch() for all backend calls.
 */
export async function apiFetch(
  url: string,
  options: RequestInit = {}
): Promise<Response> {
  return fetch(url, {
    ...options,
    headers: {
      "Content-Type": "application/json",
      ...options.headers,
    },
  });
}
