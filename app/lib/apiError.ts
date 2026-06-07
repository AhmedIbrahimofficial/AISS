/**
 * Parses any FastAPI / backend error response into a clean string.
 *
 * FastAPI can return errors in multiple shapes:
 *   { detail: "string" }
 *   { detail: [{ msg: "...", loc: [...], type: "..." }] }  ← Pydantic validation
 *   { error: "string" }
 *   { message: "string" }
 */
export function parseApiError(data: unknown, fallback = "Something went wrong"): string {
  if (!data || typeof data !== "object") return fallback;

  const d = data as Record<string, unknown>;

  // Pydantic validation array
  if (Array.isArray(d.detail)) {
    return d.detail
      .map((e: unknown) => {
        if (typeof e === "object" && e !== null) {
          const err = e as Record<string, unknown>;
          // Clean up "Value error, " prefix Pydantic adds
          const msg = String(err.msg ?? "").replace(/^Value error,\s*/i, "");
          return msg || fallback;
        }
        return String(e);
      })
      .filter(Boolean)
      .join(" • ");
  }

  if (typeof d.detail  === "string") return d.detail;
  if (typeof d.error   === "string") return d.error;
  if (typeof d.message === "string") return d.message;

  return fallback;
}
