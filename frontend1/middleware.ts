/**
 * Next.js Edge Middleware — Route Protection
 *
 * Protected pages: /docs, /dashboard, /importance, /team
 * Auth pages: /login, /register  (redirect to dashboard if already logged in)
 *
 * Flow:
 *   No token      → redirect to /login?next=<intended-url>
 *   Has token but not verified → redirect to /verify-pending
 *   Has token + verified → allow through
 */

import { NextResponse } from "next/server";
import type { NextRequest } from "next/server";

// Pages that require login + email verification
const PROTECTED = ["/docs", "/dashboard", "/importance", "/team"];

// Pages only for guests (redirect logged-in users away)
const GUEST_ONLY = ["/login", "/register"];

export function middleware(request: NextRequest) {
  // Auth protection temporarily disabled
  // Uncomment the block below to re-enable login requirements
  return NextResponse.next();

  /*
  const { pathname } = request.nextUrl;

  const accessToken  = request.cookies.get("access_token")?.value;
  const isVerified   = request.cookies.get("is_verified")?.value === "true";

  const isProtected = PROTECTED.some(p => pathname.startsWith(p));
  const isGuestOnly = GUEST_ONLY.some(p => pathname.startsWith(p));

  if (isProtected && !accessToken) {
    const url = request.nextUrl.clone();
    url.pathname = "/login";
    url.searchParams.set("next", pathname);
    return NextResponse.redirect(url);
  }

  if (isProtected && accessToken && !isVerified) {
    const url = request.nextUrl.clone();
    url.pathname = "/verify-pending";
    url.searchParams.set("next", pathname);
    return NextResponse.redirect(url);
  }

  if (isGuestOnly && accessToken && isVerified) {
    const url = request.nextUrl.clone();
    url.pathname = "/dashboard";
    return NextResponse.redirect(url);
  }

  return NextResponse.next();
  */
}

export const config = {
  // Run middleware on these paths only (skip static files, API)
  matcher: [
    "/docs/:path*",
    "/dashboard/:path*",
    "/importance/:path*",
    "/team/:path*",
    "/login",
    "/register",
  ],
};
