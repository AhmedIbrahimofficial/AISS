import { NextResponse } from "next/server";
import type { NextRequest } from "next/server";

const PUBLIC = ["/login", "/setup", "/api/health", "/api/setup", "/api/auth/login"];

export function middleware(req: NextRequest) {
  const { pathname } = req.nextUrl;
  if (
    PUBLIC.some((p) => pathname === p || pathname.startsWith(p + "/")) ||
    pathname.startsWith("/_next") ||
    pathname.startsWith("/favicon")
  ) {
    return NextResponse.next();
  }

  // API auth enforced in route handlers; pages check cookie lightly
  if (pathname.startsWith("/api/")) {
    return NextResponse.next();
  }

  const session = req.cookies.get("aiss_session");
  if (!session && (pathname.startsWith("/dashboard") || pathname === "/")) {
    // let page redirect after health check — avoid blocking setup flow hard
    return NextResponse.next();
  }

  return NextResponse.next();
}

export const config = {
  matcher: ["/((?!_next/static|_next/image|.*\\.png$).*)"],
};
