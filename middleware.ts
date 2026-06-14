import { clerkMiddleware } from "@clerk/nextjs/server";

// Public middleware — no route protection
// Dashboard is protected via page-level auth check instead
export default clerkMiddleware();

export const config = {
  matcher: [
    "/((?!_next/static|_next/image|favicon.ico|.*\\.(?:svg|png|jpg|jpeg|gif|webp)$).*)",
  ],
};
