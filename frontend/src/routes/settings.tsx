/**
 * /settings — redirects to /system (the new consolidated settings page).
 * Kept for backward-compat so bookmarks and old links don't 404.
 */
import { createFileRoute, redirect } from "@tanstack/react-router";

export const Route = createFileRoute("/settings")({
  beforeLoad: () => {
    throw redirect({ to: "/system" });
  },
  component: () => null,
});
