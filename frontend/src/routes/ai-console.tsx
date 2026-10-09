/**
 * /ai-console — redirects to Command Center (/).
 * The AI console is now fully integrated into the Command Center page.
 */
import { createFileRoute, redirect } from "@tanstack/react-router";

export const Route = createFileRoute("/ai-console")({
  beforeLoad: () => {
    throw redirect({ to: "/" });
  },
  component: () => null,
});
