import { createFileRoute, redirect } from "@tanstack/react-router";
import AgentPage from "../pages/AgentPage";
import { getToken } from "../lib/api";

export const Route = createFileRoute("/agent")({
  beforeLoad: () => {
    if (!getToken()) {
      throw redirect({ to: "/login" });
    }
  },
  head: () => ({
    meta: [
      { title: "Security Agent — AISS" },
      { name: "description", content: "Autonomous AI security orchestration agent" },
    ],
  }),
  component: AgentPage,
});
