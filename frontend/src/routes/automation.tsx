import { createFileRoute } from "@tanstack/react-router";
import { ModulePage } from "@/components/soc/module";
import { MODULES } from "@/components/soc/modules";

const m = MODULES["automation"]!;

export const Route = createFileRoute("/automation")({
  head: () => ({
    meta: [
      { title: "Automation — AISS Security Operations" },
      { name: "description", content: "Autonomous response policy, guardrails and machine-speed actions" },
      { property: "og:title", content: "Automation — AISS" },
      { property: "og:description", content: "Autonomous response policy, guardrails and machine-speed actions" },
      { property: "og:type", content: "website" },
      { name: "twitter:card", content: "summary_large_image" },
    ],
  }),
  component: () => <ModulePage m={m} />,
});
