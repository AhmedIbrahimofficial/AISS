import { createFileRoute } from "@tanstack/react-router";
import { ModulePage } from "@/components/soc/module";
import { MODULES } from "@/components/soc/modules";

const m = MODULES["audit-logs"]!;

export const Route = createFileRoute("/audit-logs")({
  head: () => ({
    meta: [
      { title: "Audit Logs — AISS Security Operations" },
      { name: "description", content: "Immutable record of operator, policy and automation actions" },
      { property: "og:title", content: "Audit Logs — AISS" },
      { property: "og:description", content: "Immutable record of operator, policy and automation actions" },
      { property: "og:type", content: "website" },
      { name: "twitter:card", content: "summary_large_image" },
    ],
  }),
  component: () => <ModulePage m={m} />,
});
