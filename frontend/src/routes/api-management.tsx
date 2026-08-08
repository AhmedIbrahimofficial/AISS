import { createFileRoute } from "@tanstack/react-router";
import { ModulePage } from "@/components/soc/module";
import { MODULES } from "@/components/soc/modules";

const m = MODULES["api-management"]!;

export const Route = createFileRoute("/api-management")({
  head: () => ({
    meta: [
      { title: "API Management — AISS Security Operations" },
      { name: "description", content: "Integration keys, webhook health and outbound connector rate limits" },
      { property: "og:title", content: "API Management — AISS" },
      { property: "og:description", content: "Integration keys, webhook health and outbound connector rate limits" },
      { property: "og:type", content: "website" },
      { name: "twitter:card", content: "summary_large_image" },
    ],
  }),
  component: () => <ModulePage m={m} />,
});
