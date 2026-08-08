import { createFileRoute } from "@tanstack/react-router";
import { ModulePage } from "@/components/soc/module";
import { MODULES } from "@/components/soc/modules";

const m = MODULES["endpoints"]!;

export const Route = createFileRoute("/endpoints")({
  head: () => ({
    meta: [
      { title: "Endpoints — AISS Security Operations" },
      { name: "description", content: "Agent fleet health, live response sessions and endpoint risk scoring" },
      { property: "og:title", content: "Endpoints — AISS" },
      { property: "og:description", content: "Agent fleet health, live response sessions and endpoint risk scoring" },
      { property: "og:type", content: "website" },
      { name: "twitter:card", content: "summary_large_image" },
    ],
  }),
  component: () => <ModulePage m={m} />,
});
