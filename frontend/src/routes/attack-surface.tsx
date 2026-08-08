import { createFileRoute } from "@tanstack/react-router";
import { ModulePage } from "@/components/soc/module";
import { MODULES } from "@/components/soc/modules";

const m = MODULES["attack-surface"]!;

export const Route = createFileRoute("/attack-surface")({
  head: () => ({
    meta: [
      { title: "Attack Surface — AISS Security Operations" },
      { name: "description", content: "External exposure discovery, shadow IT and certificate hygiene" },
      { property: "og:title", content: "Attack Surface — AISS" },
      { property: "og:description", content: "External exposure discovery, shadow IT and certificate hygiene" },
      { property: "og:type", content: "website" },
      { name: "twitter:card", content: "summary_large_image" },
    ],
  }),
  component: () => <ModulePage m={m} />,
});
