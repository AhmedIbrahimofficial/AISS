import { createFileRoute } from "@tanstack/react-router";
import { ModulePage } from "@/components/soc/module";
import { MODULES } from "@/components/soc/modules";

const m = MODULES["incident-response"]!;

export const Route = createFileRoute("/incident-response")({
  head: () => ({
    meta: [
      { title: "Incident Response — AISS Security Operations" },
      { name: "description", content: "Case management, war-room coordination and containment tracking" },
      { property: "og:title", content: "Incident Response — AISS" },
      { property: "og:description", content: "Case management, war-room coordination and containment tracking" },
      { property: "og:type", content: "website" },
      { name: "twitter:card", content: "summary_large_image" },
    ],
  }),
  component: () => <ModulePage m={m} />,
});
