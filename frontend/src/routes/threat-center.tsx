import { createFileRoute } from "@tanstack/react-router";
import { ModulePage } from "@/components/soc/module";
import { MODULES } from "@/components/soc/modules";

const m = MODULES["threat-center"]!;

export const Route = createFileRoute("/threat-center")({
  head: () => ({
    meta: [
      { title: "Threat Center — AISS Security Operations" },
      { name: "description", content: "Unified detection queue across endpoint, identity, network and cloud sensors" },
      { property: "og:title", content: "Threat Center — AISS" },
      { property: "og:description", content: "Unified detection queue across endpoint, identity, network and cloud sensors" },
      { property: "og:type", content: "website" },
      { name: "twitter:card", content: "summary_large_image" },
    ],
  }),
  component: () => <ModulePage m={m} />,
});
